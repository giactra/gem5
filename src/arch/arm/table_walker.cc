/*
 * Copyright (c) 2010, 2012-2018 ARM Limited
 * Copyright (c) 2018 Metempsy Technology Consulting
 * All rights reserved
 *
 * The license below extends only to copyright in the software and shall
 * not be construed as granting a license to any other intellectual
 * property including but not limited to intellectual property relating
 * to a hardware implementation of the functionality of the software
 * licensed hereunder.  You may use the software subject to the license
 * terms below provided that you ensure that this notice is replicated
 * unmodified and in its entirety in all distributions of the software,
 * modified or unmodified, in source code or in binary form.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met: redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer;
 * redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution;
 * neither the name of the copyright holders nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Authors: Ali Saidi
 *          Giacomo Gabrielli
 *          Ivan Pizarro
 */
#include "arch/arm/table_walker.hh"

#include <memory>

#include "arch/arm/mmu.hh"
#include "arch/arm/system.hh"
#include "cpu/base.hh"
#include "cpu/thread_context.hh"
#include "debug/Checkpoint.hh"
#include "debug/Drain.hh"
#include "debug/TLB.hh"
#include "debug/TLBVerbose.hh"
#include "debug/TableWalker.hh"
#include "dev/dma_device.hh"
#include "sim/system.hh"

using namespace ArmISA;

TableWalker::TableWalker(const Params *p)
    : ClockedObject(p), mmu(NULL), currState(NULL), id(0),
      currentId(-1), masterId(p->sys->getMasterId(this, name())),
      isStage2(p->is_stage2), numSquashable(p->num_squash_per_cycle),
      maxInflightWalks(p->max_inflight_walks), inflightWalks(0),
      doL1ShortDescEvent([this]{ doL1ShortDescriptorWrapper(); }, name()),
      doL2ShortDescEvent([this]{ doL2ShortDescriptorWrapper(); }, name()),
      doL0LongDescEvent([this]{ doL0LongDescriptorWrapper(); }, name()),
      doL1LongDescEvent([this]{ doL1LongDescriptorWrapper(); }, name()),
      doL2LongDescEvent([this]{ doL2LongDescriptorWrapper(); }, name()),
      doL3LongDescEvent([this]{ doL3LongDescriptorWrapper(); }, name()),
      LongDescEventByLevel { &doL0LongDescEvent, &doL1LongDescEvent,
                            &doL2LongDescEvent, &doL3LongDescEvent },
      doProcessEvent([this]{ processWalkWrapper(); }, name())
{
    // Cache system-level properties
    if (FullSystem) {
        ArmSystem *armSys = dynamic_cast<ArmSystem *>(p->sys);
        assert(armSys);
        haveSecurity = armSys->haveSecurity();
        _haveLPAE = armSys->haveLPAE();
        _haveVirtualization = armSys->haveVirtualization();
        physAddrRange = armSys->physAddrRange();
        _haveLargeAsid64 = armSys->haveLargeAsid64();
    } else {
        haveSecurity = _haveLPAE = _haveVirtualization = false;
        _haveLargeAsid64 = false;
        physAddrRange = 32;
    }

    for (int i = 0; i < p->port_slave_connection_count; i++) {
        cpuSidePort.push_back(new CpuSidePort(csprintf("%s.port%d", name(), i),
                                                this, 0));
    }

    memSidePort = new MemSidePort(csprintf("%s.port", name()), this, 0);

    id = 0;
    currentId = -1;
}

TableWalker::~TableWalker()
{
    ;
}

Port&
TableWalker::getPort(const std::string &if_name, PortID idx)
{
    if (if_name == "slave") {
        if (idx >= static_cast<PortID>(cpuSidePort.size())) {
            panic("TableWalker::getPort: unknown index %d\n", idx);
        }

        return *cpuSidePort[idx];
    } else if (if_name == "master") {
        return *memSidePort;
    } else {
        panic("TableWalker::getPort: unknown index %d\n", idx);
    }
}

bool
TableWalker::CpuSidePort::recvTimingReq(PacketPtr pkt)
{
    assert(pkt);
    TLB::TranslationState* tran =
        safe_cast<TLB::TranslationState*>(pkt->senderState);
    tran->ports.push_back(this);
    walker->walk(tran);

    return true;
}

Tick
TableWalker::CpuSidePort::recvAtomic(PacketPtr pkt)
{
    assert(pkt);
    TLB::TranslationState* tran =
        safe_cast<TLB::TranslationState*>(pkt->senderState);
    walker->walk(tran);

    return 0;
}

void
TableWalker::CpuSidePort::recvReqRetry()
{
    panic("%s:%s not implemented", __FILE__, __LINE__);
}

void
TableWalker::CpuSidePort::recvRespRetry()
{
    panic("%s:%s not implemented", __FILE__, __LINE__);
}

bool
TableWalker::MemSidePort::recvTimingResp(PacketPtr pkt)
{
    assert(pkt);

    // We are returning from a timing request to the memory or the stage 2
    // TLB with the descriptor data. Process the event that was saved before
    // sending the resquest
    TableWalker::WalkerState *walkerState =
        safe_cast<WalkerState*>(pkt->senderState);
    delete pkt;

    DPRINTF(TableWalker, "Timing response from %s for VA=%#x, desc_addr=%#x "
            "(%#x)\n", walkerState->tran->s2fs1walk ? "S2 TLB" : "memory",
            walkerState->address, walkerState->desc_addr, walkerState->data);

    walker->currentId = walkerState->id;
    walkerState->next_event->process();

    return true;
}

void
TableWalker::MemSidePort::recvReqRetry()
{
    for (int i = 0; i < retries.size(); i++) {
        PacketPtr pkt = retries.front();
        TableWalker::WalkerState M5_VAR_USED *walkerState =
            safe_cast<WalkerState*>(pkt->senderState);
        if (!sendTimingReq(pkt)) {
            DPRINTF(TableWalker, "Retrying timing request failed for address "
                    "%#x\n", walkerState->address);
        } else {
            DPRINTF(TableWalker, "Timing request retried successful for %#x\n",
                    walkerState->address);
            retries.pop_front();
        }
    }
}

void
TableWalker::setMMU(MMU *_mmu)
{
    mmu = _mmu;
}

void
TableWalker::walk(TLB::TranslationState* tran)
{
    statWalks++;

    bool timing = tran->timing;
    bool functional = tran->functional;

    assert(!(timing && functional));

    WalkerState* savedCurrState = NULL;

    if (!currState && !functional) {
        // For atomic mode, a new WalkerState instance should be only created
        // once per TLB. For timing mode, a new instance is generated for every
        // TLB miss.
        DPRINTF(TableWalker, "creating new instance of WalkerState\n");

        currState = new WalkerState(this, id++);
        currState->walker = this;
    } else if (functional) {
        // If we are mixing functional mode with timing (or even
        // atomic), we need to to be careful and clean up after
        // ourselves to not risk getting into an inconsistent state.
        DPRINTF(TableWalker, "creating functional instance of WalkerState\n");
        savedCurrState = currState;
        currState = new WalkerState(this, id++);
        currState->walker = this;
    } else if (timing) {
        // This is a translation that was completed and then faulted again
        // because some underlying parameters that affect the translation
        // changed out from under us (e.g. asid). It will either be a
        // misprediction, in which case nothing will happen or we'll use
        // this fault to re-execute the faulting instruction which should clean
        // up everything.
        if (currState->address == tran->req->getVaddr()) {
            ++statSquashedBefore;
            tran->fault = std::make_shared<ReExec>();
        }
    }

    currState->tlb = tran->tlb;

    statRequestOrigin[REQUESTED][tran->isFetch()]++;

    ThreadContext *tc = tran->tc;

    // ARM DDI 0487A.f (ARMv8 ARM) pg J8-5672
    // aarch32/translation/translation/AArch32.TranslateAddress dictates
    // even AArch32 EL0 will use AArch64 translation if EL1 is in AArch64.
    if (isStage2) {
        currState->el = EL1;
        currState->aarch64 = ELIs64(tc, EL2);
    } else {
        ExceptionLevel el = TLB::tranTypeEL(tran->cpsr, tran->tranType);
        currState->aarch64 = ELIs64(tc, el == EL0 ? EL1 : el);
        currState->el = el;
    }

    currState->tran = tran;
    currState->tc = tc;
    currState->sctlr = tran->sctlr;
    currState->timing = timing;
    currState->functional = functional;
    currState->stage2Req = !isStage2 && tran->stage2Req;
    currState->address = isStage2 ? tran->ipaddress : tran->vaddress;
    currState->physAddrRange = physAddrRange;

    bool long_desc_format = currState->aarch64 || tran->isHyp || isStage2 ||
                            tran->usingLongDescFormat;

    if (long_desc_format) {
        statWalksLongDescriptor++;
    } else {
        statWalksShortDescriptor++;
    }

    if (!currState->timing) {
        if (currState->aarch64) {
            translationTableWalk64(tran);
        } else if (long_desc_format) {
            translationTableWalkLD(tran);
        } else {
            translationTableWalkSD(tran);
        }

        delete currState;

        // If this was a functional non-timing access restore state to
        // how we found it.
        if (tran->functional) {
            currState = savedCurrState;
        } else {
            currState = NULL;
        }

        return;
    }

    DPRINTF(TableWalker, "Starting walk for %#x. Slots available: %u\n",
            currState->address, maxInflightWalks - inflightWalks);

    if (inflightWalks < maxInflightWalks) {
        if (currState->aarch64) {
            translationTableWalk64(tran);
        } else if (long_desc_format) {
            translationTableWalkLD(tran);
        } else {
            translationTableWalkSD(tran);
        }

        if (tran->fault != NoFault) {
            sendTimingResponse();
            delete currState;
            currState = NULL;
        }
    } else {
        DPRINTF(TableWalker, "Adding walk to the pending queue\n");
        pendingQueue.push_back(
            std::pair<uint64_t, WalkerState*>(currState->id, currState));
        currState = NULL;
        printPendingQueue();
    }
}

void
TableWalker::translationTableWalkSD(TLB::TranslationState* tran)
{
    Addr inputaddr = currState->address;
    auto& l1descaddr = currState->addrdesc;
    l1descaddr->vaddress = inputaddr;

    // Determine correct Translation Table Base register to use
    TTBCR ttbcr = tran->ttbcr;
    Addr ttbr;
    uint8_t n = ttbcr.n;
    bool disabled = false;

    DPRINTF(TableWalker, "Beginning table walk for address %#x, TTBCR: %#x, "
            "bits:%#x\n", inputaddr, ttbcr, n);

    increaseInflightWalks();

    statWalkWaitTime.sample(curTick() - currState->startTime);

    if ((n == 0) || !bits(inputaddr, 31, 32 - n)) {
        DPRINTF(TableWalker, " - Selecting TTBR0\n");
        ttbr = tran->ttbr0_el1; // AArch32 TTBR0 is mapped to AArch64 TTBR0_EL1
        disabled = ttbcr.pd0;
    } else {
        DPRINTF(TableWalker, " - Selecting TTBR1\n");
        ttbr = tran->ttbr1_el1; // AArch32 TTBR1 is mapped to AArch64 TTBR1_EL1
        disabled = ttbcr.pd1;
        n = 0; // TBR1 translations always work like N=0 TTBR0 translation
    }

    // Check if Translation Table Base Register is not disabled
    if (disabled) {
        currState->level = 1;
        translationFault(TlbEntry::DomainType::NoAccess, ArmFault::VmsaTran);
        statWalksShortTerminatedAtLevel[0]++;
        return;
    }

    // Obtain descriptor from initial lookup
    uint32_t table_index = bits(inputaddr, 31-n, 20);
    uint32_t translation_base = mbits(ttbr, 31, 14-n);

    ThreadContext* tc = tran->tc;

    Addr l1desc_addr = translation_base | (table_index << 2);

    uint8_t irgn = bits(ttbr, 6) | (bits(ttbr, 0) << 1); // TTBR.IRGN
    uint8_t rgn  = bits(ttbr, 4, 3);                     // TTBR.RGN
    uint8_t sh   = bits(ttbr, 5) | (bits(ttbr, 1) << 1); // TTBR.S:TTBR.NOS

    walkAttrDecode(tc, l1descaddr->memattrs, sh, rgn, irgn,
                    tran->aarch64EL, tran->sctlr, tran->hcr);

    DPRINTF(TableWalker, " - Descriptor at address %#x (%s)\n",
            l1desc_addr, tran->isSecure ? "s" : "ns");

    l1descaddr->paddress.physicaladdress = l1desc_addr;
    l1descaddr->paddress.ns = !tran->isSecure;

    // Trickbox address check
    Fault f = testWalk(l1desc_addr, sizeof(uint32_t),
                       TlbEntry::DomainType::NoAccess, L1);

    if (f) {
        DPRINTF(TLB, "Trickbox check caused fault on %#x\n",
                currState->address);
        currState->tran->fault = f;
        if (currState->timing) {
            nextWalk();
        } else {
            currState->tc = NULL;
            currState->req = NULL;
        }
        return;
    }

    Request::Flags flag = Request::PT_WALK;
    if (!currState->sctlr.c) {
        flag.set(Request::UNCACHEABLE);
    }
    if (tran->isSecure) {
        flag.set(Request::SECURE);
    }

    fetchDescriptor(4, flag, 1,&doL1ShortDescEvent,
                    &TableWalker::doL1ShortDescriptor);
}

void
TableWalker::translationTableWalkLD(TLB::TranslationState* tran)
{
    ThreadContext* tc = tran->tc;
    Addr baseregister = 0;
    auto& addrdesc = currState->addrdesc;
    MemoryAttributes* memattrs = addrdesc->memattrs;
    memattrs->type = TlbEntry::MemoryType::Normal;

    // Fixed parameters for the page table walk:
    //  grainsize = Log2(Size of Table)  - Size of Table is 4KB in AArch32
    //  stride = Log2(Address per Level) - Bits of address consumed at each lvl
    const int grainsize = 12;         // Log2(4KB page size)
    const int stride = grainsize - 3; // Log2(page size / 8 bytes)

    // Derived parameters for the page table walk:
    //  inputsize = Log2(Size of Input Address) - Input Address size in bits
    //  level = Level to start walk from
    // This means that the number of levels after start level = 3-level
    ExceptionLevel el = currState->el;

    bool basefound, disabled;
    int level;
    int inputsize = 0;

    Addr inputaddr = currState->address;

    addrdesc->vaddress = inputaddr;

    DPRINTF(TableWalker, "Beginning table walk for address %#x, TTBCR: %#x\n",
            inputaddr, tran->isHyp ? tran->htcr : tran->ttbcr);

    increaseInflightWalks();

    statWalkWaitTime.sample(curTick() - currState->startTime);

    if (!isStage2) {
        // First stage translation
        if (tran->isHyp) {
            DPRINTF(TableWalker, " - Selecting HTTBR (long-desc.)\n");

            HTCR htcr = tran->htcr;
            inputsize = 32 - htcr.t0sz;
            basefound = (inputsize == 32) || !bits(inputaddr, 31, inputsize);
            disabled = false;
            baseregister = tc->readMiscReg(MISCREG_HTTBR);
            walkAttrDecode(tc, memattrs, htcr.sh0, htcr.orgn0, htcr.irgn0,
                            el, tran->sctlr, tran->hcr);
            currState->lookupsecure = false;
            currState->singlepriv = true;
            currState->hierattrsdisabled = htcr.hpd;
        } else {
            basefound = false;
            disabled = false;

            TTBCR ttbcr = tran->ttbcr;

            uint8_t t0size = ttbcr.t0sz;

            if ((t0size == 0) || !bits(inputaddr, 31, 32-t0size)) {
                DPRINTF(TableWalker, " - Selecting TTBR0 (long-desc.)\n");

                inputsize = 32 - t0size;
                basefound = true;
                disabled = ttbcr.epd0;
                baseregister = tran->ttbr0_el1;
                walkAttrDecode(tc, memattrs, ttbcr.sh0, ttbcr.orgn0,
                                ttbcr.irgn0, tran->aarch64EL,
                                tran->sctlr, tran->hcr);
                currState->hierattrsdisabled = (ttbcr.t2e && ttbcr.hpd0);
            }

            uint8_t t1size = ttbcr.t1sz;

            if (((t1size == 0) && !basefound) ||
                ((t1size > 0) && isOnes(inputaddr, 31, 32-t1size)))
            {
                DPRINTF(TableWalker, " - Selecting TTBR1 (long-desc.)\n");

                inputsize = 32 - t1size;
                basefound = true;
                disabled = ttbcr.epd1;
                baseregister = tran->ttbr1_el1;
                walkAttrDecode(tc, memattrs, ttbcr.sh1, ttbcr.orgn1,
                                ttbcr.irgn1, tran->aarch64EL,
                                tran->sctlr, tran->hcr);
                currState->hierattrsdisabled = (ttbcr.t2e && ttbcr.hpd1);
            }

            currState->reversedescriptors = tran->sctlr.ee;
            currState->lookupsecure = tran->isSecure;
            currState->singlepriv = false;
        }

        // The starting level is the number of strudes needed to consume the
        // input address
        level = 4 - ceil((float)(inputsize - grainsize) / (float)(stride));
    } else {
        // Second stage translation
        DPRINTF(TableWalker, " - Selecting VTTBR (long-desc.)\n");

        VTCR_t vtcr = tc->readMiscReg(MISCREG_VTCR);

        // VTCR.S must match VTCR.T0SZ[3]

        int tsz = sext<4>(vtcr.t0sz);

        inputaddr = tran->ipaddress;
        inputsize = 32 - tsz;

        basefound = (inputsize == 40) || !bits(inputaddr, 39, inputsize);
        disabled = false;
        baseregister = tc->readMiscReg(MISCREG_VTTBR);
        walkAttrDecode(tc, memattrs, vtcr.irgn0, vtcr.orgn0, vtcr.sh0,
                        tran->aarch64EL, tran->sctlr, tran->hcr);
        currState->reversedescriptors = tran->sctlr.ee;
        currState->lookupsecure = false;
        currState->singlepriv = true;

        uint8_t startlevel = vtcr.sl0;
        level = 2 - startlevel;
        if (level <= 0) {
            basefound = false;
        }

        uint8_t startsizecheck = inputsize - ((3-level) * stride + grainsize);

        if ((startsizecheck < 1) || (startsizecheck > (stride + 4))) {
            basefound = false;
        }
    }

    if (!basefound || disabled) {
        translationFault(TlbEntry::DomainType::NoAccess, ArmFault::LpaeTran);
        statWalksLongTerminatedAtLevel[currState->level]++;
        return;
    }

    if (bits(baseregister, 47, 40)) {
        panic("%s:%s not implemented", __FILE__, __LINE__);
    }

    currState->baseregister = baseregister;
    currState->level = level;
    currState->inputsize = inputsize;

    // Bottom bound of the Base address is:
    // -Log2(8 bytes per entry)+Log2(Number of entries in starting level table)
    // Number of entries in starting level table =
    // -(Size of Input Addr)/((Addr per lvl)^(#lvl remaining)*(Size of Table))
    uint8_t baselowerbound = 3 + inputsize - ((3-level) * stride + grainsize);
    Addr baseaddress = mbits(baseregister, 39, baselowerbound);

    currState->ns_table = (currState->lookupsecure) ? false : true;

    uint8_t addrselecttop = inputsize - 1;
    uint8_t addrselectbottom = (3 - level) * stride + grainsize;

    uint64_t index = bits(inputaddr, addrselecttop, addrselectbottom) << 3;

    Addr desc_addr = baseaddress | index;
    addrdesc->paddress.physicaladdress = desc_addr;
    addrdesc->paddress.ns = !currState->lookupsecure;

    DPRINTF(TableWalker, " - Descriptor at address %#x (%s) (long-desc.)\n",
            desc_addr, currState->lookupsecure ? "s" : "ns");

    // Trickbox address check
    Fault f = testWalk(desc_addr, sizeof(uint64_t),
                       TlbEntry::DomainType::NoAccess, (LookupLevel) level);

    if (f) {
        DPRINTF(TLB, "Trickbox check caused fault on %#x\n",
                currState->address);
        currState->tran->fault = f;
        if (currState->timing) {
            nextWalk();
        } else {
            currState->tc = NULL;
            currState->req = NULL;
        }
        return;
    }

    Request::Flags flag = Request::PT_WALK;
    if (!currState->sctlr.c) {
        flag.set(Request::UNCACHEABLE);
    }
    if (tran->isSecure) {
        flag.set(Request::SECURE);
    }

    if (currState->timing) {
        fetchDescriptor(8, flag, level,
                LongDescEventByLevel[level], &TableWalker::doLongDescriptor);
    } else {
        fetchDescriptor(8, flag, -1,
                LongDescEventByLevel[level], &TableWalker::doLongDescriptor);
    }
}

void
TableWalker::translationTableWalk64(TLB::TranslationState* tran)
{
    assert(currState->aarch64);

    Addr inputaddr = currState->address;

    bool iswrite = tran->isWrite();
    bool s2fs1walk = tran->s2fs1walk;
    ExceptionLevel aarch64EL = tran->aarch64EL;

    ThreadContext* tc = tran->tc;

    tran->stage2Req &= !isStage2;

    currState->iswrite = iswrite;
    currState->s2fs1walk = s2fs1walk;

    DPRINTF(TableWalker, "Beginning table walk for address %#x, " "TCR: %#x\n",
            inputaddr, tran->tcr);

    increaseInflightWalks();

    statWalkWaitTime.sample(curTick() - currState->startTime);

    Addr baseregister;
    assert(currState);
    auto& addrdesc = currState->addrdesc;

    addrdesc->vaddress = inputaddr;
    MemoryAttributes* memattrs = addrdesc->memattrs;
    memattrs->type = TlbEntry::MemoryType::Normal;

    int level, firstblocklevel;
    bool largegrain, midgrain;
    bool basefound, disabled;

    largegrain = midgrain = false;
    basefound = disabled = false;

    uint8_t grainsize, stride, ps;
    uint32_t inputsize;

    // First stage translation
    if (!isStage2) {
        HCR hcr = tran->hcr;
        TTBCR ttbcr = tran->ttbcr;

        int top = mmu->addrTop(tc, inputaddr, true, aarch64EL, hcr, ttbcr);

        if (aarch64EL == EL3) {
            DPRINTF(TableWalker, " - Selecting TTBR0 (AArch64)\n");

            TCR tcr_el3 = tran->tcr;
            uint8_t tg0 = tcr_el3.tg0;

            largegrain = (tg0 == static_cast<uint8_t>(TG0::GRANULE_64KB));
            midgrain   = (tg0 == static_cast<uint8_t>(TG0::GRANULE_16KB));

            inputsize  = 64 - tcr_el3.t0sz;

            int inputsize_max = largegrain ? 52 : 48;

            if (inputsize > inputsize_max) {
                inputsize = inputsize_max;
            }

            int inputsize_min = 64 - 39;

            if (inputsize < inputsize_min) {
                panic("%s:%s not implemented", __FILE__, __LINE__);
            }

            ps = tcr_el3.ps;

            basefound = (inputsize >= inputsize_min) &&
                        (inputsize <= inputsize_max) &&
                        (!bits(inputaddr, top, inputsize));

            disabled = false;
            baseregister = tc->readMiscReg(MISCREG_TTBR0_EL3);

            SCTLR sctlr_el3 = tran->sctlr;

            walkAttrDecode(tc, memattrs, tcr_el3.sh0, tcr_el3.orgn0,
                            tcr_el3.irgn0, tran->aarch64EL,
                            sctlr_el3, tran->hcr);

            currState->reversedescriptors = sctlr_el3.ee;
            currState->lookupsecure = true;
            currState->singlepriv = true;
            currState->update_AF = tcr_el3.ha;
            currState->update_AP = tcr_el3.ha && tcr_el3.hd;
            currState->hierattrsdisabled = bits(tcr_el3, 24);
        } else if (ELIsInHost(tc, aarch64EL)) {
            TCR tcr_el2 = tran->tcr;
            SCTLR sctlr_el2 = tran->sctlr;

            if (bits(inputaddr, top) == 0) {
                uint8_t tg0 = tcr_el2.tg0;

                largegrain = (tg0 == static_cast<uint8_t>(TG0::GRANULE_64KB));
                midgrain   = (tg0 == static_cast<uint8_t>(TG0::GRANULE_16KB));

                inputsize = 64 - tcr_el2.t0sz;

                int inputsize_max = largegrain ? 52 : 48;
                int inputsize_min = 64 - 32;

                if (inputsize < inputsize_min) {
                    panic("%s:%s not implemented", __FILE__, __LINE__);
                }

                basefound = (inputsize >= inputsize_min) &&
                            (inputsize <= inputsize_max) &&
                            (!bits(inputaddr, top, inputsize));

                disabled = tcr_el2.epd0 == 1;
                baseregister = tc->readMiscReg(MISCREG_TTBR0_EL2);

                walkAttrDecode(tc, memattrs, tcr_el2.sh0, tcr_el2.orgn0,
                                tcr_el2.irgn0, tran->aarch64EL, sctlr_el2,
                                tran->hcr);

                currState->hierattrsdisabled = tcr_el2.hpd0 == 1;
            } else {
                panic("%s:%s not implemented", __FILE__, __LINE__);
            }

            ps = tcr_el2.ips;

            currState->reversedescriptors = sctlr_el2.ee == 1;
            currState->lookupsecure = tran->isSecure;
            currState->singlepriv = false;
            currState->update_AF = (tcr_el2.ha == 1);
            currState->update_AP = (tcr_el2.hd == 1) && currState->update_AF;
        } else if (aarch64EL == EL2) {
            DPRINTF(TableWalker, " - Selecting TTBR0 (AArch64)\n");

            TCR tcr_el2 = tran->tcr;

            inputsize = 64 - tcr_el2.t0sz;

            uint8_t tg0 = tcr_el2.tg0;

            largegrain = (tg0 == static_cast<uint8_t>(TG0::GRANULE_64KB));
            midgrain   = (tg0 == static_cast<uint8_t>(TG0::GRANULE_16KB));

            int inputsize_max = largegrain ? 52 : 48;

            if (inputsize > inputsize_max) {
                inputsize = inputsize_max;
            }

            int inputsize_min = 64 - 39;

            if (inputsize < inputsize_min) {
                inputsize = inputsize_min;
            }

            ps = tcr_el2.ps;

            basefound = (inputsize >= inputsize_min) &&
                        (inputsize <= inputsize_max) &&
                        (!bits(inputaddr, top, inputsize));

            disabled = false;
            baseregister = tc->readMiscReg(MISCREG_TTBR0_EL2);

            SCTLR sctlr_el2 = tran->sctlr;

            walkAttrDecode(tc, memattrs, tcr_el2.sh0, tcr_el2.orgn0,
                            tcr_el2.irgn0, tran->aarch64EL,
                            sctlr_el2, tran->hcr);

            currState->reversedescriptors = sctlr_el2.ee;
            currState->lookupsecure = false;
            currState->singlepriv = true;
            currState->update_AF = tcr_el2.ha;
            currState->update_AP = tcr_el2.ha && tcr_el2.hd;
            currState->hierattrsdisabled = bits(tcr_el2, 24);
        } else { // EL1
            TCR tcr_el1 = tran->tcr;
            SCTLR sctlr_el1 = tran->sctlr;

            if (bits(inputaddr, top) == 0) { // TTBR0_EL1
                DPRINTF(TableWalker, "- Selecting TTBR0 (AArch64)\n");

                inputsize  = 64 - tcr_el1.t0sz;

                uint8_t tg0 = tcr_el1.tg0;

                largegrain = (tg0 == static_cast<uint8_t>(TG0::GRANULE_64KB));
                midgrain   = (tg0 == static_cast<uint8_t>(TG0::GRANULE_16KB));

                int inputsize_max = largegrain ? 52 : 48;

                if (inputsize > inputsize_max) {
                    inputsize = inputsize_max;
                }

                int inputsize_min = 64 - 39;

                if (inputsize < inputsize_min) {
                    inputsize = inputsize_min;
                }

                basefound = (inputsize >= inputsize_min) &&
                            (inputsize <= inputsize_max) &&
                            (!bits(inputaddr, top, inputsize));

                disabled = (tcr_el1.epd0 == 1);
                baseregister = tran->ttbr0_el1;

                walkAttrDecode(tc, memattrs, tcr_el1.sh1, tcr_el1.orgn1,
                                tcr_el1.irgn1, tran->aarch64EL,
                                sctlr_el1, tran->hcr);

                currState->hierattrsdisabled = tcr_el1.hpd0;
            } else { // TTBR1_EL1
                DPRINTF(TableWalker, "- Selecting TTBR1 (AArch64)\n");

                inputsize = 64 - tcr_el1.t1sz;

                uint8_t tg1 = tcr_el1.tg1;

                largegrain = (tg1 == static_cast<uint8_t>(TG1::GRANULE_64KB));
                midgrain   = (tg1 == static_cast<uint8_t>(TG1::GRANULE_16KB));

                int inputsize_max = largegrain ? 52 : 48;

                if (inputsize > inputsize_max) {
                    inputsize = inputsize_max;
                }

                int inputsize_min = 64 - 39;

                if (inputsize < inputsize_min) {
                    inputsize = inputsize_min;
                }

                basefound = (inputsize >= inputsize_min) &&
                            (inputsize <= inputsize_max) &&
                            (isOnes(inputaddr, top, inputsize));

                disabled = (tcr_el1.epd1 == 1);
                baseregister = tran->ttbr1_el1;
                walkAttrDecode(tc, memattrs, tcr_el1.sh1, tcr_el1.orgn1,
                                tcr_el1.irgn1, tran->aarch64EL,
                                sctlr_el1, tran->hcr);

                currState->hierattrsdisabled = tcr_el1.hpd1;
            }

            ps = tcr_el1.ips;

            currState->reversedescriptors = sctlr_el1.ee;
            currState->lookupsecure = tran->isSecure;
            currState->singlepriv = false;
            currState->update_AF = tcr_el1.ha;
            currState->update_AP = tcr_el1.ha && tcr_el1.hd;
        }

        currState->inputsize = inputsize;

        if (largegrain) {
            grainsize = 16;      // Log2(64KB page size)
                                 // Largest block is 4TB (2^42 bytes)
            firstblocklevel = mmu->have52BitVAExt() ? 1 : 2;
        } else if (midgrain) {
            grainsize = 14;      // Log2(16KB page size)
            firstblocklevel = 2; // Largest block is 32MB (2^25 bytes)
        } else {
            grainsize = 12;      // Log2(4KB page size)
            firstblocklevel = 1; // Largest block is 1GB (2^30 bytes)
        }

        stride = grainsize - 3;
        // The starting level is the number of strides needed to consume the
        // input address
        level = 4 - ceil((float)(inputsize - grainsize) / (float)(stride));
    } else { // Second stage translation
        DPRINTF(TableWalker, " - Selecting VTTBR0 (AArch64 stage 2)\n");

        SCTLR sctlr_el2 = tran->sctlr;
        VTCR_t vtcr_el2 = tc->readMiscReg(MISCREG_VTCR_EL2);

        inputsize = 64 - vtcr_el2.t0sz64;

        uint8_t tg0 = vtcr_el2.tg0;

        largegrain = (tg0 == static_cast<uint8_t>(TG0::GRANULE_64KB));
        midgrain   = (tg0 == static_cast<uint8_t>(TG0::GRANULE_16KB));

        const uint8_t inputsize_max = largegrain ? 52 : 48;

        if (inputsize > inputsize_max) {
            inputsize = inputsize_max;
        }

        const uint8_t inputsize_min = 64 - 39;

        if (inputsize < inputsize_min) {
            inputsize = inputsize_min;
        }

        ps = vtcr_el2.ps;

        basefound = !bits(inputaddr, 63, inputsize);

        disabled = false;
        baseregister = tc->readMiscReg(MISCREG_VTTBR_EL2);
        walkAttrDecode(tc, memattrs, vtcr_el2.sh0, vtcr_el2.orgn0,
                vtcr_el2.irgn0, tran->aarch64EL, sctlr_el2,
                tran->hcr);

        currState->reversedescriptors = sctlr_el2.ee;
        currState->lookupsecure = true;
        currState->singlepriv = true;
        currState->update_AF = vtcr_el2.ha;
        currState->update_AP = vtcr_el2.ha && vtcr_el2.hd;

        uint8_t startlevel = vtcr_el2.sl0;

        if (largegrain) {
            grainsize = 16; // Log2 (64KB page size)
            level = 3 - startlevel;
            firstblocklevel = mmu->have52BitVAExt() ? 1 : 2;
        } else if (midgrain) {
            grainsize = 14; // Log2 (16KB page size)
            level = 3 - startlevel;
            firstblocklevel = 2;
        } else {
            grainsize = 12; // Log2 (4KB page size)
            level = 2 - startlevel;
            firstblocklevel = 1;
        }

        stride = grainsize - 3; // Log2(page size / 8 bytes)

        // Limits on IPA controls based on implemented PA size. Level 0 is
        // only supported by small grain translations
        if (largegrain) {
            // Level 1 only supported if implemented PA is greater than 2^42 B
            if ((level == 0) || ((level == 1) && mmu->PAMax(tc) <= 42)) {
                basefound = false;
            }
        } else if (midgrain) {
            // Level 1 only supported if implemented PA is greater than 2^40 B
            if ((level == 0) || ((level == 1) && mmu->PAMax(tc) <= 40)) {
                basefound = false;
            }
        } else {
            // Level 0 only supported if implemented PA is greater than 2^42 B
            if ((level < 0) || ((level == 0) && mmu->PAMax(tc) <= 42)) {
                basefound = false;
            }
        }

        uint8_t startsizecheck;
        uint8_t inputsizecheck = inputsize;

        // If the inputsize exceeds the PAMax value, the behavior is
        // CONSTRAINED UNPREDICTABLE

        // Number of entries in the starting level table
        startsizecheck = inputsizecheck - ((3 - level) * stride + grainsize);

        // Check for starting level table with fewer than 2 entries or longer
        // than 16 pages
        // Lower bound check is: startsizecheck < Log2(2 entries)
        // Upper bound check is: startsizecheck > Log2(pagesize/8*16)
        if ((startsizecheck < 1) || (startsizecheck > (stride + 4))) {
            basefound = false;
        }

        currState->stage2Req = false;
    }

    currState->stride = stride;
    currState->level = level;
    currState->firstblocklevel = firstblocklevel;

    currState->largegrain = largegrain;
    currState->midgrain = midgrain;
    currState->grainsize = grainsize;

    if (!basefound || disabled) {
        currState->level = 0; // AArch32 reports this as a level 1 fault
        translationFault(TlbEntry::DomainType::NoAccess, ArmFault::LpaeTran);
        statWalksLongTerminatedAtLevel[currState->level]++;
        return;
    }

    // Determine physical address size and raise an Address Size Fault if
    // necessary
    int outputsize = decodePhysAddrRange64(ps);

    if (outputsize > physAddrRange)
        currState->physAddrRange = physAddrRange;
    else
        currState->physAddrRange = outputsize;

    currState->outputsize = currState->physAddrRange;

    // Bottom bound of the Base address is:
    // -Log2(8 bytes per entry)+Log2(Number of entries in starting level table)
    // Number of entries in starting level table =
    // -(Size of Input Addr)/((Addr per lvl)^(#lvl remaining)*(Size of Table))
    uint32_t baselowerbound = 3 + inputsize - ((3-level) * stride + grainsize);
    uint64_t baseaddress;

    if (outputsize == 52) {
        // ARM DDI 0487D.a (J1-7004)
        panic("%s:%s not implemented", __FILE__, __LINE__);
    } else {
        baseaddress = mbits(baseregister, 47, baselowerbound);
    }

    if (checkAddrSizeFaultAArch64(baseaddress, currState->physAddrRange)) {
        DPRINTF(TableWalker, "Address size fault before any lookup\n");
        currState->level = 0;
        addressSizeFault(TlbEntry::DomainType::NoAccess, ArmFault::LpaeTran,
                         false);
        statWalksLongTerminatedAtLevel[0]++;
        return;
    }

    currState->ns_table = !currState->lookupsecure;

    uint8_t addrselecttop = inputsize - 1;
    uint8_t addrselectbottom = (3 - level) * stride + grainsize;

    currState->addrselecttop = addrselecttop;
    currState->addrselectbottom = addrselectbottom;

    uint64_t index = bits(inputaddr, addrselecttop, addrselectbottom) << 3;

    addrdesc->paddress.physicaladdress = baseaddress | index;
    addrdesc->paddress.ns = currState->ns_table;

    // Trickbox address check
    Fault f = testWalk(addrdesc->paddress.physicaladdress, sizeof(uint64_t),
        TlbEntry::DomainType::NoAccess, toLookupLevel(level));

    if (f) {
        DPRINTF(TLB, "Trickbox check caused fault on %#x\n",
                currState->address);
        currState->tran->fault = f;
        if (currState->timing) {
            nextWalk();
        } else {
            currState->tc = NULL;
            currState->req = NULL;
        }
        return;
    }

    Request::Flags flag = Request::PT_WALK;
    if (!currState->sctlr.c) {
        flag.set(Request::UNCACHEABLE);
    }
    if (tran->isSecure) {
        flag.set(Request::SECURE);
    }

    if (currState->timing) {
        fetchDescriptor(8, flag, level,
            LongDescEventByLevel[level], &TableWalker::doAArch64Descriptor);
    } else {
        fetchDescriptor(8, flag, -1,
            LongDescEventByLevel[level], &TableWalker::doAArch64Descriptor);
    }
}

void
TableWalker::processWalkWrapper()
{
    // Nothing to process
    if (pendingQueue.size() == 0) {
        return;
    }

    currState = pendingQueue.front().second;

    // Check if a previous walk filled this request already
    bool tlb_hit = currState->tlb->lookup(currState->tran, false, true, false);

    TLB::Translation *translation = currState->tran->translation;

    // Check if we still need to have a walk for this request. If the
    // requesting instruction has been squashed, or a previous walk has filled
    // the TLB with a match, we just want to get rid of the walk. The latter
    // could happen when there are multiple outstanding misses to a single page
    // and a previous request has been successfully translated
    if (!translation->squashed() && !tlb_hit) {
        // We've got a valid request, lets process it
        pendingQueue.pop_front();

        TLB::TranslationState* tran = currState->tran;

        bool long_desc_format = currState->aarch64 || tran->isHyp ||
                                    isStage2 || tran->usingLongDescFormat;

        DPRINTF(TableWalker, "Processing walk %lu from pending queue\n",
                currState->id);

        if (currState->aarch64) {
            translationTableWalk64(tran);
        } else if (long_desc_format) {
            translationTableWalkLD(tran);
        } else {
            translationTableWalkSD(tran);
        }

        if (tran->fault != NoFault) {
            sendTimingResponse();
            delete currState;
            currState = NULL;
        }

        return;
    }

    // If the instruction that we were translating for has been squashed we
    // shouldn't bother
    unsigned num_squashed = 0;

    while ((num_squashed < numSquashable) && currState &&
            (translation->squashed() || tlb_hit))
    {
        pendingQueue.pop_front();
        num_squashed++;
        statSquashedBefore++;

        DPRINTF(TLB, "Squashing table walk for address %#x. Squashed(%u). "
                "TLB hit(%u)\n", currState->address, translation->squashed(),
                tlb_hit);

        if (translation->squashed()) {
            // The underlying instruction has been squashed and thus we have
            // to send this back to the TLB so it can clean its translation
            // structures
            currState->tran->finished = true;
            delete currState->tran;
            translation->finish(
                std::make_shared<UnimpFault>("Squashed Inst"),
                currState->tran->req, currState->tc, currState->tran->mode);
        } else {
            // A previous walk has filled the TLB which makes the current
            // walk to already hit in the TLB, no need to continue with it,
            // just send the response to the TLB with this information
            statWalkServiceTime.sample(curTick() - currState->startTime);
            sendTimingResponse();
        }

        // Delete the current request
        delete currState;

        // Peak at the next one
        if (pendingQueue.size()) {
            currState = pendingQueue.front().second;
            translation = currState->tran->translation;
            tlb_hit = currState->tlb->lookup(
                                        currState->tran, false, true, false);
        } else {
            // Terminate the loop, nothing more to do
            currState = NULL;
        }
    }

    // If we still have pending translations, schedule more work
    nextWalk();
    currState = NULL;
}

bool
TableWalker::checkAddrSizeFaultAArch64(Addr addr, int currPhysAddrRange)
{
    return (currPhysAddrRange != MaxPhysAddrRange &&
            bits(addr, MaxPhysAddrRange - 1, currPhysAddrRange));
}

void
TableWalker::doL1ShortDescriptorWrapper()
{
    auto it = stateQueues[1].find(currentId);
    assert(it != stateQueues[1].end());
    currState = it->second;
    currState->delayed = false;

    // If there's a stage 2 translation object we don't need it anymore
    if (currState->stage2Tran) {
        delete currState->stage2Tran;
        currState->stage2Tran = NULL;
    }

    DPRINTF(TableWalker, "L1 Desc object host addr: %p\n", &currState->data);
    DPRINTF(TableWalker, "L1 Desc object      data: %#x\n", currState->data);

    DPRINTF(TableWalker, "calling doL1Descriptor for vaddr:%#x\n",
            currState->address);

    statWalkServiceTime.sample(curTick() - currState->startTime);

    doL1ShortDescriptor();

    stateQueues[1].erase(currentId);

    if (currState->tran->fault != NoFault) {
        sendTimingResponse();
        cleanup();
    } else if (!currState->delayed) {
        // No additional lookups required
        // Don't finish the translation if a stage 2 lookup is underway
        if (!currState->stage2Tran) {
            sendTimingResponse();
        }
        cleanup();
    } else {
        stateQueues[2].insert(
            std::pair<uint64_t, WalkerState*>(currState->id, currState));
    }

    currState = NULL;
}

void
TableWalker::doL1ShortDescriptor()
{
    if (currState->tran->fault != NoFault) {
        return;
    }

    auto& addrdesc = currState->addrdesc;

    Addr vaddress = addrdesc->vaddress;
    uint32_t desc = (uint32_t) currState->data;

    DPRINTF(TableWalker, "L1 descriptor for %#x is %#x\n", vaddress, desc);

    insertPartialTranslation();

    if (currState->reversedescriptors) {
        panic("%s:%s not implemented", __FILE__, __LINE__);
    }

    // Process descriptor from initial lookup
    /*
     * Figure G4-4 VMSAv8-32 Short-descriptor level 1 descriptor formats
     * Figure G4-5           Short-descriptor level 2 descriptor formats
     * In the ARM Architecture Reference Manual (DDI0487C)
     */
    switch (bits(desc, 1, 0))
    {
        case SD_INVALID: // Fault, reserved
            currState->level = 1;
            translationFault(TlbEntry::DomainType::NoAccess,
                             ArmFault::VmsaTran);
            statWalksShortTerminatedAtLevel[0]++;
            return;

        case SD_PAGE_TABLE: // Large page or Small page
        {
            bool lookupsecure = currState->lookupsecure;

            // save the L1 descriptor before doing the L2 lookup because
            // we need some of its values to complete the translation
            currState->l1desc = desc;

            // Obtain descriptor from level 2 lookup
            addrdesc->paddress.physicaladdress = mbits(desc, 31, 10) |
                                                (bits(vaddress, 19, 12) << 2);
            addrdesc->paddress.ns = lookupsecure;

            DPRINTF(TableWalker, "L1 descriptor points to page table at: %#x"
                    "(%s)\n", addrdesc->paddress.physicaladdress,
                    lookupsecure ? "s" : "ns");

            // Trickbox address check
            Fault f = testWalk(addrdesc->paddress.physicaladdress,
                        sizeof(uint32_t),TlbEntry::DomainType::NoAccess, L1);

            if (f) {
                DPRINTF(TLB, "Trickbox check caused fault on %#x\n",
                        currState->address);
                currState->tran->fault = f;
                if (currState->timing) {
                    nextWalk();
                } else {
                    currState->tc = NULL;
                    currState->req = NULL;
                }
                return;
            }

            Request::Flags flag = Request::PT_WALK;
            if (currState->tran->isSecure) {
                flag.set(Request::SECURE);
            }

            fetchDescriptor(4, flag, -1,
                &doL2ShortDescEvent, &TableWalker::doL2ShortDescriptor);

            if (currState->timing)
                currState->delayed = true;
            return;
        }

        default:
            break;
    }

    // ARMv8 VMSAv8-32 does not support hardware management of the Access flag
    if (currState->sctlr.afe && bits(desc, 10)) {
        panic("%s:%s not implemented", __FILE__, __LINE__);
    }

    bool ns  = bits(desc, 19);
    bool nG  = bits(desc, 17);
    bool s   = bits(desc, 16);
    uint8_t ap  = bits(desc, 11, 10) | (bits(desc, 15) << 2);
    uint8_t tex = bits(desc, 14, 12);
    bool xn  = bits(desc, 4);
    bool c   = bits(desc, 3);
    bool b   = bits(desc, 2);
    bool pxn = bits(desc, 0);

    int blocksize;
    TlbEntry::DomainType domain;
    Addr outputaddress;

    if (bits(desc, 18) == 0) { // Section
        domain = static_cast<TlbEntry::DomainType>(bits(desc, 8, 5));
        blocksize = 1024 * 1024; // 1MB
        outputaddress = mbits(desc, 31, 20) | bits(vaddress, 19, 0);
    } else {                     // Supersection
        domain = TlbEntry::DomainType::NoAccess;
        blocksize = 16384 * 1024; // 16MB
        outputaddress = ((uint64_t)bits(desc, 8, 5) << 36) |
                        (bits(desc, 23, 20) << 20) |
                        (bits(desc, 31, 24) << 24) |
                         bits(vaddress, 23, 0);
    }

    MemoryAttributes *memattrs = addrdesc->memattrs;

    // Decode the TEX, C, B and S bits to produce the memory attributes
    if (currState->tran->sctlr.tre == 0) {
        defaultTEXDecode(memattrs, tex, c, b, s);
    } else {
        remappedTEXDecode(memattrs, tex, c, b, s);
    }

    // Set the rest of fields
    TLBRecord* result = new TLBRecord(addrdesc);

    bool isSecure = currState->tran->isSecure;

    result->perms.ap = ap;
    result->perms.xn = xn;
    result->perms.pxn = pxn;
    result->nG = nG;
    result->domain = domain;
    result->level = L1;
    result->blocksize = blocksize;
    result->addrdesc->paddress.physicaladdress = outputaddress;
    result->addrdesc->paddress.ns = isSecure ? ns : true;

    if (!isStage2)
        currState->tran->s1 = result;
    else
        currState->tran->s2 = result;
}

void
TableWalker::doL2ShortDescriptorWrapper()
{
    auto it = stateQueues[2].find(currentId);
    assert(it != stateQueues[2].end());
    currState = it->second;
    assert(currState->delayed);

    // If there's a stage 2 translation object we don't need it any more
    if (currState->stage2Tran) {
        delete currState->stage2Tran;
        currState->stage2Tran = NULL;
    }

    auto& M5_VAR_USED addrdesc = currState->addrdesc;

    DPRINTF(TableWalker, "calling doL2Descriptor for vaddr:%#x\n",
            addrdesc->vaddress);

    statWalkServiceTime.sample(curTick() - currState->startTime);

    doL2ShortDescriptor();

    if ((currState->tran->fault != NoFault) || (!isStage2)) {
        sendTimingResponse();
    }

    stateQueues[2].erase(currentId);

    cleanup();
    currState = NULL;
}

void
TableWalker::doL2ShortDescriptor()
{
    if (currState->tran->fault != NoFault) {
        return;
    }

    auto& addrdesc = currState->addrdesc;

    Addr vaddress = addrdesc->vaddress;

    uint32_t l2desc = (uint32_t) currState->data;
    uint32_t l1desc = currState->l1desc;

    DPRINTF(TableWalker, "L2 descriptor for %#x is %#x\n", vaddress, l2desc);

    insertPartialTranslation();

    if (currState->reversedescriptors) {
        panic("%s:%s not implemented", __FILE__, __LINE__);
    }

    TlbEntry::DomainType domain =
        static_cast<TlbEntry::DomainType>(bits(l1desc, 8, 5));

    // Process l2descriptor from level 2 lookup
    if (bits(l2desc, 1, 0) == 0) {
        currState->level = 2;
        translationFault(domain, ArmFault::VmsaTran);
        statWalksShortTerminatedAtLevel[1]++;
        return;
    }

    bool nG = bits(l2desc, 11);
    bool s  = bits(l2desc, 10);
    uint8_t ap = bits(l2desc, 5, 4) | (bits(l2desc, 9) << 2);

    if (currState->sctlr.afe && !bits(l2desc, 4)) {
        panic("%s:%s not implemented", __FILE__, __LINE__);
    }

    bool xn, c, b;
    uint8_t tex;
    int blocksize;
    Addr outputaddress;

    if (bits(l2desc, 1) == 0) { // Large page
        xn  = bits(l2desc, 15);
        tex = bits(l2desc, 14, 12);
        c   = bits(l2desc, 3);
        b   = bits(l2desc, 2);
        blocksize = 65536; // 64KB
        outputaddress = mbits(l2desc, 31, 16) | bits(vaddress, 15, 0);
    } else {                    // Small page
        tex = bits(l2desc, 8, 6);
        c   = bits(l2desc, 3);
        b   = bits(l2desc, 2);
        xn  = bits(l2desc, 0);
        blocksize = 4096; // 4KB
        outputaddress = mbits(l2desc, 31, 12) | bits(vaddress, 11, 0);
    }

    bool ns  = bits(l1desc, 3);
    bool pxn = bits(l1desc, 2);

    MemoryAttributes *memattrs = addrdesc->memattrs;

    // Decode the TEX, C, B and S bits to produce the memory attributes
    if (currState->tran->sctlr.tre == 0) {
        defaultTEXDecode(memattrs, tex, c, b, s);
    } else {
        remappedTEXDecode(memattrs, tex, c, b, s);
    }

    // Set the rest of fields
    TLBRecord* result = new TLBRecord(addrdesc);

    bool isSecure = currState->tran->isSecure;

    result->perms.ap = ap;
    result->perms.xn = xn;
    result->perms.pxn = pxn;
    result->nG = nG;
    result->domain = domain;
    result->level = L2;
    result->blocksize = blocksize;
    result->addrdesc->paddress.physicaladdress = outputaddress;
    result->addrdesc->paddress.ns = isSecure ? ns : true;

    if (!isStage2)
        currState->tran->s1 = result;
    else
        currState->tran->s2 = result;
}

void
TableWalker::doLongDescriptor()
{
    if (currState->tran->fault != NoFault) {
        return;
    }

    auto& addrdesc = currState->addrdesc;

    int level = currState->level;
    Addr inputaddr = addrdesc->vaddress;
    uint64_t desc = currState->data;

    DPRINTF(TableWalker, "L%d descriptor for %#x is %#x (long-desc.)\n",
            level, inputaddr, desc);

    insertPartialTranslation();

    if (currState->reversedescriptors) {
        panic("%s:%s not implemented", __FILE__, __LINE__);
    }

    if ((bits(desc, 0) == 0) || ((bits(desc, 1, 0) == 1 && level == 3))) {
        // Fault (00), Reserved (10) or Block (01) at level 3
        translationFault(TlbEntry::DomainType::NoAccess, ArmFault::LpaeTran);
        statWalksLongTerminatedAtLevel[level]++;
        return;
    }

    uint8_t addrselecttop = (level == 1) ? 29 : 20;
    uint8_t addrselectbottom = (level == 1) ? 21 : 12;

    // Block (01) Page (11)
    if (!((bits(desc, 1, 0) == 1) || (level == 3)))
    {
        if (bits(desc, 47, 40)) {
            panic("%s:%s not implemented", __FILE__, __LINE__);
        }

        Addr baseaddress = mbits(desc, 39, 12); // Grainsize always 12

        if (!isStage2) {
            // Unpack the upper and lower table attributes
            currState->ns_table |= bits(desc, 63);
        }

        if (!isStage2 && !currState->hierattrsdisabled) {
            currState->ap_table |= bits(desc, 63) << 1; // read-only
            currState->xn_table |= bits(desc, 62);

            // pxn_table and ap_table[0] apply only in EL1&0 translation
            // regimes
            if (!currState->singlepriv) {
                currState->pxn_table |= bits(desc, 59);
                currState->ap_table  |= bits(desc, 61); // privileged
            }
        }

        level++;
        currState->level = level;

        uint64_t index = bits(inputaddr, addrselecttop, addrselectbottom) << 3;

        addrdesc->paddress.physicaladdress = baseaddress | index;
        addrdesc->paddress.ns = !currState->lookupsecure;

        DPRINTF(TableWalker, "L%u descriptor points to L%u descriptor at: %#x "
                "(%s)\n", level-1, level, baseaddress | index,
                currState->lookupsecure ? "s" : "ns");

        // Trickbox address check
        Fault f;
        f = testWalk(addrdesc->paddress.physicaladdress, sizeof(uint64_t),
                    TlbEntry::DomainType::NoAccess, toLookupLevel(level));

        if (f) {
            DPRINTF(TLB, "Trickbox check caused fault on %#x\n",
                    currState->address);
            currState->tran->fault = f;
            if (currState->timing) {
                nextWalk();
            } else {
                currState->tc = NULL;
                currState->req = NULL;
            }
            return;
        }

        Request::Flags flag = Request::PT_WALK;
        if (currState->tran->isSecure) {
            flag.set(Request::SECURE);
        }

        bool delayed = fetchDescriptor(8, flag, -1,
                            LongDescEventByLevel[level],
                            &TableWalker::doLongDescriptor);

        if (delayed) {
            currState->delayed = true;
        }

        return;
    }

    // Check the output address is inside the supported range
    if (bits(desc, 47, 40)) {
        panic("%s:%s not implemented", __FILE__, __LINE__);
    }

    // Unpack the descriptor into address and upper and lower block attributes
    Addr outputaddress = mbits(desc, 39, addrselectbottom) |
                          bits(inputaddr, addrselectbottom-1, 0);

    // Check the access flag
    if (bits(desc, 10) == 0) {
        accessFlagFault(TlbEntry::DomainType::NoAccess, ArmFault::LpaeTran);
        statWalksLongTerminatedAtLevel[currState->level]++;
        return;
    }

    bool xn = bits(desc, 54);
    bool pxn = bits(desc, 53);
    bool contiguousbit = bits(desc, 52);
    bool nG = bits(desc, 11);
    uint8_t sh = bits(desc, 9, 8);
    uint8_t ap = (bits(desc, 7, 6) << 1) | 1;
    uint8_t memattr = bits(desc, 5, 2); // AttrIndx and NS bit in stage 1

    const int grainsize = 12;
    const int stride = grainsize - 3;

    TLBRecord* result = new TLBRecord(addrdesc);

    result->level = toLookupLevel(level);
    result->blocksize = exp2((3 - level) * stride + grainsize);

    // Stage 1 translation regimes also inherit attributes from the tables
    if (!isStage2) {
        uint8_t ap_table = currState->ap_table;
        uint8_t ns_table = currState->ns_table;
        uint8_t xn_table = currState->xn_table;

        result->perms.xn  = xn | xn_table;
        result->perms.ap |= (bits(ap, 2) | ap_table) << 2; // RO

        // PXN, nG and AP[1] apply only in EL1&0 stage 1 translations regimes
        if (!currState->singlepriv) {
            bool pxn_table = currState->pxn_table;
            // Force privileged only
            result->perms.ap |= (bits(ap, 1) | !bits(ap_table, 0)) << 1;
            result->perms.pxn = pxn | pxn_table;
            // Pages from Non-secure tables are marked non-global in Secure
            // EL1&0
            bool isSecure = currState->tran->isSecure;
            result->nG = isSecure ? (nG | ns_table) : nG;
        } else {
            result->perms.ap |= (1 << 1);
            result->perms.pxn = false;
            result->nG = false;
        }

        result->perms.ap |= 1;
        currState->s1AttrDecode32(sh, memattr);
        addrdesc->paddress.ns = bits(memattr, 3) | ns_table;
    } else {
        result->perms.ap |= bits(ap, 2, 1) << 1;
        result->perms.ap |= 1;
        result->perms.xn  = xn;
        result->perms.xxn = bits(desc, 53); // HaveExtendedExecuteNeverExt?
        result->perms.pxn = false;
        result->nG = false;
        currState->s2AttrDecode(sh, memattr);
        addrdesc->paddress.ns = true;
    }

    DPRINTF(TableWalker, "Analyzing L%d descriptor: %#x, pxn: %u, xn: %u, "
            "ap: %u, af: %u, type: %u\n", level, desc, result->perms.pxn,
            result->perms.xn, result->perms.ap, 0, 3);

    addrdesc->paddress.physicaladdress = outputaddress;

    result->contiguous = contiguousbit;
    result->CnP = bits(currState->baseregister, 0);

    if (!isStage2) {
        currState->tran->s1 = result;
    } else {
        currState->tran->s2 = result;
    }
}

void
TableWalker::doL0LongDescriptorWrapper()
{
    doLongDescriptorWrapper(0);
}

void
TableWalker::doL1LongDescriptorWrapper()
{
    doLongDescriptorWrapper(1);
}

void
TableWalker::doL2LongDescriptorWrapper()
{
    doLongDescriptorWrapper(2);
}

void
TableWalker::doL3LongDescriptorWrapper()
{
    doLongDescriptorWrapper(3);
}


void
TableWalker::doLongDescriptorWrapper(int level)
{
    auto it = stateQueues[level].find(currentId);
    assert(it != stateQueues[level].end());
    currState = it->second;
    assert(currState);
    assert(currState->level == level);
    currState->delayed = false;

    // If there's a stage 2 translation object we don't need it any more
    if (currState->stage2Tran) {
        delete currState->stage2Tran;
        currState->stage2Tran = NULL;
    }

    DPRINTF(TableWalker, "calling doLongDescriptor for vaddr:%#x (level:%d)\n",
            currState->address, level);

    statWalkServiceTime.sample(curTick() - currState->startTime);

    if (currState->aarch64) {
        doAArch64Descriptor();
    } else {
        doLongDescriptor();
    }

    stateQueues[level].erase(currentId);

    if (currState->tran->fault != NoFault || !currState->delayed) {
        sendTimingResponse();
        cleanup();
    } else {
        stateQueues[currState->level].insert(
            std::pair<uint64_t, WalkerState*>(currState->id, currState));
    }

    currState = NULL;
}

void
TableWalker::doAArch64Descriptor()
{
    if (currState->tran->fault != NoFault) {
        return;
    }

    auto& addrdesc = currState->addrdesc;

    uint64_t desc = currState->data;
    int level = currState->level;
    int firstblocklevel = currState->firstblocklevel;

    DPRINTF(TableWalker, "L%u descriptor for %#x is %#x (AArch64)\n",
            level, currState->address, desc);

    insertPartialTranslation();

    if (currState->reversedescriptors) {
        panic("%s:%s not implemented", __FILE__, __LINE__);
    }

    if ((bits(desc, 0) == 0) || ((bits(desc, 1, 0) == 1) && (level == 3))) {
        translationFault(TlbEntry::DomainType::NoAccess, ArmFault::LpaeTran);
        statWalksLongTerminatedAtLevel[currState->level]++;
        return;
    }

    uint8_t addrselectbottom = currState->addrselectbottom;
    uint8_t stride = currState->stride;

    // Valid Block, Page, or Table entry
    if ((bits(desc, 1, 0) == 1) || (level == 3)) // Block (01) Page (11)
    {
        // Check block size is supported at this level
        if (level < firstblocklevel) {
            translationFault(TlbEntry::DomainType::NoAccess,
                             ArmFault::LpaeTran);
            statWalksLongTerminatedAtLevel[currState->level]++;
            return;
        }

        bool contiguousbitcheck;

        bool largegrain = currState->largegrain;
        bool midgrain = currState->midgrain;

        uint32_t inputsize = currState->inputsize;

        if (largegrain) {
            contiguousbitcheck = (level == 2) && (inputsize < 34);
        } else if (midgrain) {
            contiguousbitcheck = (level == 2) && (inputsize < 30);
        } else {
            contiguousbitcheck = (level == 1) && (inputsize < 34);
        }

        if (contiguousbitcheck && (bits(desc, 52) == 1)) {
            // ARM DDI 0487D.a (J1-7005)
            panic("%s:%s not implemented", __FILE__, __LINE__);
        }

        int outputsize = currState->outputsize;

        // Check the output address is inside the supported range
        if (checkAddrSizeFaultAArch64(desc, currState->physAddrRange))
        {
            bool aff = !bits(desc, 10);
            addressSizeFault(TlbEntry::DomainType::NoAccess,
                             ArmFault::LpaeTran, aff);
            statWalksLongTerminatedAtLevel[currState->level]++;
            return;
        }

        Addr inputaddr = currState->address;
        Addr outputaddress = 0;

        // Unpack the descriptor into address and upper and lower block
        // attributes
        if (outputsize == 52) {
            panic("%s:%s not implemented", __FILE__, __LINE__);
        } else {
            outputaddress = mbits(desc, 47, addrselectbottom) |
                             bits(inputaddr, addrselectbottom - 1, 0);
        }

        // Check access flag
        // [ARM DDI 0487C.a - D4.4.6]
        // The access flag indicates when a page or a section of memory is
        // accessed for the first time since the Access flag in the
        // corresponding translation table was set to 0
        if (bits(desc, 10) == 0) {
            if (!currState->update_AF) {
                statWalksLongTerminatedAtLevel[currState->level]++;
                accessFlagFault(TlbEntry::DomainType::NoAccess,
                                ArmFault::LpaeTran);
                return;
            }
        }

        if (currState->update_AP && (bits(desc, 51) == 1)) {
            // If hw update of access permission field is configured consider
            // AP[2] as '0' / S2AP[2] as '1'
            if (!isStage2 && (bits(desc, 7) == 1)) {
                panic("%s:%s not implemented", __FILE__, __LINE__);
            } else if (isStage2 && (bits(desc, 7) == 0)) {
                panic("%s:%s not implemented", __FILE__, __LINE__);
            }
        }

        bool apply_nvn1_effect = false;

        bool xn, pxn;
        if (apply_nvn1_effect) {
            pxn = bits(desc, 54);
            xn = false;
        } else {
            xn = bits(desc, 54);
            pxn = bits(desc, 53);
        }
        bool contiguousbit = bits(desc, 52);
        bool nG = bits(desc, 11);
        uint8_t sh = bits(desc, 9, 8);
        uint8_t ap;
        if (apply_nvn1_effect) {
            ap = (bits(desc, 7) << 2) | 0x1;
        } else {
            ap = (bits(desc, 7, 6) << 1) | 0x1;
        }
        uint8_t memattr = bits(desc, 5, 2); // AttrIndx and NS bit in stage 1

        TLBRecord* result = new TLBRecord(addrdesc);

        result->domain = TlbEntry::DomainType::Client;
        result->level = toLookupLevel(level);
        result->blocksize = exp2((3 - level) * stride + currState->grainsize);

        // Stage 1 translation regime also inherit attributes from the tables
        if (!isStage2) {
            uint8_t xn_table = currState->xn_table;
            uint8_t ap_table = currState->ap_table;
            uint8_t ns_table = currState->ns_table;
            result->perms.xn  = (xn | xn_table);
            result->perms.ap |= (bits(ap, 2) | bits(ap_table, 1)) << 2; // RO
            // PXN, nG and AP[1] apply in EL1&0 or EL2&0 stage 1
            // translation regime
            if (!currState->singlepriv) {
                bool pxn_table = currState->pxn_table;
                // Force privileged only
                result->perms.ap |= (bits(ap, 1) & (!bits(ap_table, 0))) << 1;
                result->perms.pxn = pxn | pxn_table;
                // Pages from Non-secure tables are marked non-global in Secure
                // EL1&0
                if (currState->lookupsecure) {
                    result->nG = nG | ns_table;
                } else {
                    result->nG = nG;
                }
            } else {
                result->perms.ap |= 0x2; // ap<1> = 1
                result->perms.pxn = false;
                result->nG        = false;
            }
            result->perms.ap |= 0x1;
            currState->s1AttrDecode64(sh, memattr);
            addrdesc->paddress.ns = (bits(memattr, 3) | ns_table);
        } else {
            result->perms.ap  = mbits(ap, 2, 1);
            result->perms.ap |= 0x1; // ap<0> = 1
            result->perms.xn  = xn;
            result->perms.xxn = bits(desc, 53);
            result->perms.xn  = false;
            result->nG = false;
            currState->s2AttrDecode(sh, memattr);
            result->addrdesc->paddress.ns = true;
        }

        DPRINTF(TableWalker, "Analyzing L%u descriptor: %#x, pxn: %u, xn: %u, "
                "ap: %u, af: %u, type: %u\n", level, desc, result->perms.pxn,
                result->perms.xn, result->perms.ap, bits(desc, 10),
                bits(desc, 1, 0));

        addrdesc->paddress.physicaladdress = outputaddress;
        addrdesc->vaddress = inputaddr;

        result->contiguous = contiguousbit;

        if (!isStage2) {
            currState->tran->s1 = result;
        } else {
            currState->tran->s2 = result;
        }
    }
    else // Table (11)
    {
        DPRINTF(TableWalker, "Analyzing L%u descriptor: %#x, type: %u\n",
                level, desc, (level == 3) ? bits(desc, 1, 0) : bits(desc, 0));

        uint32_t outputsize = currState->outputsize;

        if (checkAddrSizeFaultAArch64(desc, currState->physAddrRange))
        {
            addressSizeFault(TlbEntry::DomainType::NoAccess,
                             ArmFault::LpaeTran, false);
            statWalksLongTerminatedAtLevel[currState->level]++;
            return;
        }

        uint8_t grainsize = currState->grainsize;

        Addr baseaddress;

        if (outputsize == 52) {
            baseaddress = (((bits(desc, 15, 12) << 47) |
                            (bits(desc, 47, grainsize))) &
                             ~mask(grainsize));
        } else {
            baseaddress = mbits(desc, 47, grainsize);
        }

        if (!isStage2) {
            // Unpack the upper and lower table attributes
            currState->ns_table |= bits(desc, 63);
        }

        if (!isStage2 && !currState->hierattrsdisabled) {
            uint8_t ap_table = currState->ap_table;
            currState->ap_table |= (bits(ap_table, 1) | bits(desc, 62)) << 1;
            currState->xn_table |= bits(desc, 60);
            // pxn_table and ap_table[0] apply in EL1&0 or EL2&0
            // translation regimes
            if (!currState->singlepriv) {
                currState->ap_table  |= bits(desc, 61); // privileged
                currState->pxn_table |= bits(desc, 59);
            }
        }

        level++;

        uint8_t addrselecttop = currState->addrselecttop;

        addrselecttop = addrselectbottom - 1;
        addrselectbottom = (3 - level) * stride + grainsize;

        Addr inputaddr = currState->address;

        uint64_t index = bits(inputaddr, addrselecttop, addrselectbottom) << 3;

        currState->addrselecttop = addrselecttop;
        currState->addrselectbottom = addrselectbottom;

        addrdesc->paddress.physicaladdress = (baseaddress | index);

        currState->level = level;

        DPRINTF(TableWalker, "L%d descriptor points to L%d descriptor at: %#x "
                "(%s)\n", level - 1, level, addrdesc->paddress.physicaladdress,
                currState->lookupsecure ? "s" : "ns");

        // Trickbox address check
        Fault f;
        f = testWalk(addrdesc->paddress.physicaladdress, sizeof(uint64_t),
                    TlbEntry::DomainType::NoAccess, toLookupLevel(level));

        if (f) {
            DPRINTF(TLB, "Trickbox check caused fault on %#x\n",
                    currState->address);
            currState->tran->fault = f;
            if (currState->timing) {
                nextWalk();
            } else {
                currState->tc = NULL;
                currState->req = NULL;
            }
            return;
        }

        Request::Flags flag = Request::PT_WALK;
        if (currState->tran->isSecure) {
            flag.set(Request::SECURE);
        }

        bool delayed = fetchDescriptor(8, flag, -1,
                            LongDescEventByLevel[currState->level],
                            &TableWalker::doAArch64Descriptor);

        if (delayed) {
            currState->delayed = true;
        }
    }
}

void
TableWalker::accessFlagFault(TlbEntry::DomainType domain,
                             ArmFault::TranMethod fault)
{
    int level = currState->level;

    DPRINTF(TableWalker, "L%d descriptor causing access fault\n", level);

    Addr faultAddr;

    if (isStage2) {
        faultAddr = currState->address; // IPA
    } else {
        faultAddr = currState->tran->req->getVaddr();
    }

    if (currState->tran->isFetch()) {
        currState->tran->fault = std::make_shared<PrefetchAbort>(
            faultAddr, ArmFault::AccessFlagLL + level, isStage2, fault);
    } else {
        bool wnr = currState->tran->isAtomic() ?
            false : currState->tran->isWrite();
        currState->tran->fault = std::make_shared<DataAbort>(
            faultAddr, domain, wnr,
            ArmFault::AccessFlagLL + level, isStage2, fault);
    }

    if (isStage2 && currState->tran->stage2lookup) {
        annotateStage2Fault();
    }
}

void
TableWalker::addressSizeFault(TlbEntry::DomainType domain,
                              ArmFault::TranMethod fault, bool aff)
{
    int level = currState->level;

    DPRINTF(TableWalker, "L%d descriptor causing address size fault\n", level);

    ArmFault::FaultSource src = ArmFault::AddressSizeLL;

    Addr faultAddr;

    if (isStage2) {
        faultAddr = currState->address; // IPA
    } else {
        faultAddr = currState->tran->req->getVaddr();
    }

    if (currState->tran->isFetch()) {
        currState->tran->fault = std::make_shared<PrefetchAbort>(
            faultAddr, ArmFault::AddressSizeLL + level, isStage2, fault);
    } else {
        bool wnr = currState->tran->isAtomic() ?
            false : currState->tran->isWrite();
        currState->tran->fault = std::make_shared<DataAbort>(
            faultAddr, domain, wnr, src + level,
            isStage2, fault);
    }

    if (isStage2 && currState->tran->stage2lookup) {
        annotateStage2Fault();
    }
}

void
TableWalker::translationFault(TlbEntry::DomainType domain,
                              ArmFault::TranMethod fault)
{
    int level = currState->level;

    DPRINTF(TableWalker, "Translation fault. VA:%#x, level:%d, iswrite:%u, "
            "isfetch:%u, isStage2:%u\n", currState->address, level,
            currState->tran->isWrite(), currState->tran->isFetch(), isStage2);

    Addr faultAddr;

    if (isStage2) {
        faultAddr = currState->address; // IPA
    } else {
        faultAddr = currState->tran->req->getVaddr();
    }

    if (currState->tran->isFetch()) {
        currState->tran->fault = std::make_shared<PrefetchAbort>(
            faultAddr, ArmFault::TranslationLL + level, isStage2, fault);
    } else {
        bool wnr = currState->tran->isAtomic() ?
            false : currState->tran->isWrite();
        currState->tran->fault = std::make_shared<DataAbort>(
            faultAddr, domain, wnr,
            ArmFault::TranslationLL + level, isStage2, fault);
    }

    if (isStage2 && currState->tran->stage2lookup) {
        annotateStage2Fault();
    }
}

bool
TableWalker::s1CacheDisabled()
{
    SCTLR sctlr = currState->sctlr;
    bool enable = currState->tran->isFetch() ? sctlr.i : sctlr.c;

    return !enable;
}

bool
TableWalker::s2CacheDisabled()
{
    HCR hcr = currState->tran->hcr;
    // HCR2 and HCR_EL2 share the same bits int the miscregs_types
    // implementation: Bits[33:32]
    bool disable = currState->tran->isFetch() ? hcr.id : hcr.cd;

    return disable;
}

void
TableWalker::s1AttrDecode32(ThreadContext* tc, MemoryAttributes* memattr,
    uint8_t sh, uint8_t attr, ExceptionLevel el, SCTLR sctlr, HCR hcr,
    uint64_t mair)
{
    uint8_t attrfield = bits(mair, (attr << 3) + 7, attr << 3);
    uint8_t attr_hi = bits(attrfield, 7, 4);
    uint8_t attr_lo = bits(attrfield, 3, 0);

    DPRINTF(TableWalker, "memAttrsLPAE AttrIndx:%#x sh:%#x, attr %#x\n",
            attrfield, sh, attr);

    // Device memory
    if (attr_hi == 0) {
        memattr->type = TlbEntry::MemoryType::Device;

        switch (bits(attrfield, 3, 0)) {
            case 0x0:
                memattr->device = DeviceType::nGnRnE;
                break;
            case 0x4:
                memattr->device = DeviceType::nGnRE;
                break;
            case 0x8:
                memattr->device = DeviceType::nGRE;
                break;
            case 0xc:
                memattr->device = DeviceType::GRE;
                break;
            default:
                panic("Reserved attrfield value");
        }
    }
    else if (attr_lo != 0) {
        memattr->type = TlbEntry::MemoryType::Normal;
        memattr->outer = longConvertAttrsHints(attr_hi, sctlr, hcr);
        memattr->inner = longConvertAttrsHints(attr_lo, sctlr, hcr);
        memattr->shareable = (bits(sh, 1) == 1);
        memattr->outershareable = (sh == 0x2);
    }
    else {
        panic("Unreachable attribute field decode");
    }

    TLB::memAttrDefaults(memattr);
}

void
TableWalker::s1AttrDecode64(ThreadContext* tc, MemoryAttributes* memattrs,
    uint8_t sh, uint8_t attr, ExceptionLevel el, SCTLR sctlr, HCR hcr,
    uint64_t mair)
{
    uint8_t attrfield = bits(mair, (attr << 3) + 7, attr << 3);
    uint8_t attr_hi = bits(attrfield, 7, 4);
    uint8_t attr_lo = bits(attrfield, 3, 0);

    memattrs->attr = attrfield;

    DPRINTF(TableWalker, "memAttrsAArch64 AttrIndx:%#x sh:%#x\n", attr, sh);

    // Normal memory
    if ((attr_hi != 0) && (attr_lo != 0)) {
        memattrs->type  = TlbEntry::MemoryType::Normal;
        memattrs->outer = longConvertAttrsHints(attr_hi, sctlr, hcr);
        memattrs->inner = longConvertAttrsHints(attr_lo, sctlr, hcr);
        memattrs->shareable = (bits(sh, 1) == 1);
        memattrs->outershareable = (sh == 0x2);
    }
    // Device memory and unpredictable
    else {
        memattrs->type = TlbEntry::MemoryType::Device;
        switch (attr_lo) {
            case 0x0:
                memattrs->device = DeviceType::nGnRnE;
                break;
            case 0x4:
                memattrs->device = DeviceType::nGnRE;
                break;
            case 0x8:
                memattrs->device = DeviceType::nGRE;
                break;
            case 0xc:
                memattrs->device = DeviceType::GRE;
                break;
            default:  // Unpredictable
                panic("%s:%s attribute unpredictable", __FILE__, __LINE__);
        }
    }

    TLB::memAttrDefaults(memattrs);
}

void
TableWalker::s2AttrDecode(MemoryAttributes* memattr, uint8_t sh, uint8_t attr)
{
    if (bits(attr, 3, 2) == 0) { // Device
        memattr->type = TlbEntry::MemoryType::Device;

        switch (bits(attr, 1, 0)) {
            case 0x0:
                memattr->device = DeviceType::nGnRnE;
                break;
            case 0x1:
                memattr->device = DeviceType::nGnRE;
                break;
            case 0x2:
                memattr->device = DeviceType::nGRE;
                break;
            case 0x3:
                memattr->device = DeviceType::GRE;
                break;
        }
    } else if (bits(attr, 1, 0) != 0) { // Normal
        memattr->type = TlbEntry::MemoryType::Normal;
        uint8_t o_attr = bits(attr, 3, 2);
        uint8_t i_attr = bits(attr, 1, 0);
        memattr->outer = s2ConvertAttrsHints(o_attr);
        memattr->inner = s2ConvertAttrsHints(i_attr);
        memattr->shareable = bits(sh, 1);
        memattr->outershareable = (sh == 0x2);
    } else {
        panic("%s:%s reserved S2 attribute decode", __FILE__, __LINE__);
    }

    TLB::memAttrDefaults(memattr);
}

MemAttrHints
TableWalker::shortConvertAttrsHints(uint8_t rgn)
{
    MemAttrHints result;

    if ((!isStage2 && s1CacheDisabled()) ||
         (isStage2 && s2CacheDisabled())) {
        // Force Non-cacheable
        result.attrs = MemAttr::NC;
        result.hints = MemHint::No;
    } else {
        switch (rgn)
        {
            case 0: // Non-cacheable (no allocate)
                result.attrs = MemAttr::NC;
                result.hints = MemHint::No;
                break;
            case 1: // Write-back, Read and Write allocate
                result.attrs = MemAttr::WB;
                result.hints = MemHint::RWA;
                break;
            case 2: // Write-through, Read allocate
                result.attrs = MemAttr::WT;
                result.hints = MemHint::RA;
                break;
            case 3: // Write-back, Read allocate
                result.attrs = MemAttr::WB;
                result.hints = MemHint::RA;
                break;
            default:
                panic("%s:%s Unknown RGN field", __FILE__, __LINE__);
        }
    }

    result.transient = false;

    return result;
}

MemAttrHints
TableWalker::longConvertAttrsHints(uint8_t attrfield, SCTLR sctlr, HCR hcr)
{
    assert(attrfield != 0);

    MemAttrHints result;

    if (s1CacheDisabled()) { // Force Non-cacheable
        result.attrs = MemAttr::NC;
        result.hints = MemHint::No;
    } else {
        // Write-through transient
        if (bits(attrfield, 3, 2) == 0x0) {
            result.attrs = MemAttr::WT;
            result.hints = static_cast<MemHint>(bits(attrfield, 1, 0));
            result.transient = true;
        }
        // Non-cacheable (no allocate)
        else if (bits(attrfield, 3, 0) == 0x4) {
            result.attrs = MemAttr::NC;
            result.hints = MemHint::No;
            result.transient = false;
        }
        // Write-back transient
        else if (bits(attrfield, 3, 2) == 0x1) {
            result.attrs = MemAttr::WB;
            result.hints = static_cast<MemHint>(bits(attrfield, 1, 0));
            result.transient = true;
        }
        // Write-through/Write-back non-transient
        else {
            result.attrs = static_cast<MemAttr>(bits(attrfield, 3, 2));
            result.hints = static_cast<MemHint>(bits(attrfield, 1, 0));
            result.transient = false;
        }
    }

    return result;
}

MemAttrHints
TableWalker::s2ConvertAttrsHints(uint8_t attr)
{
    assert(attr != 0);

    MemAttrHints result;

    if (s2CacheDisabled()) { // Force Non-cacheable
        result.attrs = MemAttr::NC;
        result.hints = MemHint::No;
    } else {
        switch (attr) {
            case 0x1: // Non-cacheable (no allocate)
                result.attrs = MemAttr::NC;
                result.hints = MemHint::No;
                break;
            case 0x2: // Write-through
                result.attrs = MemAttr::WT;
                result.hints = MemHint::RWA;
                break;
            case 0x3: // Write-back
                result.attrs = MemAttr::WB;
                result.hints = MemHint::RWA;
                break;
            default:
                panic("%s:%s undefined attribute hint", __FILE__, __LINE__);
        }
    }

    result.transient = false;

    return result;
}

void
TableWalker::defaultTEXDecode(MemoryAttributes* memattrs, uint8_t tex, bool c,
                              bool b, bool s)
{
    uint8_t cb = (c << 1) | b;

    // Reserved values map to allocate values
    if (((tex == 1) && (cb == 1)) || ((tex == 2) && (cb != 0)) || (tex == 3)) {
        panic("%s:%s constraint unpredictable bits", __FILE__, __LINE__);
    }

    uint8_t texcb = (tex << 2) | cb;

    switch (texcb) {
        case 0x00: // Device-nGnRnE
            memattrs->type = TlbEntry::MemoryType::Device;
            memattrs->device = DeviceType::nGnRnE;
            break;
        case 0x01: // Device-nGnRE
        case 0x08:
            memattrs->type = TlbEntry::MemoryType::Device;
            memattrs->device = DeviceType::nGnRE;
            break;
        case 0x02: // Write-back
        case 0x03: // Write-through Read allocate
        case 0x04: // Non-cacheable
            memattrs->type = TlbEntry::MemoryType::Normal;
            memattrs->inner = shortConvertAttrsHints(cb);
            memattrs->outer = shortConvertAttrsHints(cb);
            memattrs->shareable = s;
            break;
        case 0x06:
            panic("%s:%s impl. defined attributes", __FILE__, __LINE__);
            break;
        case 0x07: // Write-back Read and Write allocate
            memattrs->type = TlbEntry::MemoryType::Normal;
            memattrs->inner = shortConvertAttrsHints(1);
            memattrs->outer = shortConvertAttrsHints(1);
            memattrs->shareable = s;
            break;
        case 0x10 ... 0x1f:
            // Cacheable, TEX<1:0> = Outer attrs, {C,B} = Inner attrs
            memattrs->type = TlbEntry::MemoryType::Normal;
            memattrs->inner = shortConvertAttrsHints(cb);
            memattrs->outer = shortConvertAttrsHints(bits(tex, 1, 0));
            memattrs->shareable = s;
            break;
        default:
            panic("%s:%s Unreachable attr.: %#x", __FILE__, __LINE__, texcb);
    }

    // Transient bits are not supported in this format
    memattrs->inner.transient = false;
    memattrs->outer.transient = false;

    // Distinction between inner and outer shareable is not supported in
    // this format
    memattrs->outershareable = memattrs->shareable;

    TLB::memAttrDefaults(memattrs);
}

void
TableWalker::remappedTEXDecode(MemoryAttributes* memattrs, uint8_t tex, bool c,
                               bool b, bool s)
{
    uint8_t region = bits(tex, 0) << 2 | (c << 1) | b;

    PRRR prrr = currState->tran->prrr;
    NMRR nmrr = currState->tran->nmrr;

    DPRINTF(TableWalker, "memAttrs texcb:%u s:%u\n", region, s);
    DPRINTF(TableWalker, "memAttrs PRRR:%x NMRR:%x\n", prrr, nmrr);

    if (region == 6) {
        panic("%s:%s not implemented", __FILE__, __LINE__);
    } else {
        uint8_t base = (region << 1);
        uint8_t attrfield = bits(prrr, base+1, base);

        if (attrfield == 3) { // Reserved, maps to allocated value
            panic("%s:%s Reserved, maps to allocated value",
                    __FILE__, __LINE__);
        }

        switch (attrfield)
        {
            case 0: // Device-nGnRnE
                memattrs->type = TlbEntry::MemoryType::Device;
                memattrs->device = DeviceType::nGnRnE;
                break;
            case 1: // Device-nGnRE
                memattrs->type = TlbEntry::MemoryType::Device;
                memattrs->device = DeviceType::nGnRE;
                break;
            case 2:
            {
                memattrs->type = TlbEntry::MemoryType::Normal;
                uint8_t irgn = bits(nmrr, base + 1, base);
                uint8_t orgn = bits(nmrr, base + 17, base + 16);
                memattrs->inner = shortConvertAttrsHints(irgn);
                memattrs->outer = shortConvertAttrsHints(orgn);

                bool s_bit = !s ? prrr.ns0 : prrr.ns1;

                memattrs->shareable = s_bit;
                memattrs->outershareable = s_bit && !bits(prrr, region + 24);
            }
                break;
            default:
                panic("Unreachable attrfield!");
        }
    }

    DPRINTF(TableWalker, "%s ns1:%u ns0:%u s:%u\n",
            memattrs->type == TlbEntry::MemoryType::Normal ? "Normal" : "Dev",
            prrr.ns1, prrr.ns0, memattrs->shareable);

    // Transient bits are not supported in this format
    memattrs->inner.transient = false;
    memattrs->outer.transient = false;

    TLB::memAttrDefaults(memattrs);

    DPRINTF(TableWalker, "memAttrs: shareable: %u, innerAttrs: %u, "
            "outerAttrs: %u\n", memattrs->shareable,
            static_cast<uint8_t>(memattrs->inner.attrs),
            static_cast<uint8_t>(memattrs->outer.attrs));
}

void
TableWalker::walkAttrDecode(ThreadContext* tc, MemoryAttributes* memattrs,
                            uint8_t sh, uint8_t orgn, uint8_t irgn,
                            ExceptionLevel el, SCTLR sctlr, HCR hcr)
{
    assert(memattrs);

    memattrs->type  = TlbEntry::MemoryType::Normal;
    memattrs->inner = shortConvertAttrsHints(irgn);
    memattrs->outer = shortConvertAttrsHints(orgn);

    memattrs->shareable      = ((sh & 0x2) == 0x2);
    memattrs->outershareable = (sh == 0x2);

    TLB::memAttrDefaults(memattrs);
}

bool
TableWalker::fetchDescriptor(int bytes,
                Request::Flags flags, int queueIndex, Event* event,
                void (TableWalker::*doDescriptor)())
{
    bool timing = currState->timing;

    Addr desc_addr = currState->addrdesc->paddress.physicaladdress;

    currState->tran->ptw_desc_addr = desc_addr;
    bool tlb_hit = currState->tlb->lookup(currState->tran, true, false, true);

    DPRINTF(TableWalker, "Fetching descriptor at address: %#x stage2Req: %u\n",
            desc_addr, currState->stage2Req);

    currentId = currState->id;

    if (tlb_hit && timing) {
        currState->data = currState->tran->ptw_desc_value;
        schedule(event, curTick() + clockPeriod());
    } else {
        // Save the event to process for when we are back from the
        // timing request
        currState->next_event = event;
    }

    uint8_t *data = (uint8_t*)&(currState->data);

    // Save the descriptor address to return after waiting in the
    // inflight queue
    currState->desc_addr = desc_addr;

    // Update the current walk with the result of the TLB lookup
    currState->partial_hit = tlb_hit;

    // If there are two stages of translation, then the first stage page
    // walk addresses are themselves subject to translation
    if (currState->stage2Req) {
        Fault fault;
        flags = flags | TLB::MustBeOne;
        currState->tran->s2fs1walk = true;

        if (timing) {
            if (!tlb_hit) {
                RequestPtr req =
                    std::make_shared<Request>(
                        desc_addr, bytes, flags, masterId);

                MMU::Stage2Translation *tran = new
                    MMU::Stage2Translation(*mmu, desc_addr, data, req, event,
                        currState->address, currState->tran->isFetch(),
                        currState, memSidePort);
                currState->stage2Tran = tran;
                DPRINTF(TableWalker, "Doing second stage translation timed "
                        "%#x\n", desc_addr);
                mmu->secondStageTranslateTimed(currState->tran->tc, desc_addr,
                                tran, data, bytes, flags, masterId);
                fault = tran->fault;
            }
        } else {
            TLB::TranslationState* tran = currState->tran;
            DPRINTF(TableWalker, "Doing second stage translation untimed "
                    "%#x\n", desc_addr);
            fault = mmu->secondStageTranslateUntimed(tran, desc_addr, data,
                            bytes, flags, currState->functional, memSidePort,
                            masterId);
        }

        if (fault != NoFault) {
            currState->addrdesc->fault = fault;
        }

        if (timing) {
            if (queueIndex >= 0) {
                DPRINTF(TableWalker, "Adding to walker fifo: queue size "
                        "before adding: %d\n", stateQueues[queueIndex].size());
                stateQueues[queueIndex].insert(
                    std::pair<uint64_t, WalkerState*>(
                        currState->id, currState));
                currState = NULL;
            }
        } else {
            (this->*doDescriptor)();
        }
    } else {
        if (timing) {
            if (!tlb_hit) {
                RequestPtr req =
                    std::make_shared<Request>(
                        desc_addr, bytes, flags, masterId);
                PacketPtr pkt = new Packet(req, MemCmd::ReadReq);
                pkt->dataStatic(data);
                pkt->senderState = safe_cast<WalkerState*>(currState);

                if (!memSidePort->sendTimingReq(pkt)) {
                    DPRINTF(TableWalker, "Failed sending timing req for %#x. "
                            "Adding to port retries\n", desc_addr);
                    memSidePort->retries.push_back(pkt);
                } else {
                    DPRINTF(TableWalker, "Sent timing req for %#x\n",
                            desc_addr);
                }
            }

            if (queueIndex >= 0) {
                DPRINTF(TableWalker, "Adding ID(%u) to walker fifo index(%d): "
                        "queue size before adding: %d\n", currState->id,
                        queueIndex, stateQueues[queueIndex].size());
                stateQueues[queueIndex].insert(
                    std::pair<uint64_t, WalkerState*>(
                        currState->id, currState));
                currState = NULL;
            }
        } else if (!currState->functional) {
            RequestPtr req =
                std::make_shared<Request>(desc_addr, bytes, flags, masterId);
            Packet pkt(req, MemCmd::ReadReq);
            pkt.dataStatic(data);
            memSidePort->sendAtomic(&pkt);
            (this->*doDescriptor)();
        } else {
            RequestPtr req =
                std::make_shared<Request>(desc_addr, bytes, flags, masterId);
            req->taskId(ContextSwitchTaskId::DMA);
            PacketPtr pkt = new Packet(req, MemCmd::ReadReq);
            pkt->dataStatic(data);
            memSidePort->sendFunctional(pkt);
            (this->*doDescriptor)();
            delete pkt;
        }
    }

    return timing;
}

void
TableWalker::nextWalk()
{
    if (pendingQueue.size() > 0) {
        DPRINTF(TableWalker, "Scheduling next walk\n");
        processWalkWrapper();
    } else {
        completeDrain();
    }
}

void
TableWalker::cleanup()
{
    delete currState;
    currState = NULL;
    nextWalk();
}

void
TableWalker::completeDrain()
{
    DPRINTF(TLB, "Doing completeDrain()\n");
    if (drainState() == DrainState::Draining &&
        stateQueues[0].empty() && stateQueues[1].empty() &&
        stateQueues[2].empty() && stateQueues[3].empty() &&
        pendingQueue.empty())
    {
        DPRINTF(Drain, "TableWalker done draining, processing drain event\n");
        signalDrainDone();
    }
}

DrainState
TableWalker::drain()
{
    bool state_queues_not_empty = false;

    for (int i = 0; i < MAX_LOOKUP_LEVELS; ++i) {
        if (!stateQueues[i].empty()) {
            state_queues_not_empty = true;
            break;
        }
    }

    if (state_queues_not_empty || pendingQueue.size()) {
        DPRINTF(Drain, "TableWalker not drained\n");
        return DrainState::Draining;
    } else {
        DPRINTF(Drain, "TableWalker free, no need to drain\n");
        return DrainState::Drained;
    }
}

void
TableWalker::drainResume()
{
    if (params()->sys->isTimingMode() && currState) {
        delete currState;
        currState = NULL;
    }
}


void
TableWalker::regStats()
{
    ClockedObject::regStats();

    statWalks
        .name(name() + ".walks")
        .desc("Table walker walks requested")
        ;

    statWalksShortDescriptor
        .name(name() + ".walksShort")
        .desc("Table walker walks initiated with short descriptors")
        .flags(Stats::nozero)
        ;

    statWalksLongDescriptor
        .name(name() + ".walksLong")
        .desc("Table walker walks initiated with long descriptors")
        .flags(Stats::nozero)
        ;

    statWalksShortTerminatedAtLevel
        .init(2)
        .name(name() + ".walksShortTerminationLevel")
        .desc("Level at which table walker walks "
              "with short descriptors terminate")
        .flags(Stats::nozero)
        ;
    statWalksShortTerminatedAtLevel.subname(0, "Level1");
    statWalksShortTerminatedAtLevel.subname(1, "Level2");

    statWalksLongTerminatedAtLevel
        .init(4)
        .name(name() + ".walksLongTerminationLevel")
        .desc("Level at which table walker walks "
              "with long descriptors terminate")
        .flags(Stats::nozero)
        ;
    statWalksLongTerminatedAtLevel.subname(0, "Level0");
    statWalksLongTerminatedAtLevel.subname(1, "Level1");
    statWalksLongTerminatedAtLevel.subname(2, "Level2");
    statWalksLongTerminatedAtLevel.subname(3, "Level3");

    statSquashedBefore
        .name(name() + ".walksSquashedBefore")
        .desc("Table walks squashed before starting")
        .flags(Stats::nozero)
        ;

    statSquashedAfter
        .name(name() + ".walksSquashedAfter")
        .desc("Table walks squashed after completion")
        .flags(Stats::nozero)
        ;

    statWalkWaitTime
        .init(16)
        .name(name() + ".walkWaitTime")
        .desc("Table walker wait (enqueue to first request) latency")
        .flags(Stats::pdf | Stats::nozero | Stats::nonan)
        ;

    statWalkServiceTime
        .init(16)
        .name(name() + ".walkCompletionTime")
        .desc("Table walker service (enqueue to completion) latency")
        .flags(Stats::pdf | Stats::nozero | Stats::nonan)
        ;

    statPendingWalks
        .init(16)
        .name(name() + ".walksPending")
        .desc("Table walker pending requests distribution")
        .flags(Stats::pdf | Stats::dist | Stats::nozero | Stats::nonan)
        ;

    statPageSizes // see DDI 0487A D4-1661
        .init(9)
        .name(name() + ".walkPageSizes")
        .desc("Table walker page sizes translated")
        .flags(Stats::total | Stats::pdf | Stats::dist | Stats::nozero)
        ;
    statPageSizes.subname(0, "4K");
    statPageSizes.subname(1, "16K");
    statPageSizes.subname(2, "64K");
    statPageSizes.subname(3, "1M");
    statPageSizes.subname(4, "2M");
    statPageSizes.subname(5, "16M");
    statPageSizes.subname(6, "32M");
    statPageSizes.subname(7, "512M");
    statPageSizes.subname(8, "1G");

    statRequestOrigin
        .init(2,2) // Instruction/Data, requests/completed
        .name(name() + ".walkRequestOrigin")
        .desc("Table walker requests started/completed, data/inst")
        .flags(Stats::total)
        ;
    statRequestOrigin.subname(0,"Requested");
    statRequestOrigin.subname(1,"Completed");
    statRequestOrigin.ysubname(0,"Data");
    statRequestOrigin.ysubname(1,"Inst");
}

void
TableWalker::sendTimingResponse()
{
    currState->tran->fromPTW = true;

    PacketPtr pkt = new Packet(currState->tran->req, MemCmd::ReadReq);
    pkt->senderState = safe_cast<TLB::TranslationState*>(currState->tran);

    DPRINTF(TableWalker, "Sending timing response for %#x\n",
            currState->address);

    SlavePort *return_port = currState->tran->ports.back();
    currState->tran->ports.pop_back();

    delete currState;
    currState = NULL;

    if (pkt->isRequest()) {
        pkt->makeTimingResponse();
    }

    if (!return_port->sendTimingResp(pkt)) {
        panic("%s:%s failed sending timing resp", __FILE__, __LINE__);
    }
}

void
TableWalker::insertPartialTranslation()
{
    if (!currState->partial_hit) {
        currState->tran->ptw_desc_addr = currState->desc_addr;
        currState->tran->ptw_desc_value = currState->data;
        currState->tlb->insert(currState->tran, true /*from PTW*/);
    }
}

void
TableWalker::annotateStage2Fault()
{
    TLB::TranslationState* tran = currState->tran;
    Fault fault = tran->fault;

    ArmFault *armFault = reinterpret_cast<ArmFault*>(fault.get());
    armFault->annotate(ArmFault::S1PTW, false);
    armFault->annotate(ArmFault::OVA, tran->vaddress);
}

void
TableWalker::printPendingQueue()
{
    DPRINTF(TableWalker, "Pending queue:\n");
    for (auto it = pendingQueue.begin(); it != pendingQueue.end(); it++) {
        DPRINTF(TableWalker, " - %lu: %#x\n", it->first, it->second->address);
    }
}

bool
TableWalker::isOnes(uint64_t n, uint32_t h, uint32_t l)
{
    return (bits(n, h, l) == mask(h - l + 1));
}

int TableWalker::WalkerState::var = 0;

TableWalker::WalkerState::WalkerState(TableWalker* _walker, uint64_t _id) :
    id(_id), tc(nullptr), walker(_walker), aarch64(false), el(EL0), level(0),
    firstblocklevel(-1), addrdesc(NULL), req(nullptr), sctlr(0), hcr(0),
    mair(0), isStage2(false), stage2Req(false), timing(false),
    functional(false), data(0), l1desc(0), inputsize(0), outputsize(0),
    largegrain(false), midgrain(false), grainsize(0), ap_table(0), ns_table(0),
    xn_table(0), pxn_table(0), update_AP(false), update_AF(false),
    reversedescriptors(false), lookupsecure(false), singlepriv(false),
    hierattrsdisabled(false), iswrite(false), s2fs1walk(false), address(0),
    baseregister(0), addrselecttop(0), addrselectbottom(0), tran(nullptr),
    stage2Tran(NULL), startTime(curTick()), delayed(false), partial_hit(false),
    isInflight(false)
{
    addrdesc = std::make_shared<AddressDescriptor>();
    var++;
    if (var > 12)
        std::cout << "Walker State: " << var << std::endl;
}

TableWalker::WalkerState::~WalkerState()
{
    walker->decreaseInflightWalks();
    var--;
}

Fault
TableWalker::testWalk(Addr pa, Addr size, TlbEntry::DomainType domain,
                      LookupLevel lookup_level)
{
    return currState->tlb->testWalk(pa, size, currState->address,
                    currState->tran->isSecure, currState->tran->mode, domain,
                    lookup_level);
}

ArmISA::TableWalker *
ArmTableWalkerParams::create()
{
    return new ArmISA::TableWalker(this);
}

LookupLevel
TableWalker::toLookupLevel(uint8_t lookup_level_as_int)
{
    switch (lookup_level_as_int) {
      case L0:
        return L0;
      case L1:
        return L1;
      case L2:
        return L2;
      case L3:
        return L3;
      default:
        panic("Invalid lookup level conversion: %d", lookup_level_as_int);
    }
}

