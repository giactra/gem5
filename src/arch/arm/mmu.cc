/*
 * Copyright (c) 2012-2013, 2015 ARM Limited
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
 * Authors: Thomas Grocutt
 *          Ivan Pizarro
 */

#include "arch/arm/mmu.hh"

#include "arch/arm/faults.hh"
#include "arch/arm/system.hh"
#include "arch/arm/tlb.hh"
#include "cpu/base.hh"
#include "cpu/thread_context.hh"
#include "debug/TLB.hh"

using namespace ArmISA;

MMU::MMU(const Params *p)
    : BaseMMU(p),
      stage1_tlbs(p->stage1_tlbs), stage2_tlbs(p->stage2_tlbs),
      stage1_walkers(p->stage1_walkers), stage2_walkers(p->stage2_walkers)
{
    for (int i = 0; i < stage1_tlbs.size(); i++) {
        stage1_tlbs[i]->setMMU(this, masterId);
    }

    for (int i = 0; i < stage2_tlbs.size(); i++) {
        stage2_tlbs[i]->setMMU(this, masterId);
    }

    for (int i = 0; i < stage1_walkers.size(); i++) {
        stage1_walkers[i]->setMMU(this);
    }

    for (int i = 0; i < stage2_walkers.size(); i++) {
        stage2_walkers[i]->setMMU(this);
    }
}

Fault
MMU::secondStageTranslateUntimed(TLB::TranslationState* tran, Addr descAddr,
        uint8_t *data, int numBytes, Request::Flags flags, bool functional,
        TableWalker::MemSidePort* port, MasterID masterId)
{
    Fault fault;

    TLB* stage2Tlb = tran->tlb->getStage2TLB();
    assert(stage2Tlb);

    // Translate to physical address using the second stage MMU
    RequestPtr req = std::make_shared<Request>();
    req->setVirt(0, descAddr, numBytes, flags | Request::PT_WALK, masterId, 0);
    if (tran->functional) {
        fault = stage2Tlb->translateFunctional(req, tran->tc, BaseTLB::Read);
    } else {
        fault = stage2Tlb->translateAtomic(req, tran->tc, BaseTLB::Read);
    }

    // Now do the access
    if (fault == NoFault && !req->getFlags().isSet(Request::NO_ACCESS)) {
        Packet pkt = Packet(req, MemCmd::ReadReq);
        pkt.dataStatic(data);
        if (functional) {
            port->sendFunctional(&pkt);
        } else {
            port->sendAtomic(&pkt);
        }
        assert(!pkt.isError());
    }

    // If there was a fault annotate it with the flag saying the fault occured
    // while doing a translation for a stage 1 page table walk
    if (fault != NoFault) {
        ArmFault *armFault = reinterpret_cast<ArmFault*>(fault.get());
        armFault->annotate(ArmFault::S1PTW, true);
        armFault->annotate(ArmFault::OVA, tran->vaddress);
    }

    return fault;
}

void
MMU::secondStageTranslateTimed(ThreadContext* tc, Addr descAddr,
        Stage2Translation* translation, uint8_t* data, int numBytes,
        Request::Flags flags, MasterID masterId)
{
    // translate to physical address using the second stage MMU
    translation->setVirt(
            descAddr, numBytes, flags | Request::PT_WALK, masterId);
    translation->translateTiming(tc);
}

MMU::Stage2Translation::Stage2Translation(MMU &_parent, Addr _descAddr,
        uint8_t *_data, RequestPtr req, Event *_event, Addr _oVAddr,
        bool _isfetch, TableWalker::WalkerState* _walkerState ,
        TableWalker::MemSidePort* _port)
    : descAddr(_descAddr), data(_data), numBytes(0), _req(req), event(_event),
    parent(_parent), oVAddr(_oVAddr), isfetch(_isfetch),
    walkerState(_walkerState), port(_port), fault(NoFault)
{
    stage2tlb = walkerState->tran->stage2Tlb;
}

void
MMU::Stage2Translation::finish(const Fault &_fault, const RequestPtr &req,
                                     ThreadContext *tc, BaseTLB::Mode mode)
{
    fault = _fault;

    // If there was a fault annotate it with the flag saying the foult occured
    // while doing a translation for a stage 1 page table walk.
    if (fault != NoFault) {
        ArmFault *armFault = reinterpret_cast<ArmFault *>(fault.get());
        armFault->annotate(ArmFault::S1PTW, true);
        armFault->annotate(ArmFault::OVA, oVAddr);
    }

    if (_fault == NoFault && !_req->getFlags().isSet(Request::NO_ACCESS)) {
        PacketPtr pkt = new Packet(req, MemCmd::ReadReq);
        pkt->dataStatic(data);
        pkt->senderState = safe_cast<TableWalker::WalkerState*>(walkerState);
        if (!port->sendTimingReq(pkt)) {
            port->retries.push_back(pkt);
        }
    } else {
        // We can't do the DMA access as there's been a problem, so tell the
        // event we're done
        event->process();
    }
}

int
MMU::PAMax(ThreadContext* tc)
{
    AA64MMFR0 id_aa64mmfr0_el1 = tc->readMiscReg(MISCREG_ID_AA64MMFR0_EL1);

    switch (id_aa64mmfr0_el1.parange)
    {
        case 0: return 32; // 4 GB
        case 1: return 36; // 64 GB
        case 2: return 40; // 1 TB
        case 3: return 42; // 4 TB
        case 4: return 44; // 16 TB
        case 5: return 48; // 256 TB
        case 6: return 52; // 4 PB. Only defined from ARMv8.1, indicates that
                           //       ARMv8.2-LPA is implemented
        default:
            panic("ID_AA64MMFR0_EL1: PARange with reserved value %u\n",
                  id_aa64mmfr0_el1.parange);
    }
}

bool
MMU::hasArchVersion(ArchVersion version)
{
    return ((version == ARMv8p0)/* || (IMPLEMENTATION_DEFINED)*/);
}

bool
MMU::have52BitVAExt()
{
    return hasArchVersion(ARMv8p2);
}

int
MMU::addrTop(ThreadContext* tc, Addr address, bool aarch64, ExceptionLevel el,
                HCR hcr, TTBCR ttbcr)
{
    assert(ArmSystem::haveEL(tc, el));

    if (!aarch64) {
        return 31;
    }

    ExceptionLevel regime = s1TranslationRegime(tc, el, hcr);

    uint8_t tbi;

    // AArch64 translation regime
    switch (regime) {
        case EL1:
            tbi = bits(address, 55) ? ttbcr.tbi1 : ttbcr.tbi0;
            break;
        case EL2:
            if (ArmSystem::haveVirtualization(tc) && ELIsInHost(tc, el)) {
                tbi = bits(address, 55) ? ttbcr.tbi1 : ttbcr.tbi0;
            } else {
                tbi = ttbcr.tbi;
            }
            break;
        case EL3:
            tbi = ttbcr.tbi;
            break;
        default:
            panic("%s:%s: unknown translation regime %u\n",
                    __FILE__, __LINE__, regime);
    }

    return ((tbi == 1) ? 55 : 63);
}

ExceptionLevel
MMU::s1TranslationRegime(ThreadContext* tc, ExceptionLevel el, HCR hcr)
{
    SCR scr = tc->readMiscReg(MISCREG_SCR_EL3);

    if (el != EL0) {
        return el;
    } else if (ArmSystem::haveEL(tc, EL3) && ELIs32(tc, EL3) && (scr.ns == 0))
    {
        return EL3;
    } else if (ArmSystem::haveVirtualization(tc) && ELIsInHost(tc, el)) {
        return EL2;
    }
    return EL1;
}

ArmISA::MMU *
ArmMMUParams::create()
{
    return new ArmISA::MMU(this);
}
