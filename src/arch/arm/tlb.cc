/*
 * Copyright (c) 2010-2013, 2016-2019 ARM Limited
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
 * Copyright (c) 2001-2005 The Regents of The University of Michigan
 * All rights reserved.
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
 *          Nathan Binkert
 *          Steve Reinhardt
 *          Ivan Pizarro
 */

#include "arch/arm/tlb.hh"

#include <memory>
#include <string>
#include <vector>

#include "arch/arm/mmu.hh"
#include "arch/arm/pagetable.hh"
#include "arch/arm/system.hh"
#include "arch/arm/table_walker.hh"
#include "arch/arm/utility.hh"
#include "arch/generic/mmapped_ipr.hh"
#include "base/inifile.hh"
#include "base/str.hh"
#include "base/trace.hh"
#include "cpu/base.hh"
#include "cpu/thread_context.hh"
#include "debug/Checkpoint.hh"
#include "debug/TLB.hh"
#include "debug/TLBVerbose.hh"
#include "mem/cache/replacement_policies/base.hh"
#include "mem/cache/tags/indexing_policies/base.hh"
#include "mem/page_table.hh"
#include "mem/request.hh"
#include "params/ArmMMU.hh"
#include "params/ArmTLB.hh"
#include "sim/full_system.hh"
#include "sim/process.hh"

using namespace std;
using namespace ArmISA;

TLB::TLB(const Params *p)
    : BaseTLB(p), table(p->size), size(p->size), assoc(p->assoc),
      isStage2(p->is_stage2), stage2Req(false), stage2DescReq(false), _attr(0),
      directToStage2(false), level(p->level),
      allowPartial(p->allow_partial_translations), access_latency(p->lat),
      indexingPolicy(p->indexing_policy),
      replacementPolicy(p->replacement_policy), stage2Tlb(p->stage2tlb),
      next_tlb(p->next_tlb), mmu(NULL), test(nullptr), rangeMRU(1),
      aarch64(false), aarch64EL(EL0), isPriv(false), isSecure(false),
      isHyp(false), asid(0), vmid(0), hcr(0), dacr(0), miscRegValid(false),
      miscRegContext(0), curTranType(NormalTran)
{
    assert(assoc < size);

    for (unsigned int i = 0; i < size; i++) {
        TlbEntryRepl* entry = &table[i];
        indexingPolicy->setEntry(entry, i);
        entry->replacementData = replacementPolicy->instantiateEntry();
        entry->flush();
    }

    for (int i = 0; i < p->port_slave_connection_count; i++) {
        cpuSidePort.push_back(new CpuSidePort(csprintf("%s.port%d", name(), i),
                                              this, 0));
    }

    memSidePort = new MemSidePort(csprintf("%s.port", name()), this, 0);

    // Cache system-level properties
    if (FullSystem) {
        ArmSystem *armSys = dynamic_cast<ArmSystem *>(p->sys);
        assert(armSys);
        haveLPAE = armSys->haveLPAE();
        haveVirtualization = armSys->haveVirtualization();
        haveLargeAsid64 = armSys->haveLargeAsid64();
    } else {
        haveLPAE = haveVirtualization = haveLargeAsid64 = false;
    }
}

TLB::~TLB()
{
}

void
TLB::setMMU(MMU* _mmu, MasterID master_id)
{
    mmu = _mmu;
}

bool
TLB::translateFunctional(ThreadContext *tc, Addr va, Addr &pa)
{
    updateMiscReg(tc);

    if (directToStage2) {
        assert(stage2Tlb);
        return stage2Tlb->translateFunctional(tc, va, pa);
    }

    TlbEntry *e = lookup(va, asid, vmid, isHyp, isSecure, true, false,
                         aarch64 ? aarch64EL : EL1);
    if (!e)
        return false;
    pa = e->pAddr(va);
    return true;
}

Fault
TLB::finalizePhysical(const RequestPtr &req,
                      ThreadContext *tc, Mode mode) const
{
    const Addr paddr = req->getPaddr();

    if (m5opRange.contains(paddr)) {
        req->setFlags(Request::MMAPPED_IPR | Request::GENERIC_IPR);
        req->setPaddr(GenericISA::iprAddressPseudoInst(
                          (paddr >> 8) & 0xFF,
                          paddr & 0xFF));
    }

    return NoFault;
}

bool
TLB::lookup(TranslationState* tran, bool ignore_asn, bool functional,
            bool from_ptw)
{
    if (from_ptw && !allowPartial) {
        return false;
    }

    Addr va;
    uint16_t asn  = 0;
    uint8_t  vmid = 0;
    bool      hyp = false;
    bool   secure = false;
    ExceptionLevel target_el = EL1;

    if (!from_ptw) {
        va = isStage2 ? tran->ipaddress : tran->vaddress;
        asn       = tran->asid;
        vmid      = tran->vmid;
        hyp       = tran->isHyp;
        secure    = tran->isSecure;
        target_el = tran->aarch64 ? tran->aarch64EL : EL1;
    } else {
        va = tran->ptw_desc_addr;
        if (!functional) printTlb();
    }

    DPRINTF(TLBVerbose, "Lookup ignore_asn %u, functional %u, va %#x,"
            "asn %#x, vmid %u, hyp %u, secure %u, target_el %u\n", ignore_asn,
            functional, va, asn, vmid, hyp, secure, target_el);

    TlbEntryPtr _te = nullptr; // For debugging
    bool tlb_hit = false;

    for (unsigned int i = 0; i < size; i++)
    {
        TlbEntryPtr te = table[i].getData();
        if (te)
        {
            if ((!ignore_asn && te->match(va, asn, vmid, hyp, secure, false,
               target_el)) ||
              (ignore_asn && te->match(va, vmid, hyp, secure, target_el)))
            {
                setAttr(te->attributes);

                if (from_ptw) {
                    tran->ptw_desc_value = te->pAddr(va);
                    tlb_hit = true;
                    _te = te;
                    break;
                } else {
                    if (!isStage2) {
                        tran->s1_physaddr = te->pAddr(va);
                        if (tran->stage2Req) {
                            tran->ipaddress = tran->s1_physaddr;
                        }
                    } else {
                        tran->s2_physaddr = te->pAddr(va);
                    }

                    tran->domain = te->domain;

                    if (!isStage2)
                        tran->s1te = te;
                    else
                        tran->s2te = te;

                    if (!functional) {
                        replacementPolicy->touch(table[i].replacementData);
                    }

                    tlb_hit = true;
                    _te = te;

                    break;
                }
            }
        }
    }

    if (from_ptw && !functional) {
        if (tlb_hit) {
            partialHits++;
        } else {
            partialMisses++;
        }
    }

    return tlb_hit;
}


TlbEntry*
TLB::lookup(Addr va, uint16_t asn, uint8_t vmid, bool hyp, bool secure,
            bool functional, bool ignore_asn, ExceptionLevel target_el)
{
    TlbEntry *retval = NULL;

    for (unsigned int i = 0; retval == NULL && i < size; i++) {
        TlbEntryPtr te = table[i].getData();
        if (te) {
            if ((!ignore_asn && te->match(va, asn, vmid, hyp, secure, false,
               target_el)) ||
              (ignore_asn && te->match(va, vmid, hyp, secure, target_el)))
            {
                retval = te.get();
                retval->index = i;
            }
        }
    }

    DPRINTF(TLBVerbose, "Lookup %#x, asn %#x -> %s vmn 0x%x hyp %d secure %d "
            "ppn %#x size: %#x pa: %#x ap:%d ns:%d nstid:%d g:%d asid: %d "
            "el: %d\n",
            va, asn, retval ? "hit" : "miss", vmid, hyp, secure,
            retval ? retval->pfn       : 0, retval ? retval->size  : 0,
            retval ? retval->pAddr(va) : 0, retval ? 0xff : 0,
            retval ? retval->ns        : 0, retval ? retval->nstid : 0,
            retval ? retval->global    : 0, retval ? retval->asid  : 0,
            retval ? retval->el        : 0);

    return retval;
}

void
TLB::insert(TranslationState* tran, bool from_ptw)
{
    TlbEntryPtr te = nullptr;

    uint64_t attr = 0;

    if (from_ptw) {
        // Don't continue if this TLB does not support partial translations
        if (!allowPartial) {
            return;
        }

        te = std::make_shared<TlbEntry>();

        te->valid = true;
        te->global = true;
        te->size = 0;
        te->N = 0;
        te->vpn = tran->ptw_desc_addr;
        te->pfn = tran->ptw_desc_value;
    } else {
        te = isStage2 ? tran->s2te : tran->s1te;

        // If we have a pointer to a TLB entry is because we are filling this
        // level after a hit in a lower TLB entry. Use this to insert instead
        // the TranslationState fields
        if (te == nullptr) {
            TLBRecord* record = isStage2 ? tran->s2 : tran->s1;
            const auto& addrdesc = record->addrdesc;
            MemoryAttributes *memattrs = addrdesc->memattrs;

            te = std::make_shared<TlbEntry>();

            te->valid  = true;
            te->isHyp  = tran->isHyp;
            te->asid   = tran->asid;
            te->vmid   = tran->vmid;
            te->size   = (record->blocksize - 1);
            te->N      = popCount(te->size);
            te->ns     = addrdesc->paddress.ns;
            te->nstid  = !tran->isSecure;
            te->domain = record->domain;
            te->global = !record->nG;
            te->vpn    = addrdesc->vaddress >> te->N;
            te->pfn    = addrdesc->paddress.physicaladdress >> te->N;
            // Memory attributes
            te->mtype          = memattrs->type;
            te->innerAttrs     = static_cast<uint8_t>(memattrs->inner.attrs);
            te->outerAttrs     = static_cast<uint8_t>(memattrs->outer.attrs);
            te->shareable      = memattrs->shareable;
            te->outerShareable = memattrs->outershareable;
            // Permissions
            te->ap  = record->perms.ap;
            te->xn  = record->perms.xn;
            te->pxn = record->perms.pxn;
            // Descriptor type
            te->longDescFormat = tran->aarch64 || tran->usingLongDescFormat;
            te->lookupLevel = record->level;
            if (tran->aarch64) {
                te->el = tran->aarch64EL;
            } else {
                te->el = EL1;
            }

            if (!isStage2) {
                tran->s1te = te;
                tran->s1_physaddr = te->pAddr(addrdesc->vaddress);
                if (tran->stage2Req) {
                    tran->ipaddress = tran->s1_physaddr;
                }
            } else {
                tran->s2te = te;
                tran->s2_physaddr = te->pAddr(addrdesc->vaddress);
            }

            attr = (uint64_t)(memattrs->attr) << 56;

            te->setAttributes();
            te->attributes |= attr;
            setAttr(te->attributes);
        }
    }

    te->partial = from_ptw;

    // Get possible entries to be victimized
    const std::vector<ReplaceableEntry*> entries =
        indexingPolicy->getPossibleEntries(te->vpn);

    // Choose replacement victim from replacement candidates
    TlbEntryRepl* victim =
        static_cast<TlbEntryRepl*>(replacementPolicy->getVictim(entries));

    // Invalidate the victim
    replacementPolicy->invalidate(victim->replacementData);

    // Update replacement policy
    replacementPolicy->reset(victim->replacementData);

    victim->setEntry(te);

    DPRINTF(TLB, "Inserting entry into TLB with pfn:%#x size:%#x vpn: %#x "
            "asid:%u vmid:%u N:%u global:%u valid:%u ns:%u "
            "nstid:%u isHyp:%u\n", te->pfn, te->size, te->vpn, te->asid,
            te->vmid, te->N, te->global, te->valid, te->ns, te->nstid,
            te->isHyp);

    inserts++;
    ppRefills->notify(1);

    if (tran->aarch64) {
        tran->permissioncheck = true;
        tran->fault = checkPermissions64(tran);
    } else {
        tran->fault = checkPermissions(tran);
    }

    setMemoryAttributes(tran);
}

void
TLB::printTlb()
{
    DPRINTF(TLB, "Current TLB contents:\n");
    for (unsigned int i = 0; i < size; i++) {
        if (table[i].getData()) {
            DPRINTF(TLB, " * [%u] %s\n", i, table[i].getData()->print());
        }
    }
}

void
TLB::flushAllSecurity(bool secure_lookup, ExceptionLevel target_el,
                      bool ignore_el)
{
    DPRINTF(TLB, "Flushing all TLB entries (%s lookup)\n",
            (secure_lookup ? "secure" : "non-secure"));

    for (unsigned int i = 0; i < size; i++) {
        TlbEntryPtr te = table[i].getData();
        if (te) {
            const bool el_match = ignore_el ?
                true : te->checkELMatch(target_el);

            if (te->valid && secure_lookup == !te->nstid &&
                (te->vmid == vmid || secure_lookup) && el_match)
            {
                DPRINTF(TLB, " -  %s\n", te->print());
                table[i].flush();
                flushedEntries++;
            }
        }
    }

    flushTlb++;

    // If there's a second stage TLB (and we're not it) then flush it as well
    // if we're currently in hyp mode. Do this only if we are in the first
    // TLB level
    if (stage2Tlb && (level == 1)) {
        stage2Tlb->flushAllSecurity(secure_lookup, target_el, true);
    }

    if (next_tlb) {
        next_tlb->flushAllSecurity(secure_lookup, target_el, ignore_el);
    }
}

void
TLB::flushAllNs(ExceptionLevel target_el, bool ignore_el)
{
    bool hyp = target_el == EL2;

    DPRINTF(TLB, "Flushing all NS TLB entries (%s lookup)\n",
            (hyp ? "hyp" : "non-hyp"));

    for (unsigned int i = 0; i < size; i++) {
        TlbEntryPtr te = table[i].getData();
        if (te && (te->partial ||
            (te->nstid &&
            (te->isHyp == hyp) &&
            te->checkELMatch(target_el))))
        {
            DPRINTF(TLB, " -  %s\n", te->print());
            table[i].flush();
            flushedEntries++;
        }
    }

    flushTlb++;

    // If there's a second stage TLB (and we're not it) then flush it as well
    if (stage2Tlb && (level == 1) && !hyp) {
        stage2Tlb->flushAllNs(EL1, true);
    }

    if (next_tlb) {
        next_tlb->flushAllNs(target_el, ignore_el);
    }
}

void
TLB::flushMvaAsid(Addr mva, uint64_t asn, bool secure_lookup,
                  ExceptionLevel target_el)
{
    DPRINTF(TLB, "Flushing TLB entries with mva: %#x, asid: %#x "
            "(%s lookup)\n", mva, asn, (secure_lookup ?
            "secure" : "non-secure"));
    _flushMva(mva, asn, secure_lookup, false, target_el);
    flushTlbMvaAsid++;

    if (next_tlb) {
        next_tlb->flushMvaAsid(mva, asn, secure_lookup, target_el);
    }
}

void
TLB::flushAsid(uint64_t asn, bool secure_lookup, ExceptionLevel target_el)
{
    DPRINTF(TLB, "Flushing TLB entries with asid: %#x (%s lookup)\n", asn,
            (secure_lookup ? "secure" : "non-secure"));

    for (unsigned int i = 0; i < size; i++) {
        TlbEntryPtr te = table[i].getData();
        if (te && (te->partial ||
            ((te->asid == asn) &&
            (secure_lookup == !te->nstid) &&
            te->checkELMatch(target_el))))
        {
            DPRINTF(TLB, " -  %s: ", te->print());
            table[i].flush();
            flushedEntries++;
        }
    }

    flushTlbAsid++;

    if (next_tlb) {
        next_tlb->flushAsid(asn, secure_lookup, target_el);
    }
}

void
TLB::flushMva(Addr mva, bool secure_lookup, ExceptionLevel target_el)
{
    DPRINTF(TLB, "Flushing TLB entries with mva: %#x (%s lookup)\n", mva,
            (secure_lookup ? "secure" : "non-secure"));
    _flushMva(mva, 0xbeef, secure_lookup, true, target_el);
    flushTlbMva++;

    if (next_tlb) {
        next_tlb->flushMva(mva, secure_lookup, target_el);
    }
}

void
TLB::_flushMva(Addr mva, uint64_t asn, bool secure_lookup,
               bool ignore_asn, ExceptionLevel target_el)
{
    TlbEntry *te;
    // D5.7.2: Sign-extend address to 64 bits
    mva = sext<56>(mva);

    bool hyp = target_el == EL2;

    te = lookup(mva, asn, vmid, hyp, secure_lookup, false, ignore_asn,
                target_el);
    while (te != NULL) {
        if (secure_lookup == !te->nstid) {
            DPRINTF(TLB, " -  %s\n", te->print());
            table[te->index].flush();
            flushedEntries++;
        }
        te = lookup(mva, asn, vmid, hyp, secure_lookup, false, ignore_asn,
                    target_el);
    }
}

void
TLB::flushIpaVmid(Addr ipa, bool secure_lookup, ExceptionLevel target_el)
{
    DPRINTF(TLB, "Flushing TLB entries with IPA:%#x (%s lookup)\n",
                    ipa, secure_lookup ? "secure" : "non-secure");

    if (stage2Tlb) {
        _flushMva(ipa, 0xbeef, secure_lookup, true, target_el);
    }

    if (next_tlb) {
        next_tlb->flushIpaVmid(ipa, secure_lookup, target_el);
    }
}

void
TLB::drainResume()
{
    // We might have unserialized something or switched CPUs, so make
    // sure to re-read the misc regs.
    miscRegValid = false;
}

void
TLB::takeOverFrom(BaseTLB *_otlb)
{
    TLB *otlb = dynamic_cast<TLB*>(_otlb);
    /* Make sure we actually have a valid type */
    if (otlb) {
        _attr = otlb->_attr;
        haveLPAE = otlb->haveLPAE;
        directToStage2 = otlb->directToStage2;
        stage2Req = otlb->stage2Req;
        stage2DescReq = otlb->stage2DescReq;

        /* Sync the stage2 MMU if they exist in both
         * the old CPU and the new
         */
        if (!isStage2 &&
            stage2Tlb && otlb->stage2Tlb) {
            stage2Tlb->takeOverFrom(otlb->stage2Tlb);
        }
    } else {
        panic("Incompatible TLB type!");
    }
}

void
TLB::serialize(CheckpointOut &cp) const
{
    // Left empty on purpose
}

void
TLB::unserialize(CheckpointIn &cp)
{
    // Left empty on purpose
}

void
TLB::regStats()
{
    BaseTLB::regStats();
    instHits
        .name(name() + ".inst_hits")
        .desc("ITB inst hits")
        ;

    instMisses
        .name(name() + ".inst_misses")
        .desc("ITB inst misses")
        ;

    instAccesses
        .name(name() + ".inst_accesses")
        .desc("ITB inst accesses")
        ;

    readHits
        .name(name() + ".read_hits")
        .desc("DTB read hits")
        ;

    readMisses
        .name(name() + ".read_misses")
        .desc("DTB read misses")
        ;

    readAccesses
        .name(name() + ".read_accesses")
        .desc("DTB read accesses")
        ;

    writeHits
        .name(name() + ".write_hits")
        .desc("DTB write hits")
        ;

    writeMisses
        .name(name() + ".write_misses")
        .desc("DTB write misses")
        ;

    partialHits
        .name(name() + ".partial_hits")
        .desc("Hits from PTW partial translation")
        ;

    partialMisses
        .name(name() + ".partial_misses")
        .desc("Misses from PTW partial translation")
        ;

    writeAccesses
        .name(name() + ".write_accesses")
        .desc("DTB write accesses")
        ;

    hits
        .name(name() + ".hits")
        .desc("DTB hits")
        ;

    misses
        .name(name() + ".misses")
        .desc("DTB misses")
        ;

    accesses
        .name(name() + ".accesses")
        .desc("DTB accesses")
        ;

    partialAccesses
        .name(name() + ".partial_accesses")
        .desc("PTW partial accesses")
        ;

    flushTlb
        .name(name() + ".flush_tlb")
        .desc("Number of times complete TLB was flushed")
        ;

    flushTlbMva
        .name(name() + ".flush_tlb_mva")
        .desc("Number of times TLB was flushed by MVA")
        ;

    flushTlbMvaAsid
        .name(name() + ".flush_tlb_mva_asid")
        .desc("Number of times TLB was flushed by MVA & ASID")
        ;

    flushTlbAsid
        .name(name() + ".flush_tlb_asid")
        .desc("Number of times TLB was flushed by ASID")
        ;

    flushedEntries
        .name(name() + ".flush_entries")
        .desc("Number of entries that have been flushed from TLB")
        ;

    alignFaults
        .name(name() + ".align_faults")
        .desc("Number of TLB faults due to alignment restrictions")
        ;

    prefetchFaults
        .name(name() + ".prefetch_faults")
        .desc("Number of TLB faults due to prefetch")
        ;

    domainFaults
        .name(name() + ".domain_faults")
        .desc("Number of TLB faults due to domain restrictions")
        ;

    permsFaults
        .name(name() + ".perms_faults")
        .desc("Number of TLB faults due to permissions restrictions")
        ;

    instAccesses = instHits + instMisses;
    readAccesses = readHits + readMisses;
    writeAccesses = writeHits + writeMisses;
    hits = readHits + writeHits + instHits;
    misses = readMisses + writeMisses + instMisses;
    accesses = readAccesses + writeAccesses + instAccesses;
    partialAccesses = partialHits + partialMisses;
}

void
TLB::regProbePoints()
{
    ppRefills.reset(new ProbePoints::PMU(getProbeManager(), "Refills"));
}

Fault
TLB::translateSe(const RequestPtr &req, ThreadContext *tc, Mode mode,
                 Translation *translation, bool &delay, bool timing)
{
    updateMiscReg(tc);
    Addr vaddr_tainted = req->getVaddr();
    Addr vaddr = 0;
    if (aarch64)
        vaddr = purifyTaggedAddr(vaddr_tainted, tc, aarch64EL, ttbcr);
    else
        vaddr = vaddr_tainted;
    Request::Flags flags = req->getFlags();

    bool is_fetch = (mode == Execute);
    bool is_write = (mode == Write);

    if (!is_fetch) {
        assert(flags & MustBeOne || req->isPrefetch());
        if (sctlr.a || !(flags & AllowUnaligned)) {
            if (vaddr & mask(flags & AlignmentMask)) {
                // LPAE is always disabled in SE mode
                return std::make_shared<DataAbort>(
                    vaddr_tainted,
                    TlbEntry::DomainType::NoAccess, is_write,
                    ArmFault::AlignmentFault, isStage2,
                    ArmFault::VmsaTran);
            }
        }
    }

    Addr paddr;
    Process *p = tc->getProcessPtr();

    if (!p->pTable->translate(vaddr, paddr))
        return std::make_shared<GenericPageTableFault>(vaddr_tainted);
    req->setPaddr(paddr);

    return finalizePhysical(req, tc, mode);
}

Fault
TLB::checkPermissions(TranslationState* tran)
{
    Fault fault = NoFault;

    if (!isStage2) {
        if (tran->domaincheck)
            fault = checkDomain(tran);
        if ((fault == NoFault) && tran->permissioncheck)
            fault = checkS1Permission32(tran);
    } else {
        fault = checkS2Permission32(tran);
    }

    return fault;
}

Fault
TLB::checkPermissions64(TranslationState* tran)
{
    if (!isStage2) {
        if (tran->permissioncheck) {
            return checkS1Permission64(tran);
        }
    } else {
        return checkS2Permission64(tran);
    }

    return NoFault;
}

Fault
TLB::translateFs(const RequestPtr &req, ThreadContext *tc, Mode mode,
        Translation *translation, bool &delay, bool timing,
        TLB::ArmTranslationType tranType, bool functional)
{
    // No such thing as a functional timing access
    assert(!(timing && functional));

    updateMiscReg(tc, tranType);

    Addr vaddr_tainted = req->getVaddr();
    Addr vaddr = 0;
    if (aarch64)
        vaddr = purifyTaggedAddr(vaddr_tainted, tc, aarch64EL, ttbcr);
    else
        vaddr = vaddr_tainted;
    Request::Flags flags = req->getFlags();

    bool is_fetch  = (mode == Execute);
    bool is_write  = (mode == Write);
    bool long_desc_format = aarch64 || longDescFormatInUse(tc);
    ArmFault::TranMethod tranMethod = long_desc_format ? ArmFault::LpaeTran
                                                       : ArmFault::VmsaTran;

    req->setAsid(asid);

    DPRINTF(TLBVerbose, "CPSR is priv:%d UserMode:%d secure:%d "
            "S1S2NsTran:%d\n", isPriv, flags & UserMode, isSecure,
            tranType & S1S2NsTran);

    DPRINTF(TLB, "translateFs addr %#x, mode %u, st2 %u, scr %#x sctlr %#x"
            " flags %#x tranType 0x%x\n", vaddr_tainted, mode, isStage2, scr,
            sctlr, flags, tranType);

    if ((req->isInstFetch() && (!sctlr.i)) ||
        ((!req->isInstFetch()) && (!sctlr.c))){
        if (!req->isCacheMaintenance()) {
            req->setFlags(Request::UNCACHEABLE);
        }
        req->setFlags(Request::STRICT_ORDER);
    }
    if (!is_fetch) {
        assert(flags & MustBeOne || req->isPrefetch());
        if (sctlr.a || !(flags & AllowUnaligned)) {
            if (vaddr & mask(flags & AlignmentMask)) {
                alignFaults++;
                return std::make_shared<DataAbort>(
                    vaddr_tainted,
                    TlbEntry::DomainType::NoAccess, is_write,
                    ArmFault::AlignmentFault, isStage2,
                    tranMethod);
            }
        }
    }

    TranslationState* tran = new TranslationState(this);

    DPRINTF(TLBVerbose, "Starting translation for %s=%#x\n",
                        isStage2 ? "IPA" : "VA", vaddr);

    tran->stage2Tlb = stage2Tlb;
    tran->translation = translation;
    tran->req = req;
    tran->tc = tc;
    tran->mode = mode;
    tran->tranType = tranType;
    tran->stage2Req = stage2Req;
    tran->usingLongDescFormat = longDescFormatInUse(tc);
    tran->timing = timing;
    tran->functional = functional;
    tran->tranMethod = tranMethod;
    tran->fault = NoFault;
    tran->pc = req->getPC();
    tran->start = curTick();

    // Update the registers in the translation state
    updateTranslationRegisters(tran);

    if (isStage2) {
        tran->ipaddress = vaddr;
        secondStageTranslate(tran);
    } else {
        tran->vaddress = vaddr;
        if (!aarch64) {
            firstStageTranslate32(tran);
        } else {
            firstStageTranslate64(tran);
        }
    }

    if ((isStage2 && !hcr.vm) || (!isStage2 && !sctlr.m)) {
        if (isSecure) {
            req->setFlags(Request::SECURE);
        }
    }

    delay = timing && tran->mmuEnabled;

    return delay ? NoFault : finalizeTranslation(tran);
}

Fault
TLB::translateAtomic(const RequestPtr &req, ThreadContext *tc, Mode mode,
    TLB::ArmTranslationType tranType)
{
    updateMiscReg(tc, tranType);

    if (directToStage2) {
        assert(stage2Tlb);
        return stage2Tlb->translateAtomic(req, tc, mode, tranType);
    }

    bool delay = false;
    Fault fault;
    if (FullSystem)
        fault = translateFs(req, tc, mode, NULL, delay, false, tranType);
    else
        fault = translateSe(req, tc, mode, NULL, delay, false);
    assert(!delay);
    return fault;
}

Fault
TLB::translateFunctional(const RequestPtr &req, ThreadContext *tc, Mode mode,
    TLB::ArmTranslationType tranType)
{
    updateMiscReg(tc, tranType);

    if (directToStage2) {
        assert(stage2Tlb);
        return stage2Tlb->translateFunctional(req, tc, mode, tranType);
    }

    bool delay = false;
    Fault fault;
    if (FullSystem)
        fault = translateFs(req, tc, mode, NULL, delay, false, tranType, true);
    else
        fault = translateSe(req, tc, mode, NULL, delay, false);
    assert(!delay);
    return fault;
}

void
TLB::translateTiming(const RequestPtr &req, ThreadContext *tc,
    Translation *translation, Mode mode, TLB::ArmTranslationType tranType)
{
    updateMiscReg(tc, tranType);

    if (directToStage2) {
        assert(stage2Tlb);
        stage2Tlb->translateTiming(req, tc, translation, mode, tranType);
        return;
    }

    assert(translation);

    translateComplete(req, tc, translation, mode, tranType, isStage2);
}

Fault
TLB::translateComplete(const RequestPtr &req, ThreadContext *tc,
        Translation *translation, Mode mode, TLB::ArmTranslationType tranType,
        bool callFromS2)
{
    bool delay = false;
    Fault fault;
    if (FullSystem)
        fault = translateFs(req, tc, mode, translation, delay, true, tranType);
    else
        fault = translateSe(req, tc, mode, translation, delay, true);
    DPRINTF(TLBVerbose, "Translation returning delay=%d fault=%d\n", delay,
                fault != NoFault);
    // If we have a translation, and we're not in the middle of doing a stage
    // 2 translation tell the translation that we've either finished or its
    // going to take a while. By not doing this when we're in the middle of a
    // stage 2 translation we prevent marking the translation as delayed twice,
    // one when the translation starts and again when the stage 1 translation
    // completes.
    if (translation && (callFromS2 || !stage2Req || req->hasPaddr() ||
                        fault != NoFault)) {
        if (!delay)
            translation->finish(fault, req, tc, mode);
    }

    return fault;
}

Port&
TLB::getPort(const std::string &if_name, PortID idx)
{
    if (if_name == "slave") {
        if (idx >= static_cast<PortID>(cpuSidePort.size())) {
            panic("TLB::getPort: unknown index %d\n", idx);
        }

        return *cpuSidePort[idx];
    } else if (if_name == "master") {
        return *memSidePort;
    } else {
        panic("TLB::getPort: unknown port %s\n", if_name);
    }
}

void
TLB::updateMiscReg(ThreadContext *tc, ArmTranslationType tranType)
{
    // check if the regs have changed, or the translation mode is different.
    // NOTE: the tran type doesn't affect stage 2 TLB's as they only handle
    // one type of translation anyway
    if (miscRegValid && miscRegContext == tc->contextId() &&
            ((tranType == curTranType) || isStage2)) {
        return;
    }

    DPRINTF(TLBVerbose, "TLB variables changed!\n");
    cpsr = tc->readMiscReg(MISCREG_CPSR);

    // Dependencies: SCR/SCR_EL3, CPSR
    isSecure = inSecureState(tc) &&
        !(tranType & HypMode) && !(tranType & S1S2NsTran);

    aarch64EL = tranTypeEL(cpsr, tranType);
    aarch64 = isStage2 ?
        ELIs64(tc, EL2) :
        ELIs64(tc, aarch64EL == EL0 ? EL1 : aarch64EL);

    if (aarch64) {  // AArch64
        // determine EL we need to translate in
        switch (aarch64EL) {
          case EL0:
          case EL1:
            {
                sctlr = tc->readMiscReg(MISCREG_SCTLR_EL1);
                ttbcr = tc->readMiscReg(MISCREG_TCR_EL1);
                uint64_t ttbr_asid = ttbcr.a1 ?
                    tc->readMiscReg(MISCREG_TTBR1_EL1) :
                    tc->readMiscReg(MISCREG_TTBR0_EL1);
                asid = bits(ttbr_asid,
                            (haveLargeAsid64 && ttbcr.as) ? 63 : 55, 48);
                ttbr0_el1 = tc->readMiscReg(MISCREG_TTBR0_EL1);
                ttbr1_el1 = tc->readMiscReg(MISCREG_TTBR1_EL1);
                mair = tc->readMiscReg(MISCREG_MAIR_EL1);
            }
            break;
          case EL2:
            sctlr = tc->readMiscReg(MISCREG_SCTLR_EL2);
            ttbcr = tc->readMiscReg(MISCREG_TCR_EL2);
            asid = -1;
            mair = tc->readMiscReg(MISCREG_MAIR_EL2);
            break;
          case EL3:
            sctlr = tc->readMiscReg(MISCREG_SCTLR_EL3);
            ttbcr = tc->readMiscReg(MISCREG_TCR_EL3);
            asid = -1;
            mair = tc->readMiscReg(MISCREG_MAIR_EL3);
            break;
        }
        hcr = tc->readMiscReg(MISCREG_HCR_EL2);
        scr = tc->readMiscReg(MISCREG_SCR_EL3);
        isPriv = aarch64EL != EL0;
        if (haveVirtualization) {
            vmid           = bits(tc->readMiscReg(MISCREG_VTTBR_EL2), 55, 48);
            isHyp = aarch64EL == EL2;
            isHyp |= tranType & HypMode;
            isHyp &= (tranType & S1S2NsTran) == 0;
            isHyp &= (tranType & S1CTran)    == 0;
            // Work out if we should skip the first stage of translation and go
            // directly to stage 2. This value is cached so we don't have to
            // compute it for every translation.
            stage2Req = isStage2 ||
                        (hcr.vm && !isHyp && !isSecure &&
                         !(tranType & S1CTran) && (aarch64EL < EL2) &&
                         !(tranType & S1E1Tran)); // <--- FIX THIS HACK
            directToStage2 = !isStage2 && stage2Req && !sctlr.m;
            vttbr_el2 = tc->readMiscReg(MISCREG_VTTBR_EL2);
        } else {
            vmid           = 0;
            isHyp          = false;
            directToStage2 = false;
            stage2Req      = false;
        }
    } else {  // AArch32
        sctlr  = tc->readMiscReg(snsBankedIndex(MISCREG_SCTLR, tc,
                                 !isSecure));
        ttbcr  = tc->readMiscReg(snsBankedIndex(MISCREG_TTBCR, tc,
                                 !isSecure));
        htcr   = tc->readMiscReg(MISCREG_HTCR);
        scr    = tc->readMiscReg(MISCREG_SCR);
        isPriv = cpsr.mode != MODE_USER;
        if (longDescFormatInUse(tc)) {
            uint64_t ttbr_asid = tc->readMiscReg(
                snsBankedIndex(ttbcr.a1 ? MISCREG_TTBR1 :
                                          MISCREG_TTBR0,
                                       tc, !isSecure));
            asid = bits(ttbr_asid, 55, 48);
        } else { // Short-descriptor translation table format in use
            CONTEXTIDR context_id = tc->readMiscReg(snsBankedIndex(
                MISCREG_CONTEXTIDR, tc,!isSecure));
            asid = context_id.asid;
        }
        prrr = tc->readMiscReg(snsBankedIndex(MISCREG_PRRR, tc,
                               !isSecure));
        nmrr = tc->readMiscReg(snsBankedIndex(MISCREG_NMRR, tc,
                               !isSecure));
        dacr = tc->readMiscReg(snsBankedIndex(MISCREG_DACR, tc,
                               !isSecure));
        hcr  = tc->readMiscReg(MISCREG_HCR);

        ttbr0_el1 = tc->readMiscReg(MISCREG_TTBR0);
        ttbr1_el1 = tc->readMiscReg(MISCREG_TTBR1);

        if (haveVirtualization) {
            vmid   = bits(tc->readMiscReg(MISCREG_VTTBR), 55, 48);
            isHyp  = cpsr.mode == MODE_HYP;
            isHyp |=  tranType & HypMode;
            isHyp &= (tranType & S1S2NsTran) == 0;
            isHyp &= (tranType & S1CTran)    == 0;
            if (isHyp) {
                sctlr = tc->readMiscReg(MISCREG_HSCTLR);
            }
            // Work out if we should skip the first stage of translation and go
            // directly to stage 2. This value is cached so we don't have to
            // compute it for every translation.
            stage2Req      = hcr.vm && !isStage2 && !isHyp && !isSecure &&
                             !(tranType & S1CTran);
            directToStage2 = stage2Req && !sctlr.m;
            vttbr_el2 = tc->readMiscReg(MISCREG_VTTBR);
        } else {
            vmid           = 0;
            stage2Req      = false;
            isHyp          = false;
            directToStage2 = false;
        }
    }

    hcr_el2 = tc->readMiscReg(MISCREG_HCR_EL2);

    miscRegValid = true;
    miscRegContext = tc->contextId();
    curTranType  = tranType;
}

ExceptionLevel
TLB::tranTypeEL(CPSR cpsr, ArmTranslationType type)
{
    switch (type) {
      case S1E0Tran:
      case S12E0Tran:
        return EL0;

      case S1E1Tran:
      case S12E1Tran:
        return EL1;

      case S1E2Tran:
        return EL2;

      case S1E3Tran:
        return EL3;

      case NormalTran:
      case S1CTran:
      case S1S2NsTran:
      case HypMode:
        return currEL(cpsr);

      default:
        panic("Unknown translation mode!\n");
    }
}

void
TLB::setTestInterface(SimObject *_ti)
{
    if (!_ti) {
        test = nullptr;
    } else {
        TlbTestInterface *ti(dynamic_cast<TlbTestInterface *>(_ti));
        fatal_if(!ti, "%s is not a valid ARM TLB tester\n", _ti->name());
        test = ti;
    }
}

Fault
TLB::testTranslation(const RequestPtr &req, Mode mode,
                     TlbEntry::DomainType domain)
{
    if (!test || !req->hasSize() || req->getSize() == 0 ||
        req->isCacheMaintenance()) {
        return NoFault;
    } else {
        return test->translationCheck(req, isPriv, mode, domain);
    }
}

Fault
TLB::testWalk(Addr pa, Addr size, Addr va, bool is_secure, Mode mode,
              TlbEntry::DomainType domain, LookupLevel lookup_level)
{
    if (!test) {
        return NoFault;
    } else {
        return test->walkCheck(pa, size, va, is_secure, isPriv, mode,
                               domain, lookup_level);
    }
}


ArmISA::TLB *
ArmTLBParams::create()
{
    return new ArmISA::TLB(this);
}

void
TLB::memAttrDefaults(MemoryAttributes* memattrs)
{
    assert(memattrs);

    if (memattrs->type == TlbEntry::MemoryType::Device) {
        memattrs->shareable      = true;
        memattrs->outershareable = true;
    } else {
        if ((memattrs->inner.attrs == MemAttr::NC) &&
            (memattrs->outer.attrs == MemAttr::NC))
        {
            memattrs->shareable      = true;
            memattrs->outershareable = true;
        }
    }
}

Fault
TLB::permissionFault(TranslationState* tran)
{
    Addr vaddr = tran->vaddress;
    TlbEntryPtr te = isStage2 ? tran->s2te : tran->s1te;
    assert(te);

    permsFaults++;

    DPRINTF(TLBVerbose, "Permission fault for AArch%d vaddr:%#x\n",
            tran->aarch64 ? 64 : 32, vaddr);

    if (tran->isFetch()) {
        return std::make_shared<PrefetchAbort>(
            tran->req->getPC(), ArmFault::PermissionLL + te->lookupLevel,
            isStage2, tran->aarch64 ? ArmFault::LpaeTran : ArmFault::VmsaTran);
    } else {
        return std::make_shared<DataAbort>(
            vaddr, te->domain, tran->isWrite(),
            ArmFault::PermissionLL + te->lookupLevel, isStage2,
            tran->aarch64 ? ArmFault::LpaeTran : ArmFault::VmsaTran);
    }
}

void
TLB::firstStageTranslate32(TranslationState* tran)
{
    bool s1_enabled, dc, tge;

    if (tran->aarch64EL == EL2) {
        s1_enabled = (tran->sctlr.m == 1);
    } else if (ArmSystem::haveEL(tran->tc, EL2) && !tran->isSecure) {
        tge = tran->hcr.tge;
        dc  = tran->hcr.dc;
        s1_enabled = !tge && !dc && tran->sctlr.m;
    } else {
        dc = tran->hcr.dc;
        s1_enabled = !dc && tran->sctlr.m;
    }

    tran->s2fs1walk = false;

    if (s1_enabled) {
        bool long_desc_format = tran->aarch64 || tran->isHyp ||
                                tran->usingLongDescFormat;

        if (long_desc_format) {
            tran->permissioncheck = true;
            tran->domaincheck = false;
        } else {
            tran->permissioncheck = true;
            tran->domaincheck = true;
        }
        translateAddressOn(tran);
    } else {
        translateAddressS1Off32(tran);
    }
}

void
TLB::firstStageTranslate64(TranslationState* tran)
{
    bool s1_enabled;

    SCTLR sctlr_el1 = tran->sctlr;

    if (stage2Req) {
        HCR hcr_el2 = tran->hcr;
        s1_enabled = !hcr_el2.tge && !hcr_el2.dc && sctlr_el1.m;
    } else {
        s1_enabled = sctlr_el1.m;
    }

    if (s1_enabled) {
        translateAddressOn(tran);
        tran->permissioncheck = true;
    } else {
        translateAddressS1Off64(tran);
        tran->permissioncheck = false;
    }
}

void
TLB::secondStageTranslate(TranslationState* tran)
{
    HCR hcr = tran->hcr;

    bool s2_enabled = hcr.vm || hcr.dc;

    if (s2_enabled) {
        translateAddressOn(tran);
    }
}

void
TLB::stage2lookup(TranslationState* tran)
{
    tran->stage2lookup = true;
    assert(tran->stage2Tlb);
    tran->stage2Tlb->translateAddressOn(tran);
}

void
TLB::translateAddressOn(TranslationState* tran)
{
    tran->mmuEnabled = true;

    bool tlb_hit = lookup(tran, false, false, false);

    LookupStatus status = tlb_hit ? TLB_HIT : TLB_MISS;

    if (tran->timing) {
        tran->latency += access_latency;

        if (tran->timing && !tran->delayed) {
            tran->delayed = true;
            tran->translation->markDelayed();
        }

        scheduleEvent(tran, status);
    } else {
        lookupReturn(tran, status);

        // If the translation needs a stage 2 and stage 1 finished without
        // a fault, perform the lookup here before finish returning the
        // physical address
        if (!isStage2 && stage2Req) {
            stage2lookup(tran);
            tran->stage2lookupDone = true;
        }
    }
}

void
TLB::lookupReturn(TranslationState* tran, LookupStatus status)
{
    DPRINTF(TLB, "Returning from a lookup for %#x (%s)\n",
            isStage2 ? tran->ipaddress : tran->vaddress,
            status == TLB_HIT ? "hit" : "miss");

    switch (status)
    {
        case TLB_HIT:
        {
            if (tran->isFetch()) {
                instHits++;
            } else if (tran->isWrite()) {
                writeHits++;
            } else {
                readHits++;
            }

            // If a stage 2 lookup was done and we are the stage 2 TLB, mark
            // the translation as the lookup was finished so the S1 and S2
            // descriptors will be combined
            if (isStage2 && tran->stage2lookup) {
                tran->stage2lookupDone = true;
            }

            // Check the permissions before sending any more requests to
            // lower TLB levels if the translation didn't fault before
            if (tran->fault == NoFault) {
                if (tran->aarch64) {
                    tran->permissioncheck = true;
                    tran->fault = checkPermissions64(tran);
                } else {
                    tran->fault = checkPermissions(tran);
                }
            }

            setMemoryAttributes(tran);

            // We can return the result of the translation back to the CPU
            // and send it also to the upper TLB level
            if (tran->fault == NoFault) {
                // Perform a stage 2 translation with the result of the stage 1
                // translation before finalize
                if (!tran->stage2lookupDone && !isStage2 && tran->stage2Req) {
                    stage2lookup(tran);
                }
                // The translation is finished but we still need to fill
                // the lower TLB levels. If it requires a stage 2 translation,
                // it will be the stage 2 TLB the one finalizing it
                if (tran->timing) {
                    sendTimingResponse(tran);
                    bool stage2Req = tran->stage2Req;
                    bool stage2lookupDone = tran->stage2lookupDone;
                    if (isStage2 ||
                        (!stage2Req || (stage2Req && stage2lookupDone))) {
                        finalizeTranslation(tran);
                    }
                }
            } else {
                DPRINTF(TLB, "Translation fault=%u\n", tran->fault);

                if (tran->timing) {
                    // There was a fault during the lookup checking the
                    // permissions. Finish here the current translation.
                    // Update the original translation structure with the fault
                    // and send a response to the upper TLB so it cleans its
                    // translation structures
                    finalizeTranslation(tran);
                }
            }
        }
            break;

        case TLB_MISS:
        {
            DPRINTF(TLB, "TLB Miss: sending request through the mem side port "
                    "for address %#x\n",
                    isStage2 ? tran->ipaddress : tran->vaddress);

            if (tran->isFetch()) {
                instMisses++;
            } else if (tran->isWrite()) {
                writeMisses++;
            } else {
                readMisses++;
            }

            if (tran->req->isPrefetch()) {
                // if the request is a prefetch don't attempt to fill the TLB
                // or go any further with the memory access, here we can safely
                // use the fault status for the short desc. format in all cases
                prefetchFaults++;
                tran->fault = std::make_shared<PrefetchAbort>(
                        tran->req->getVaddr(),
                        ArmFault::PrefetchTLBMiss,
                        isStage2);
            } else {
                // Setup a Packet to send the translation through the port
                // connecting the next TLB level
                PacketPtr pkt = new Packet(tran->req, MemCmd::ReadReq);
                pkt->senderState = safe_cast<TranslationState*>(tran);
                tran->tlb = this;

                if (tran->timing) {
                    if (!memSidePort->sendTimingReq(pkt)) {
                        memSidePort->retries.push_back(pkt);
                    }
                } else {
                    memSidePort->sendAtomic(pkt);
                    // We own the packet in these cases, so delete it
                    delete pkt;
                    if (tran->fault == NoFault) {
                        insert(tran);
                    }
                }
            }
        }
            break;

        default:
            panic("%s:%s Invalid TLB lookup status", __FILE__, __LINE__);
    }
}

void
TLB::setMemoryAttributes(TranslationState* tran)
{
    assert(tran);
    RequestPtr req = tran->req;
    TlbEntryPtr te = isStage2 ? tran->s2te : tran->s1te;

    setAttr(te->attributes);

    bool uncacheable = te->mtype == TlbEntry::MemoryType::Device ||
                       te->innerAttrs == static_cast<uint8_t>(MemAttr::NC) ||
                       te->outerAttrs == static_cast<uint8_t>(MemAttr::NC);

    DPRINTF(TLBVerbose, "Setting memory attributes: shareable: %d, "
            "innerAttrs: %s, outerAttrs: %s, mtype: %d, isStage2: %d\n",
            te->shareable, s_memattrs[te->innerAttrs],
            s_memattrs[te->outerAttrs],
            s_memtypes[static_cast<uint8_t>(te->mtype)], isStage2);

    if (uncacheable && !req->isCacheMaintenance()) {
        req->setFlags(Request::UNCACHEABLE);
    }

    // Require requests to be ordered if the request goes to strongly
    // ordered or device memory (i.e, anything other than normal memory
    // requires strict order)
    if (te->mtype != TlbEntry::MemoryType::Normal) {
        req->setFlags(Request::STRICT_ORDER);
    }

    if (tran->isSecure && !te->ns) {
        req->setFlags(Request::SECURE);
    }
    if ((!tran->isFetch()) &&
        (req->getVaddr() & mask(req->getFlags() & AlignmentMask)) &&
        (te->mtype != TlbEntry::MemoryType::Normal))
    {
        DPRINTF(TLB, "Unaligned access to device memory\n");
        // Unaligned accesses to Device memory should always cause an
        // abort regardless of sctlr.a
        alignFaults++;
        tran->fault = std::make_shared<DataAbort>(
            tran->req->getVaddr(),
            TlbEntry::DomainType::NoAccess, tran->isWrite(),
            ArmFault::AlignmentFault, isStage2,
            tran->tranMethod);
    }
}

void
TLB::setPhysicalAddress(TranslationState* tran)
{
    assert(tran);

    if (!tran->mmuEnabled)
    {
        tran->req->setPaddr(tran->vaddress);

        // When the MMU is off the security attribute corresponds to the
        // security state of the processor
        if (isSecure) {
            tran->req->setFlags(Request::SECURE);
        }

        // @todo: double check this (ARM ARM issue C B3.2.1)
        bool long_desc_format = aarch64 || longDescFormatInUse(tran->tc);
        if (long_desc_format || sctlr.tre == 0 || nmrr.ir0 == 0 ||
            nmrr.or0 == 0 || prrr.tr0 != 0x2) {
            if (!tran->req->isCacheMaintenance()) {
                tran->req->setFlags(Request::UNCACHEABLE);
            }
            tran->req->setFlags(Request::STRICT_ORDER);
        }

        tran->fault = testTranslation(tran->req, tran->mode,
                                      TlbEntry::DomainType::NoAccess);
    }
    else
    {
        Addr physaddr = isStage2 ? tran->s2_physaddr : tran->s1_physaddr;

        if (tran->stage2lookupDone) {
            physaddr = tran->s2_physaddr;
        }

        tran->req->setPaddr(physaddr);
    }
}

void
TLB::sendTimingResponse(TranslationState* tran)
{
    assert(tran);

    // Send the TranslationState back to the upper TLB using the port saved
    // when the timing request was sent
    if (tran->ports.size() == 0) {
        return; // No more TLB levels
    }

    PacketPtr pkt = new Packet(tran->req, MemCmd::ReadReq);
    pkt->senderState = safe_cast<TranslationState*>(tran);
    SlavePort *return_port = tran->ports.back();
    tran->ports.pop_back();
    if (pkt->isRequest()) {
        pkt->makeTimingResponse();
    }
    if (!return_port->sendTimingResp(pkt)) {
        panic("%s:%s failed sending timing resp", __FILE__, __LINE__);
    }
}

void
TLB::firstStageTranslateFinalize(TranslationState* tran)
{
    bool wasaligned = tran->wasaligned;
    Fault fault = tran->fault;
    MemoryAttributes *memattrs = tran->s1->addrdesc->memattrs;

    assert(memattrs);

    // Check for unaligned data accesses to device memory
    if ((!wasaligned) &&
        (memattrs->type == TlbEntry::MemoryType::Device) &&
        (fault == NoFault))
    {
        panic("Unimplemented alignment fault");
    }

    bool permissioncheck = tran->permissioncheck;

    if ((fault == NoFault) && permissioncheck) {
        panic("Unimplemented permission check");
    }

    // Check for instruction fetches from device memory not marked as
    // execute-never. If there has not been a permission fault then the
    // memory is not marked execute-never
    if ((fault == NoFault) &&
        (memattrs->type == TlbEntry::MemoryType::Device))
    {
        panic("Unimplemented fetch from device memory check");
    }
}

Fault
TLB::finalizeTranslation(TranslationState* tran)
{
    assert(tran);

    Fault fault = tran->fault;

    if (fault == NoFault) {
        setPhysicalAddress(tran);
    } else if (tran->stage2lookupDone) {
        // If the second stage of translation generated a fault add the
        // details of the original stage 1 virtual address
        reinterpret_cast<ArmFault*>(fault.get())->annotate(ArmFault::OVA,
            tran->req->getVaddr());
    }

    // Generate Illegal Inst Set State fault if IL bit is set in CPSR
    if (tran->aarch64 && tran->isFetch() && tran->cpsr.il) {
        fault = std::make_shared<IllegalInstSetStateFault>();
    }

    if (fault == NoFault) {
        // Check for a trickbox generated address fault
        fault = testTranslation(tran->req, tran->mode, tran->domain);
        // Don't try to finalize a physical address unless the translation
        // has completed
        finalizePhysical(tran->req, tran->tc, tran->mode);
    }

    if (tran->mmuEnabled && tran->timing)
    {
        assert(tran->translation);

        DPRINTF(TLB, "PC:%#x Finish translation %#x -> %#x Fault: %s\n",
                tran->req->getPC(),
                tran->req->hasVaddr() ? tran->req->getVaddr() : 0,
                tran->req->hasPaddr() ? tran->req->getPaddr() : 0,
                fault == NoFault ? "no" : "yes");

        tran->translation->finish(fault, tran->req, tran->tc, tran->mode);
    }

    tran->finished = true;
    delete tran;

    return fault;
}

void
TLB::translateAddressS1Off32(TranslationState* tran)
{
    assert(!tran->aarch64);

    bool default_cacheable = (stage2Req && tran->hcr.dc);

    auto addrdesc = std::make_shared<AddressDescriptor>();
    MemoryAttributes* memattrs = addrdesc->memattrs;

    if (default_cacheable) {
        // Use default cacheable settings
        memattrs->type = TlbEntry::MemoryType::Normal;
        memattrs->inner.attrs = MemAttr::WB; // Write-back
        memattrs->inner.hints = MemHint::RWA;
        memattrs->shareable = false;
        memattrs->outershareable = false;
    } else if (!tran->req->isInstFetch()) {
        // Treat data as Device
        memattrs->type = TlbEntry::MemoryType::Device;
        memattrs->device = DeviceType::nGnRnE;
    } else {
        // Instruction cacheability controlled by SCTLR/HSCTLR.I
        bool cacheable = (tran->sctlr.i == 1);

        memattrs->type = TlbEntry::MemoryType::Normal;

        if (cacheable) {
            memattrs->inner.attrs = MemAttr::WT;
            memattrs->inner.hints = MemHint::RA;
        } else {
            memattrs->inner.attrs = MemAttr::NC;
            memattrs->inner.hints = MemHint::No;
        }

        memattrs->shareable      = true;
        memattrs->outershareable = true;
    }

    memattrs->outer = memattrs->inner;
    memAttrDefaults(memattrs);

    addrdesc->fault = NoFault;
    addrdesc->paddress.ns = !tran->isSecure;
    addrdesc->paddress.physicaladdress = tran->vaddress;

    tran->s1_physaddr = addrdesc->paddress.physicaladdress;

    DPRINTF(TLBVerbose, "(No MMU) setting memory attributes: shareable: "
            "%d, innerAttrs: %d, outerAttrs: %d, mtype: %s, isStage2: %d\n",
            memattrs->shareable,
            s_memattrs[static_cast<uint8_t>(memattrs->inner.attrs)],
            s_memattrs[static_cast<uint8_t>(memattrs->outer.attrs)],
            s_memattrs[static_cast<uint8_t>(memattrs->type)],
            isStage2);

    // Update the memory attributes
    TlbEntry temp_te;
    temp_te.setAttributes();
    setAttr(temp_te.attributes);

    tran->finished = true;

    TLBRecord* result = new TLBRecord(addrdesc);
    result->perms.xn  = false;
    result->perms.pxn = false;

    tran->s1 = result;
}

void
TLB::translateAddressS1Off64(TranslationState* tran)
{
    assert(tran->aarch64);

    auto addrdesc = std::make_shared<AddressDescriptor>();
    MemoryAttributes* memattrs = addrdesc->memattrs;

    bool default_cacheable = (stage2Req && tran->hcr.dc);

    if (default_cacheable) {
        // Use default cacheable settings
        memattrs->type           = TlbEntry::MemoryType::Normal;
        memattrs->inner.attrs    = MemAttr::WB; // Write-back
        memattrs->inner.hints    = MemHint::RWA;
        memattrs->shareable      = false;
        memattrs->outershareable = false;
    } else if (!tran->req->isInstFetch()) {
        // Treat data as Device
        memattrs->type   = TlbEntry::MemoryType::Device;
        memattrs->device = DeviceType::nGnRnE;
    } else {
        // Instruction cacheability controlled by SCTLR_ELx.I
        bool cacheable = (tran->sctlr.i == 1);

        memattrs->type = TlbEntry::MemoryType::Normal;

        if (cacheable) {
            memattrs->inner.attrs = MemAttr::WT;
            memattrs->inner.hints = MemHint::RA;
        } else {
            memattrs->inner.attrs = MemAttr::NC;
            memattrs->inner.hints = MemHint::No;
        }

        memattrs->shareable      = true;
        memattrs->outershareable = true;
    }

    memattrs->outer = memattrs->inner;
    memAttrDefaults(memattrs);

    addrdesc->fault = NoFault;
    addrdesc->paddress.ns = !tran->isSecure;
    addrdesc->paddress.physicaladdress = bits(tran->vaddress, 51, 0);

    tran->s1_physaddr = addrdesc->paddress.physicaladdress;

    DPRINTF(TLBVerbose, "(No MMU) setting memory attributes: shareable: "
            "%d, innerAttrs: %d, outerAttrs: %d, mtype: %s, isStage2: %d\n",
            memattrs->shareable,
            s_memattrs[static_cast<uint8_t>(memattrs->inner.attrs)],
            s_memattrs[static_cast<uint8_t>(memattrs->outer.attrs)],
            s_memattrs[static_cast<uint8_t>(memattrs->type)],
            isStage2);

    // Update the memory attributes
    TlbEntry temp_te;
    temp_te.setAttributes();
    setAttr(temp_te.attributes);

    tran->finished = true;

    TLBRecord* result = new TLBRecord(addrdesc);
    result->perms.xn  = false;
    result->perms.pxn = false;

    tran->s1 = result;
}

AddressDescriptor*
TLB::combineS1S2Desc(AddressDescriptor* s1desc, AddressDescriptor* s2desc)
{
    assert(s1desc);
    assert(s2desc);

    AddressDescriptor* result = new AddressDescriptor();
    MemoryAttributes* memattrs = result->memattrs;

    result->paddress = s2desc->paddress;

    if (s1desc->isFault()) {
        result = s1desc;
    } else if (s2desc->isFault()) {
        result = s2desc;
    } else if (s2desc->memattrs->type == TlbEntry::MemoryType::Device ||
               s1desc->memattrs->type == TlbEntry::MemoryType::Device)
    {
        memattrs->type = TlbEntry::MemoryType::Device;

        if (s1desc->memattrs->type == TlbEntry::MemoryType::Normal) {
            memattrs->device = s2desc->memattrs->device;
        } else if (s2desc->memattrs->type == TlbEntry::MemoryType::Normal) {
            memattrs->device = s1desc->memattrs->device;
        } else { // Both device
            DeviceType s1device = s1desc->memattrs->device;
            DeviceType s2device = s2desc->memattrs->device;
            memattrs->device = combineS1S2Device(s1device, s2device);
        }
    }
    else { // Both normal
        memattrs->type = TlbEntry::MemoryType::Normal;

        MemAttrHints s1_inner = s1desc->memattrs->inner;
        MemAttrHints s2_inner = s2desc->memattrs->inner;
        MemAttrHints s1_outer = s1desc->memattrs->outer;
        MemAttrHints s2_outer = s2desc->memattrs->outer;

        memattrs->inner = combineS1S2AttrHints(s1_inner, s2_inner);
        memattrs->inner = combineS1S2AttrHints(s1_outer, s2_outer);

        bool s1_shareable = s1desc->memattrs->shareable;
        bool s2_shareable = s2desc->memattrs->shareable;

        memattrs->shareable = (s1_shareable || s2_shareable);

        bool s1_outershareable = s1desc->memattrs->outershareable;
        bool s2_outershareable = s2desc->memattrs->outershareable;

        memattrs->outershareable = (s1_outershareable || s2_outershareable);
    }

    memAttrDefaults(result->memattrs);

    DPRINTF(TLBVerbose, "Combining S1 and S2 descriptors: %#x\n",
            result->paddress.physicaladdress);

    return result;
}

DeviceType
TLB::combineS1S2Device(DeviceType s1device, DeviceType s2device)
{
    if (s2device == DeviceType::nGnRnE ||
        s1device == DeviceType::nGnRnE) {
        return DeviceType::nGnRnE;
    } else if (s2device == DeviceType::nGnRE ||
               s2device == DeviceType::nGnRE) {
        return DeviceType::nGnRE;
    } else if (s2device == DeviceType::nGRE ||
               s2device == DeviceType::nGRE) {
        return DeviceType::nGRE;
    }
    return DeviceType::GRE;
}

MemAttrHints
TLB::combineS1S2AttrHints(MemAttrHints s1desc, MemAttrHints s2desc)
{
    MemAttrHints result;

    if (s2desc.attrs == MemAttr::RESERVED ||
        s1desc.attrs == MemAttr::RESERVED) {
        // Unknown. Reserved
    } else if (s2desc.attrs == MemAttr::NC ||
               s1desc.attrs == MemAttr::NC) {
        result.attrs = MemAttr::NC; // Non-cacheable
    } else if (s2desc.attrs == MemAttr::WT ||
               s1desc.attrs == MemAttr::WT) {
        result.attrs = MemAttr::WT; // Write-through
    } else {
        result.attrs = MemAttr::WB; // Write-back
    }

    result.hints = s1desc.hints;
    result.transient = s1desc.transient;

    return result;
}

Fault
TLB::checkDomain(TranslationState* tran)
{
    TlbEntry::DomainType domain = tran->domain;

    uint8_t index = 2 * static_cast<uint8_t>(domain);
    uint8_t attrfield = bits(tran->dacr, index+1, index);

    switch (attrfield)
    {
        // No access. Any access to the domain generates a domain fault
        case 0x0:
            domainFaults++;

            DPRINTF(TLB, "TLB Fault: Data abort on domain. DACR:%#x"
                    " domain:%#x write:%d\n", tran->dacr,
                    static_cast<uint8_t>(domain), tran->isWrite());

            if (tran->isFetch()) {
                // Use PC value instead of vaddr because vaddr might
                // be aligned to cache line and should not be the
                // address reported in FAR
                return std::make_shared<PrefetchAbort>(tran->req->getPC(),
                    ArmFault::DomainLL + tran->s1->level, isStage2,
                    tran->tranMethod);
            } else {
                bool is_write = tran->isWrite();
                return std::make_shared<DataAbort>(tran->req->getVaddr(),
                    domain, is_write, ArmFault::DomainLL + tran->s1->level,
                    isStage2, tran->tranMethod);
            }
            break;
        // Reserved, maps to an allocated value
        case 0x2:
            panic("Reserved value in DACR domain check");
            break;
        // 0b01: Client. Accesses are checked against the permission bits
        // 0b11: Manager. Accesses are NOT checked against the permission bits
        default:
            tran->permissioncheck = (attrfield == 0x1);
            break;
    }

    return NoFault;
}

Fault
TLB::checkS1Permission32(TranslationState* tran)
{
    // A data cache maintenance instruction that operates by MVA does not
    // generate a Data Abort exception due to a Permission fault
    if (tran->req->isCacheMaintenance()) {
        return NoFault;
    }

    assert(tran);
    assert(tran->s1te);

    TlbEntryPtr te = tran->s1te;

    bool priv_r, priv_w, user_r, user_w;
    bool r, w, xn, wxn;

    priv_r = priv_w = user_r = user_w = false;

    ExceptionLevel pstateEL = (ExceptionLevel)(uint8_t)(tran->cpsr.el);

    bool is_write = tran->isWrite();
    bool M5_VAR_USED is_fetch = tran->isFetch();

    uint8_t ap = tran->usingLongDescFormat ? (te->ap << 1) : te->ap;
    ap &= 0x3; // Always 3 bits

    DPRINTF(TLBVerbose, "(AArch32) Checking stage 1 permissions: ap:%u, xn:%u,"
            " pxn:%u, r:%u, w:%u, x:%u\n", ap, te->xn, te->pxn,
            !is_write && !is_fetch, is_write, is_fetch);

    bool is_priv = tran->accessIsPrivileged();

    if (pstateEL != EL2) {
        SCTLR sctlr = tran->sctlr;
        TTBCR ttbcr = tran->ttbcr;
        wxn = sctlr.wxn;
        if (ttbcr.eae || sctlr.afe || bits(te->ap, 0)) {
            priv_r = true;
            priv_w = bits(te->ap, 2) == 0x0;
            user_r = bits(te->ap, 1) == 0x1;
            user_w = bits(te->ap, 2, 1) == 0x1;
        } else {
            priv_r = bits(te->ap, 2, 1) != 0x0;
            priv_w = bits(te->ap, 2, 1) == 0x1;
            user_r = bits(te->ap, 1) == 0x1;
            user_w = false;
        }

        bool uwxn = sctlr.uwxn;

        // TODO: implement more checks with PAN extensions

        bool user_xn = !user_r || te->xn || (user_w && wxn);
        bool priv_xn = !priv_r || te->xn || te->pxn ||
                       (priv_w && wxn) || (user_w && uwxn);

        if (is_priv) {
            r = priv_r;
            w = priv_w;
            xn = priv_xn;
        } else {
            r = user_r;
            w = user_w;
            xn = user_xn;
        }

        DPRINTF(TLBVerbose, "r:%u w:%u xn:%u wxn:%u uwxn:%u priv_r:%u "
                "priv_w:%u priv_xn:%u user_r:%u user_w:%u user_xn:%u "
                "is_priv:%u\n", r, w, xn, wxn, uwxn, priv_r, priv_w, priv_xn,
                user_r, user_w, user_xn, is_priv);
    } else {
        // Access from EL2
        wxn = sctlr.wxn; // This is SCTLR read as HSCTLR
        r = true;
        w = bits(ap, 2) == 0x0;
        xn = te->xn || (w && wxn);
    }

    bool fail;

    if (tran->req->isInstFetch()) {
        fail = xn;
    } else {
        if (is_write && !tran->isSecure && (pstateEL == EL1)) {
            fail = !w;
        } else {
            fail = !r;
        }
    }

    if (fail) {
        return permissionFault(tran);
    }

    return NoFault;
}

Fault
TLB::checkS1Permission64(TranslationState* tran)
{
    assert(tran);
    assert(tran->s1te);

    TlbEntryPtr te = tran->s1te;

    bool wxn = tran->sctlr.wxn;

    bool r = false;
    bool w = false;
    bool xn = false;

    bool M5_VAR_USED is_fetch = tran->isFetch();
    bool is_write = tran->isWrite();

    bool pan_fail = false;
    const bool priv_w = bits(te->ap, 2) == 0;
    const bool user_r = bits(te->ap, 1) == 1;
    const bool user_w = bits(te->ap, 2, 1) == 1;

    DPRINTF(TLBVerbose, "(AArch64) Checking stage 1 permissions: ap:%u, xn:%u,"
            " pxn:%u, r:%u, w:%u, x:%u, el:%u\n", te->ap, te->xn, te->pxn,
            !is_write && !is_fetch, is_write, is_fetch, tran->aarch64EL);

    switch (tran->aarch64EL)
    {
        case EL0:
        case EL1:
        {
            bool is_priv = tran->accessIsPrivileged();
            if (is_priv) {
                r  = true;
                w  = priv_w;
                xn = (te->pxn == 1) || (priv_w && wxn) || user_w;

                pan_fail = panFault(tran, user_r || user_w);
            } else {
                r  = user_r;
                w  = user_w;
                xn = (te->xn == 1) || (user_w && wxn);
            }
        }
        break;

        case EL2:
            if (hcr.e2h) {
                pan_fail = panFault(tran, user_r || user_w);
            }
            M5_FALLTHROUGH;
        case EL3:
            r = true;
            w = bits(te->ap, 2) == 0;
            xn = te->xn || (w && wxn);
            break;
    }

    bool fail;

    if (tran->req->isInstFetch()) {
        fail = xn;
    } else {
        if (is_write) {
            fail = !w;
        } else {
            fail = !r;
        }
    }

    if (fail || pan_fail) {
        return permissionFault(tran);
    }

    return NoFault;
}

Fault
TLB::checkS2Permission32(TranslationState* tran)
{
    assert(tran);
    assert(tran->s2te);

    TlbEntryPtr te = tran->s2te;

    bool M5_VAR_USED is_fetch = tran->isFetch();
    bool is_write = tran->isWrite();

    DPRINTF(TLBVerbose, "(AArch32) Checking stage 2 permissions: ap:%u, xn:%u,"
            "pxn:%u, r:%u, w:%u, x:%u\n", te->ap, te->xn, te->pxn,
            !is_write && !is_fetch, is_write, is_fetch);

    bool r = bits(te->ap, 1);
    bool w = bits(te->ap, 2);
    bool xn;

#if EXTENDED_EXECUTE_NEVER_EXT
    if (haveExtendedExecuteNeverExt()) {
        panic("%s:%s not implemented", __FILE__, __LINE__);
    } else {
#endif
        xn = !r || te->xn;
# if EXTENDED_EXECUTE_NEVER_EXT
    }
#endif

    bool s2fs1walk = tran->s2fs1walk;
    bool fail;

    // Stage 1 walk is checked as a read, regardless of the original type
    if (tran->req->isInstFetch() && !s2fs1walk) {
        fail = xn;
    } else if (is_write && s2fs1walk) {
        fail = !w;
    } else {
        fail = !r;
    }

    if (fail) {
        return permissionFault(tran);
    }

    return NoFault;
}

Fault
TLB::checkS2Permission64(TranslationState* tran)
{
    assert(tran);
    assert(tran->s2te);

    TlbEntryPtr te = tran->s2te;

    bool r = bits(te->ap, 1) == 1;
    bool w = bits(te->ap, 2) == 1;
    bool xn;

#if EXTENDED_EXECUTE_NEVER_EXT
    if (haveExtendedExecuteNeverExt()) {
        panic("%s:%s not implemented", __FILE__, __LINE__);
    } else {
#endif
        xn = te->xn;
#if EXTENDED_EXECUTE_NEVER_EXT
    }
#endif

    bool s2fs1walk = tran->s2fs1walk;
    bool M5_VAR_USED is_fetch = tran->isFetch();
    bool is_write = tran->isWrite();
    bool hwupdatewalk = tran->hwupdatewalk;
    bool fail;

    DPRINTF(TLBVerbose, "(AArch64) Checking stage 2 permissions: ap:%u, xn:%u,"
            " pxn:%u, r:%u, w:%u, x:%u\n", te->ap, te->xn, te->pxn,
            !is_write && !is_fetch, is_write, is_fetch);

    // Stage 1 walk is checked as a read, regardless of the original type
    if (tran->req->isInstFetch() && !s2fs1walk) {
        fail = xn;
    } else if (is_write && s2fs1walk) {
        fail = !w;
    } else if (hwupdatewalk) {
        fail = !w;
    } else {
        fail = !r;
    }

    if (fail) {
        return permissionFault(tran);
    }

    return NoFault;
}

bool
TLB::panFault(TranslationState* tran, bool user)
{
    // The PAN bit has no effect on:
    // 1) Instruction accesses.
    // 2) Data Cache instructions other than DC ZVA
    // 3) Address translation instructions, other than ATS1E1RP and
    // ATS1E1WP when ARMv8.2-ATS1E1 is implemented. (Unimplemented in
    // gem5)
    // 4) Unprivileged instructions (Unimplemented in gem5)
    const auto& req = tran->req;
    AA64MMFR1 mmfr1 = tran->tc->readMiscReg(MISCREG_ID_AA64MMFR1_EL1);
    if (mmfr1.pan && tran->cpsr.pan && user && !req->isInstFetch() &&
        (!req->isCacheMaintenance() ||
            (req->getFlags() & Request::CACHE_BLOCK_ZERO))) {
        return true;
    } else {
        return false;
    }
}

bool
TLB::CpuSidePort::recvTimingReq(PacketPtr pkt)
{
    assert(pkt);
    TranslationState* tran = safe_cast<TranslationState*>(pkt->senderState);
    delete pkt;
    // Save the port to know the path back
    tran->ports.push_back(this);
    tlb->translateAddressOn(tran);
    return true;
}

Tick
TLB::CpuSidePort::recvAtomic(PacketPtr pkt)
{
    assert(pkt);
    TranslationState* tran = safe_cast<TranslationState*>(pkt->senderState);
    // Issue the translation in this level
    tlb->translateAddressOn(tran);
    return 0;
}

void
TLB::CpuSidePort::recvReqRetry()
{
    panic("%s:%s not implemented", __FILE__, __LINE__);
}

void
TLB::CpuSidePort::recvRespRetry()
{
    panic("%s:%s not implemented", __FILE__, __LINE__);
}

bool
TLB::MemSidePort::recvTimingResp(PacketPtr pkt)
{
    assert(pkt);
    TranslationState* tran = safe_cast<TranslationState*>(pkt->senderState);
    delete pkt;

    assert(tran);

    Addr M5_VAR_USED addr = tlb->is_stage2() ?
        tran->ipaddress : tran->vaddress;

    DPRINTF(TLBVerbose, "Received timing response for %#x (fault:%u)\n",
            addr, tran->fault != NoFault);

    // The response can be sent from the table walker or a lower TLB level,
    // no matter the result of the walk, we send the request to upper TLBs
    // and each level will take appropiate actions
    if (tran->fault == NoFault) {
        // If there was no fault, we can just insert the entry for the next
        // TLB lookups
        tlb->insert(tran);
        // If we are also coming from a page walk, schedule an event to
        // finish the translation knowing that we will hit in the TLB.
        if (tran->fromPTW) {
            tran->fromPTW = false;
            tlb->translateAddressOn(tran);
        }

        // Propagate the translation result to upper TLBs
        tlb->sendTimingResponse(tran);
    } else {
        if (tran->fromPTW) {
            tran->fromPTW = false;
            tlb->finalizeTranslation(tran);
        }
    }

    return true;
}

Tick
TLB::MemSidePort::recvAtomic(PacketPtr pkt)
{
    panic("%s:%s not implemented", __FILE__, __LINE__);
}

void
TLB::MemSidePort::recvReqRetry()
{
    panic("%s:%s not implemented", __FILE__, __LINE__);
}

void
TLB::scheduleEvent(TranslationState* tran, LookupStatus status)
{
    TLBEvent* tlb_event = new TLBEvent(this, tran, status);
    translationReturnEvent.push_back(tlb_event);
    schedule(tlb_event, curTick() + cyclesToTicks(access_latency));
}

void
TLB::updateTranslationRegisters(TLB::TranslationState* tran)
{
    tran->isSecure = isSecure;
    tran->aarch64 = aarch64;
    tran->aarch64EL = aarch64EL;
    tran->isSecure = isSecure;
    tran->_isPriv = isPriv;
    tran->isHyp = isHyp;
    tran->asid = asid;
    tran->vmid = vmid;
    tran->cpsr = cpsr;
    tran->sctlr = sctlr;
    tran->scr = scr;
    tran->ttbcr = ttbcr;
    tran->htcr = htcr;
    tran->ttbr0_el1 = ttbr0_el1;
    tran->ttbr1_el1 = ttbr1_el1;
    tran->mair = mair;
    tran->dacr = dacr;
    tran->hcr = hcr;
    tran->prrr = prrr;
    tran->nmrr = nmrr;
}

void
TLB::cleanupEvent(TLBEvent *tlb_event)
{
    std::vector<TLBEvent*>::iterator it;
    it = std::find(translationReturnEvent.begin(),
                   translationReturnEvent.end(),
                   tlb_event);
    assert(it != translationReturnEvent.end());
    translationReturnEvent.erase(it);
    delete tlb_event;
}

TLB::TranslationState::TranslationState(TLB* _tlb) :
    s1(NULL), s2(NULL), timing(false), functional(false), req(nullptr),
    tc(NULL), vaddress(0), ipaddress(0), s1_physaddr(0), s2_physaddr(0),
    wasaligned(false), hwupdatewalk(false), s2fs1walk(false), size(0),
    aarch64EL(EL0), aarch64(false), isHyp(false), _isPriv(false),
    isSecure(false), stage2Req(false), usingLongDescFormat(false), asid(-1),
    vmid(-1), delayed(false), finished(false), mmuEnabled(false),
    stage2lookup(false), stage2lookupDone(false), permissioncheck(false),
    domaincheck(false), domain(TlbEntry::DomainType::NoAccess), cpsr(0),
    sctlr(0), scr(0), tcr(0), ttbr0_el1(0), ttbr1_el1(0), mair(0), hcr(0),
    prrr(0), nmrr(0), fault(NoFault), fromPTW(false), tlb(_tlb),
    stage2Tlb(NULL), translation(NULL), latency(0), s1te(nullptr),
    s2te(nullptr), start(curTick())
{
}

TLB::TranslationState::~TranslationState()
{
    delete s1;
    delete s2;

    if (!functional && mmuEnabled && !finished) {
        panic("Deleting translation %#x that didn't finish: tick %lu pc %#x",
              stage2Tlb ? ipaddress : vaddress, start, pc);
    }
}

void
TLB::TLBEvent::process()
{
    tlb->lookupReturn(tran, status);
    tlb->cleanupEvent(this);
}

TLB::TLBEvent::TLBEvent(TLB *_tlb, TranslationState* _tran,
        LookupStatus _status) : tlb(_tlb), tran(_tran), status(_status)
{
}
