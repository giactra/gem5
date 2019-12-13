/*
 * Copyright (c) 2010-2016 ARM Limited
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

#ifndef __ARCH_ARM_TABLE_WALKER_HH__
#define __ARCH_ARM_TABLE_WALKER_HH__

#include <list>

#include "arch/arm/faults.hh"
#include "arch/arm/miscregs.hh"
#include "arch/arm/system.hh"
#include "arch/arm/tlb.hh"
#include "mem/request.hh"
#include "params/ArmTableWalker.hh"
#include "sim/clocked_object.hh"
#include "sim/eventq.hh"

#define SD_INVALID    0
#define SD_PAGE_TABLE 1

class DmaPort;

namespace ArmISA {

class TLB;

class TableWalker : public ClockedObject
{
  public:
    class WalkerState : public Packet::SenderState
    {
      public:
        /** ID identifying the walk */
        const uint64_t id;
        /** Thread context that we're doing the walk for */
        ThreadContext *tc;
        /** Pointer to the Table Walker performing the translation */
        TableWalker *walker;
        /** If the access is performed in AArch64 state */
        bool aarch64;
        /** Current exception level */
        ExceptionLevel el;
        /** Current physical address range in bits */
        int physAddrRange;
        /** Current lookup level */
        int level;
        /** First block where the translation started */
        int firstblocklevel;
        /** Address descriptor used during the table walk */
        std::shared_ptr<AddressDescriptor> addrdesc;
        /** Request  that is currently being service */
        RequestPtr req;
        /** Cached copy of the sctlr when the translation started */
        SCTLR sctlr;
        /** Cached copy of the hcr when the translation started */
        HCR hcr;
        /** Cached copy of the mair when the translation started */
        uint64_t mair;
        /** Flag indicating if a we are a second stage walker */
        bool isStage2;
        /** Flag indicating if a second stage of lookup is required */
        bool stage2Req;
        /** If the mode is timing or atomic */
        bool timing;
        /** If the atomic mode should be functional */
        bool functional;
        /** Raw bits of the descriptor fetched */
        uint64_t data;
        /** Copy of the L1 short descriptor lookup */
        uint32_t l1desc;
        /** Address used to index in the inflight list */
        Addr desc_addr;

        /** Input address size for the current translation */
        uint8_t inputsize;
        /** Output address size for the current translation */
        uint8_t outputsize;
        /** Flag to indicate if we are using 64KB granule */
        bool largegrain;
        /** Flag to indicate if we are using 16KB granule */
        bool midgrain;
        /** Grain size used during the translation */
        uint8_t grainsize;
        /** Number of strides needed to consume the address */
        uint8_t stride;

        /** Access flags values */
        uint8_t ap_table, ns_table, xn_table, pxn_table;
        /** Flags to indicate update in the descriptor */
        bool update_AP, update_AF;
        /** Flag to indicate if the desciptor is in big endian */
        bool reversedescriptors;
        /** Other access flags values */
        bool lookupsecure, singlepriv, hierattrsdisabled;

        /** Flag to indicate if it's a write */
        bool iswrite;
        /** Flag to indicate a stage 2 from stage 1 translation */
        bool s2fs1walk;

        /** virtual address for this translation */
        Addr address;
        /** Base address register value for this translation */
        Addr baseregister;
        /** Next descriptor address bit selection */
        uint8_t addrselecttop, addrselectbottom;

        /** TLB that initiated the table walk. Used for functional lookups */
        TLB *tlb;

        /** Pointer to the translation structure being used */
        TLB::TranslationState* tran;

        TLB::Translation* stage2Tran;
        Event* next_event;
        Tick startTime;
        bool delayed;
        bool partial_hit;
        bool isInflight;

        static int var;
        WalkerState(TableWalker*, uint64_t);
        ~WalkerState();

        void
        s1AttrDecode64(uint8_t sh, uint8_t memattr)
        {
            MemoryAttributes* memattrs = addrdesc->memattrs;
            uint8_t attr = bits(memattr, 2, 0);
            SCTLR sctlr = tran->sctlr;
            HCR hcr = tran->hcr;
            uint64_t mair = tran->mair;
            walker->s1AttrDecode64(tc, memattrs, sh, attr, el, sctlr, hcr,
                                   mair);
        }

        void
        s1AttrDecode32(uint8_t sh, uint8_t memattr)
        {
            MemoryAttributes* memattrs = addrdesc->memattrs;
            uint8_t attr = bits(memattr, 2, 0);
            walker->s1AttrDecode32(tc, memattrs, sh, attr, el, sctlr, hcr,
                                   mair);
        }

        void
        s2AttrDecode(uint8_t sh, uint8_t memattr)
        {
            MemoryAttributes* memattrs = addrdesc->memattrs;
            walker->s2AttrDecode(memattrs, sh, memattr);
        }

        void maxtickReached();
        EventFunctionWrapper* maxtickReachedEvent;
    };

  protected:

    /** Queues of requests for all the different lookup levels */
    std::map<uint64_t, WalkerState*> stateQueues[MAX_LOOKUP_LEVELS];

    /** Queue of requests that have passed are waiting because the walker is
     * currently busy. */
    std::deque<std::pair<uint64_t, WalkerState*>> pendingQueue;

    /** The MMU to forward second stage look upts to */
    MMU* mmu;

    WalkerState* currState;

    /** Global walk ID */
    uint64_t id, currentId;

    /** Master id assigned by the MMU */
    MasterID masterId;

    /** Indicates whether this table walker is part of the stage 2 MMU */
    const bool isStage2;
    const unsigned numSquashable;
    const unsigned maxInflightWalks;

    /** Keep track of how many walks are inflight */
    unsigned inflightWalks;

    /** Cached copies of system-level properties */
    bool haveSecurity;
    bool _haveLPAE;
    bool _haveVirtualization;
    uint8_t physAddrRange;
    bool _haveLargeAsid64;

    /** Statistics */
    Stats::Scalar statWalks;
    Stats::Scalar statWalksShortDescriptor;
    Stats::Scalar statWalksLongDescriptor;
    Stats::Vector statWalksShortTerminatedAtLevel;
    Stats::Vector statWalksLongTerminatedAtLevel;
    Stats::Scalar statSquashedBefore;
    Stats::Scalar statSquashedAfter;
    Stats::Histogram statWalkWaitTime;
    Stats::Histogram statWalkServiceTime;
    // Essentially "L" of queueing theory
    Stats::Histogram statPendingWalks;
    Stats::Vector statPageSizes;
    Stats::Vector2d statRequestOrigin;

    static const unsigned REQUESTED = 0;
    static const unsigned COMPLETED = 1;

    enum {
        SIZE_4GB = 0,
        SIZE_64GB,
        SIZE_1TB,
        SIZE_4TB,
        SIZE_16TB,
        SIZE_256TB,
        SIZE_4PB
    };

    enum class TG0 : std::uint8_t {
        GRANULE_4KB = 0,
        GRANULE_64KB = 1,
        GRANULE_16KB = 2,
        UNUSED = 3
    };

    enum class TG1 : long unsigned int {
        UNUSED = 0,
        GRANULE_16KB = 1,
        GRANULE_4KB = 2,
        GRANULE_64KB = 3
    };

  public:
   typedef ArmTableWalkerParams Params;
    TableWalker(const Params *p);
    virtual ~TableWalker();

    const Params *
    params() const
    {
        return dynamic_cast<const Params *>(_params);
    }

    bool haveLPAE() const { return _haveLPAE; }
    bool haveVirtualization() const { return _haveVirtualization; }
    bool haveLargeAsid64() const { return _haveLargeAsid64; }
    /** Checks if all state is cleared and if so, completes drain */
    void completeDrain();
    DrainState drain() override;
    void drainResume() override;

    void regStats() override;

    class CpuSidePort : public SlavePort
    {
        public:
            CpuSidePort(const std::string &_name, TableWalker *_walker,
                PortID _index) : SlavePort(_name, _walker),
                    walker(_walker), index(_index) {}

        protected:
            TableWalker *walker;
            int index;

            virtual bool recvTimingReq(PacketPtr pkt);
            virtual Tick recvAtomic(PacketPtr pkt);
            virtual void recvFunctional(PacketPtr pkt) { };
            virtual void recvRangeChange() { };
            virtual void recvReqRetry();
            virtual void recvRespRetry();
            virtual AddrRangeList getAddrRanges() const
            {
                AddrRangeList range;
                return range;
            }
    };

    class MemSidePort : public MasterPort
    {
        public:
            MemSidePort(const std::string &_name, TableWalker *_walker,
                PortID _index) : MasterPort(_name, _walker),
                    walker(_walker), index(_index) {}

            std::deque<PacketPtr> retries;

        protected:
            TableWalker *walker;
            int index;

            virtual bool recvTimingResp(PacketPtr pkt);
            virtual Tick recvAtomic(PacketPtr pkt) { return 0; }
            virtual void recvFunctional(PacketPtr pkt) { };
            virtual void recvRangeChange() { };
            virtual void recvReqRetry();
    };

    std::vector<CpuSidePort*> cpuSidePort;
    MemSidePort* memSidePort;

    Port &getPort(const std::string &if_name,
                  PortID idx=InvalidPortID) override;

    void increaseInflightWalks() {
        if (currState->timing) {
            currState->isInflight = true;
            inflightWalks++;
        }
    }

    void decreaseInflightWalks() {
        if (currState->isInflight) {
            assert(inflightWalks > 0);
            inflightWalks--;
        }
    }

    static LookupLevel toLookupLevel(uint8_t lookup_level_as_int);

private:

    // Returns TRUE if the bits of the input (n) between the high bit (h)
    // and the low bit (l) are ones
    bool isOnes(uint64_t n, uint32_t h, uint32_t l);

    /** Short descriptor event functions */
    void doL1ShortDescriptor();
    void doL1ShortDescriptorWrapper();
    EventFunctionWrapper doL1ShortDescEvent;

    void doL2ShortDescriptor();
    void doL2ShortDescriptorWrapper();
    EventFunctionWrapper doL2ShortDescEvent;

    /** Long descriptor event functions for LPAE and AArch64*/
    void doL0LongDescriptorWrapper();
    EventFunctionWrapper doL0LongDescEvent;
    void doL1LongDescriptorWrapper();
    EventFunctionWrapper doL1LongDescEvent;
    void doL2LongDescriptorWrapper();
    EventFunctionWrapper doL2LongDescEvent;
    void doL3LongDescriptorWrapper();
    EventFunctionWrapper doL3LongDescEvent;

    void doLongDescriptor();
    void doLongDescriptorWrapper(int);
    Event* LongDescEventByLevel[4];

    /** AArch64 descriptor event functions */
    void doAArch64Descriptor();
    void doAArch64DescriptorWrapper(int);

    void processWalkWrapper();
    EventFunctionWrapper doProcessEvent;

    // Returns the descriptor at the physical address specified by the
    // AddressDescriptor, checks access permissions and sets the fault
    // field if needed
    bool fetchDescriptor(int, Request::Flags, int,
                         Event *event, void (TableWalker::*doDescriptor)());

    // Schedule the next table walk in the pending queue
    void nextWalk();

    void sendTimingResponse();

    void insertPartialTranslation();

    // Annotate the fault as it was produced during a stage 1 translation
    // in a stage 2 page walk
    void annotateStage2Fault();

    /// Returns true if the address exceeds the range permitted by the
    /// system-wide setting or by the TCR_ELx IPS/PS setting
    bool checkAddrSizeFaultAArch64(Addr addr, int currPhysAddrRange);

protected:

    void accessFlagFault(TlbEntry::DomainType, ArmFault::TranMethod);
    void addressSizeFault(TlbEntry::DomainType, ArmFault::TranMethod, bool);
    void translationFault(TlbEntry::DomainType, ArmFault::TranMethod);

    bool s1CacheDisabled();
    bool s2CacheDisabled();

    // Converts the Stage 1 attribute fields, using the uint64_t
    // to orthogonal attributes and hints
    void s1AttrDecode32(ThreadContext*, MemoryAttributes*, uint8_t, uint8_t,
        ExceptionLevel, SCTLR, HCR, uint64_t);
    void s1AttrDecode64(ThreadContext*, MemoryAttributes*, uint8_t, uint8_t,
        ExceptionLevel, SCTLR, HCR, uint64_t);

    // Converts the Stage 2 attribute fields into othogonal attributes and
    // hints
    void s2AttrDecode(MemoryAttributes*, uint8_t, uint8_t);

    // Converts the short attribute fields for Normal memory as used in the
    // TTBR and TEX fields to orthogonal attributes and hints
    MemAttrHints shortConvertAttrsHints(uint8_t);

    // Converts the long attribute fields for Normal memory as used in the
    // uint64_t fields to orthogonal attributes and hints
    MemAttrHints longConvertAttrsHints(uint8_t, SCTLR, HCR);

    // Converts the attribute fields for Normal memory as used in stage 2
    // descriptors to orthogonal attributes and hints
    MemAttrHints s2ConvertAttrsHints(uint8_t);

    void walkAttrDecode(ThreadContext*, MemoryAttributes*, uint8_t,
                        uint8_t, uint8_t, ExceptionLevel, SCTLR, HCR);

    void defaultTEXDecode(MemoryAttributes*, uint8_t, bool, bool, bool);
    void remappedTEXDecode(MemoryAttributes*, uint8_t, bool, bool, bool);

    void setCurrentStateId(uint64_t currId) {
        currentId = currId;
    }

    void printPendingQueue();

public:

    // Clean up the currState and pending walk
    void cleanup();

    bool haveLPAE() {
        return _haveLPAE;
    }

    bool haveVirtualization() {
        return _haveVirtualization;
    }

    bool haveLargeAsid64() {
        return _haveLargeAsid64;
    }

    void walk(TLB::TranslationState*);

    void setMMU(MMU*);

    // Returns TRUE if the page walk is being delayed, FALSE otherwise
    // The result of the page walk will be updated in the TranslationState
    // structure
    void translationTableWalkSD(TLB::TranslationState*);
    void translationTableWalkLD(TLB::TranslationState*);
    void translationTableWalk64(TLB::TranslationState*);

    Fault testWalk(Addr pa, Addr size, TlbEntry::DomainType domain,
                   LookupLevel lookup_level);
};

} // namespace ArmISA

#endif //__ARCH_ARM_TABLE_WALKER_HH__
