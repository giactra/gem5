/*
 * Copyright (c) 2010, 2012-2013 ARM Limited
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
 * Copyright (c) 2002-2005 The Regents of The University of Michigan
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
 *          Ivan Pizarro
 */

#ifndef __ARCH_ARM_PAGETABLE_H__
#define __ARCH_ARM_PAGETABLE_H__

#include <cstdint>

#include "arch/arm/isa_traits.hh"
#include "arch/arm/utility.hh"
#include "arch/arm/vtophys.hh"
#include "mem/cache/replacement_policies/base.hh"

namespace ArmISA {

struct VAddr
{
    VAddr(Addr a) { panic("not implemented yet."); }
};


// ITB/DTB page table entry
struct PTE
{
    void serialize(CheckpointOut &cp) const
    {
        panic("Need to implement PTE serialization\n");
    }

    void unserialize(CheckpointIn &cp)
    {
        panic("Need to implement PTE serialization\n");
    }

};

// Lookup level
enum LookupLevel {
    L0 = 0,  // AArch64 only
    L1,
    L2,
    L3,
    MAX_LOOKUP_LEVELS
};

// ITB/DTB table entry
struct TlbEntry
{
  public:
    enum class MemoryType : std::uint8_t {
        StronglyOrdered,
        Device,
        Normal
    };

    enum class DomainType : std::uint8_t {
        NoAccess = 0,
        Client,
        Reserved,
        Manager
    };

    // Matching variables
    Addr pfn;
    Addr size;              // Size of this entry, == Type of TLB Rec
    Addr vpn;               // Virtual Page Number
    uint64_t attributes;    // Memory attributes formatted for PAR

    LookupLevel lookupLevel; // Lookup level where the descriptor was fetched
                             // from.  Used to set the FSR for faults
                             // occurring while the long desc. format is in
                             // use (AArch32 w/ LPAE and AArch64)

    uint16_t asid;          // Address Space Identifier
    uint8_t vmid;           // Virtual machine Identifier
    uint8_t N;              // Number of bits in pagesize
    uint8_t innerAttrs;
    uint8_t outerAttrs;
    uint8_t ap;             // Access permissions bits
    uint8_t hap;            // Hyp access permissions bits
    DomainType domain;         // Access Domain

    MemoryType mtype;

    // True if the long descriptor format is used for this entry (LPAE only)
    bool longDescFormat; // @todo use this in the update attribute bethod

    bool isHyp;
    bool global;
    bool valid;

    // True if the entry targets the non-secure physical address space
    bool ns;
    // True if the entry was brought in from a non-secure page table
    bool nstid;
    // Exception level on insert, AARCH64 EL0&1, AARCH32 -> el=1
    ExceptionLevel el;

    // Type of memory
    bool nonCacheable;     // Can we wrap this in mtype?

    // Memory Attributes
    bool shareable;
    bool outerShareable;

    // Access permissions
    bool xn;                // Execute Never
    bool pxn;               // Privileged Execute Never (LPAE only)

    bool partial;         // Is a partial translation from the PTW
    unsigned int index;

    //Construct an entry that maps to physical address addr for SE mode
    TlbEntry(Addr _asn, Addr _vaddr, Addr _paddr,
             bool uncacheable, bool read_only) :
         pfn(_paddr >> PageShift), size(PageBytes-1), vpn(_vaddr >> PageShift),
         attributes(0), lookupLevel(L1), asid(_asn), vmid(0), N(0),
         innerAttrs(0), outerAttrs(0), ap(read_only ? 0x3 : 0), hap(0x3),
         domain(DomainType::Client),  mtype(MemoryType::StronglyOrdered),
         longDescFormat(false), isHyp(false), global(false), valid(true),
         ns(true), nstid(true), el(EL0), nonCacheable(uncacheable),
         shareable(false), outerShareable(false), xn(0), pxn(0), partial(false)
    {
        // no restrictions by default, hap = 0x3

        // @todo Check the memory type
        if (read_only)
            warn("ARM TlbEntry does not support read-only mappings\n");
    }

    TlbEntry() :
         pfn(0), size(0), vpn(0), attributes(0), lookupLevel(L1), asid(0),
         vmid(0), N(0), innerAttrs(0), outerAttrs(0), ap(0), hap(0x3),
         domain(DomainType::Client), mtype(MemoryType::StronglyOrdered),
         longDescFormat(false), isHyp(false), global(false), valid(false),
         ns(true), nstid(true), el(EL0), nonCacheable(false),
         shareable(false), outerShareable(false), xn(0), pxn(0), partial(false)
    {
        // no restrictions by default, hap = 0x3

        // @todo Check the memory type
    }

    void
    updateVaddr(Addr new_vaddr)
    {
        vpn = new_vaddr >> PageShift;
    }

    Addr
    pageStart() const
    {
        return pfn << PageShift;
    }

    bool
    match(Addr va, uint8_t _vmid, bool hypLookUp, bool secure_lookup,
          ExceptionLevel target_el, bool _partial = false) const
    {
        return match(va, 0, _vmid, hypLookUp, secure_lookup, true, target_el,
                     _partial);
    }

    bool
    match(Addr va, uint16_t asn, uint8_t _vmid, bool hypLookUp,
          bool secure_lookup, bool ignore_asn, ExceptionLevel target_el,
          bool _partial = false) const
    {
        bool match = false;
        Addr v = vpn << N;

        if (valid && va >= v && va <= v + size && (secure_lookup == !nstid) &&
            (hypLookUp == isHyp) && (_partial == partial))
        {
            match = checkELMatch(target_el);

            if (match && !ignore_asn) {
                match = global || (asn == asid);
            }
            if (match && nstid) {
                match = isHyp || (_vmid == vmid);
            }
        }
        return match;
    }

    bool
    checkELMatch(ExceptionLevel target_el) const
    {
        if (target_el == EL2 || target_el == EL3) {
            return (el  == target_el);
        } else {
            return (el == EL0) || (el == EL1);
        }
    }

    Addr
    pAddr(Addr va) const
    {
        return (pfn << N) | (va & size);
    }

    void
    updateAttributes()
    {
        uint64_t mask;
        uint64_t newBits;

        // chec bit 11 to determine if its currently LPAE or VMSA format.
        if ( attributes & (1 << 11) ) {
            newBits = ((outerShareable ? 0x2 :
                      shareable         ? 0x3 : 0) << 7);
            mask = 0x180;
        } else {
            /** Formatting for Physical Address Register (PAR)
             *  Only including lower bits (TLB info here)
             *  PAR (32-bit format):
             *  PA   [31:12]
             *  LPAE [11] (Large Physical Address Extension)
             *  TLB info [10:1]
             *      NOS  [10] (Not Outer Sharable)
             *      NS   [9]  (Non-Secure)
             *      --   [8]  (Implementation Defined)
             *      SH   [7]  (Sharable)
             *      Inner[6:4](Inner memory attributes)
             *      Outer[3:2](Outer memory attributes)
             *      SS   [1]  (SuperSection)
             *      F    [0]  (Fault, Fault Status in [6:1] if faulted)
            */
            newBits = ((outerShareable ? 0:1) << 10) |
                      ((shareable ? 1:0) << 7) |
                      (innerAttrs << 4) |
                      (outerAttrs << 2);
                      // TODO: Supersection bit
            mask = 0x4FC;
        }
        // common bits
        newBits |= ns << 9;  // NS bit
        mask    |= 1  << 9;
        // add in the new bits
        attributes &= ~mask;
        attributes |= newBits;
    }

    void
    setAttributes()
    {
        attributes = longDescFormat ? (1 << 11) : 0;
        updateAttributes();
    }

    std::string
    print() const
    {
        return csprintf("%#x, asn %d vmn %d hyp %d ppn %#x size: %#x ap:%d "
                        "ns:%d nstid:%d g:%d el:%d attr:%#lx", vpn << N, asid,
                        vmid, isHyp, pfn << N, size, ap, ns, nstid, global,
                        el, attributes);
    }
};

typedef std::shared_ptr<TlbEntry> TlbEntryPtr;

class TlbEntryRepl : public ReplaceableEntry
{
    private:
        TlbEntryPtr data;

    public:
        TlbEntryPtr getData() {
            return data;
        }
        void setEntry(TlbEntryPtr _data) {
            data = _data;
        }

        void flush() {
            setEntry(nullptr);
        }
};

const std::string s_memtypes[] = { "Device", "Normal" };

enum class DeviceType : std::uint8_t {
    GRE,
    nGRE,
    nGnRE,
    nGnRnE
};

const std::string s_devicetypes[] = { "GRE", "nGRE", "nGnRE", "nGnRnE" };

enum class MemAttr : std::uint8_t {
    NC = 0, // Non-cacheable
    RESERVED = 1,
    WT = 2, // Write-through
    WB = 3  // Write-back
};

const std::string s_memattrs[] = { "NC", "RESERVED", "WT", "WB" };

enum class MemHint : std::uint8_t {
    No,  // No Read-Allocate, No Write-Allocate
    WA,  // No Read-Allocate, Write-Allocate
    RA,  // Read-Allocate, No Write-Allocate
    RWA, // Read-Allocate, Write-Allocate
    RESERVED
};

const std::string s_memhints[] = { "No", "WA", "RA", "RWA", "RESERVED" };

typedef struct {
    bool page_table_walk;
    bool secondstage;
    bool s2fs1walk;
    int level;
} AccessDescriptor;

typedef struct {
    Addr physicaladdress;
    bool ns;
} FullAddress;

typedef struct Permissions {
    uint8_t ap; // Access permission bits
    bool    xn; // Execute-never bit
    bool   xxn; // [ARMv8.2] Extended execute-never bit for stage 2
    bool   pxn; // Privileged execute-never bit

    Permissions() :
        ap(0), xn(false), xxn(false), pxn(false) {
    }
} Permissions;

typedef struct MemAttrHints {
    MemAttr attrs;
    MemHint hints;
    bool transient;

    MemAttrHints() :
        attrs(MemAttr::RESERVED), hints(MemHint::RESERVED), transient(false) {
    }
} MemAttrHints;

typedef struct MemoryAttributes {
    TlbEntry::MemoryType type;
    DeviceType   device; // For Device memory types
    MemAttrHints inner;  // Inner hints and attributes
    MemAttrHints outer;  // Outer hints and attributes
    bool         shareable;
    bool         outershareable;
    uint8_t      attr;  // Memory attributes to fill PAR upper bits

    MemoryAttributes() :
        shareable(false), outershareable(false), attr(0) {
    }
    ~MemoryAttributes() {
    }
} MemoryAttributes;

struct AddressDescriptor {
    Fault             fault;
    MemoryAttributes* memattrs;
    FullAddress       paddress;
    Addr              vaddress;

    AddressDescriptor() :
        fault(NoFault), memattrs(new MemoryAttributes()), vaddress(0)
    {
    }

    ~AddressDescriptor() {
        delete memattrs;
    }

    bool isFault() {
        return (fault != NoFault);
    }
};

struct TLBRecord
{
    Permissions          perms;
    bool                 nG;         // '0' = Global, '1' = not Global
    TlbEntry::DomainType domain;     // Access Domain (AArch32)
    bool                 contiguous; // Contiguous bit from page table
    LookupLevel          level;      // AArch32 Short-descriptor format
                                     //  Indicates Section/Page
    int                  blocksize;  // Size of memory translateble KB
    bool                 CnP;        // [ARMv8.2] TLB entry can be
                                     // shared between different PEs
    std::shared_ptr<AddressDescriptor> addrdesc;

    TLBRecord() :
        nG(false), domain(TlbEntry::DomainType::Client), contiguous(false),
        level(L0), blocksize(0), CnP(false), addrdesc(NULL)
    {
    }

    TLBRecord(const std::shared_ptr<AddressDescriptor> &_addrdesc) :
        nG(false), domain(TlbEntry::DomainType::Client), contiguous(false),
        level(L0), blocksize(0), CnP(false)
    {
        addrdesc = _addrdesc;
    }

    ~TLBRecord() {
    }
};
}
#endif // __ARCH_ARM_PAGETABLE_H__

