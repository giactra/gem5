# -*- mode:python -*-

# Copyright (c) 2009, 2013, 2015 ARM Limited
# Copyright (c) 2018  Metempsy Technology Consulting
# All rights reserved.
#
# The license below extends only to copyright in the software and shall
# not be construed as granting a license to any other intellectual
# property including but not limited to intellectual property relating
# to a hardware implementation of the functionality of the software
# licensed hereunder.  You may use the software subject to the license
# terms below provided that you ensure that this notice is replicated
# unmodified and in its entirety in all distributions of the software,
# modified or unmodified, in source code or in binary form.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met: redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer;
# redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution;
# neither the name of the copyright holders nor the names of its
# contributors may be used to endorse or promote products derived from
# this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# Authors: Ali Saidi
#          Ivan Pizarro

from m5.SimObject import SimObject
from m5.params import *
from m5.proxy import *
from m5.objects.BaseTLB import BaseTLB, BaseMMU
from m5.objects.ClockedObject import ClockedObject
from m5.objects.IndexingPolicies import *
from m5.objects.ReplacementPolicies import *

# Stage 1 translation objects
class ArmTableWalker(ClockedObject):
    type = 'ArmTableWalker'
    cxx_class = 'ArmISA::TableWalker'
    cxx_header = "arch/arm/table_walker.hh"
    is_stage2 = Param.Bool(False, "Is this object for stage 2 translation?")
    num_squash_per_cycle = Param.Unsigned(2,
            "Number of outstanding walks that can be squashed per cycle")
    max_inflight_walks = Param.Unsigned(1,
            "Number of outstanding walks that can be issued")
    # The walker will be connected as a one more level in the TLB hierarchy,
    # thus slave and master ports are defined the same way
    slave = VectorSlavePort("Port closer to the CPU side")
    master = MasterPort("Port closer to memory side")

    sys = Param.System(Parent.any, "system object parameter")

class ArmTLB(BaseTLB):
    type = 'ArmTLB'
    cxx_class = 'ArmISA::TLB'
    cxx_header = "arch/arm/tlb.hh"
    sys = Param.System(Parent.any, "system object parameter")
    size = Param.MemorySize(str(64), "Number of TLB entries")
    assoc = Param.Int(1, "TLB associativity")
    is_stage2 = Param.Bool(False, "Is this a stage 2 TLB?")
    allow_partial_translations = Param.Bool(False,
        "Allow storing partial translation from the walker")
    lat = Param.Int(0, "Latency of an access to the TLB")
    next_tlb = Param.ArmTLB(NULL, "Next TLB level")
    stage2tlb = Param.ArmTLB(NULL, "Pointer to the stage 2 TLB")
    walker = Param.ArmTableWalker(NULL, "Table Walker");
    level = Param.Unsigned(1, "TLB level")
    indexing_policy = Param.BaseIndexingPolicy(SetAssociative(entry_size = 1),
        "Indexing policy")
    replacement_policy = Param.BaseReplacementPolicy(LRURP(),
        "Replacement policy")

class ArmMMU(BaseMMU):
    type = 'ArmMMU'
    cxx_class = 'ArmISA::MMU'
    cxx_header = 'arch/arm/mmu.hh'

    stage1_tlbs = VectorParam.ArmTLB([], "ARM TLB array for Stage 1")
    stage2_tlbs = VectorParam.ArmTLB([], "ARM TLB array for Stage 2")

    stage1_walkers = VectorParam.ArmTableWalker([], "S1 walkers")
    stage2_walkers = VectorParam.ArmTableWalker([], "S2 walkers")

    sys = Param.System(Parent.any, "system object parameter")

    def addWalkerCache(self, iwc, dwc):
        self.itb.walker.master = iwc.cpu_side
        self.dtb.walker.master = dwc.cpu_side

    @classmethod
    def walkerPorts(cls):
        return [ "mmu.itb.walker.master", "mmu.dtb.walker.master" ]

    def connectTLB(self):
        for stage1_tlb in self.stage1_tlbs:
            if stage1_tlb.next_tlb is not NULL:
                stage1_tlb.master = stage1_tlb.next_tlb.slave
            else:
                stage1_tlb.master = stage1_tlb.walker.slave

        for stage2_tlb in self.stage2_tlbs:
            if stage2_tlb.next_tlb is not NULL:
                stage2_tlb.master = stage2_tlb.next_tlb.slave
            else:
                stage2_tlb.master = stage2_tlb.walker.slave

class DefaultArmMMU(ArmMMU):
    # Table Walkers
    _itb_walker = ArmTableWalker()
    _dtb_walker = ArmTableWalker()
    _itb_stage2_walker = ArmTableWalker(is_stage2=True)
    _dtb_stage2_walker = ArmTableWalker(is_stage2=True)

    # TLBs
    _itb_stage2 = ArmTLB(is_stage2=True, walker=_itb_stage2_walker)
    _dtb_stage2 = ArmTLB(is_stage2=True, walker=_dtb_stage2_walker)
    itb = ArmTLB(stage2tlb=_itb_stage2, walker=_itb_walker)
    dtb = ArmTLB(stage2tlb=_dtb_stage2, walker=_dtb_walker)

    stage1_tlbs = [ itb, dtb ]
    stage2_tlbs = [ _itb_stage2, _dtb_stage2 ]

    stage1_walkers = [ _itb_walker, _dtb_walker ]
    stage2_walkers = [ _itb_stage2_walker, _dtb_stage2_walker ]
