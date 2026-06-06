package idec

import "coresight/trace"

// DecodeInstruction processes an instruction based on its ISA.
func DecodeInstruction(instrInfo *trace.InstrInfo) error {
	info := DecodeInfo{
		InstrSubType: trace.SInstrNone,
		ArchVersion:  instrInfo.PeType.Arch,
	}

	var err error
	switch instrInfo.ISA {
	case trace.ISAArm:
		err = decodeA32(instrInfo, &info)
	case trace.ISAThumb2:
		err = decodeT32(instrInfo, &info)
	case trace.ISAAArch64:
		err = decodeA64(instrInfo, &info)
	default:
		err = trace.ErrUnsupportedISA
	}

	instrInfo.Subtype = info.InstrSubType
	return err
}

func resetInstrInfo(instrInfo *trace.InstrInfo) {
	instrInfo.Type = trace.InstrOther
	instrInfo.NextISA = instrInfo.ISA
	instrInfo.IsLink = false
	instrInfo.IsConditional = false
}

func applyBarrier(instrInfo *trace.InstrInfo, barrier ArmBarrierT) bool {
	switch barrier {
	case ArmBarrierIsb:
		instrInfo.Type = trace.InstrIsb
		return true
	case ArmBarrierDsb, ArmBarrierDmb:
		if instrInfo.DsbDmbWaypoints != 0 {
			instrInfo.Type = trace.InstrDsbDmb
		}
		return true
	default:
		return false
	}
}

func canonicalThumbOpcode(opcode uint32) uint32 {
	return (opcode>>16)&0xFFFF | (opcode&0xFFFF)<<16
}

func setThumbInstrSize(instrInfo *trace.InstrInfo) {
	if IsWideThumb(uint16(instrInfo.Opcode >> 16)) {
		instrInfo.InstrSize = 4
		return
	}
	instrInfo.InstrSize = 2
}

func decodeA32(instrInfo *trace.InstrInfo, info *DecodeInfo) error {
	resetInstrInfo(instrInfo)
	instrInfo.InstrSize = 4
	instrInfo.ThumbItConditions = 0 // not Thumb

	switch {
	case InstARMIsIndirectBranch(instrInfo.Opcode, info):
		instrInfo.Type = trace.InstrBrIndirect
		instrInfo.IsLink = InstARMIsBranchAndLink(instrInfo.Opcode, info)

	case InstARMIsDirectBranch(instrInfo.Opcode):
		branchAddr, _ := InstARMBranchDestination(uint32(instrInfo.InstrAddr), instrInfo.Opcode)
		instrInfo.Type = trace.InstrBr
		if branchAddr&0x1 != 0 {
			instrInfo.NextISA = trace.ISAThumb2
			branchAddr &^= 0x1
		}
		instrInfo.BranchAddr = trace.VAddr(branchAddr)
		instrInfo.IsLink = InstARMIsBranchAndLink(instrInfo.Opcode, info)

	case applyBarrier(instrInfo, InstARMBarrier(instrInfo.Opcode)):
	case instrInfo.WfiWfeBranch != 0 && InstARMWfiWfe(instrInfo.Opcode):
		instrInfo.Type = trace.InstrWfiWfe
	}

	instrInfo.IsConditional = InstARMIsConditional(instrInfo.Opcode)
	return nil
}

func decodeA64(instrInfo *trace.InstrInfo, info *DecodeInfo) error {
	resetInstrInfo(instrInfo)
	instrInfo.InstrSize = 4
	instrInfo.ThumbItConditions = 0

	switch {
	case decodeA64IndirectBranch(instrInfo, info):
	case decodeA64DirectBranch(instrInfo, info):
	case applyBarrier(instrInfo, InstA64Barrier(instrInfo.Opcode)):
	case instrInfo.WfiWfeBranch != 0 && InstA64WfiWfe(instrInfo.Opcode, info):
		instrInfo.Type = trace.InstrWfiWfe
	case trace.IsArchMinVer(info.ArchVersion, trace.ArchAA64) && InstA64Tstart(instrInfo.Opcode):
		instrInfo.Type = trace.InstrTstart
	}

	instrInfo.IsConditional = InstA64IsConditional(instrInfo.Opcode)
	return nil
}

func decodeA64IndirectBranch(instrInfo *trace.InstrInfo, info *DecodeInfo) bool {
	isBranch, isLink := InstA64IsIndirectBranchLink(instrInfo.Opcode, info)
	if !isBranch {
		return false
	}
	instrInfo.Type = trace.InstrBrIndirect
	instrInfo.IsLink = isLink
	return true
}

func decodeA64DirectBranch(instrInfo *trace.InstrInfo, info *DecodeInfo) bool {
	isBranch, isLink := InstA64IsDirectBranchLink(instrInfo.Opcode, info)
	if !isBranch {
		return false
	}

	var branchAddr uint64
	InstA64BranchDestination(uint64(instrInfo.InstrAddr), instrInfo.Opcode, &branchAddr)
	instrInfo.Type = trace.InstrBr
	instrInfo.BranchAddr = trace.VAddr(branchAddr)
	instrInfo.IsLink = isLink
	return true
}

func decodeT32(instrInfo *trace.InstrInfo, info *DecodeInfo) error {
	instrInfo.Opcode = canonicalThumbOpcode(instrInfo.Opcode)
	resetInstrInfo(instrInfo)
	setThumbInstrSize(instrInfo)

	switch {
	case decodeT32DirectBranch(instrInfo, info):
	case decodeT32IndirectBranch(instrInfo, info):
	case applyBarrier(instrInfo, InstThumbBarrier(instrInfo.Opcode)):
	case instrInfo.WfiWfeBranch != 0 && InstThumbWfiWfe(instrInfo.Opcode):
		instrInfo.Type = trace.InstrWfiWfe
	}

	if InstThumbIsConditional(instrInfo.Opcode) {
		instrInfo.IsConditional = true
	}
	updateThumbITBlock(instrInfo)
	return nil
}

func decodeT32DirectBranch(instrInfo *trace.InstrInfo, info *DecodeInfo) bool {
	isBranch, isLink, isCond := InstThumbIsDirectBranchLink(instrInfo.Opcode, info)
	if !isBranch {
		return false
	}

	branchAddr, _ := InstThumbBranchDestination(uint32(instrInfo.InstrAddr), instrInfo.Opcode)
	instrInfo.Type = trace.InstrBr
	instrInfo.BranchAddr = trace.VAddr(branchAddr &^ 0x1)
	instrInfo.IsLink = isLink
	instrInfo.IsConditional = isCond
	if branchAddr&0x1 == 0 {
		instrInfo.NextISA = trace.ISAArm
	}
	return true
}

func decodeT32IndirectBranch(instrInfo *trace.InstrInfo, info *DecodeInfo) bool {
	isBranch, isLink := InstThumbIsIndirectBranchLink(instrInfo.Opcode, info)
	if !isBranch {
		return false
	}
	instrInfo.Type = trace.InstrBrIndirect
	instrInfo.IsLink = isLink
	return true
}

func updateThumbITBlock(instrInfo *trace.InstrInfo) {
	if instrInfo.TrackItBlock == 0 {
		return
	}
	if instrInfo.ThumbItConditions > 0 {
		instrInfo.IsConditional = true
		instrInfo.ThumbItConditions--
		return
	}
	if instrInfo.Type == trace.InstrOther {
		instrInfo.ThumbItConditions = uint8(InstThumbIsIT(instrInfo.Opcode))
	}
}
