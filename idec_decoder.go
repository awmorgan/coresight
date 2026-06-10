package coresight


// decodeInstruction processes an instruction based on its ISA.
func decodeInstruction(instrInfo *instrInfo) error {
	info := decodeInfo{
		InstrSubType: SInstrNone,
		ArchVersion:  instrInfo.PeType.Arch,
	}

	var err error
	switch instrInfo.ISA {
	case ISAArm:
		err = decodeA32(instrInfo, &info)
	case ISAThumb2:
		err = decodeT32(instrInfo, &info)
	case ISAAArch64:
		err = decodeA64(instrInfo, &info)
	default:
		err = errUnsupportedISA
	}

	instrInfo.Subtype = info.InstrSubType
	return err
}

func resetInstrInfo(instrInfo *instrInfo) {
	instrInfo.Type = InstrOther
	instrInfo.NextISA = instrInfo.ISA
	instrInfo.IsLink = false
	instrInfo.IsConditional = false
}

func applyBarrier(instrInfo *instrInfo, barrier armBarrierT) bool {
	switch barrier {
	case armBarrierIsb:
		instrInfo.Type = InstrIsb
		return true
	case armBarrierDsb, armBarrierDmb:
		if instrInfo.DsbDmbWaypoints != 0 {
			instrInfo.Type = InstrDsbDmb
		}
		return true
	default:
		return false
	}
}

func canonicalThumbOpcode(opcode uint32) uint32 {
	return (opcode>>16)&0xFFFF | (opcode&0xFFFF)<<16
}

func setThumbInstrSize(instrInfo *instrInfo) {
	if isWideThumb(uint16(instrInfo.Opcode >> 16)) {
		instrInfo.InstrSize = 4
		return
	}
	instrInfo.InstrSize = 2
}

func decodeA32(instrInfo *instrInfo, info *decodeInfo) error {
	resetInstrInfo(instrInfo)
	instrInfo.InstrSize = 4
	instrInfo.ThumbItConditions = 0 // not Thumb

	switch {
	case instARMIsIndirectBranch(instrInfo.Opcode, info):
		instrInfo.Type = InstrBrIndirect
		instrInfo.IsLink = instARMIsBranchAndLink(instrInfo.Opcode, info)

	case instARMIsDirectBranch(instrInfo.Opcode):
		branchAddr, _ := instARMBranchDestination(uint32(instrInfo.InstrAddr), instrInfo.Opcode)
		instrInfo.Type = InstrBr
		if branchAddr&0x1 != 0 {
			instrInfo.NextISA = ISAThumb2
			branchAddr &^= 0x1
		}
		instrInfo.BranchAddr = VAddr(branchAddr)
		instrInfo.IsLink = instARMIsBranchAndLink(instrInfo.Opcode, info)

	case applyBarrier(instrInfo, instARMBarrier(instrInfo.Opcode)):
	case instrInfo.WfiWfeBranch != 0 && instARMWfiWfe(instrInfo.Opcode):
		instrInfo.Type = InstrWfiWfe
	}

	instrInfo.IsConditional = instARMIsConditional(instrInfo.Opcode)
	return nil
}

func decodeA64(instrInfo *instrInfo, info *decodeInfo) error {
	resetInstrInfo(instrInfo)
	instrInfo.InstrSize = 4
	instrInfo.ThumbItConditions = 0

	switch {
	case decodeA64IndirectBranch(instrInfo, info):
	case decodeA64DirectBranch(instrInfo, info):
	case applyBarrier(instrInfo, instA64Barrier(instrInfo.Opcode)):
	case instrInfo.WfiWfeBranch != 0 && instA64WfiWfe(instrInfo.Opcode, info):
		instrInfo.Type = InstrWfiWfe
	case isArchMinVer(info.ArchVersion, ArchAA64) && instA64Tstart(instrInfo.Opcode):
		instrInfo.Type = InstrTstart
	}

	instrInfo.IsConditional = instA64IsConditional(instrInfo.Opcode)
	return nil
}

func decodeA64IndirectBranch(instrInfo *instrInfo, info *decodeInfo) bool {
	isBranch, isLink := instA64IsIndirectBranchLink(instrInfo.Opcode, info)
	if !isBranch {
		return false
	}
	instrInfo.Type = InstrBrIndirect
	instrInfo.IsLink = isLink
	return true
}

func decodeA64DirectBranch(instrInfo *instrInfo, info *decodeInfo) bool {
	isBranch, isLink := instA64IsDirectBranchLink(instrInfo.Opcode, info)
	if !isBranch {
		return false
	}

	var branchAddr uint64
	instA64BranchDestination(uint64(instrInfo.InstrAddr), instrInfo.Opcode, &branchAddr)
	instrInfo.Type = InstrBr
	instrInfo.BranchAddr = VAddr(branchAddr)
	instrInfo.IsLink = isLink
	return true
}

func decodeT32(instrInfo *instrInfo, info *decodeInfo) error {
	instrInfo.Opcode = canonicalThumbOpcode(instrInfo.Opcode)
	resetInstrInfo(instrInfo)
	setThumbInstrSize(instrInfo)

	switch {
	case decodeT32DirectBranch(instrInfo, info):
	case decodeT32IndirectBranch(instrInfo, info):
	case applyBarrier(instrInfo, instThumbBarrier(instrInfo.Opcode)):
	case instrInfo.WfiWfeBranch != 0 && instThumbWfiWfe(instrInfo.Opcode):
		instrInfo.Type = InstrWfiWfe
	}

	if instThumbIsConditional(instrInfo.Opcode) {
		instrInfo.IsConditional = true
	}
	updateThumbITBlock(instrInfo)
	return nil
}

func decodeT32DirectBranch(instrInfo *instrInfo, info *decodeInfo) bool {
	isBranch, isLink, isCond := instThumbIsDirectBranchLink(instrInfo.Opcode, info)
	if !isBranch {
		return false
	}

	branchAddr, _ := instThumbBranchDestination(uint32(instrInfo.InstrAddr), instrInfo.Opcode)
	instrInfo.Type = InstrBr
	instrInfo.BranchAddr = VAddr(branchAddr &^ 0x1)
	instrInfo.IsLink = isLink
	instrInfo.IsConditional = isCond
	if branchAddr&0x1 == 0 {
		instrInfo.NextISA = ISAArm
	}
	return true
}

func decodeT32IndirectBranch(instrInfo *instrInfo, info *decodeInfo) bool {
	isBranch, isLink := instThumbIsIndirectBranchLink(instrInfo.Opcode, info)
	if !isBranch {
		return false
	}
	instrInfo.Type = InstrBrIndirect
	instrInfo.IsLink = isLink
	return true
}

func updateThumbITBlock(instrInfo *instrInfo) {
	if instrInfo.TrackItBlock == 0 {
		return
	}
	if instrInfo.ThumbItConditions > 0 {
		instrInfo.IsConditional = true
		instrInfo.ThumbItConditions--
		return
	}
	if instrInfo.Type == InstrOther {
		instrInfo.ThumbItConditions = uint8(instThumbIsIT(instrInfo.Opcode))
	}
}
