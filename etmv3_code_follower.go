package coresight

import (
	"encoding/binary"
	"errors"

)

const opcodeBytes = 4

// CodeFollower follows the execution path by decoding instructions.
type CodeFollower struct {
	InstrInfo InstrInfo
	MemAccess internalMemoryReader
	IdDecode  internalInstructionDecoder
	MemSpace  MemSpaceAcc
	TraceID   uint8
	Arch      ArchProfile
	Isa       ISA

	ErrOnAA64BadOpcode bool
	InstrRangeLimit    uint32

	ReadBuf   [opcodeBytes]byte
	TempInstr InstrInfo
}

// FollowResult contains the decoded single-atom follow outcome.
type FollowResult struct {
	HasNext   bool
	HasNacc   bool
	NaccAddr  VAddr
	NumInstr  uint32
	RangeSt   VAddr
	RangeEn   VAddr
	NextAddr  VAddr
	InstrInfo InstrInfo
}

// SetDSBDMBasWP configures the follower to treat DSB/DMB as waypoints.
func (cf *CodeFollower) SetDSBDMBasWP() {
	cf.InstrInfo.DsbDmbWaypoints = 1
}

// DecodeSingleOpCode decodes a single opcode at instrInfo.InstrAddr.
func (cf *CodeFollower) DecodeSingleOpCode(instrInfo *InstrInfo, traceID uint8, memSpace MemSpaceAcc) error {
	readBytes, err := cf.MemAccess.Read(instrInfo.InstrAddr, traceID, memSpace, opcodeBytes, cf.ReadBuf[:])
	if errors.Is(err, ErrNoAccessor) {
		return ErrMemNacc
	}
	if err != nil {
		return err
	}
	if readBytes != opcodeBytes {
		return ErrMemNacc
	}

	instrInfo.Opcode = binary.LittleEndian.Uint32(cf.ReadBuf[:])
	if cf.ErrOnAA64BadOpcode && instrInfo.ISA == ISAAArch64 && instrInfo.Opcode&0xFFFF0000 == 0 {
		return ErrInvalidOpcode
	}

	return cf.IdDecode(instrInfo)
}

// FollowSingleAtom decodes an instruction and returns the result snapshot by value.
func (cf *CodeFollower) FollowSingleAtom(addrStart VAddr, atom AtmVal) (FollowResult, error) {
	cf.TempInstr = cf.InstrInfo
	cf.TempInstr.InstrAddr = addrStart

	res := FollowResult{
		NaccAddr: addrStart,
		RangeSt:  addrStart,
		RangeEn:  addrStart,
		NextAddr: addrStart,
	}

	if err := cf.DecodeSingleOpCode(&cf.TempInstr, cf.TraceID, cf.MemSpace); err != nil {
		res.HasNacc = errors.Is(err, ErrMemNacc)
		res.InstrInfo = cf.TempInstr
		return res, err
	}

	res.InstrInfo = cf.TempInstr
	res.RangeEn = cf.TempInstr.InstrAddr + VAddr(cf.TempInstr.InstrSize)
	res.NumInstr = 1
	res.NextAddr = res.RangeEn
	res.HasNext = true

	if atom != AtomE {
		return res, nil
	}

	switch cf.TempInstr.Type {
	case InstrBr:
		res.NextAddr = cf.TempInstr.BranchAddr
	case InstrBrIndirect:
		res.HasNext = false
	}

	return res, nil
}

// FollowAtomWaypoint follows sequential instructions until the atom's waypoint is reached.
func (cf *CodeFollower) FollowAtomWaypoint(addrStart VAddr, atom AtmVal) (FollowResult, error) {
	instrInfo := cf.InstrInfo
	instrInfo.InstrAddr = addrStart
	rangeStart := addrStart
	var out FollowResult

	for {
		res, err := cf.FollowSingleAtom(instrInfo.InstrAddr, atom)
		if err != nil {
			res.RangeSt = rangeStart
			res.NumInstr += out.NumInstr
			return res, err
		}
		if out.NumInstr == 0 {
			out = res
			out.RangeSt = rangeStart
		} else {
			out.RangeEn = res.RangeEn
			out.NextAddr = res.NextAddr
			out.HasNext = res.HasNext
			out.HasNacc = res.HasNacc
			out.NaccAddr = res.NaccAddr
			out.NumInstr += res.NumInstr
			out.InstrInfo = res.InstrInfo
		}
		if cf.InstrRangeLimit > 0 && out.NumInstr > cf.InstrRangeLimit {
			return out, ErrIRangeLimitOverrun
		}

		switch res.InstrInfo.Type {
		case InstrBr, InstrBrIndirect, InstrIsb, InstrDsbDmb, InstrWfiWfe, InstrTstart:
			cf.InstrInfo = res.InstrInfo
			return out, nil
		}

		instrInfo = res.InstrInfo
		instrInfo.InstrAddr = res.RangeEn
		cf.InstrInfo = instrInfo
	}
}
