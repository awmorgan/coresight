package coresight

import (
	"encoding/binary"
	"errors"
)

const opcodeBytes = 4

// codeFollower follows the execution path by decoding instructions.
type codeFollower struct {
	InstrInfo instrInfo
	MemAccess internalMemoryReader
	IdDecode  internalInstructionDecoder
	MemSpace  MemSpaceAcc
	TraceID   uint8
	Arch      archProfile
	Isa       ISA

	ErrOnAA64BadOpcode bool
	InstrRangeLimit    uint32

	ReadBuf   [opcodeBytes]byte
	TempInstr instrInfo
}

// followResult contains the decoded single-atom follow outcome.
type followResult struct {
	HasNext   bool
	HasNacc   bool
	NaccAddr  VAddr
	NumInstr  uint32
	RangeSt   VAddr
	RangeEn   VAddr
	NextAddr  VAddr
	InstrInfo instrInfo
}

// decodeSingleOpCode decodes a single opcode at instrInfo.InstrAddr.
func (cf *codeFollower) decodeSingleOpCode(instrInfo *instrInfo, traceID uint8, memSpace MemSpaceAcc) error {
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

// followSingleAtom decodes an instruction and returns the result snapshot by value.
func (cf *codeFollower) followSingleAtom(addrStart VAddr, atom atmVal) (followResult, error) {
	cf.TempInstr = cf.InstrInfo
	cf.TempInstr.InstrAddr = addrStart

	res := followResult{
		NaccAddr: addrStart,
		RangeSt:  addrStart,
		RangeEn:  addrStart,
		NextAddr: addrStart,
	}

	if err := cf.decodeSingleOpCode(&cf.TempInstr, cf.TraceID, cf.MemSpace); err != nil {
		res.HasNacc = errors.Is(err, ErrMemNacc)
		res.InstrInfo = cf.TempInstr
		return res, err
	}

	res.InstrInfo = cf.TempInstr
	res.RangeEn = cf.TempInstr.InstrAddr + VAddr(cf.TempInstr.InstrSize)
	res.NumInstr = 1
	res.NextAddr = res.RangeEn
	res.HasNext = true

	if atom != atomE {
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

// followAtomWaypoint follows sequential instructions until the atom's waypoint is reached.
func (cf *codeFollower) followAtomWaypoint(addrStart VAddr, atom atmVal) (followResult, error) {
	instrInfo := cf.InstrInfo
	instrInfo.InstrAddr = addrStart
	rangeStart := addrStart
	var out followResult

	for {
		res, err := cf.followSingleAtom(instrInfo.InstrAddr, atom)
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
