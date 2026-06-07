package coresight

import (
	"fmt"
	"strings"
)

// ptmPacketType represents a PTM specific packet type.
type ptmPacketType int

const (
	PacketNotSync       ptmPacketType = iota // no sync found yet
	PacketIncompleteEOT                   // flushing incomplete packet at end of 
	PacketNoError                         // no error base type packet.

	PacketBranchAddress     // Branch address with optional exception.
	PacketASync             // Alignment Synchronisation.
	PacketISync             // Instruction sync with address.
	PacketTrigger           // trigger packet
	PacketWPointUpdate      // Waypoint update.
	PacketIgnore            // ignore packet.
	PacketContextID         // context id packet.
	PacketVMID              // VMID packet
	PacketAtom              // atom waypoint packet.
	PacketTimestamp         // timestamp packet.
	PacketExceptionRet      // exception return.
	PacketBranchOrBypassEOT // interpreter FSM 'state'
	PacketTPIUPadEOB        // pad end of a buffer

	PacketBadSequence // invalid sequence for packet type
	PacketReserved    // Reserved packet encoding
)

const (
	PktHeaderBranchAddrMask uint8 = 0x01
	PktHeaderAtomMask       uint8 = 0x81
	PktHeaderAtomVal        uint8 = 0x80

	PktHeaderASync      uint8 = 0x00
	PktHeaderISync      uint8 = 0x08
	PktHeaderWPoint     uint8 = 0x72
	PktHeaderTrigger    uint8 = 0x0C
	PktHeaderContextID  uint8 = 0x6E
	PktHeaderVMID       uint8 = 0x3C
	PktHeaderTimestamp1 uint8 = 0x42
	PktHeaderTimestamp2 uint8 = 0x46
	PktHeaderExcepRet   uint8 = 0x76
	PktHeaderIgnore     uint8 = 0x66

	PktContMask   uint8 = 0x80 // Bit 7 is continuation for most fields
	PktCCContMask uint8 = 0x40 // Bit 6 is continuation for cycle counts

	PktASyncByte uint8 = 0x80 // Alignment sync byte (after N zeros)

	PktISyncNSMask     uint8 = 0x08
	PktISyncAltISAMask uint8 = 0x04
	PktISyncHypMask    uint8 = 0x02

	PktBranchISAMask    uint8 = 0x30
	PktBranchISAThumb2  uint8 = 0x10
	PktBranchISAJazelle uint8 = 0x20
)

// ptmContext represents the execution context state for PTM.
type ptmContext struct {
	CurrAltISA bool
	CurrNS     bool
	CurrHyp    bool
	Updated    bool
	UpdatedC   bool
	UpdatedV   bool

	CtxtID uint32
	VMID   uint8
}

// ptmExcep represents an exception inside a PTM packet.
type ptmExcep struct {
	Type    armV7Exception
	Number  uint16
	Present bool
}

// ptmPacket represents a parsed PTM packet element.
type ptmPacket struct {
	Index   Index
	Type    ptmPacketType
	ErrType ptmPacketType

	CurrISA ISA
	PrevISA ISA

	AddrBits      int
	AddrValid     bool
	AddrValidBits int
	AddrVal       VAddr

	Context ptmContext
	Atom    ptmAtomPkt
	ISyncReason iSyncReason

	CycleCount uint32
	CCValid    bool

	Timestamp    uint64
	TSUpdateBits uint8

	Exception ptmExcep
}

func (p *ptmPacket) Clear() {
	p.ErrType = PacketNoError
	p.CycleCount = 0
	p.CCValid = false
	p.Context.Updated = false
	p.Context.UpdatedC = false
	p.Context.UpdatedV = false
	p.TSUpdateBits = 0
	p.Atom.EnBits = 0
	p.Exception.Present = false
	p.PrevISA = p.CurrISA
}

func (p *ptmPacket) ResetState() {
	p.Type = PacketNotSync

	p.Context.CtxtID = 0
	p.Context.VMID = 0
	p.Context.CurrAltISA = false
	p.Context.CurrHyp = false
	p.Context.CurrNS = false

	p.AddrBits = 0
	p.AddrValid = false
	p.AddrValidBits = 0
	p.AddrVal = 0

	p.PrevISA = ISAUnknown
	p.CurrISA = ISAUnknown

	p.Timestamp = 0

	p.Clear()
}

func (p *ptmPacket) SetType(pktType ptmPacketType) {
	p.Type = pktType
}

func (p *ptmPacket) SetErrType(errType ptmPacketType) {
	p.ErrType = p.Type
	p.Type = errType
}

func (p *ptmPacket) UpdateAddress(partAddrVal VAddr, updateBits int) {
	validMask := VAddr(ptmMaskBits64(updateBits))
	p.AddrBits = updateBits
	p.AddrVal &^= validMask
	p.AddrVal |= (partAddrVal & validMask)
	p.AddrValid = updateBits > 0
	if updateBits > p.AddrValidBits {
		p.AddrValidBits = updateBits
	}
}

func (p *ptmPacket) UpdateContextID(ctxtID uint32) {
	p.Context.CtxtID = ctxtID
	p.Context.UpdatedC = true
}

func (p *ptmPacket) UpdateVMID(vmid uint8) {
	p.Context.VMID = vmid
	p.Context.UpdatedV = true
}

func (p *ptmPacket) UpdateISA(currISA ISA) {
	p.PrevISA = p.CurrISA
	p.CurrISA = currISA
}

func (p *ptmPacket) SetException(exType armV7Exception, exNum uint16) {
	p.Exception.Present = true
	p.Exception.Type = exType
	p.Exception.Number = exNum
}

func (p *ptmPacket) UpdateTimestamp(tsVal uint64, updateBits uint8) {
	validMask := ptmMaskBits64(int(updateBits))
	p.Timestamp &^= validMask
	p.Timestamp |= (tsVal & validMask)
	p.TSUpdateBits = updateBits
}

func (p *ptmPacket) SetCycleAccAtomFromPHdr(pHdr uint8) {
	p.Atom.Num = 1
	if (pHdr & 0x2) != 0 {
		p.Atom.EnBits = 0x0
	} else {
		p.Atom.EnBits = 0x1
	}
}

func (p *ptmPacket) SetAtomFromPHdr(pHdr uint8) {
	atomFmtID := pHdr & 0xF0
	switch atomFmtID {
	case 0x80:
		if (pHdr & 0x08) == 0x08 {
			p.Atom.Num = 2
		} else {
			p.Atom.Num = 1
		}
	case 0x90:
		p.Atom.Num = 3
	default:
		if (pHdr & 0xE0) == 0xA0 {
			p.Atom.Num = 4
		} else {
			p.Atom.Num = 5
		}
	}

	atomMask := uint8(0x2)
	p.Atom.EnBits = 0
	for i := 0; i < int(p.Atom.Num); i++ {
		p.Atom.EnBits <<= 1
		if (atomMask & pHdr) == 0 {
			p.Atom.EnBits |= 0x1
		}
		atomMask <<= 1
	}
}

func (p *ptmPacket) IsBadPacket() bool {
	switch p.Type {
	case PacketBadSequence, PacketReserved:
		return true
	default:
		return false
	}
}

func (p *ptmPacket) String() string {
	info := ptmPacketInfo(p.Type)
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s : %s; ", info.name, info.desc)
	p.writeDetails(&sb)
	return sb.String()
}

func (p *ptmPacket) writeDetails(sb *strings.Builder) {
	switch p.Type {
	case PacketBadSequence:
		fmt.Fprintf(sb, "[%s]; ", packetTypeName(p.ErrType))
	case PacketAtom:
		sb.WriteString(p.getAtomStr())
	case PacketContextID:
		fmt.Fprintf(sb, "CtxtID=0x%08x; ", p.Context.CtxtID)
	case PacketVMID:
		fmt.Fprintf(sb, "VMID=0x%02x; ", p.Context.VMID)
	case PacketWPointUpdate, PacketBranchAddress:
		sb.WriteString(p.getBranchAddressStr())
	case PacketISync:
		sb.WriteString(p.getISyncStr())
	case PacketTimestamp:
		sb.WriteString(p.getTSStr())
	}
}

func (p *ptmPacket) getAtomStr() string {
	var sb strings.Builder
	bitpattern := p.Atom.EnBits

	if p.CCValid {
		if (bitpattern & 0x1) != 0 {
			sb.WriteString("E; ")
		} else {
			sb.WriteString("N; ")
		}
		sb.WriteString(p.getCycleCountStr())
	} else {
		for i := 0; i < int(p.Atom.Num); i++ {
			if (bitpattern & 0x1) != 0 {
				sb.WriteString("E")
			} else {
				sb.WriteString("N")
			}
			bitpattern >>= 1
		}
		sb.WriteString("; ")
	}
	return sb.String()
}

func (p *ptmPacket) getBranchAddressStr() string {
	var sb strings.Builder
	sb.WriteString("Addr=")
	sb.WriteString(formatTraceValueHex(32, p.AddrValidBits, uint64(p.AddrVal), p.AddrBits))
	sb.WriteString("; ")

	if p.CurrISA != p.PrevISA {
		sb.WriteString(p.getISAStr())
	}

	if p.Context.Updated {
		if p.Context.CurrNS {
			sb.WriteString("NS; ")
		} else {
			sb.WriteString("S; ")
		}
		if p.Context.CurrHyp {
			sb.WriteString("Hyp; ")
		}
	}

	if p.Exception.Present {
		sb.WriteString(p.getExcepStr())
	}

	if p.CCValid {
		sb.WriteString(p.getCycleCountStr())
	}

	return sb.String()
}

func (p *ptmPacket) getISAStr() string {
	switch p.CurrISA {
	case ISAArm:
		return "ISA=ARM(32); "
	case ISAThumb2:
		return "ISA=Thumb2; "
	case ISAAArch64:
		return "ISA=AArch64; "
	case ISATee:
		return "ISA=ThumbEE; "
	case ISAJazelle:
		return "ISA=Jazelle; "
	default:
		return "ISA=Unknown; "
	}
}

var ptmExceptionNames = [...]string{
	"No Exception", "Debug Halt", "SMC", "Hyp",
	"Async Data Abort", "Jazelle", "Reserved", "Reserved",
	"PE Reset", "Undefined Instr", "SVC", "Prefetch Abort",
	"Data Fault", "Generic", "IRQ", "FIQ",
}

var iSyncReasonNames = [...]string{"Periodic", "Trace Enable", "Restart Overflow", "Debug Exit"}

func (p *ptmPacket) getExcepStr() string {
	name := "Unknown"
	if int(p.Exception.Number) < len(ptmExceptionNames) {
		name = ptmExceptionNames[p.Exception.Number]
	}
	return fmt.Sprintf("Excep=%s [%02x]; ", name, p.Exception.Number)
}

func (p *ptmPacket) getISyncStr() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "(%s); ", iSyncReasonName(p.ISyncReason))
	fmt.Fprintf(&sb, "Addr=0x%08x; ", uint32(p.AddrVal))

	if p.Context.CurrNS {
		sb.WriteString("NS; ")
	} else {
		sb.WriteString("S; ")
	}

	if p.Context.CurrHyp {
		sb.WriteString("Hyp; ")
	} else {
		sb.WriteString(" ")
	}

	if p.Context.UpdatedC {
		fmt.Fprintf(&sb, "CtxtID=0x%08x; ", p.Context.CtxtID)
	}

	sb.WriteString(p.getISAStr())

	if p.CCValid {
		sb.WriteString(p.getCycleCountStr())
	}

	return sb.String()
}

func (p *ptmPacket) getTSStr() string {
	var sb strings.Builder
	sb.WriteString("TS=")
	sb.WriteString(formatTraceValueHex(64, 64, p.Timestamp, int(p.TSUpdateBits)))
	fmt.Fprintf(&sb, "(%d); ", p.Timestamp)
	if p.CCValid {
		sb.WriteString(p.getCycleCountStr())
	}
	return sb.String()
}

func (p *ptmPacket) getCycleCountStr() string {
	return fmt.Sprintf("Cycles=%d; ", p.CycleCount)
}

type packetTypeInfo struct {
	name string
	desc string
}

var packetTypeInfos = map[ptmPacketType]packetTypeInfo{
	PacketNotSync:       {"NOTSYNC", "PTM Not Synchronised"},
	PacketIncompleteEOT: {"INCOMPLETE_EOT", "Incomplete packet flushed at end of trace"},
	PacketNoError:       {"NO_ERROR", "Error type not set"},
	PacketBadSequence:   {"BAD_SEQUENCE", "Invalid sequence in packet"},
	PacketReserved:      {"RESERVED", "Reserved Packet Header"},
	PacketBranchAddress: {"BRANCH_ADDRESS", "Branch address packet"},
	PacketASync:         {"ASYNC", "Alignment Synchronisation Packet"},
	PacketISync:         {"ISYNC", "Instruction Synchronisation packet"},
	PacketTrigger:       {"TRIGGER", "Trigger Event packet"},
	PacketWPointUpdate:  {"WP_UPDATE", "Waypoint update packet"},
	PacketIgnore:        {"IGNORE", "Ignore packet"},
	PacketContextID:     {"CTXTID", "Context ID packet"},
	PacketVMID:          {"VMID", "VM ID packet"},
	PacketAtom:          {"ATOM", "Atom packet"},
	PacketTimestamp:     {"TIMESTAMP", "Timestamp packet"},
	PacketExceptionRet:  {"ERET", "Exception return packet"},
}

func ptmPacketInfo(t ptmPacketType) packetTypeInfo {
	if info, ok := packetTypeInfos[t]; ok {
		return info
	}
	return packetTypeInfo{"UNKNOWN", "Unknown packet type"}
}

// packetTypeName returns the canonical packet-type name used in raw/golden output.
func packetTypeName(t ptmPacketType) string {
	return ptmPacketInfo(t).name
}

func iSyncReasonName(reason iSyncReason) string {
	idx := int(reason)
	if idx >= 0 && idx < len(iSyncReasonNames) {
		return iSyncReasonNames[idx]
	}
	return "Unknown"
}

func ptmMaskBits64(bits int) uint64 {
	if bits <= 0 {
		return 0
	}
	if bits >= 64 {
		return ^uint64(0)
	}
	return (uint64(1) << bits) - 1
}

func formatTraceValueHex(totalBits int, validBits int, value uint64, updateBits int) string {
	if totalBits < 4 {
		totalBits = 4
	}
	if totalBits > 64 {
		totalBits = 64
	}
	if validBits < 0 {
		validBits = 0
	}
	if validBits > totalBits {
		validBits = totalBits
	}

	numHexChars := (totalBits + 3) / 4
	validChars := 0
	if validBits > 0 {
		validChars = (validBits + 3) / 4
	}

	var sb strings.Builder
	sb.WriteString("0x")
	for i := validChars; i < numHexChars; i++ {
		sb.WriteByte('?')
	}
	if validChars > 0 {
		fmt.Fprintf(&sb, "%0*X", validChars, value&ptmMaskBits64(validBits))
	}
	if validBits < totalBits {
		fmt.Fprintf(&sb, " (%d:0)", validBits-1)
	}
	if updateBits > 0 {
		fmt.Fprintf(&sb, " ~[0x%X]", value&ptmMaskBits64(updateBits))
	}
	return sb.String()
}

// ptmAtomPkt represents an instruction atom packet.
type ptmAtomPkt struct {
	// EnBits stores one bit per atom, least-significant bit first:
	// 1 means executed and 0 means not executed.
	EnBits uint32
	Num    uint8
}

// Pop returns the next atom value and updates the packet state.
func (a *ptmAtomPkt) Pop() atmVal {
	if a.Num == 0 {
		return atomN
	}
	val := atomN
	if (a.EnBits & 0x1) != 0 {
		val = atomE
	}
	a.EnBits >>= 1
	a.Num--
	return val
}
