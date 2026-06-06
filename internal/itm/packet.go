package itm

import (
	"fmt"
	"strings"

	"coresight/trace"
)

type PktType int

const (
	PktNotSync PktType = iota
	PktIncompleteEOT
	PktNoErrType
	PktAsync
	PktOverflow
	PktSWIT
	PktDWT
	PktTSLocal
	PktTSGlobal1
	PktTSGlobal2
	PktExtension
	PktBadSequence
	PktReserved
)

type DwtEcntr uint8

const (
	DwtEcntrCPI DwtEcntr = 0x01
	DwtEcntrEXC DwtEcntr = 0x02
	DwtEcntrSLP DwtEcntr = 0x04
	DwtEcntrLSU DwtEcntr = 0x08
	DwtEcntrFLD DwtEcntr = 0x10
	DwtEcntrCYC DwtEcntr = 0x20
)

type Packet struct {
	Index   trace.Index
	Type    PktType
	SrcID   uint8
	Value   uint32
	ValSz   uint8
	ValExt  uint8
	ErrType PktType
}

func (p *Packet) Clear() {
	p.Type = PktReserved
	p.SrcID = 0
	p.Value = 0
	p.ValSz = 0
	p.ValExt = 0
	p.ErrType = PktNoErrType
}

func (p *Packet) UpdateErrType(errType PktType) {
	p.ErrType = p.Type
	p.Type = errType
}

func (p *Packet) IsBadPacket() bool {
	return p.Type >= PktBadSequence
}

var valMasks = [...]uint32{0xFF, 0xFFFF, 0xFFFFFF, 0xFFFFFFFF}

func (p *Packet) SetValue(val uint32, valSzBytes uint8) {
	p.ValSz = valSzBytes
	if p.ValSz < 1 || p.ValSz > 4 {
		p.ValSz = 4
	}
	p.Value = val & valMasks[p.ValSz-1]
}

func (p *Packet) SetExtValue(extVal uint64) {
	p.Value = uint32(extVal & 0xFFFFFFFF)
	p.ValExt = uint8((extVal >> 32) & 0xFF)
	p.ValSz = 5
}

func (p *Packet) ExtValue() uint64 {
	if p.ValSz < 5 {
		return uint64(p.Value)
	}
	return uint64(p.Value) | (uint64(p.ValExt) << 32)
}

func (p *Packet) String() string {
	var sb strings.Builder
	name, desc := packetTypeNameDesc(p.Type)
	sb.WriteString(name)
	sb.WriteString(": ")
	p.writePacketBody(&sb)
	sb.WriteString("; '")
	sb.WriteString(desc)
	sb.WriteString("'")
	return sb.String()
}

func packetTypeNameDesc(t PktType) (string, string) {
	switch t {
	case PktNotSync:
		return "ITM_NOTSYNC", "ITM data stream not synchronised"
	case PktIncompleteEOT:
		return "ITM_INCOMPLETE_EOT", "Incomplete packet flushed at end of trace"
	case PktAsync:
		return "ITM_ASYNC", "Alignment synchronisation packet"
	case PktOverflow:
		return "ITM_OVERFLOW", "ITM overflow packet"
	case PktSWIT:
		return "ITM_SWIT", "Software Stimulus write packet"
	case PktDWT:
		return "ITM_DWT", "DWT hardware stimulus write"
	case PktTSLocal:
		return "ITM_TS_LOCAL", "Local Timestamp"
	case PktTSGlobal1:
		return "ITM_GTS_1", "Global Timestamp [25:0]"
	case PktTSGlobal2:
		return "ITM_GTS_2", "Global Timestamp [{63|42}:26]"
	case PktExtension:
		return "ITM_EXTENSION", "Extension packet"
	case PktBadSequence:
		return "ITM_BAD_SEQUENCE", "Invalid sequence in packet"
	case PktReserved:
		return "ITM_RESERVED", "Reserved Packet Header"
	default:
		return "ITM_UNKNOWN", "ERROR: unknown packet type"
	}
}

func (p *Packet) writePacketBody(sb *strings.Builder) {
	switch p.Type {
	case PktSWIT:
		fmt.Fprintf(sb, "{src id: 0x%02x}  ", p.SrcID)
		p.writeHexVal(sb)
	case PktDWT:
		fmt.Fprintf(sb, "{desc: 0x%02x} ", p.SrcID)
		p.writeDwtPacketBody(sb)
	case PktTSLocal:
		p.writeTsLocalPacketBody(sb)
	case PktTSGlobal1:
		p.writeTsGlobal1PacketBody(sb)
	case PktTSGlobal2:
		p.writeTsGlobal2PacketBody(sb)
	case PktExtension:
		p.writeExtensionPacketBody(sb)
	case PktIncompleteEOT, PktBadSequence:
		name, _ := packetTypeNameDesc(p.ErrType)
		fmt.Fprintf(sb, "[Init type: %s] ", name)
	}
}

func (p *Packet) writeHexVal(sb *strings.Builder) {
	if p.ValSz <= 4 {
		valSz := int(p.ValSz)
		if valSz < 1 {
			valSz = 4
		}
		fmt.Fprintf(sb, "0x%0*x", valSz*2, p.Value)
	} else {
		fmt.Fprintf(sb, "0x%02x%08x", p.ValExt, p.Value)
	}
}

var dwtFlags = [...]struct {
	bit DwtEcntr
	str string
}{
	{DwtEcntrCPI, "CPI"},
	{DwtEcntrEXC, "EXC"},
	{DwtEcntrSLP, "Sleep"},
	{DwtEcntrLSU, "LSU"},
	{DwtEcntrFLD, "Fold"},
	{DwtEcntrCYC, "CYC"},
}

var dwtExcepFn = [...]string{"reserved", "entered", "exited", "returned to"}

func (p *Packet) writeDwtPacketBody(sb *strings.Builder) {
	if p.SrcID == 0 {
		fmt.Fprintf(sb, "[Event Counter: 0x%02x; Flags: ", p.Value)
		for _, f := range dwtFlags {
			if p.Value&uint32(f.bit) != 0 {
				fmt.Fprintf(sb, " %s ", f.str)
			} else {
				sb.WriteString(" --- ")
			}
		}
		sb.WriteString("] ")
		return
	}

	if p.SrcID == 1 {
		action := (p.Value >> 12) & 0x3
		fmt.Fprintf(sb, "[Exception Num:  0x%04x(%s) ]", p.Value&0x1FF, dwtExcepFn[action])
		return
	}

	if p.SrcID == 2 {
		sb.WriteString("[PC Sample: ")
		p.writeHexVal(sb)
		sb.WriteString("] ")
		return
	}

	if p.SrcID >= 8 && p.SrcID <= 23 {
		dtType := (p.SrcID >> 3) & 0x3
		dtRW := p.SrcID & 0x1
		dtComp := (p.SrcID >> 1) & 0x3
		if dtType == 0x1 && dtRW == 0 {
			fmt.Fprintf(sb, "[Data Trc: comp=%d; PC Value=", dtComp)
			p.writeHexVal(sb)
			sb.WriteString(" ] ")
			return
		}
		if dtType == 0x1 && dtRW == 1 {
			fmt.Fprintf(sb, "[Data Trc: comp=%d; Address=", dtComp)
			p.writeHexVal(sb)
			sb.WriteString(" ] ")
			return
		}
		if dtType == 0x2 {
			if dtRW == 1 {
				fmt.Fprintf(sb, "[Data Trc: comp=%d; Val write: ", dtComp)
			} else {
				fmt.Fprintf(sb, "[Data Trc: comp=%d; Val read: ", dtComp)
			}
			p.writeHexVal(sb)
			sb.WriteString("] ")
			return
		}
	}
	sb.WriteString("[Reserved discriminator value] ")
}

var tsLocalTypes = [...]string{
	"TS Sync",
	"TS Delayed",
	"TS Sync, Packet Delayed",
	"TS Delayed, Packet Delayed",
}

func (p *Packet) writeTsLocalPacketBody(sb *strings.Builder) {
	p.writeHexVal(sb)
	fmt.Fprintf(sb, " { %s }", tsLocalTypes[p.SrcID&3])
}

var tsGlobal1BitSizes = [...]int{6, 13, 20, 25}

func (p *Packet) writeTsGlobal1PacketBody(sb *strings.Builder) {
	idx := max(int(p.ValSz)-1, 0)
	if idx >= len(tsGlobal1BitSizes) {
		idx = len(tsGlobal1BitSizes) - 1
	}

	fmt.Fprintf(sb, "{ TS bits [%d:0]", tsGlobal1BitSizes[idx])
	if p.SrcID&0x1 != 0 {
		sb.WriteString(", Clk change")
	}
	if p.SrcID&0x2 != 0 {
		sb.WriteString(", Clk wrap")
	}
	sb.WriteString("} ")
	p.writeHexVal(sb)
}

func (p *Packet) writeTsGlobal2PacketBody(sb *strings.Builder) {
	if p.ValSz == 5 {
		sb.WriteString("{ TS bits [63:26]} ")
	} else {
		sb.WriteString("{ TS bits [47:26]} ")
	}
	p.writeHexVal(sb)
}

func (p *Packet) writeExtensionPacketBody(sb *strings.Builder) {
	bitsize := int(p.SrcID&0x1F) + 1
	if bitsize == 3 && (p.SrcID&0x80) == 0 {
		fmt.Fprintf(sb, "{stim port page} 0x%02x", p.Value)
		return
	}
	width := (bitsize / 4) + 1
	fmt.Fprintf(sb, "{unknown extension type, %d bits } 0x%0*x", bitsize, width, p.Value)
}
