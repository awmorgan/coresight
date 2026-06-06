package etmv3

import (
	"coresight/trace"
	"errors"
	"strconv"
)

type PktType int

const (
	PktNoError PktType = iota
	PktNotSync
	PktIncompleteEOT
	PktBranchAddress
	PktASync
	PktCycleCount
	PktISync
	PktISyncCycle
	PktTrigger
	PktPHdr
	PktStoreFail
	PktOOOData
	PktOOOAddrPlc
	PktNormData
	PktDataSuppressed
	PktValNotTraced
	PktIgnore
	PktContextID
	PktVMID
	PktExceptionEntry
	PktExceptionExit
	PktTimestamp
	PktBranchOrBypassEOT
	PktBadSequence
	PktBadTraceMode
	PktReserved
)

type Excep struct {
	Type    trace.ArmV7Exception
	Number  uint16
	Present bool
}

type Context struct {
	CurrAltIsa      bool
	CurrNS          bool
	CurrHyp         bool
	Updated         bool
	ExceptionCancel bool
	UpdatedC        bool
	UpdatedV        bool
	CtxtID          uint32
	VMID            uint8
}

type Data struct {
	Value      uint32
	Addr       uint64
	OooTag     uint8
	BE         bool
	UpdateBE   bool
	UpdateAddr bool
	UpdateDVal bool
}

type ISyncInfo struct {
	Reason        trace.ISyncReason
	HasCycleCount bool
	HasLSipAddr   bool
	NoAddress     bool
}

// AtomPkt represents an instruction atom packet.
type AtomPkt struct {
	EnBits uint32
	Num    uint8
}

type Packet struct {
	Type  PktType
	Index trace.Index

	CurrISA trace.ISA
	PrevISA trace.ISA

	Context   Context
	Addr      uint64
	ISyncInfo ISyncInfo
	Exception Excep

	ExceptionCancel bool
	Atom            AtomPkt
	PHdrFmt         uint8
	CycleCount      uint32

	Timestamp    uint64
	TsUpdateBits uint8

	Data        Data
	AddrPktBits int

	Err error
}

func (p *Packet) Clear() {
	p.Type = PktNoError
	p.Index = 0
	p.Err = nil
	p.PrevISA = p.CurrISA
	p.Context.Updated = false
	p.Context.UpdatedC = false
	p.Context.UpdatedV = false
	p.Exception = Excep{}
	p.ISyncInfo = ISyncInfo{}
	p.ExceptionCancel = false
	p.Atom = AtomPkt{}
	p.PHdrFmt = 0
	p.CycleCount = 0
	p.TsUpdateBits = 0
	p.Data.UpdateBE = false
	p.Data.UpdateAddr = false
	p.Data.UpdateDVal = false
}

func (p *Packet) ResetState() {
	p.Clear()
	p.CurrISA = trace.ISAArm
	p.PrevISA = trace.ISAArm
	p.Context = Context{}
	p.Data = Data{}
}

func (p *Packet) IsBadPacket() bool {
	return p.Err != nil || p.Type >= PktBadSequence
}

func (p *Packet) UpdateAddress(partAddrVal uint64, updateBits int) {
	var mask uint64
	if updateBits >= 64 {
		mask = ^uint64(0)
	} else if updateBits > 0 {
		mask = (uint64(1) << updateBits) - 1
	}
	p.Addr = (p.Addr & ^mask) | (partAddrVal & mask)
	p.AddrPktBits = updateBits
}

func (p *Packet) UpdateTimestamp(tsVal uint64, updateBits uint8) {
	if updateBits == 0 {
		return
	}
	var mask uint64
	if updateBits >= 64 {
		mask = ^uint64(0)
	} else {
		mask = uint64((1 << updateBits) - 1)
	}
	p.Timestamp = (p.Timestamp & ^mask) | (tsVal & mask)
	p.TsUpdateBits = updateBits
}

func (p *Packet) SetException(exType trace.ArmV7Exception, num uint16) {
	p.Exception.Type = exType
	p.Exception.Number = num
	p.Exception.Present = true
}

func (p *Packet) SetExceptionWithCancel(exType trace.ArmV7Exception, num uint16, cancel bool) {
	p.SetException(exType, num)
	p.ExceptionCancel = cancel
}

func (p *Packet) UpdateISA(isa trace.ISA) {
	p.PrevISA = p.CurrISA
	p.CurrISA = isa
}

func (p *Packet) UpdateAtomFromPHdr(pHdr uint8, cycleAccurate bool) bool {
	isValid := true
	p.Atom.EnBits = 0
	p.Atom.Num = 0

	if !cycleAccurate {
		switch pHdr & 0x3 {
		case 0x0:
			p.PHdrFmt = 1
			e := (pHdr >> 2) & 0xF
			n := uint8(0)
			if (pHdr & 0x40) != 0 {
				n = 1
			}
			p.Atom.Num = e + n
			p.Atom.EnBits = (uint32(1) << e) - 1
		case 0x2:
			p.PHdrFmt = 2
			p.Atom.Num = 2
			p.Atom.EnBits = 0
			if (pHdr & 0x8) == 0 {
				p.Atom.EnBits |= 1
			}
			if (pHdr & 0x4) == 0 {
				p.Atom.EnBits |= 2
			}
		default:
			isValid = false
		}
	} else {
		pHdrCode := pHdr & 0xA3
		switch pHdrCode {
		case 0x80:
			p.PHdrFmt = 1
			e := (pHdr >> 2) & 0x7
			n := uint8(0)
			if (pHdr & 0x40) != 0 {
				n = 1
			}
			p.Atom.Num = e + n
			if p.Atom.Num > 0 {
				p.Atom.EnBits = (uint32(1) << e) - 1
				p.CycleCount = uint32(e + n)
			} else {
				isValid = false
			}
		case 0x82:
			if (pHdr & 0x10) != 0 {
				p.PHdrFmt = 4
				p.Atom.Num = 1
				p.CycleCount = 0
				if (pHdr & 0x04) != 0 {
					p.Atom.EnBits = 0
				} else {
					p.Atom.EnBits = 1
				}
			} else {
				p.PHdrFmt = 2
				p.Atom.Num = 2
				p.CycleCount = 1
				p.Atom.EnBits = 0
				if (pHdr & 0x8) == 0 {
					p.Atom.EnBits |= 1
				}
				if (pHdr & 0x4) == 0 {
					p.Atom.EnBits |= 2
				}
			}
		case 0xA0:
			p.PHdrFmt = 3
			p.CycleCount = uint32(((pHdr >> 2) & 7) + 1)
			e := uint8(0)
			if (pHdr & 0x40) != 0 {
				e = 1
			}
			p.Atom.Num = e
			p.Atom.EnBits = uint32(e)
		default:
			isValid = false
		}
	}

	return isValid
}

var pktTypeInfos = map[PktType]struct{ name, desc string }{
	PktNotSync:        {"NOTSYNC", "Trace Stream not synchronised"},
	PktIncompleteEOT:  {"INCOMPLETE_EOT.", "Incomplete packet at end of trace data."},
	PktBranchAddress:  {"BRANCH_ADDRESS", "Branch address."},
	PktASync:          {"A_SYNC", "Alignment Synchronisation."},
	PktCycleCount:     {"CYCLE_COUNT", "Cycle Count."},
	PktISync:          {"I_SYNC", "Instruction Packet synchronisation."},
	PktISyncCycle:     {"I_SYNC_CYCLE", "Instruction Packet synchronisation with cycle count."},
	PktTrigger:        {"TRIGGER", "Trace Trigger Event."},
	PktPHdr:           {"P_HDR", "Atom P-header."},
	PktStoreFail:      {"STORE_FAIL", "Data Store Failed."},
	PktOOOData:        {"OOO_DATA", "Out of Order data value packet."},
	PktOOOAddrPlc:     {"OOO_ADDR_PLC", "Out of Order data address placeholder."},
	PktNormData:       {"NORM_DATA", "Data trace packet."},
	PktDataSuppressed: {"DATA_SUPPRESSED", "Data trace suppressed."},
	PktValNotTraced:   {"VAL_NOT_TRACED", "Data trace value not traced."},
	PktIgnore:         {"IGNORE", "Packet ignored."},
	PktContextID:      {"CONTEXT_ID", "Context ID change."},
	PktVMID:           {"VMID", "VMID change."},
	PktExceptionEntry: {"EXCEPTION_ENTRY", "Exception entry data marker."},
	PktExceptionExit:  {"EXCEPTION_EXIT", "Exception return."},
	PktTimestamp:      {"TIMESTAMP", "Timestamp Value."},
	PktBadSequence:    {"BAD_SEQUENCE", "Invalid sequence for packet type."},
	PktBadTraceMode:   {"BAD_TRACEMODE", "Invalid packet type for this trace mode."},
	PktReserved:       {"I_RESERVED", "Reserved Packet Header"},
}

func packetTypeNameDesc(pt PktType) (string, string) {
	if info, ok := pktTypeInfos[pt]; ok {
		return info.name, info.desc
	}
	return "I_RESERVED", "Reserved Packet Header"
}

// String implements fmt.Stringer for packet observers.
func (p *Packet) String() string {
	return string(p.AppendStringTo(nil))
}

func (p *Packet) AppendStringTo(dst []byte) []byte {
	name, desc := packetTypeNameDesc(p.Type)
	dst = append(dst, name...)
	dst = append(dst, " : "...)
	dst = append(dst, desc...)

	if p.Err != nil {
		if errors.Is(p.Err, trace.ErrBadPacketSeq) {
			return append(dst, "[BAD_SEQUENCE]"...)
		}
		return append(dst, "[I_RESERVED]"...)
	}

	switch p.Type {
	case PktContextID:
		dst = append(dst, "; CtxtID=0x"...)
		dst = appendLowerHex(dst, uint64(p.Context.CtxtID), 8)
	case PktVMID:
		dst = append(dst, "; VMID=0x"...)
		dst = appendLowerHex(dst, uint64(p.Context.VMID), 2)
	case PktTimestamp:
		dst = append(dst, "; TS=0x"...)
		dst = strconv.AppendUint(dst, p.Timestamp, 16)
		dst = append(dst, " ("...)
		dst = strconv.AppendUint(dst, p.Timestamp, 10)
		dst = append(dst, ") "...)
	case PktCycleCount:
		dst = append(dst, "; Cycles="...)
		dst = strconv.AppendUint(dst, uint64(p.CycleCount), 10)
	case PktPHdr:
		atomStart := len(dst)
		dst = append(dst, "; "...)
		if p.PHdrFmt == 1 && p.CycleCount > 0 {
			for i := 0; i < int(p.Atom.Num); i++ {
				dst = append(dst, 'W')
				if (p.Atom.EnBits & (1 << i)) != 0 {
					dst = append(dst, 'E')
				} else {
					dst = append(dst, 'N')
				}
			}
		} else {
			for i := 0; i < int(p.CycleCount); i++ {
				dst = append(dst, 'W')
			}
			for i := 0; i < int(p.Atom.Num); i++ {
				if (p.Atom.EnBits & (1 << i)) != 0 {
					dst = append(dst, 'E')
				} else {
					dst = append(dst, 'N')
				}
			}
		}
		if len(dst) == atomStart+2 {
			dst = dst[:atomStart]
		}

		if p.CycleCount > 0 || p.PHdrFmt == 4 {
			dst = append(dst, "; Cycles="...)
			dst = strconv.AppendUint(dst, uint64(p.CycleCount), 10)
		}
	case PktISync, PktISyncCycle:
		dst = append(dst, "; ("...)
		dst = append(dst, p.ISyncInfo.Reason.String()...)
		dst = append(dst, ')')

		if p.ISyncInfo.NoAddress {
			dst = append(dst, "; [No Address]"...)
		} else {
			dst = append(dst, "; Addr=0x"...)
			dst = appendLowerHex(dst, p.Addr, 8)
		}

		if p.Context.CurrNS {
			dst = append(dst, "; N;"...)
		} else {
			dst = append(dst, "; S;"...)
		}

		dst = append(dst, "  ISA="...)
		dst = append(dst, p.CurrISA.String()...)
		dst = append(dst, "; "...)

		if p.Type == PktISyncCycle {
			dst = append(dst, "Cycles="...)
			dst = strconv.AppendUint(dst, uint64(p.CycleCount), 10)
			dst = append(dst, "; "...)
		}
	case PktBranchAddress:
		mask := maskBits64(p.AddrPktBits)
		shortAddr := p.Addr & mask

		dst = append(dst, "; Addr=0x"...)
		dst = appendUpperHex(dst, uint64(uint32(p.Addr)), 8)
		dst = append(dst, " ~[0x"...)
		dst = appendUpperHex(dst, uint64(uint32(shortAddr)), 0)
		dst = append(dst, "]; "...)

		if p.CurrISA != p.PrevISA {
			dst = append(dst, "ISA="...)
			dst = append(dst, p.CurrISA.String()...)
			dst = append(dst, "; "...)
		}
	}
	return dst
}

func appendLowerHex(dst []byte, value uint64, minWidth int) []byte {
	var buf [16]byte
	b := strconv.AppendUint(buf[:0], value, 16)
	for i := len(b); i < minWidth; i++ {
		dst = append(dst, '0')
	}
	return append(dst, b...)
}

func appendUpperHex(dst []byte, value uint64, minWidth int) []byte {
	var buf [16]byte
	b := strconv.AppendUint(buf[:0], value, 16)
	for i := len(b); i < minWidth; i++ {
		dst = append(dst, '0')
	}
	for _, c := range b {
		if c >= 'a' && c <= 'f' {
			c -= 'a' - 'A'
		}
		dst = append(dst, c)
	}
	return dst
}

func maskBits64(bits int) uint64 {
	if bits <= 0 {
		return 0
	}
	if bits >= 64 {
		return ^uint64(0)
	}
	return (uint64(1) << bits) - 1
}
