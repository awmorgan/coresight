package etmv4

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/awmorgan/coresight/trace"
)

type PacketType int

const (
	PktExtension PacketType = iota
	PktTraceInfo
	PktTimestamp
	PktTraceOn
	PktFuncRet
	PktException
	PktExceptionReturn
	PktITE
	PktCycleCountF2
	PktCycleCountF1
	PktCycleCountF3
	PktNumDSMarker
	PktUnnumDSMarker
	PktCommit
	PktCancelF1
	PktCancelF1Mispred
	PktMispredict
	PktCancelF2
	PktCancelF3
	PktCondInstrF2
	PktCondFlush
	PktCondResultF4
	PktCondResultF2
	PktCondResultF3
	PktCondResultF1
	PktCondInstrF1
	PktCondInstrF3
	PktIgnore
	PktEvent
	PktContext
	PktAddrCtxtL32IS0
	PktAddrCtxtL32IS1
	PktAddrCtxtL64IS0
	PktAddrCtxtL64IS1
	PktAddrMatch
	PktAddrSIS0
	PktAddrSIS1
	PktAddrL32IS0
	PktAddrL32IS1
	PktAddrL64IS0
	PktAddrL64IS1
	PktQ
	PktSrcAddrMatch
	PktSrcAddrSIS0
	PktSrcAddrSIS1
	PktSrcAddrL32IS0
	PktSrcAddrL32IS1
	PktSrcAddrL64IS0
	PktSrcAddrL64IS1
	PktAtomF6
	PktAtomF5
	PktAtomF2
	PktAtomF4
	PktAtomF1
	PktAtomF3
	PktASync
	PktDiscard
	PktOverflow
	PktNotSync
	PktIncompleteEOT
	PktNoErrType
	PktTransStart
	PktTransCommit
	PktTransFail
	PktPEReset
	PktTSMarker
	PktBadSequence
	PktBadTraceMode
	PktReserved
	PktReservedCfg
)

type TraceInfo struct {
	Value            uint32
	CCEnabled        bool
	InTransState     bool
	Initial          bool
	SpecFieldPresent bool
}

type Context struct {
	EL       uint8
	SF       bool
	NS       bool
	NSE      bool
	Updated  bool
	UpdatedC bool
	UpdatedV bool
	CtxtID   uint32
	VMID     uint32
}

type Atom struct {
	EnBits uint32
	Num    uint8
}

type Address struct {
	Val       trace.VAddr
	IS        uint8
	Size      int
	PktBits   int
	ValidBits int
}

type ExceptionInfo struct {
	Type          uint16
	AddrInterp    uint8
	MFaultPending bool
	MType         bool
}

type QInfo struct {
	Count        uint32
	CountPresent bool
	AddrPresent  bool
	AddrMatch    bool
	Type         uint8
}

type ITEInfo struct {
	EL    uint8
	Value uint64
}

type Packet struct {
	Type      PacketType
	ErrType   PacketType
	Err       error
	Index     trace.Index
	IsETE     bool
	RawPrefix string

	TraceInfo     TraceInfo
	Context       Context
	Addr          Address
	Timestamp     uint64
	TSBitsChanged uint8
	CycleCount    uint32
	CCValid       bool
	Atom          Atom
	Commit        uint32
	CommitValid   bool
	Cancel        uint32
	CancelValid   bool
	CurrSpecDepth uint32
	P0Key         uint32
	CCThreshold   uint32
	Exception     ExceptionInfo
	AddrMatchIdx  uint8
	DSMVal        uint8
	EventVal      uint8
	Q             QInfo
	ITE           ITEInfo

	addrStack [3]Address
}

func (p *Packet) InitStartState() {
	*p = Packet{Type: PktNotSync, ErrType: PktNoErrType}
	p.Addr = Address{Size: 64, ValidBits: 64}
	for i := range p.addrStack {
		p.addrStack[i] = Address{Size: 64, ValidBits: 64}
	}
}

func (p *Packet) InitNextPacket() {
	p.Err = nil
	p.ErrType = PktNoErrType
	p.RawPrefix = ""
	p.CCValid = false
	p.CommitValid = false
	p.CancelValid = false
	p.Atom = Atom{}
	p.Context.Updated = false
	p.Context.UpdatedC = false
	p.Context.UpdatedV = false
	p.TraceInfo.Initial = false
	p.TraceInfo.SpecFieldPresent = false
}

func (p *Packet) updateErr(t PacketType, err error) {
	p.ErrType = p.Type
	p.Type = t
	p.Err = err
}

func (p *Packet) setTimestamp(value uint64, bits uint8) {
	mask := ^uint64(0)
	if bits < 64 {
		mask = (uint64(1) << bits) - 1
	}
	p.Timestamp = (p.Timestamp & ^mask) | (value & mask)
	p.TSBitsChanged = bits
}

func (p *Packet) pushAddr(addr Address) {
	p.addrStack[2] = p.addrStack[1]
	p.addrStack[1] = p.addrStack[0]
	p.addrStack[0] = addr
	p.Addr = addr
}

func (p *Packet) setAddressExactMatch(idx uint8) {
	p.AddrMatchIdx = idx
	if idx < 3 {
		p.pushAddr(p.addrStack[idx])
	}
}

func (p *Packet) IsBadPacket() bool {
	return p.Err != nil || p.Type >= PktBadSequence
}

type packetInfo struct {
	name string
	desc string
}

var packetInfos = map[PacketType]packetInfo{
	PktNotSync:         {"I_NOT_SYNC", "I Stream not synchronised"},
	PktIncompleteEOT:   {"I_INCOMPLETE_EOT", "Incomplete packet at end of trace."},
	PktBadSequence:     {"I_BAD_SEQUENCE", "Invalid Sequence in packet."},
	PktBadTraceMode:    {"I_BAD_TRACEMODE", "Invalid Packet for trace mode."},
	PktReserved:        {"I_RESERVED", "Reserved Packet Header"},
	PktReservedCfg:     {"I_RESERVED_CFG", "Reserved header for current configuration."},
	PktExtension:       {"I_EXTENSION", "Extension packet header."},
	PktTraceInfo:       {"I_TRACE_INFO", "Trace Info."},
	PktTimestamp:       {"I_TIMESTAMP", "Timestamp."},
	PktTraceOn:         {"I_TRACE_ON", "Trace On."},
	PktFuncRet:         {"I_FUNC_RET", "V8M - function return."},
	PktException:       {"I_EXCEPT", "Exception."},
	PktExceptionReturn: {"I_EXCEPT_RTN", "Exception Return."},
	PktITE:             {"I_ITE", "Instrumentation"},
	PktCycleCountF1:    {"I_CCNT_F1", "Cycle Count format 1."},
	PktCycleCountF2:    {"I_CCNT_F2", "Cycle Count format 2."},
	PktCycleCountF3:    {"I_CCNT_F3", "Cycle Count format 3."},
	PktNumDSMarker:     {"I_NUM_DS_MKR", "Data Synchronisation Marker - Numbered."},
	PktUnnumDSMarker:   {"I_UNNUM_DS_MKR", "Data Synchronisation Marker - Unnumbered."},
	PktCommit:          {"I_COMMIT", "Commit"},
	PktCancelF1:        {"I_CANCEL_F1", "Cancel Format 1."},
	PktCancelF1Mispred: {"I_CANCEL_F1_MISPRED", "Cancel Format 1 + Mispredict."},
	PktMispredict:      {"I_MISPREDICT", "Mispredict."},
	PktCancelF2:        {"I_CANCEL_F2", "Cancel Format 2."},
	PktCancelF3:        {"I_CANCEL_F3", "Cancel Format 3."},
	PktCondInstrF2:     {"I_COND_I_F2", "Conditional Instruction, format 2."},
	PktCondFlush:       {"I_COND_FLUSH", "Conditional Flush."},
	PktCondResultF4:    {"I_COND_RES_F4", "Conditional Result, format 4."},
	PktCondResultF2:    {"I_COND_RES_F2", "Conditional Result, format 2."},
	PktCondResultF3:    {"I_COND_RES_F3", "Conditional Result, format 3."},
	PktCondResultF1:    {"I_COND_RES_F1", "Conditional Result, format 1."},
	PktCondInstrF1:     {"I_COND_I_F1", "Conditional Instruction, format 1."},
	PktCondInstrF3:     {"I_COND_I_F3", "Conditional Instruction, format 3."},
	PktIgnore:          {"I_IGNORE", "Ignore."},
	PktEvent:           {"I_EVENT", "Trace Event."},
	PktContext:         {"I_CTXT", "Context Packet."},
	PktAddrCtxtL32IS0:  {"I_ADDR_CTXT_L_32IS0", "Address & Context, Long, 32 bit, IS0."},
	PktAddrCtxtL32IS1:  {"I_ADDR_CTXT_L_32IS1", "Address & Context, Long, 32 bit, IS1."},
	PktAddrCtxtL64IS0:  {"I_ADDR_CTXT_L_64IS0", "Address & Context, Long, 64 bit, IS0."},
	PktAddrCtxtL64IS1:  {"I_ADDR_CTXT_L_64IS1", "Address & Context, Long, 64 bit, IS1."},
	PktAddrMatch:       {"I_ADDR_MATCH", "Exact Address Match."},
	PktAddrSIS0:        {"I_ADDR_S_IS0", "Address, Short, IS0."},
	PktAddrSIS1:        {"I_ADDR_S_IS1", "Address, Short, IS1."},
	PktAddrL32IS0:      {"I_ADDR_L_32IS0", "Address, Long, 32 bit, IS0."},
	PktAddrL32IS1:      {"I_ADDR_L_32IS1", "Address, Long, 32 bit, IS1."},
	PktAddrL64IS0:      {"I_ADDR_L_64IS0", "Address, Long, 64 bit, IS0."},
	PktAddrL64IS1:      {"I_ADDR_L_64IS1", "Address, Long, 64 bit, IS1."},
	PktQ:               {"I_Q", "Q Packet."},
	PktSrcAddrMatch:    {"I_SRC_ADDR_MATCH", "Exact Source Address Match."},
	PktSrcAddrSIS0:     {"I_SRC_ADDR_S_IS0", "Source Address, Short, IS0."},
	PktSrcAddrSIS1:     {"I_SRC_ADDR_S_IS1", "Source Address, Short, IS1."},
	PktSrcAddrL32IS0:   {"I_SRC_ADDR_L_32IS0", "Source Address, Long, 32 bit, IS0."},
	PktSrcAddrL32IS1:   {"I_SRC_ADDR_L_32IS1", "Source Address, Long, 32 bit, IS1."},
	PktSrcAddrL64IS0:   {"I_SRC_ADDR_L_64IS0", "Source Address, Long, 64 bit, IS0."},
	PktSrcAddrL64IS1:   {"I_SRC_ADDR_L_64IS1", "Source Address, Long, 64 bit, IS1."},
	PktAtomF6:          {"I_ATOM_F6", "Atom format 6."},
	PktAtomF5:          {"I_ATOM_F5", "Atom format 5."},
	PktAtomF2:          {"I_ATOM_F2", "Atom format 2."},
	PktAtomF4:          {"I_ATOM_F4", "Atom format 4."},
	PktAtomF1:          {"I_ATOM_F1", "Atom format 1."},
	PktAtomF3:          {"I_ATOM_F3", "Atom format 3."},
	PktASync:           {"I_ASYNC", "Alignment Synchronisation."},
	PktDiscard:         {"I_DISCARD", "Discard."},
	PktOverflow:        {"I_OVERFLOW", "Overflow."},
	PktTransStart:      {"I_TRANS_ST", "Transaction Start."},
	PktTransCommit:     {"I_TRANS_COMMIT", "Transaction Commit."},
	PktTransFail:       {"I_TRANS_FAIL", "Transaction Fail."},
	PktPEReset:         {"I_PE_RESET", "PE Reset."},
	PktTSMarker:        {"I_TS_MARKER", "Timestamp Marker"},
}

func (p *Packet) String() string {
	if isAtomPacket(p.Type) && p.Err == nil {
		return string(p.AppendStringTo(nil))
	}
	info, ok := packetInfos[p.Type]
	if !ok {
		info = packetInfo{"I_UNKNOWN", "Unknown Packet Header"}
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s : %s", info.name, info.desc)
	if p.Err != nil {
		if ei, ok := packetInfos[p.ErrType]; ok && (!errors.Is(p.Err, trace.ErrInvalidPcktHdr) || p.Type == PktReservedCfg) {
			fmt.Fprintf(&sb, "[%s]", ei.name)
		}
		return sb.String()
	}
	switch p.Type {
	case PktTraceInfo:
		cc := 0
		if p.TraceInfo.CCEnabled {
			cc = 1
		}
		fmt.Fprintf(&sb, "; INFO=0x%x { CC.%d", p.TraceInfo.Value&0xFF, cc)
		if p.IsETE {
			tstate := 0
			if p.TraceInfo.InTransState {
				tstate = 1
			}
			fmt.Fprintf(&sb, ", TSTATE.%d", tstate)
		}
		sb.WriteString(" }")
		if p.TraceInfo.CCEnabled {
			fmt.Fprintf(&sb, "; CC_THRESHOLD=0x%x", p.CCThreshold)
		}
		if p.TraceInfo.Initial {
			if p.TraceInfo.SpecFieldPresent {
				fmt.Fprintf(&sb, "; INIT SPEC DEPTH=%d", p.CurrSpecDepth)
			}
			fmt.Fprintf(&sb, "; Decoder Sync point TINFO")
		}
	case PktTimestamp:
		fmt.Fprintf(&sb, "; Updated val = 0x%x", p.Timestamp)
		if p.CCValid {
			fmt.Fprintf(&sb, "; CC=0x%x", p.CycleCount)
		}
	case PktContext:
		fmt.Fprintf(&sb, "; %s", p.contextString())
	case PktAddrCtxtL32IS0, PktAddrCtxtL32IS1:
		fmt.Fprintf(&sb, "; Addr=%s; %s", formatTraceValue32(p.Addr), p.contextString())
	case PktAddrCtxtL64IS0, PktAddrCtxtL64IS1:
		fmt.Fprintf(&sb, "; Addr=%s; %s", formatTraceValue(p.Addr), p.contextString())
	case PktAddrL32IS0, PktAddrL32IS1:
		fmt.Fprintf(&sb, "; Addr=%s; ", formatTraceValue32(p.Addr))
	case PktAddrL64IS0, PktAddrL64IS1:
		fmt.Fprintf(&sb, "; Addr=%s; ", formatTraceValue(p.Addr))
	case PktAddrSIS0, PktAddrSIS1, PktSrcAddrSIS0, PktSrcAddrSIS1:
		fmt.Fprintf(&sb, "; Addr=%s", formatTraceValue(p.Addr))
	case PktSrcAddrL32IS0, PktSrcAddrL32IS1:
		fmt.Fprintf(&sb, "; Addr=%s; ", formatTraceValue32(p.Addr))
	case PktSrcAddrL64IS0, PktSrcAddrL64IS1:
		fmt.Fprintf(&sb, "; Addr=%s; ", formatTraceValue(p.Addr))
	case PktAddrMatch, PktSrcAddrMatch:
		fmt.Fprintf(&sb, ", [%d]; Addr=%s; ", p.AddrMatchIdx, formatTraceValueNoPktBits(p.Addr))
	case PktAtomF1, PktAtomF2, PktAtomF3, PktAtomF4, PktAtomF5, PktAtomF6:
		fmt.Fprintf(&sb, "; %s", atomString(p.Atom))
	case PktException:
		fmt.Fprintf(&sb, "; %s", p.exceptionString())
	case PktCycleCountF1, PktCycleCountF2, PktCycleCountF3:
		fmt.Fprintf(&sb, "; Count=0x%x", p.CycleCount)
		if p.CommitValid {
			fmt.Fprintf(&sb, "; Commit(%d)", p.Commit)
		}
	case PktCommit:
		fmt.Fprintf(&sb, "; Commit(%d)", p.Commit)
	case PktCancelF1:
		fmt.Fprintf(&sb, "; Cancel(%d)", p.Cancel)
	case PktCancelF1Mispred:
		fmt.Fprintf(&sb, "; Cancel(%d), Mispredict", p.Cancel)
	case PktMispredict:
		fmt.Fprintf(&sb, "; ")
		if p.Atom.Num != 0 {
			fmt.Fprintf(&sb, "Atom: %s, ", atomString(p.Atom))
		}
		fmt.Fprintf(&sb, "Mispredict")
	case PktCancelF2:
		fmt.Fprintf(&sb, "; ")
		if p.Atom.Num != 0 {
			fmt.Fprintf(&sb, "Atom: %s, ", atomString(p.Atom))
		}
		fmt.Fprintf(&sb, "Cancel(1), Mispredict")
	case PktCancelF3:
		fmt.Fprintf(&sb, "; ")
		if p.Atom.Num != 0 {
			fmt.Fprintf(&sb, "Atom: %s, ", atomString(p.Atom))
		}
		fmt.Fprintf(&sb, "Cancel(%d), Mispredict", p.Cancel)
	case PktQ:
		if p.Q.CountPresent {
			fmt.Fprintf(&sb, "; Count(%d)", p.Q.Count)
		} else {
			fmt.Fprintf(&sb, "; Count(Unknown)")
		}
		if p.Q.AddrPresent || p.Q.AddrMatch {
			fmt.Fprintf(&sb, "; Addr=%s", formatTraceValue(p.Addr))
		}
	case PktITE:
		fmt.Fprintf(&sb, "; EL%d; Payload=0x%x", p.ITE.EL, p.ITE.Value)
	}
	return sb.String()
}

func (p *Packet) AppendStringTo(dst []byte) []byte {
	origLen := len(dst)
	if p.Err != nil {
		return append(dst, p.String()...)
	}
	info, ok := packetInfos[p.Type]
	if !ok {
		info = packetInfo{"I_UNKNOWN", "Unknown Packet Header"}
	}
	dst = append(dst, info.name...)
	dst = append(dst, " : "...)
	dst = append(dst, info.desc...)
	switch p.Type {
	case PktAddrCtxtL32IS0, PktAddrCtxtL32IS1:
		dst = append(dst, "; Addr="...)
		dst = appendTraceValue32(dst, p.Addr)
		dst = append(dst, "; "...)
		return p.appendContextString(dst)
	case PktAddrCtxtL64IS0, PktAddrCtxtL64IS1:
		dst = append(dst, "; Addr="...)
		dst = appendTraceValue(dst, p.Addr)
		dst = append(dst, "; "...)
		return p.appendContextString(dst)
	case PktAddrL32IS0, PktAddrL32IS1, PktSrcAddrL32IS0, PktSrcAddrL32IS1:
		dst = append(dst, "; Addr="...)
		dst = appendTraceValue32(dst, p.Addr)
		return append(dst, "; "...)
	case PktAddrL64IS0, PktAddrL64IS1, PktSrcAddrL64IS0, PktSrcAddrL64IS1:
		dst = append(dst, "; Addr="...)
		dst = appendTraceValue(dst, p.Addr)
		return append(dst, "; "...)
	case PktAddrSIS0, PktAddrSIS1, PktSrcAddrSIS0, PktSrcAddrSIS1:
		dst = append(dst, "; Addr="...)
		return appendTraceValue(dst, p.Addr)
	case PktAddrMatch, PktSrcAddrMatch:
		dst = append(dst, ", ["...)
		dst = strconv.AppendUint(dst, uint64(p.AddrMatchIdx), 10)
		dst = append(dst, "]; Addr="...)
		dst = appendTraceValueNoPktBits(dst, p.Addr)
		return append(dst, "; "...)
	case PktAtomF1, PktAtomF2, PktAtomF3, PktAtomF4, PktAtomF5, PktAtomF6:
		dst = append(dst, "; "...)
		return appendAtom(dst, p.Atom)
	case PktQ:
		if p.Q.CountPresent {
			dst = append(dst, "; Count("...)
			dst = strconv.AppendUint(dst, uint64(p.Q.Count), 10)
			dst = append(dst, ')')
		} else {
			dst = append(dst, "; Count(Unknown)"...)
		}
		if p.Q.AddrPresent || p.Q.AddrMatch {
			dst = append(dst, "; Addr="...)
			dst = appendTraceValue(dst, p.Addr)
		}
		return dst
	default:
		return append(dst[:origLen], p.String()...)
	}
}

func isAtomPacket(t PacketType) bool {
	return t == PktAtomF1 || t == PktAtomF2 || t == PktAtomF3 || t == PktAtomF4 || t == PktAtomF5 || t == PktAtomF6
}

func (p *Packet) exceptionString() string {
	arV8Excep := []string{
		"PE Reset", "Debug Halt", "Call", "Trap",
		"System Error", "Reserved", "Inst Debug", "Data Debug",
		"Reserved", "Reserved", "Alignment", "Inst Fault",
		"Data Fault", "Reserved", "IRQ", "FIQ",
	}
	mExcep := []string{
		"Reserved", "PE Reset", "NMI", "HardFault",
		"MemManage", "BusFault", "UsageFault", "Reserved",
		"Reserved", "Reserved", "Reserved", "SVC",
		"DebugMonitor", "Reserved", "PendSV", "SysTick",
		"IRQ0", "IRQ1", "IRQ2", "IRQ3",
		"IRQ4", "IRQ5", "IRQ6", "IRQ7",
		"DebugHalt", "LazyFP Push", "Lockup", "Reserved",
		"Reserved", "Reserved", "Reserved", "Reserved",
	}

	var sb strings.Builder
	if p.Exception.MType {
		if int(p.Exception.Type) < len(mExcep) {
			fmt.Fprintf(&sb, " %s;", mExcep[p.Exception.Type])
		} else if p.Exception.Type >= 0x208 && p.Exception.Type <= 0x3EF {
			fmt.Fprintf(&sb, " IRQ%d;", p.Exception.Type-0x200)
		} else {
			sb.WriteString(" Reserved;")
		}
		if p.Exception.MFaultPending {
			sb.WriteString(" Fault Pending;")
		}
	} else if int(p.Exception.Type) < len(arV8Excep) {
		fmt.Fprintf(&sb, " %s;", arV8Excep[p.Exception.Type])
	} else {
		sb.WriteString(" Reserved;")
	}

	switch p.Exception.AddrInterp {
	case 1:
		sb.WriteString(" Ret Addr Follows;")
	case 2:
		sb.WriteString(" Ret Addr Follows, Match Prev;")
	}
	return sb.String()
}

func (p *Packet) TraceErrorPrefix(index trace.Index, id uint8) string {
	if p.RawPrefix != "" {
		return p.RawPrefix
	}
	if !errors.Is(p.Err, trace.ErrInvalidPcktHdr) || p.Type == PktReservedCfg {
		return ""
	}
	return fmt.Sprintf("PKTP_ETMV4I_%04x : 0x0014 (OCSD_ERR_INVALID_PCKT_HDR) [Invalid packet header]; TrcIdx=%d; CS ID=%02X; ", id, index, id)
}

func (p *Packet) contextString() string {
	if !p.Context.Updated && !p.Context.UpdatedC && !p.Context.UpdatedV {
		return "Ctxt: Same"
	}
	state := "AArch32, "
	if p.Context.SF {
		state = "AArch64,"
	}
	sec := "S"
	if p.Context.NSE {
		if p.Context.NS {
			sec = "Realm"
		} else {
			sec = "Root"
		}
	} else if p.Context.NS {
		sec = "NS"
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "Ctxt: %sEL%d, %s; ", state, p.Context.EL, sec)
	if p.Context.UpdatedC {
		fmt.Fprintf(&sb, "CID=0x%08x; ", p.Context.CtxtID)
	}
	if p.Context.UpdatedV {
		fmt.Fprintf(&sb, "VMID=0x%04x; ", p.Context.VMID)
	}
	return sb.String()
}

func (p *Packet) appendContextString(dst []byte) []byte {
	if !p.Context.Updated && !p.Context.UpdatedC && !p.Context.UpdatedV {
		return append(dst, "Ctxt: Same"...)
	}
	state := "AArch32, "
	if p.Context.SF {
		state = "AArch64,"
	}
	sec := "S"
	if p.Context.NSE {
		if p.Context.NS {
			sec = "Realm"
		} else {
			sec = "Root"
		}
	} else if p.Context.NS {
		sec = "NS"
	}
	dst = append(dst, "Ctxt: "...)
	dst = append(dst, state...)
	dst = append(dst, "EL"...)
	dst = strconv.AppendUint(dst, uint64(p.Context.EL), 10)
	dst = append(dst, ", "...)
	dst = append(dst, sec...)
	dst = append(dst, "; "...)
	if p.Context.UpdatedC {
		dst = append(dst, "CID=0x"...)
		dst = appendUpperHex(dst, uint64(p.Context.CtxtID), 8)
		dst = append(dst, "; "...)
	}
	if p.Context.UpdatedV {
		dst = append(dst, "VMID=0x"...)
		dst = appendUpperHex(dst, uint64(p.Context.VMID), 4)
		dst = append(dst, "; "...)
	}
	return dst
}

func atomString(a Atom) string {
	var sb strings.Builder
	sb.Grow(int(a.Num))
	bits := a.EnBits
	for i := 0; i < int(a.Num); i++ {
		if bits&1 != 0 {
			sb.WriteByte('E')
		} else {
			sb.WriteByte('N')
		}
		bits >>= 1
	}
	return sb.String()
}

func appendAtom(dst []byte, a Atom) []byte {
	bits := a.EnBits
	for i := 0; i < int(a.Num); i++ {
		if bits&1 != 0 {
			dst = append(dst, 'E')
		} else {
			dst = append(dst, 'N')
		}
		bits >>= 1
	}
	return dst
}

func formatTraceValue(a Address) string {
	return formatTraceValueWithPktBitsLimit(a, true, a.Size)
}

func formatTraceValue32(a Address) string {
	return formatTraceValueWithPktBitsLimit(a, true, 32)
}

func formatTraceValueNoPktBits(a Address) string {
	return formatTraceValueWithPktBitsLimit(a, false, 0)
}

func formatTraceValueWithPktBitsLimit(a Address, showPktBits bool, limit int) string {
	return string(appendTraceValueWithPktBitsLimit(nil, a, showPktBits, limit))
}

func appendTraceValue(dst []byte, a Address) []byte {
	return appendTraceValueWithPktBitsLimit(dst, a, true, a.Size)
}

func appendTraceValue32(dst []byte, a Address) []byte {
	return appendTraceValueWithPktBitsLimit(dst, a, true, 32)
}

func appendTraceValueNoPktBits(dst []byte, a Address) []byte {
	return appendTraceValueWithPktBitsLimit(dst, a, false, 0)
}

func appendTraceValueWithPktBitsLimit(dst []byte, a Address, showPktBits bool, limit int) []byte {
	totalBits := a.Size
	if totalBits == 0 {
		totalBits = 64
	}
	validBits := min(a.ValidBits, totalBits)
	numHex := (totalBits + 3) / 4
	validHex := 0
	if validBits > 0 {
		validHex = (validBits + 3) / 4
	}
	dst = append(dst, "0x"...)
	for i := validHex; i < numHex; i++ {
		dst = append(dst, '?')
	}
	if validHex > 0 {
		dst = appendUpperHex(dst, uint64(a.Val)&trace.BitMask(validBits), validHex)
	}
	if validBits < totalBits {
		dst = append(dst, " ("...)
		dst = strconv.AppendInt(dst, int64(validBits-1), 10)
		dst = append(dst, ":0)"...)
	}
	if showPktBits && a.PktBits > 0 && a.PktBits < limit {
		dst = append(dst, " ~[0x"...)
		dst = appendUpperHex(dst, uint64(a.Val)&trace.BitMask(a.PktBits), 0)
		dst = append(dst, ']')
	}
	return dst
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
