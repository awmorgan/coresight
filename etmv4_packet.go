package coresight

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type etmv4PacketType int

const (
	pktExtension etmv4PacketType = iota
	pktTraceInfo
	etmv4PktTimestamp
	pktTraceOn
	pktFuncRet
	pktException
	pktExceptionReturn
	pktITE
	pktCycleCountF2
	pktCycleCountF1
	pktCycleCountF3
	pktNumDSMarker
	pktUnnumDSMarker
	pktCommit
	pktCancelF1
	pktCancelF1Mispred
	pktMispredict
	pktCancelF2
	pktCancelF3
	pktCondInstrF2
	pktCondFlush
	pktCondResultF4
	pktCondResultF2
	pktCondResultF3
	pktCondResultF1
	pktCondInstrF1
	pktCondInstrF3
	etmv4PktIgnore
	pktEvent
	pktContext
	pktAddrCtxtL32IS0
	pktAddrCtxtL32IS1
	pktAddrCtxtL64IS0
	pktAddrCtxtL64IS1
	pktAddrMatch
	pktAddrSIS0
	pktAddrSIS1
	pktAddrL32IS0
	pktAddrL32IS1
	pktAddrL64IS0
	pktAddrL64IS1
	pktQ
	pktSrcAddrMatch
	pktSrcAddrSIS0
	pktSrcAddrSIS1
	pktSrcAddrL32IS0
	pktSrcAddrL32IS1
	pktSrcAddrL64IS0
	pktSrcAddrL64IS1
	pktAtomF6
	pktAtomF5
	pktAtomF2
	pktAtomF4
	pktAtomF1
	pktAtomF3
	etmv4PktASync
	pktDiscard
	pktOverflow
	etmv4PktNotSync
	etmv4PktIncompleteEOT
	pktNoErrType
	pktTransStart
	pktTransCommit
	pktTransFail
	pktPEReset
	pktTSMarker
	etmv4PktBadSequence
	etmv4PktBadTraceMode
	etmv4PktReserved
	pktReservedCfg
)

type etmv4TraceInfo struct {
	Value            uint32
	CCEnabled        bool
	InTransState     bool
	Initial          bool
	SpecFieldPresent bool
}

type etmv4Context struct {
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

type etmv4Atom struct {
	EnBits uint32
	Num    uint8
}

type etmv4Address struct {
	Val       VAddr
	IS        uint8
	Size      int
	PktBits   int
	ValidBits int
}

type etmv4ExceptionInfo struct {
	Type          uint16
	AddrInterp    uint8
	MFaultPending bool
	MType         bool
}

type etmv4QInfo struct {
	Count        uint32
	CountPresent bool
	AddrPresent  bool
	AddrMatch    bool
	Type         uint8
}

type etmv4ITEInfo struct {
	EL    uint8
	Value uint64
}

type etmv4Packet struct {
	Type      etmv4PacketType
	errType   etmv4PacketType
	Err       error
	Index     Index
	IsETE     bool
	RawPrefix string

	TraceInfo     etmv4TraceInfo
	Context       etmv4Context
	Addr          etmv4Address
	Timestamp     uint64
	TSBitsChanged uint8
	CycleCount    uint32
	CCValid       bool
	Atom          etmv4Atom
	Commit        uint32
	CommitValid   bool
	Cancel        uint32
	CancelValid   bool
	CurrSpecDepth uint32
	P0Key         uint32
	CCThreshold   uint32
	Exception     etmv4ExceptionInfo
	AddrMatchIdx  uint8
	DSMVal        uint8
	EventVal      uint8
	Q             etmv4QInfo
	ITE           etmv4ITEInfo

	addrStack [3]etmv4Address
}

func (p *etmv4Packet) InitStartState() {
	*p = etmv4Packet{Type: etmv4PktNotSync, errType: pktNoErrType}
	p.Addr = etmv4Address{Size: 64, ValidBits: 64}
	for i := range p.addrStack {
		p.addrStack[i] = etmv4Address{Size: 64, ValidBits: 64}
	}
}

func (p *etmv4Packet) InitNextPacket() {
	p.Err = nil
	p.errType = pktNoErrType
	p.RawPrefix = ""
	p.CCValid = false
	p.CommitValid = false
	p.CancelValid = false
	p.Atom = etmv4Atom{}
	p.Context.Updated = false
	p.Context.UpdatedC = false
	p.Context.UpdatedV = false
	p.TraceInfo.Initial = false
	p.TraceInfo.SpecFieldPresent = false
}

func (p *etmv4Packet) updateErr(t etmv4PacketType, err error) {
	p.errType = p.Type
	p.Type = t
	p.Err = err
}

func (p *etmv4Packet) setTimestamp(value uint64, bits uint8) {
	mask := ^uint64(0)
	if bits < 64 {
		mask = (uint64(1) << bits) - 1
	}
	p.Timestamp = (p.Timestamp & ^mask) | (value & mask)
	p.TSBitsChanged = bits
}

func (p *etmv4Packet) pushAddr(addr etmv4Address) {
	p.addrStack[2] = p.addrStack[1]
	p.addrStack[1] = p.addrStack[0]
	p.addrStack[0] = addr
	p.Addr = addr
}

func (p *etmv4Packet) setAddressExactMatch(idx uint8) {
	p.AddrMatchIdx = idx
	if idx < 3 {
		p.pushAddr(p.addrStack[idx])
	}
}

func (p *etmv4Packet) IsBadPacket() bool {
	return p.Err != nil || p.Type >= etmv4PktBadSequence
}

type etmv4PacketInfo struct {
	name string
	desc string
}

var packetInfos = map[etmv4PacketType]etmv4PacketInfo{
	etmv4PktNotSync:       {"I_NOT_SYNC", "I Stream not synchronised"},
	etmv4PktIncompleteEOT: {"I_INCOMPLETE_EOT", "Incomplete packet at end of trace."},
	etmv4PktBadSequence:   {"I_BAD_SEQUENCE", "Invalid Sequence in packet."},
	etmv4PktBadTraceMode:  {"I_BAD_TRACEMODE", "Invalid Packet for trace mode."},
	etmv4PktReserved:      {"I_RESERVED", "Reserved Packet Header"},
	pktReservedCfg:        {"I_RESERVED_CFG", "Reserved header for current configuration."},
	pktExtension:          {"I_EXTENSION", "Extension packet header."},
	pktTraceInfo:          {"I_TRACE_INFO", "Trace Info."},
	etmv4PktTimestamp:     {"I_TIMESTAMP", "Timestamp."},
	pktTraceOn:            {"I_TRACE_ON", "Trace On."},
	pktFuncRet:            {"I_FUNC_RET", "V8M - function return."},
	pktException:          {"I_EXCEPT", "Exception."},
	pktExceptionReturn:    {"I_EXCEPT_RTN", "Exception Return."},
	pktITE:                {"I_ITE", "Instrumentation"},
	pktCycleCountF1:       {"I_CCNT_F1", "Cycle Count format 1."},
	pktCycleCountF2:       {"I_CCNT_F2", "Cycle Count format 2."},
	pktCycleCountF3:       {"I_CCNT_F3", "Cycle Count format 3."},
	pktNumDSMarker:        {"I_NUM_DS_MKR", "Data Synchronisation Marker - Numbered."},
	pktUnnumDSMarker:      {"I_UNNUM_DS_MKR", "Data Synchronisation Marker - Unnumbered."},
	pktCommit:             {"I_COMMIT", "Commit"},
	pktCancelF1:           {"I_CANCEL_F1", "Cancel Format 1."},
	pktCancelF1Mispred:    {"I_CANCEL_F1_MISPRED", "Cancel Format 1 + Mispredict."},
	pktMispredict:         {"I_MISPREDICT", "Mispredict."},
	pktCancelF2:           {"I_CANCEL_F2", "Cancel Format 2."},
	pktCancelF3:           {"I_CANCEL_F3", "Cancel Format 3."},
	pktCondInstrF2:        {"I_COND_I_F2", "Conditional Instruction, format 2."},
	pktCondFlush:          {"I_COND_FLUSH", "Conditional Flush."},
	pktCondResultF4:       {"I_COND_RES_F4", "Conditional Result, format 4."},
	pktCondResultF2:       {"I_COND_RES_F2", "Conditional Result, format 2."},
	pktCondResultF3:       {"I_COND_RES_F3", "Conditional Result, format 3."},
	pktCondResultF1:       {"I_COND_RES_F1", "Conditional Result, format 1."},
	pktCondInstrF1:        {"I_COND_I_F1", "Conditional Instruction, format 1."},
	pktCondInstrF3:        {"I_COND_I_F3", "Conditional Instruction, format 3."},
	etmv4PktIgnore:        {"I_IGNORE", "Ignore."},
	pktEvent:              {"I_EVENT", "Trace Event."},
	pktContext:            {"I_CTXT", "Context Packet."},
	pktAddrCtxtL32IS0:     {"I_ADDR_CTXT_L_32IS0", "Address & Context, Long, 32 bit, IS0."},
	pktAddrCtxtL32IS1:     {"I_ADDR_CTXT_L_32IS1", "Address & Context, Long, 32 bit, IS1."},
	pktAddrCtxtL64IS0:     {"I_ADDR_CTXT_L_64IS0", "Address & Context, Long, 64 bit, IS0."},
	pktAddrCtxtL64IS1:     {"I_ADDR_CTXT_L_64IS1", "Address & Context, Long, 64 bit, IS1."},
	pktAddrMatch:          {"I_ADDR_MATCH", "Exact Address Match."},
	pktAddrSIS0:           {"I_ADDR_S_IS0", "Address, Short, IS0."},
	pktAddrSIS1:           {"I_ADDR_S_IS1", "Address, Short, IS1."},
	pktAddrL32IS0:         {"I_ADDR_L_32IS0", "Address, Long, 32 bit, IS0."},
	pktAddrL32IS1:         {"I_ADDR_L_32IS1", "Address, Long, 32 bit, IS1."},
	pktAddrL64IS0:         {"I_ADDR_L_64IS0", "Address, Long, 64 bit, IS0."},
	pktAddrL64IS1:         {"I_ADDR_L_64IS1", "Address, Long, 64 bit, IS1."},
	pktQ:                  {"I_Q", "Q Packet."},
	pktSrcAddrMatch:       {"I_SRC_ADDR_MATCH", "Exact Source Address Match."},
	pktSrcAddrSIS0:        {"I_SRC_ADDR_S_IS0", "Source Address, Short, IS0."},
	pktSrcAddrSIS1:        {"I_SRC_ADDR_S_IS1", "Source Address, Short, IS1."},
	pktSrcAddrL32IS0:      {"I_SRC_ADDR_L_32IS0", "Source Address, Long, 32 bit, IS0."},
	pktSrcAddrL32IS1:      {"I_SRC_ADDR_L_32IS1", "Source Address, Long, 32 bit, IS1."},
	pktSrcAddrL64IS0:      {"I_SRC_ADDR_L_64IS0", "Source Address, Long, 64 bit, IS0."},
	pktSrcAddrL64IS1:      {"I_SRC_ADDR_L_64IS1", "Source Address, Long, 64 bit, IS1."},
	pktAtomF6:             {"I_ATOM_F6", "Atom format 6."},
	pktAtomF5:             {"I_ATOM_F5", "Atom format 5."},
	pktAtomF2:             {"I_ATOM_F2", "Atom format 2."},
	pktAtomF4:             {"I_ATOM_F4", "Atom format 4."},
	pktAtomF1:             {"I_ATOM_F1", "Atom format 1."},
	pktAtomF3:             {"I_ATOM_F3", "Atom format 3."},
	etmv4PktASync:         {"I_ASYNC", "Alignment Synchronisation."},
	pktDiscard:            {"I_DISCARD", "Discard."},
	pktOverflow:           {"I_OVERFLOW", "Overflow."},
	pktTransStart:         {"I_TRANS_ST", "Transaction Start."},
	pktTransCommit:        {"I_TRANS_COMMIT", "Transaction Commit."},
	pktTransFail:          {"I_TRANS_FAIL", "Transaction Fail."},
	pktPEReset:            {"I_PE_RESET", "PE Reset."},
	pktTSMarker:           {"I_TS_MARKER", "Timestamp Marker"},
}

func (p *etmv4Packet) String() string {
	if isAtomPacket(p.Type) && p.Err == nil {
		return string(p.AppendStringTo(nil))
	}
	info, ok := packetInfos[p.Type]
	if !ok {
		info = etmv4PacketInfo{"I_UNKNOWN", "Unknown Packet Header"}
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s : %s", info.name, info.desc)
	if p.Err != nil {
		if ei, ok := packetInfos[p.errType]; ok && (!errors.Is(p.Err, errInvalidPcktHdr) || p.Type == pktReservedCfg) {
			fmt.Fprintf(&sb, "[%s]", ei.name)
		}
		return sb.String()
	}
	switch p.Type {
	case pktTraceInfo:
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
	case etmv4PktTimestamp:
		fmt.Fprintf(&sb, "; Updated val = 0x%x", p.Timestamp)
		if p.CCValid {
			fmt.Fprintf(&sb, "; CC=0x%x", p.CycleCount)
		}
	case pktContext:
		fmt.Fprintf(&sb, "; %s", p.contextString())
	case pktAddrCtxtL32IS0, pktAddrCtxtL32IS1:
		fmt.Fprintf(&sb, "; Addr=%s; %s", formatTraceValue32(p.Addr), p.contextString())
	case pktAddrCtxtL64IS0, pktAddrCtxtL64IS1:
		fmt.Fprintf(&sb, "; Addr=%s; %s", formatTraceValue(p.Addr), p.contextString())
	case pktAddrL32IS0, pktAddrL32IS1:
		fmt.Fprintf(&sb, "; Addr=%s; ", formatTraceValue32(p.Addr))
	case pktAddrL64IS0, pktAddrL64IS1:
		fmt.Fprintf(&sb, "; Addr=%s; ", formatTraceValue(p.Addr))
	case pktAddrSIS0, pktAddrSIS1, pktSrcAddrSIS0, pktSrcAddrSIS1:
		fmt.Fprintf(&sb, "; Addr=%s", formatTraceValue(p.Addr))
	case pktSrcAddrL32IS0, pktSrcAddrL32IS1:
		fmt.Fprintf(&sb, "; Addr=%s; ", formatTraceValue32(p.Addr))
	case pktSrcAddrL64IS0, pktSrcAddrL64IS1:
		fmt.Fprintf(&sb, "; Addr=%s; ", formatTraceValue(p.Addr))
	case pktAddrMatch, pktSrcAddrMatch:
		fmt.Fprintf(&sb, ", [%d]; Addr=%s; ", p.AddrMatchIdx, formatTraceValueNoPktBits(p.Addr))
	case pktAtomF1, pktAtomF2, pktAtomF3, pktAtomF4, pktAtomF5, pktAtomF6:
		fmt.Fprintf(&sb, "; %s", atomString(p.Atom))
	case pktException:
		fmt.Fprintf(&sb, "; %s", p.exceptionString())
	case pktCycleCountF1, pktCycleCountF2, pktCycleCountF3:
		fmt.Fprintf(&sb, "; Count=0x%x", p.CycleCount)
		if p.CommitValid {
			fmt.Fprintf(&sb, "; Commit(%d)", p.Commit)
		}
	case pktCommit:
		fmt.Fprintf(&sb, "; Commit(%d)", p.Commit)
	case pktCancelF1:
		fmt.Fprintf(&sb, "; Cancel(%d)", p.Cancel)
	case pktCancelF1Mispred:
		fmt.Fprintf(&sb, "; Cancel(%d), Mispredict", p.Cancel)
	case pktMispredict:
		fmt.Fprintf(&sb, "; ")
		if p.Atom.Num != 0 {
			fmt.Fprintf(&sb, "Atom: %s, ", atomString(p.Atom))
		}
		fmt.Fprintf(&sb, "Mispredict")
	case pktCancelF2:
		fmt.Fprintf(&sb, "; ")
		if p.Atom.Num != 0 {
			fmt.Fprintf(&sb, "Atom: %s, ", atomString(p.Atom))
		}
		fmt.Fprintf(&sb, "Cancel(1), Mispredict")
	case pktCancelF3:
		fmt.Fprintf(&sb, "; ")
		if p.Atom.Num != 0 {
			fmt.Fprintf(&sb, "Atom: %s, ", atomString(p.Atom))
		}
		fmt.Fprintf(&sb, "Cancel(%d), Mispredict", p.Cancel)
	case pktQ:
		if p.Q.CountPresent {
			fmt.Fprintf(&sb, "; Count(%d)", p.Q.Count)
		} else {
			fmt.Fprintf(&sb, "; Count(Unknown)")
		}
		if p.Q.AddrPresent || p.Q.AddrMatch {
			fmt.Fprintf(&sb, "; Addr=%s", formatTraceValue(p.Addr))
		}
	case pktITE:
		fmt.Fprintf(&sb, "; EL%d; Payload=0x%x", p.ITE.EL, p.ITE.Value)
	}
	return sb.String()
}

func (p *etmv4Packet) AppendStringTo(dst []byte) []byte {
	origLen := len(dst)
	if p.Err != nil {
		return append(dst, p.String()...)
	}
	info, ok := packetInfos[p.Type]
	if !ok {
		info = etmv4PacketInfo{"I_UNKNOWN", "Unknown Packet Header"}
	}
	dst = append(dst, info.name...)
	dst = append(dst, " : "...)
	dst = append(dst, info.desc...)
	switch p.Type {
	case pktAddrCtxtL32IS0, pktAddrCtxtL32IS1:
		dst = append(dst, "; Addr="...)
		dst = appendTraceValue32(dst, p.Addr)
		dst = append(dst, "; "...)
		return p.appendContextString(dst)
	case pktAddrCtxtL64IS0, pktAddrCtxtL64IS1:
		dst = append(dst, "; Addr="...)
		dst = appendTraceValue(dst, p.Addr)
		dst = append(dst, "; "...)
		return p.appendContextString(dst)
	case pktAddrL32IS0, pktAddrL32IS1, pktSrcAddrL32IS0, pktSrcAddrL32IS1:
		dst = append(dst, "; Addr="...)
		dst = appendTraceValue32(dst, p.Addr)
		return append(dst, "; "...)
	case pktAddrL64IS0, pktAddrL64IS1, pktSrcAddrL64IS0, pktSrcAddrL64IS1:
		dst = append(dst, "; Addr="...)
		dst = appendTraceValue(dst, p.Addr)
		return append(dst, "; "...)
	case pktAddrSIS0, pktAddrSIS1, pktSrcAddrSIS0, pktSrcAddrSIS1:
		dst = append(dst, "; Addr="...)
		return appendTraceValue(dst, p.Addr)
	case pktAddrMatch, pktSrcAddrMatch:
		dst = append(dst, ", ["...)
		dst = strconv.AppendUint(dst, uint64(p.AddrMatchIdx), 10)
		dst = append(dst, "]; Addr="...)
		dst = appendTraceValueNoPktBits(dst, p.Addr)
		return append(dst, "; "...)
	case pktAtomF1, pktAtomF2, pktAtomF3, pktAtomF4, pktAtomF5, pktAtomF6:
		dst = append(dst, "; "...)
		return appendAtom(dst, p.Atom)
	case pktQ:
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

func isAtomPacket(t etmv4PacketType) bool {
	return t == pktAtomF1 || t == pktAtomF2 || t == pktAtomF3 || t == pktAtomF4 || t == pktAtomF5 || t == pktAtomF6
}

func (p *etmv4Packet) exceptionString() string {
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

func (p *etmv4Packet) TraceErrorPrefix(index Index, id uint8) string {
	if p.RawPrefix != "" {
		return p.RawPrefix
	}
	if !errors.Is(p.Err, errInvalidPcktHdr) || p.Type == pktReservedCfg {
		return ""
	}
	return fmt.Sprintf("PKTP_ETMV4I_%04x : 0x0014 (OCSD_ERR_INVALID_PCKT_HDR) [Invalid packet header]; TrcIdx=%d; CS ID=%02X; ", id, index, id)
}

func (p *etmv4Packet) contextString() string {
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

func (p *etmv4Packet) appendContextString(dst []byte) []byte {
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
		dst = etmv4AppendUpperHex(dst, uint64(p.Context.CtxtID), 8)
		dst = append(dst, "; "...)
	}
	if p.Context.UpdatedV {
		dst = append(dst, "VMID=0x"...)
		dst = etmv4AppendUpperHex(dst, uint64(p.Context.VMID), 4)
		dst = append(dst, "; "...)
	}
	return dst
}

func atomString(a etmv4Atom) string {
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

func appendAtom(dst []byte, a etmv4Atom) []byte {
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

func formatTraceValue(a etmv4Address) string {
	return formatTraceValueWithPktBitsLimit(a, true, a.Size)
}

func formatTraceValue32(a etmv4Address) string {
	return formatTraceValueWithPktBitsLimit(a, true, 32)
}

func formatTraceValueNoPktBits(a etmv4Address) string {
	return formatTraceValueWithPktBitsLimit(a, false, 0)
}

func formatTraceValueWithPktBitsLimit(a etmv4Address, showPktBits bool, limit int) string {
	return string(appendTraceValueWithPktBitsLimit(nil, a, showPktBits, limit))
}

func appendTraceValue(dst []byte, a etmv4Address) []byte {
	return appendTraceValueWithPktBitsLimit(dst, a, true, a.Size)
}

func appendTraceValue32(dst []byte, a etmv4Address) []byte {
	return appendTraceValueWithPktBitsLimit(dst, a, true, 32)
}

func appendTraceValueNoPktBits(dst []byte, a etmv4Address) []byte {
	return appendTraceValueWithPktBitsLimit(dst, a, false, 0)
}

func appendTraceValueWithPktBitsLimit(dst []byte, a etmv4Address, showPktBits bool, limit int) []byte {
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
		dst = etmv4AppendUpperHex(dst, uint64(a.Val)&bitMask(validBits), validHex)
	}
	if validBits < totalBits {
		dst = append(dst, " ("...)
		dst = strconv.AppendInt(dst, int64(validBits-1), 10)
		dst = append(dst, ":0)"...)
	}
	if showPktBits && a.PktBits > 0 && a.PktBits < limit {
		dst = append(dst, " ~[0x"...)
		dst = etmv4AppendUpperHex(dst, uint64(a.Val)&bitMask(a.PktBits), 0)
		dst = append(dst, ']')
	}
	return dst
}

func etmv4AppendUpperHex(dst []byte, value uint64, minWidth int) []byte {
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
