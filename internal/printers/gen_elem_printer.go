package printers

import (
	"bytes"
	"coresight/trace"
	"encoding/binary"
	"fmt"
	"io"
	"strconv"
	"strings"
)

type GenericElementPrinter struct {
	writer       io.Writer
	muted        bool
	idPrintMute  bool
	collectStats bool
	packetCounts map[trace.GenElemType]int
	idFilter     map[uint8]bool
	formatter    ElementFormatter
	sb           bytes.Buffer
}

// NewGenericElementPrinter returns a printer for OpenCSD-style generic trace elements.
func NewGenericElementPrinter(writer io.Writer) *GenericElementPrinter {
	if writer == nil {
		writer = io.Discard
	}
	return &GenericElementPrinter{
		writer:       writer,
		packetCounts: make(map[trace.GenElemType]int),
	}
}

func (p *GenericElementPrinter) SetMute(mute bool)     { p.muted = mute }
func (p *GenericElementPrinter) IsMuted() bool         { return p.muted }
func (p *GenericElementPrinter) MuteIDPrint(mute bool) { p.idPrintMute = mute }
func (p *GenericElementPrinter) IDPrintMuted() bool    { return p.idPrintMute }
func (p *GenericElementPrinter) SetCollectStats()      { p.collectStats = true }

func (p *GenericElementPrinter) PrintElement(elem trace.Element) {
	if p.idFilter != nil && !p.idFilter[elem.TraceID] {
		return
	}

	if p.collectStats {
		p.packetCounts[elem.ElemType]++
	}

	if p.muted {
		return
	}

	p.sb.Reset()
	p.sb.WriteString(elem.Diagnostic)
	if !p.idPrintMute {
		p.sb.WriteString("Idx:")
		var buf [24]byte
		p.sb.Write(strconv.AppendUint(buf[:0], uint64(elem.Index), 10))
		p.sb.WriteString("; ID:")
		p.sb.Write(strconv.AppendUint(buf[:0], uint64(elem.TraceID), 16))
		p.sb.WriteString("; ")
	}
	p.formatter.FormatElementTo(&p.sb, elem)
	p.sb.WriteByte('\n')
	_, _ = p.sb.WriteTo(p.writer)
}

func (p *GenericElementPrinter) PrintStats() {
	var sb strings.Builder
	sb.WriteString("Generic Packets processed:-\n")
	for typ := trace.GenElemUnknown; typ <= trace.GenElemCustom; typ++ {
		fmt.Fprintf(&sb, "%s : %d\n", p.formatter.GetElemName(typ), p.packetCounts[typ])
	}
	sb.WriteString("\n\n")
	io.WriteString(p.writer, sb.String())
}

// SetIDFilter configures the printer to only output elements for specific trace IDs.
// Passing a nil or empty list allows all IDs.
func (p *GenericElementPrinter) SetIDFilter(idList []uint8) {
	if len(idList) == 0 {
		p.idFilter = nil
		return
	}
	p.idFilter = make(map[uint8]bool, len(idList))
	for _, id := range idList {
		p.idFilter[id] = true
	}
}

type ElementFormatter struct{}

var elemDescs = map[trace.GenElemType]string{
	trace.GenElemUnknown:         "OCSD_GEN_TRC_ELEM_UNKNOWN",
	trace.GenElemNoSync:          "OCSD_GEN_TRC_ELEM_NO_SYNC",
	trace.GenElemTraceOn:         "OCSD_GEN_TRC_ELEM_TRACE_ON",
	trace.GenElemEOTrace:         "OCSD_GEN_TRC_ELEM_EO_TRACE",
	trace.GenElemPeContext:       "OCSD_GEN_TRC_ELEM_PE_CONTEXT",
	trace.GenElemInstrRange:      "OCSD_GEN_TRC_ELEM_INSTR_RANGE",
	trace.GenElemIRangeNopath:    "OCSD_GEN_TRC_ELEM_I_RANGE_NOPATH",
	trace.GenElemAddrNacc:        "OCSD_GEN_TRC_ELEM_ADDR_NACC",
	trace.GenElemAddrUnknown:     "OCSD_GEN_TRC_ELEM_ADDR_UNKNOWN",
	trace.GenElemException:       "OCSD_GEN_TRC_ELEM_EXCEPTION",
	trace.GenElemExceptionRet:    "OCSD_GEN_TRC_ELEM_EXCEPTION_RET",
	trace.GenElemTimestamp:       "OCSD_GEN_TRC_ELEM_TIMESTAMP",
	trace.GenElemCycleCount:      "OCSD_GEN_TRC_ELEM_CYCLE_COUNT",
	trace.GenElemEvent:           "OCSD_GEN_TRC_ELEM_EVENT",
	trace.GenElemSWTrace:         "OCSD_GEN_TRC_ELEM_SWTRACE",
	trace.GenElemSyncMarker:      "OCSD_GEN_TRC_ELEM_SYNC_MARKER",
	trace.GenElemMemTrans:        "OCSD_GEN_TRC_ELEM_MEMTRANS",
	trace.GenElemInstrumentation: "OCSD_GEN_TRC_ELEM_INSTRUMENTATION",
	trace.GenElemITMTrace:        "OCSD_GEN_TRC_ELEM_ITMTRACE",
	trace.GenElemCustom:          "OCSD_GEN_TRC_ELEM_CUSTOM",
}

var instrTypeNames = map[trace.InstrType]string{
	trace.InstrOther:      "--- ",
	trace.InstrBr:         "BR  ",
	trace.InstrBrIndirect: "iBR ",
	trace.InstrIsb:        "ISB ",
	trace.InstrDsbDmb:     "DSB.DMB",
	trace.InstrWfiWfe:     "WFI.WFE",
	trace.InstrTstart:     "TSTART",
}

var instrSubtypeNames = map[trace.InstrSubtype]string{
	trace.SInstrNone:         "--- ",
	trace.SInstrBrLink:       "b+link ",
	trace.SInstrV8Ret:        "A64:ret ",
	trace.SInstrV8Eret:       "A64:eret ",
	trace.SInstrV7ImpliedRet: "V7:impl ret",
}

var traceOnNames = map[trace.TraceOnReason]string{
	trace.TraceOnNormal:   "begin or filter",
	trace.TraceOnOverflow: "overflow",
	trace.TraceOnExDebug:  "debug restart",
}

var isaNames = map[trace.ISA]string{
	trace.ISAArm:     "A32",
	trace.ISAThumb2:  "T32",
	trace.ISAAArch64: "A64",
	trace.ISATee:     "TEE",
	trace.ISAJazelle: "Jaz",
	trace.ISACustom:  "Cst",
	trace.ISAUnknown: "Unk",
}

var unsyncNames = map[trace.UnsyncInfo]string{
	trace.UnsyncUnknown:      "undefined",
	trace.UnsyncInitDecoder:  "init-decoder",
	trace.UnsyncResetDecoder: "reset-decoder",
	trace.UnsyncOverflow:     "overflow",
	trace.UnsyncDiscard:      "discard",
	trace.UnsyncBadPacket:    "bad-packet",
	trace.UnsyncBadImage:     "bad-program-image",
	trace.UnsyncEOT:          "end-of-trace",
}

var transTypeNames = map[trace.MemoryTransaction]string{
	trace.MemTransTraceInit: "Init",
	trace.MemTransStart:     "Start",
	trace.MemTransCommit:    "Commit",
	trace.MemTransFail:      "Fail",
}

var markerTypeNames = map[trace.TraceSyncMarker]string{
	trace.ElemMarkerTS: "Timestamp marker",
}

var itmLocalTimestampNames = map[trace.SWTItmType]string{
	trace.TSSync:       "TS Sync",
	trace.TSDelay:      "TS Delay",
	trace.TSPKTDelay:   "Packet Delay",
	trace.TSPKTTSDelay: "TS and Packet Delay",
}

func (f *ElementFormatter) FormatElementTo(sb *bytes.Buffer, e trace.Element) {
	desc, ok := elemDescs[e.ElemType]
	if !ok {
		sb.WriteString("OCSD_GEN_TRC_ELEM??: index out of range.")
		return
	}

	sb.WriteString(desc)
	sb.WriteByte('(')
	f.writeElementPayload(sb, e)
	if e.HasCycleCount {
		sb.WriteString(" [CC=")
		var buf [24]byte
		sb.Write(strconv.AppendUint(buf[:0], uint64(e.CycleCount), 10))
		sb.WriteString("]; ")
	}
	sb.WriteByte(')')
}

func (f *ElementFormatter) FormatElement(e trace.Element) string {
	var sb bytes.Buffer
	f.FormatElementTo(&sb, e)
	return sb.String()
}

func (f *ElementFormatter) GetElemName(t trace.GenElemType) string {
	if name, ok := elemDescs[t]; ok {
		return name
	}
	return elemDescs[trace.GenElemUnknown]
}

func (f *ElementFormatter) writeElementPayload(sb *bytes.Buffer, e trace.Element) {
	switch e.ElemType {
	case trace.GenElemInstrRange:
		f.writeInstrRange(sb, e)
	case trace.GenElemAddrNacc:
		space := trace.MemSpaceAcc(e.Payload.ExceptionNum)
		sb.WriteString(" 0x")
		sb.WriteString(strconv.FormatUint(uint64(e.StartAddr), 16))
		sb.WriteString("; Memspace [0x")
		sb.WriteString(strconv.FormatUint(uint64(e.Payload.ExceptionNum), 16))
		sb.WriteByte(':')
		sb.WriteString(space.String())
		sb.WriteString("] ")
	case trace.GenElemIRangeNopath:
		sb.WriteString("first 0x")
		sb.WriteString(strconv.FormatUint(uint64(e.StartAddr), 16))
		sb.WriteString(":[next 0x")
		sb.WriteString(strconv.FormatUint(uint64(e.EndAddr), 16))
		sb.WriteString("] num_i(")
		sb.WriteString(strconv.FormatUint(uint64(e.Payload.NumInstrRange), 10))
		sb.WriteString(") ")
	case trace.GenElemException:
		f.writeException(sb, e)
	case trace.GenElemPeContext:
		f.writePEContext(sb, e)
	case trace.GenElemTraceOn:
		if s, ok := traceOnNames[e.Payload.TraceOnReason]; ok {
			sb.WriteString(" [")
			sb.WriteString(s)
			sb.WriteByte(']')
		}
	case trace.GenElemTimestamp:
		sb.WriteString(" [ TS=0x")
		var buf [24]byte
		b := strconv.AppendUint(buf[:0], e.Timestamp, 16)
		for range 12 - len(b) {
			sb.WriteByte('0')
		}
		sb.Write(b)
		sb.WriteString("]; ")
	case trace.GenElemSWTrace:
		f.printSWInfoPkt(sb, e)
	case trace.GenElemITMTrace:
		f.printSWInfoPktItm(sb, e)
	case trace.GenElemEvent:
		f.writeEvent(sb, e)
	case trace.GenElemEOTrace, trace.GenElemNoSync:
		if s, ok := unsyncNames[e.Payload.UnsyncEOTInfo]; ok {
			sb.WriteString(" [")
			sb.WriteString(s)
			sb.WriteByte(']')
		}
	case trace.GenElemSyncMarker:
		marker := e.Payload.SyncMarker
		if s, ok := markerTypeNames[marker.Type]; ok {
			sb.WriteString(" [")
			sb.WriteString(s)
			sb.WriteString("(0x")
			var buf [24]byte
			b := strconv.AppendUint(buf[:0], uint64(marker.Value), 16)
			for range 8 - len(b) {
				sb.WriteByte('0')
			}
			sb.Write(b)
			sb.WriteString(")]")
		}
	case trace.GenElemMemTrans:
		if s, ok := transTypeNames[e.Payload.MemTrans]; ok {
			sb.WriteString(s)
		}
	case trace.GenElemInstrumentation:
		sb.WriteString("EL")
		sb.WriteString(strconv.FormatUint(uint64(e.Payload.SWIte.EL), 10))
		sb.WriteString("; 0x")
		var buf [24]byte
		b := strconv.AppendUint(buf[:0], e.Payload.SWIte.Value, 16)
		for range 16 - len(b) {
			sb.WriteByte('0')
		}
		sb.Write(b)
	}
}

func (f *ElementFormatter) writeInstrRange(sb *bytes.Buffer, e trace.Element) {
	var buf [24]byte
	sb.WriteString("exec range=0x")
	sb.Write(strconv.AppendUint(buf[:0], uint64(e.StartAddr), 16))
	sb.WriteString(":[0x")
	sb.Write(strconv.AppendUint(buf[:0], uint64(e.EndAddr), 16))
	sb.WriteString("] num_i(")
	sb.Write(strconv.AppendUint(buf[:0], uint64(e.Payload.NumInstrRange), 10))
	sb.WriteString(") last_sz(")
	sb.Write(strconv.AppendUint(buf[:0], uint64(e.LastInstrSize), 10))
	sb.WriteString(") (ISA=")
	sb.WriteString(f.isaName(e.ISA))
	sb.WriteString(") ")
	if e.LastInstrExecuted {
		sb.WriteString("E ")
	} else {
		sb.WriteString("N ")
	}
	if s, ok := instrTypeNames[e.LastInstrType]; ok {
		sb.WriteString(s)
	}
	if e.LastInstrSubtype != trace.SInstrNone {
		if s, ok := instrSubtypeNames[e.LastInstrSubtype]; ok {
			sb.WriteString(s)
		}
	}
	if e.LastInstrCond {
		sb.WriteString(" <cond>")
	}
}

func (f *ElementFormatter) writeException(sb *bytes.Buffer, e trace.Element) {
	if e.ExceptionRetAddr {
		sb.WriteString("pref ret addr:0x")
		sb.WriteString(strconv.FormatUint(uint64(e.EndAddr), 16))
		if e.ExceptionRetAddrBrTgt {
			sb.WriteString(" [addr also prev br tgt]")
		}
		sb.WriteString("; ")
	}
	sb.WriteString("excep num (0x")
	if e.Payload.ExceptionNum < 0x10 {
		sb.WriteByte('0')
	}
	sb.WriteString(strconv.FormatUint(uint64(e.Payload.ExceptionNum), 16))
	sb.WriteString(") ")
}

func (f *ElementFormatter) writePEContext(sb *bytes.Buffer, e trace.Element) {
	sb.WriteString("(ISA=")
	sb.WriteString(f.isaName(e.ISA))
	sb.WriteString(") ")
	if e.Context.ExceptionLevel > trace.ELUnknown && e.Context.ELValid {
		sb.WriteString("EL")
		sb.WriteString(strconv.FormatUint(uint64(e.Context.ExceptionLevel), 10))
	}
	sb.WriteString(f.securityLevelName(e.Context.SecurityLevel))
	if e.Context.Bits64 {
		sb.WriteString("64-bit; ")
	} else {
		sb.WriteString("32-bit; ")
	}
	if e.Context.VMIDValid {
		sb.WriteString("VMID=0x")
		sb.WriteString(strconv.FormatUint(uint64(e.Context.VMID), 16))
		sb.WriteString("; ")
	}
	if e.Context.ContextIDValid {
		sb.WriteString("CTXTID=0x")
		sb.WriteString(strconv.FormatUint(uint64(e.Context.ContextID), 16))
		sb.WriteString("; ")
	}
}

func (f *ElementFormatter) writeEvent(sb *bytes.Buffer, e trace.Element) {
	switch e.Payload.TraceEvent.EvType {
	case trace.EventTrigger:
		sb.WriteString(" Trigger; ")
	case trace.EventNumbered:
		sb.WriteString(" Numbered:")
		sb.WriteString(strconv.FormatUint(uint64(e.Payload.TraceEvent.EvNumber), 10))
		sb.WriteString("; ")
	}
}

func (f *ElementFormatter) isaName(isa trace.ISA) string {
	if s, ok := isaNames[isa]; ok {
		return s
	}
	return isaNames[trace.ISAUnknown]
}

func (f *ElementFormatter) securityLevelName(level trace.SecLevel) string {
	switch level {
	case trace.SecSecure:
		return "S; "
	case trace.SecNonsecure:
		return "N; "
	case trace.SecRoot:
		return "Root; "
	case trace.SecRealm:
		return "Realm; "
	default:
		return ""
	}
}

func (f *ElementFormatter) printSWInfoPkt(sb *bytes.Buffer, e trace.Element) {
	info := e.Payload.SWTraceInfo
	if info.GlobalErr {
		sb.WriteString("{Global Error.}")
		return
	}

	f.writeSWTID(sb, info)
	f.writeSWTPayload(sb, e, info.PayloadPktBitsize)
	f.writeSWTFlags(sb, info, e.Timestamp)
}

func (f *ElementFormatter) writeSWTID(sb *bytes.Buffer, info trace.SWTInfo) {
	if info.IDValid {
		var buf [24]byte
		sb.WriteString(" (Ma:0x")
		if info.MasterID < 0x10 {
			sb.WriteByte('0')
		}
		sb.Write(strconv.AppendUint(buf[:0], uint64(info.MasterID), 16))
		sb.WriteString("; Ch:0x")
		if info.ChannelID < 0x10 {
			sb.WriteByte('0')
		}
		sb.Write(strconv.AppendUint(buf[:0], uint64(info.ChannelID), 16))
		sb.WriteString(") ")
		return
	}
	sb.WriteString("(Ma:0x??; Ch:0x??) ")
}

func (f *ElementFormatter) writeSWTPayload(sb *bytes.Buffer, e trace.Element, bitSize uint8) {
	if bitSize == 0 || len(e.ExtendedDataBytes) == 0 {
		return
	}

	sb.WriteString("0x")
	var buf [24]byte
	switch bitSize {
	case 4:
		b := strconv.AppendUint(buf[:0], uint64(e.ExtendedDataBytes[0]&0xF), 16)
		sb.Write(b)
	case 8:
		b := strconv.AppendUint(buf[:0], uint64(e.ExtendedDataBytes[0]), 16)
		if len(b) < 2 {
			sb.WriteByte('0')
		}
		sb.Write(b)
	case 16:
		if len(e.ExtendedDataBytes) >= 2 {
			val := binary.LittleEndian.Uint16(e.ExtendedDataBytes)
			b := strconv.AppendUint(buf[:0], uint64(val), 16)
			for range 4 - len(b) {
				sb.WriteByte('0')
			}
			sb.Write(b)
		}
	case 32:
		if len(e.ExtendedDataBytes) >= 4 {
			val := binary.LittleEndian.Uint32(e.ExtendedDataBytes)
			b := strconv.AppendUint(buf[:0], uint64(val), 16)
			for range 8 - len(b) {
				sb.WriteByte('0')
			}
			sb.Write(b)
		}
	case 64:
		if len(e.ExtendedDataBytes) >= 8 {
			val := binary.LittleEndian.Uint64(e.ExtendedDataBytes)
			b := strconv.AppendUint(buf[:0], val, 16)
			for range 16 - len(b) {
				sb.WriteByte('0')
			}
			sb.Write(b)
		}
	default:
		sb.WriteString("{Data Error : unsupported bit width.}")
	}
	sb.WriteString("; ")
}

func (f *ElementFormatter) writeSWTFlags(sb *bytes.Buffer, info trace.SWTInfo, timestamp uint64) {
	if info.MarkerPacket {
		sb.WriteString("+Mrk ")
	}
	if info.TriggerEvent {
		sb.WriteString("Trig ")
	}
	if info.HasTimestamp {
		sb.WriteString(" [ TS=0x")
		var buf [24]byte
		b := strconv.AppendUint(buf[:0], timestamp, 16)
		for range 12 - len(b) {
			sb.WriteByte('0')
		}
		sb.Write(b)
		sb.WriteString("]; ")
	}
	if info.Frequency {
		sb.WriteString("Freq")
	}
	if info.MasterErr {
		sb.WriteString("{Master Error.}")
	}
}

func (f *ElementFormatter) printSWInfoPktItm(sb *bytes.Buffer, e trace.Element) {
	itm := e.Payload.SWTItm

	if itm.Overflow != 0 {
		sb.WriteString("ITM_OVERFLOW; ")
	}

	var buf [24]byte
	switch itm.PktType {
	case trace.SWITPayload:
		sb.WriteString("ITM_SWIT (ch: 0x")
		sb.WriteString(strconv.FormatUint(uint64(itm.PayloadSrcID), 16))
		sb.WriteString("; Data: 0x")
		b := strconv.AppendUint(buf[:0], uint64(itm.Value), 16)
		for range int(itm.PayloadSize)*2 - len(b) {
			sb.WriteByte('0')
		}
		sb.Write(b)
		sb.WriteString(") ")
	case trace.DWTPayload:
		sb.WriteString("ITM_DWT (desc: 0x")
		sb.WriteString(strconv.FormatUint(uint64(itm.PayloadSrcID), 16))
		sb.WriteString("; Data: 0x")
		b := strconv.AppendUint(buf[:0], uint64(itm.Value), 16)
		for range int(itm.PayloadSize)*2 - len(b) {
			sb.WriteByte('0')
		}
		sb.Write(b)
		sb.WriteString(") ")
	case trace.TSGlobal:
		sb.WriteString("ITM_TS_GLOBAL ( TS: 0x")
		b := strconv.AppendUint(buf[:0], e.Timestamp, 16)
		for range 16 - len(b) {
			sb.WriteByte('0')
		}
		sb.Write(b)
		sb.WriteString(") ")
	}

	if desc := itmLocalTimestampNames[itm.PktType]; desc != "" {
		sb.WriteString("ITM_TS_LOCAL ( TS delta: 0x")
		b := strconv.AppendUint(buf[:0], uint64(itm.Value), 16)
		for range 8 - len(b) {
			sb.WriteByte('0')
		}
		sb.Write(b)
		sb.WriteString(", { ")
		sb.WriteString(desc)
		sb.WriteString("}; TS cumulative: 0x")
		b2 := strconv.AppendUint(buf[:0], e.Timestamp, 16)
		for range 16 - len(b2) {
			sb.WriteByte('0')
		}
		sb.Write(b2)
		sb.WriteString(") ")
	}
}
