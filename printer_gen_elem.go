package coresight

import (
	"bytes"
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
	packetCounts map[GenElemType]int
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
		packetCounts: make(map[GenElemType]int),
	}
}

func (p *GenericElementPrinter) SetMute(mute bool)     { p.muted = mute }
func (p *GenericElementPrinter) IsMuted() bool         { return p.muted }
func (p *GenericElementPrinter) MuteIDPrint(mute bool) { p.idPrintMute = mute }
func (p *GenericElementPrinter) IDPrintMuted() bool    { return p.idPrintMute }
func (p *GenericElementPrinter) SetCollectStats()      { p.collectStats = true }

func (p *GenericElementPrinter) PrintElement(elem Element) {
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
	for typ := GenElemUnknown; typ <= GenElemCustom; typ++ {
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

var elemDescs = [...]string{
	GenElemUnknown:         "OCSD_GEN_TRC_ELEM_UNKNOWN",
	GenElemNoSync:          "OCSD_GEN_TRC_ELEM_NO_SYNC",
	GenElemTraceOn:         "OCSD_GEN_TRC_ELEM_TRACE_ON",
	GenElemEOTrace:         "OCSD_GEN_TRC_ELEM_EO_TRACE",
	GenElemPeContext:       "OCSD_GEN_TRC_ELEM_PE_CONTEXT",
	GenElemInstrRange:      "OCSD_GEN_TRC_ELEM_INSTR_RANGE",
	GenElemIRangeNopath:    "OCSD_GEN_TRC_ELEM_I_RANGE_NOPATH",
	GenElemAddrNacc:        "OCSD_GEN_TRC_ELEM_ADDR_NACC",
	GenElemAddrUnknown:     "OCSD_GEN_TRC_ELEM_ADDR_UNKNOWN",
	GenElemException:       "OCSD_GEN_TRC_ELEM_EXCEPTION",
	GenElemExceptionRet:    "OCSD_GEN_TRC_ELEM_EXCEPTION_RET",
	GenElemTimestamp:       "OCSD_GEN_TRC_ELEM_TIMESTAMP",
	GenElemCycleCount:      "OCSD_GEN_TRC_ELEM_CYCLE_COUNT",
	GenElemEvent:           "OCSD_GEN_TRC_ELEM_EVENT",
	GenElemSWTrace:         "OCSD_GEN_TRC_ELEM_SWTRACE",
	GenElemSyncMarker:      "OCSD_GEN_TRC_ELEM_SYNC_MARKER",
	GenElemMemTrans:        "OCSD_GEN_TRC_ELEM_MEMTRANS",
	GenElemInstrumentation: "OCSD_GEN_TRC_ELEM_INSTRUMENTATION",
	GenElemITMTrace:        "OCSD_GEN_TRC_ELEM_ITMTRACE",
	GenElemCustom:          "OCSD_GEN_TRC_ELEM_CUSTOM",
}

var instrTypeNames = [...]string{
	InstrOther:      "--- ",
	InstrBr:         "BR  ",
	InstrBrIndirect: "iBR ",
	InstrIsb:        "ISB ",
	InstrDsbDmb:     "DSB.DMB",
	InstrWfiWfe:     "WFI.WFE",
	InstrTstart:     "TSTART",
}

var instrSubtypeNames = [...]string{
	SInstrNone:         "--- ",
	SInstrBrLink:       "b+link ",
	SInstrV8Ret:        "A64:ret ",
	SInstrV8Eret:       "A64:eret ",
	SInstrV7ImpliedRet: "V7:impl ret",
}

var traceOnNames = [...]string{
	TraceOnNormal:   "begin or filter",
	TraceOnOverflow: "overflow",
	TraceOnExDebug:  "debug restart",
}

var isaNames = [...]string{
	ISAArm:     "A32",
	ISAThumb2:  "T32",
	ISAAArch64: "A64",
	ISATee:     "TEE",
	ISAJazelle: "Jaz",
	ISACustom:  "Cst",
	ISAUnknown: "Unk",
}

var unsyncNames = [...]string{
	UnsyncUnknown:      "undefined",
	UnsyncInitDecoder:  "init-decoder",
	UnsyncResetDecoder: "reset-decoder",
	UnsyncOverflow:     "overflow",
	UnsyncDiscard:      "discard",
	UnsyncBadPacket:    "bad-packet",
	UnsyncBadImage:     "bad-program-image",
	UnsyncEOT:          "end-of-trace",
}

var transTypeNames = [...]string{
	MemTransTraceInit: "Init",
	MemTransStart:     "Start",
	MemTransCommit:    "Commit",
	MemTransFail:      "Fail",
}

var markerTypeNames = [...]string{
	ElemMarkerTS: "Timestamp marker",
}

var itmLocalTimestampNames = [...]string{
	TSSync:       "TS Sync",
	TSDelay:      "TS Delay",
	TSPKTDelay:   "Packet Delay",
	TSPKTTSDelay: "TS and Packet Delay",
}

func (f *ElementFormatter) FormatElementTo(sb *bytes.Buffer, e Element) {
	if e.ElemType >= GenElemType(len(elemDescs)) {
		sb.WriteString("OCSD_GEN_TRC_ELEM??: index out of range.")
		return
	}
	desc := elemDescs[e.ElemType]

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

func (f *ElementFormatter) FormatElement(e Element) string {
	var sb bytes.Buffer
	f.FormatElementTo(&sb, e)
	return sb.String()
}

func (f *ElementFormatter) GetElemName(t GenElemType) string {
	if t < GenElemType(len(elemDescs)) {
		return elemDescs[t]
	}
	return elemDescs[GenElemUnknown]
}

func (f *ElementFormatter) writeElementPayload(sb *bytes.Buffer, e Element) {
	switch e.ElemType {
	case GenElemInstrRange:
		f.writeInstrRange(sb, e)
	case GenElemAddrNacc:
		space := MemSpaceAcc(e.Payload.ExceptionNum)
		sb.WriteString(" 0x")
		sb.WriteString(strconv.FormatUint(uint64(e.StartAddr), 16))
		sb.WriteString("; Memspace [0x")
		sb.WriteString(strconv.FormatUint(uint64(e.Payload.ExceptionNum), 16))
		sb.WriteByte(':')
		sb.WriteString(space.String())
		sb.WriteString("] ")
	case GenElemIRangeNopath:
		sb.WriteString("first 0x")
		sb.WriteString(strconv.FormatUint(uint64(e.StartAddr), 16))
		sb.WriteString(":[next 0x")
		sb.WriteString(strconv.FormatUint(uint64(e.EndAddr), 16))
		sb.WriteString("] num_i(")
		sb.WriteString(strconv.FormatUint(uint64(e.Payload.NumInstrRange), 10))
		sb.WriteString(") ")
	case GenElemException:
		f.writeException(sb, e)
	case GenElemPeContext:
		f.writePEContext(sb, e)
	case GenElemTraceOn:
		if e.Payload.TraceOnReason < TraceOnReason(len(traceOnNames)) {
			sb.WriteString(" [")
			sb.WriteString(traceOnNames[e.Payload.TraceOnReason])
			sb.WriteByte(']')
		}
	case GenElemTimestamp:
		sb.WriteString(" [ TS=0x")
		var buf [24]byte
		b := strconv.AppendUint(buf[:0], e.Timestamp, 16)
		for range 12 - len(b) {
			sb.WriteByte('0')
		}
		sb.Write(b)
		sb.WriteString("]; ")
	case GenElemSWTrace:
		f.printSWInfoPkt(sb, e)
	case GenElemITMTrace:
		f.printSWInfoPktItm(sb, e)
	case GenElemEvent:
		f.writeEvent(sb, e)
	case GenElemEOTrace, GenElemNoSync:
		if e.Payload.UnsyncEOTInfo < UnsyncInfo(len(unsyncNames)) {
			sb.WriteString(" [")
			sb.WriteString(unsyncNames[e.Payload.UnsyncEOTInfo])
			sb.WriteByte(']')
		}
	case GenElemSyncMarker:
		marker := e.Payload.SyncMarker
		if marker.Type < TraceSyncMarker(len(markerTypeNames)) {
			sb.WriteString(" [")
			sb.WriteString(markerTypeNames[marker.Type])
			sb.WriteString("(0x")
			var buf [24]byte
			b := strconv.AppendUint(buf[:0], uint64(marker.Value), 16)
			for range 8 - len(b) {
				sb.WriteByte('0')
			}
			sb.Write(b)
			sb.WriteString(")]")
		}
	case GenElemMemTrans:
		if e.Payload.MemTrans < MemoryTransaction(len(transTypeNames)) {
			sb.WriteString(transTypeNames[e.Payload.MemTrans])
		}
	case GenElemInstrumentation:
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

func (f *ElementFormatter) writeInstrRange(sb *bytes.Buffer, e Element) {
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
	if e.LastInstrType < InstrType(len(instrTypeNames)) {
		sb.WriteString(instrTypeNames[e.LastInstrType])
	}
	if e.LastInstrSubtype != SInstrNone {
		if e.LastInstrSubtype < InstrSubtype(len(instrSubtypeNames)) {
			sb.WriteString(instrSubtypeNames[e.LastInstrSubtype])
		}
	}
	if e.LastInstrCond {
		sb.WriteString(" <cond>")
	}
}

func (f *ElementFormatter) writeException(sb *bytes.Buffer, e Element) {
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

func (f *ElementFormatter) writePEContext(sb *bytes.Buffer, e Element) {
	sb.WriteString("(ISA=")
	sb.WriteString(f.isaName(e.ISA))
	sb.WriteString(") ")
	if e.Context.ExceptionLevel > ELUnknown && e.Context.ELValid {
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

func (f *ElementFormatter) writeEvent(sb *bytes.Buffer, e Element) {
	switch e.Payload.TraceEvent.EvType {
	case EventTrigger:
		sb.WriteString(" Trigger; ")
	case EventNumbered:
		sb.WriteString(" Numbered:")
		sb.WriteString(strconv.FormatUint(uint64(e.Payload.TraceEvent.EvNumber), 10))
		sb.WriteString("; ")
	}
}

func (f *ElementFormatter) isaName(isa ISA) string {
	if isa < ISA(len(isaNames)) {
		return isaNames[isa]
	}
	return isaNames[ISAUnknown]
}

func (f *ElementFormatter) securityLevelName(level SecLevel) string {
	switch level {
	case SecSecure:
		return "S; "
	case SecNonsecure:
		return "N; "
	case SecRoot:
		return "Root; "
	case SecRealm:
		return "Realm; "
	default:
		return ""
	}
}

func (f *ElementFormatter) printSWInfoPkt(sb *bytes.Buffer, e Element) {
	info := e.Payload.SWTraceInfo
	if info.GlobalErr {
		sb.WriteString("{Global Error.}")
		return
	}

	f.writeSWTID(sb, info)
	f.writeSWTPayload(sb, e, info.PayloadPktBitsize)
	f.writeSWTFlags(sb, info, e.Timestamp)
}

func (f *ElementFormatter) writeSWTID(sb *bytes.Buffer, info SWTInfo) {
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

func (f *ElementFormatter) writeSWTPayload(sb *bytes.Buffer, e Element, bitSize uint8) {
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

func (f *ElementFormatter) writeSWTFlags(sb *bytes.Buffer, info SWTInfo, timestamp uint64) {
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

func (f *ElementFormatter) printSWInfoPktItm(sb *bytes.Buffer, e Element) {
	itm := e.Payload.SWTItm
 
	if itm.Overflow != 0 {
		sb.WriteString("ITM_OVERFLOW; ")
	}
 
	var buf [24]byte
	switch itm.PktType {
	case SWITPayload:
		sb.WriteString("ITM_SWIT (ch: 0x")
		sb.WriteString(strconv.FormatUint(uint64(itm.PayloadSrcID), 16))
		sb.WriteString("; Data: 0x")
		b := strconv.AppendUint(buf[:0], uint64(itm.Value), 16)
		for range int(itm.PayloadSize)*2 - len(b) {
			sb.WriteByte('0')
		}
		sb.Write(b)
		sb.WriteString(") ")
	case DWTPayload:
		sb.WriteString("ITM_DWT (desc: 0x")
		sb.WriteString(strconv.FormatUint(uint64(itm.PayloadSrcID), 16))
		sb.WriteString("; Data: 0x")
		b := strconv.AppendUint(buf[:0], uint64(itm.Value), 16)
		for range int(itm.PayloadSize)*2 - len(b) {
			sb.WriteByte('0')
		}
		sb.Write(b)
		sb.WriteString(") ")
	case TSGlobal:
		sb.WriteString("ITM_TS_GLOBAL ( TS: 0x")
		b := strconv.AppendUint(buf[:0], e.Timestamp, 16)
		for range 16 - len(b) {
			sb.WriteByte('0')
		}
		sb.Write(b)
		sb.WriteString(") ")
	}
 
	if itm.PktType < SWTItmType(len(itmLocalTimestampNames)) {
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
}
