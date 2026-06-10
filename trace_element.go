package coresight

// GenElemType represents the generic trace element type.
type GenElemType uint32

const (
	// GenElemUnknown represents an unknown/unitialized trace element.
	GenElemUnknown GenElemType = 0
	// GenElemNoSync represents a trace element before synchronization is achieved.
	GenElemNoSync GenElemType = 1
	// GenElemTraceOn represents trace start or restart.
	GenElemTraceOn GenElemType = 2
	// GenElemEOTrace represents end of trace stream.
	GenElemEOTrace GenElemType = 3
	// GenElemPeContext represents a processing element context change.
	GenElemPeContext GenElemType = 4
	// GenElemInstrRange represents a range of executed instructions.
	GenElemInstrRange GenElemType = 5
	// GenElemIRangeNopath represents a range of executed instructions with no path info.
	GenElemIRangeNopath GenElemType = 6
	// GenElemAddrNacc represents a target address that is non-accessible.
	GenElemAddrNacc GenElemType = 7
	// GenElemAddrUnknown represents an unknown target address.
	GenElemAddrUnknown GenElemType = 8
	// GenElemException represents target exception entry.
	GenElemException GenElemType = 9
	// GenElemExceptionRet represents target exception return.
	GenElemExceptionRet GenElemType = 10
	// GenElemTimestamp represents a timestamp packet.
	GenElemTimestamp GenElemType = 11
	// GenElemCycleCount represents a cycle count packet.
	GenElemCycleCount GenElemType = 12
	// GenElemEvent represents a trace event.
	GenElemEvent GenElemType = 13
	// GenElemSWTrace represents a software trace packet.
	GenElemSWTrace GenElemType = 14
	// GenElemSyncMarker represents a synchronization marker.
	GenElemSyncMarker GenElemType = 15
	// GenElemMemTrans represents a memory transaction element.
	GenElemMemTrans GenElemType = 16
	// GenElemInstrumentation represents instrumentation trace data.
	GenElemInstrumentation GenElemType = 17
	// GenElemITMTrace represents ITM trace data.
	GenElemITMTrace GenElemType = 18
	// GenElemCustom represents a custom user-defined trace element.
	GenElemCustom GenElemType = 19
)

// TraceOnReason represents the reason why tracing has started or restarted.
type TraceOnReason uint32

const (
	// TraceOnNormal indicates trace started normally.
	TraceOnNormal TraceOnReason = 0
	// TraceOnOverflow indicates trace restarted after an overflow.
	TraceOnOverflow TraceOnReason = 1
	// TraceOnExDebug indicates trace restarted after debug exclusion.
	TraceOnExDebug TraceOnReason = 2
)

// EventType represents the type of a trace event.
type EventType uint16

const (
	// EventUnknown is an unknown event type.
	EventUnknown EventType = 0
	// EventTrigger represents a trace trigger event.
	EventTrigger EventType = 1
	// EventNumbered represents a numbered event.
	EventNumbered EventType = 2
)

// TraceEvent contains info about trace events emitted by the decoder.
type TraceEvent struct {
	EvType   EventType
	EvNumber uint16
}

// UnsyncInfo represents the cause or type of decoder unsync state.
type UnsyncInfo uint32

const (
	// UnsyncUnknown indicates unknown unsync reason.
	UnsyncUnknown UnsyncInfo = 0
	// UnsyncInitDecoder indicates decoder initialization unsync.
	UnsyncInitDecoder UnsyncInfo = 1
	// UnsyncResetDecoder indicates decoder reset unsync.
	UnsyncResetDecoder UnsyncInfo = 2
	// UnsyncOverflow indicates buffer overflow unsync.
	UnsyncOverflow UnsyncInfo = 3
	// UnsyncDiscard indicates data discard unsync.
	UnsyncDiscard UnsyncInfo = 4
	// UnsyncBadPacket indicates invalid packet format unsync.
	UnsyncBadPacket UnsyncInfo = 5
	// UnsyncBadImage indicates missing/bad memory image unsync.
	UnsyncBadImage UnsyncInfo = 6
	// UnsyncEOT indicates trace end-of-transmission unsync.
	UnsyncEOT UnsyncInfo = 7
)

// TraceSyncMarker indicates type of trace synchronization marker.
type TraceSyncMarker uint32

const (
	// ElemMarkerTS indicates a timestamp synchronization marker.
	ElemMarkerTS TraceSyncMarker = 0
)

// TraceMarkerPayload contains payload for a synchronization marker.
type TraceMarkerPayload struct {
	Type  TraceSyncMarker
	Value uint32
}

// MemoryTransaction represents the state of a memory transaction element.
type MemoryTransaction uint32

const (
	// MemTransTraceInit represents memory transaction initialization.
	MemTransTraceInit MemoryTransaction = 0
	// MemTransStart represents memory transaction start.
	MemTransStart MemoryTransaction = 1
	// MemTransCommit represents memory transaction commit.
	MemTransCommit MemoryTransaction = 2
	// MemTransFail represents memory transaction fail/abort.
	MemTransFail MemoryTransaction = 3
)

// ITEEvent represents an Instrumentation Trace Extension event.
type ITEEvent struct {
	EL    uint8
	Value uint64
}

// SWTItmType represents the software trace/ITM sub-packet type.
type SWTItmType uint32

const (
	// SWITPayload is a software trace payload packet.
	SWITPayload SWTItmType = 0
	// DWTPayload is a DWT payload packet.
	DWTPayload SWTItmType = 1
	// TSSync is a timestamp sync packet.
	TSSync SWTItmType = 2
	// TSDelay is a timestamp delay packet.
	TSDelay SWTItmType = 3
	// TSPKTDelay is a timestamp packet delay.
	TSPKTDelay SWTItmType = 4
	// TSPKTTSDelay is a timestamp packet timestamp delay.
	TSPKTTSDelay SWTItmType = 5
	// TSGlobal is a global timestamp packet.
	TSGlobal SWTItmType = 6
)

// SWTItmInfo holds details about a decoded software trace or ITM packet.
type SWTItmInfo struct {
	PktType      SWTItmType
	PayloadSrcID uint8
	PayloadSize  uint8
	Value        uint32
	Overflow     uint8
}

// ElementPayload holds the protocol-specific data for a decoded trace element.
// Only the fields relevant to the current ElemType are populated.
type ElementPayload struct {
	SWIte         ITEEvent
	ExceptionNum  uint32
	TraceEvent    TraceEvent
	TraceOnReason TraceOnReason
	SWTraceInfo   SWTInfo
	NumInstrRange uint32
	UnsyncEOTInfo UnsyncInfo
	SyncMarker    TraceMarkerPayload
	MemTrans      MemoryTransaction
	SWTItm        SWTItmInfo
}

// Element is the decoded trace element passed to element sinks.
type Element struct {
	ExtendedDataBytes []byte
	Diagnostic        string
	Index             Index
	StartAddr         VAddr
	EndAddr           VAddr
	Timestamp         uint64

	Payload ElementPayload

	ElemType         GenElemType
	ISA              ISA
	CycleCount       uint32
	LastInstrType    InstrType
	LastInstrSubtype InstrSubtype
	Context          PEContext

	TraceID               uint8
	LastInstrSize         uint8
	LastInstrExecuted     bool
	HasCycleCount         bool
	CPUFreqChange         bool
	ExceptionRetAddr      bool
	ExceptionDataMarker   bool
	ExtendedData          bool
	HasTS                 bool
	LastInstrCond         bool
	ExceptionRetAddrBrTgt bool
	ExceptionMTailChain   bool
}

func (e *Element) setContext(newCtx PEContext) {
	e.Context = newCtx
}

func (e *Element) setCycleCount(cycleCount uint32) {
	e.CycleCount = cycleCount
	e.HasCycleCount = true
}

func (e *Element) setEvent(evType EventType, number uint16) {
	e.Payload.TraceEvent.EvType = evType
	if evType == EventNumbered {
		e.Payload.TraceEvent.EvNumber = number
	} else {
		e.Payload.TraceEvent.EvNumber = 0
	}
}

func (e *Element) setTimestamp(ts uint64, freqChange bool) {
	e.Timestamp = ts
	e.CPUFreqChange = freqChange
	e.HasTS = true
}

func (e *Element) setExceptionNum(excepNum uint32) {
	e.Payload.ExceptionNum = excepNum
}

func (e *Element) setTraceOnReason(reason TraceOnReason) {
	e.Payload.TraceOnReason = reason
}

func (e *Element) setUnsyncEndReason(reason UnsyncInfo) {
	e.Payload.UnsyncEOTInfo = reason
}

func (e *Element) setTransactionType(trans MemoryTransaction) {
	e.Payload.MemTrans = trans
}

func (e *Element) setLastInstrInfo(exec bool, lastIType InstrType, lastISubtype InstrSubtype, size uint8) {
	e.LastInstrExecuted = exec
	e.LastInstrSize = size & 0x7
	e.LastInstrType = lastIType
	e.LastInstrSubtype = lastISubtype
}

func (e *Element) setSWTInfo(swtInfo SWTInfo) {
	e.Payload.SWTraceInfo = swtInfo
}

func (e *Element) setExtendedDataPtr(data []byte) {
	e.ExtendedData = true
	e.ExtendedDataBytes = data
}

func (e *Element) setITEInfo(swInstrumentation ITEEvent) {
	e.Payload.SWIte = swInstrumentation
}

func (e *Element) setITMInfo(itmInfo SWTItmInfo) {
	e.Payload.SWTItm = itmInfo
}

func (e *Element) setSyncMarker(marker TraceMarkerPayload) {
	e.Payload.SyncMarker = marker
}
