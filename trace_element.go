package coresight

// GenElemType represents the generic trace element type.
type GenElemType uint32

const (
	GenElemUnknown         GenElemType = 0
	GenElemNoSync          GenElemType = 1
	GenElemTraceOn         GenElemType = 2
	GenElemEOTrace         GenElemType = 3
	GenElemPeContext       GenElemType = 4
	GenElemInstrRange      GenElemType = 5
	GenElemIRangeNopath    GenElemType = 6
	GenElemAddrNacc        GenElemType = 7
	GenElemAddrUnknown     GenElemType = 8
	GenElemException       GenElemType = 9
	GenElemExceptionRet    GenElemType = 10
	GenElemTimestamp       GenElemType = 11
	GenElemCycleCount      GenElemType = 12
	GenElemEvent           GenElemType = 13
	GenElemSWTrace         GenElemType = 14
	GenElemSyncMarker      GenElemType = 15
	GenElemMemTrans        GenElemType = 16
	GenElemInstrumentation GenElemType = 17
	GenElemITMTrace        GenElemType = 18
	GenElemCustom          GenElemType = 19
)

type TraceOnReason uint32

const (
	TraceOnNormal   TraceOnReason = 0
	TraceOnOverflow TraceOnReason = 1
	TraceOnExDebug  TraceOnReason = 2
)

type EventType uint16

const (
	EventUnknown  EventType = 0
	EventTrigger  EventType = 1
	EventNumbered EventType = 2
)

type TraceEvent struct {
	EvType   EventType
	EvNumber uint16
}

type UnsyncInfo uint32

const (
	UnsyncUnknown      UnsyncInfo = 0
	UnsyncInitDecoder  UnsyncInfo = 1
	UnsyncResetDecoder UnsyncInfo = 2
	UnsyncOverflow     UnsyncInfo = 3
	UnsyncDiscard      UnsyncInfo = 4
	UnsyncBadPacket    UnsyncInfo = 5
	UnsyncBadImage     UnsyncInfo = 6
	UnsyncEOT          UnsyncInfo = 7
)

type TraceSyncMarker uint32

const (
	ElemMarkerTS TraceSyncMarker = 0
)

type TraceMarkerPayload struct {
	Type  TraceSyncMarker
	Value uint32
}

type MemoryTransaction uint32

const (
	MemTransTraceInit MemoryTransaction = 0
	MemTransStart     MemoryTransaction = 1
	MemTransCommit    MemoryTransaction = 2
	MemTransFail      MemoryTransaction = 3
)

type ITEEvent struct {
	EL    uint8
	Value uint64
}

type SWTItmType uint32

const (
	SWITPayload  SWTItmType = 0
	DWTPayload   SWTItmType = 1
	TSSync       SWTItmType = 2
	TSDelay      SWTItmType = 3
	TSPKTDelay   SWTItmType = 4
	TSPKTTSDelay SWTItmType = 5
	TSGlobal     SWTItmType = 6
)

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

func (e *Element) SetContext(newCtx PEContext) {
	e.Context = newCtx
}

func (e *Element) SetISA(isa ISA) {
	e.ISA = min(isa, ISAUnknown)
}

func (e *Element) SetCycleCount(cycleCount uint32) {
	e.CycleCount = cycleCount
	e.HasCycleCount = true
}

func (e *Element) SetEvent(evType EventType, number uint16) {
	e.Payload.TraceEvent.EvType = evType
	if evType == EventNumbered {
		e.Payload.TraceEvent.EvNumber = number
	} else {
		e.Payload.TraceEvent.EvNumber = 0
	}
}

func (e *Element) SetTimestamp(ts uint64, freqChange bool) {
	e.Timestamp = ts
	e.CPUFreqChange = freqChange
	e.HasTS = true
}

func (e *Element) MarkExceptionData() {
	e.ExceptionDataMarker = true
}

func (e *Element) SetExceptionNum(excepNum uint32) {
	e.Payload.ExceptionNum = excepNum
}

func (e *Element) SetTraceOnReason(reason TraceOnReason) {
	e.Payload.TraceOnReason = reason
}

func (e *Element) SetUnsyncEndReason(reason UnsyncInfo) {
	e.Payload.UnsyncEOTInfo = reason
}

func (e *Element) SetTransactionType(trans MemoryTransaction) {
	e.Payload.MemTrans = trans
}

func (e *Element) SetAddrRange(stAddr, enAddr VAddr, numInstr uint32) {
	e.StartAddr = stAddr
	e.EndAddr = enAddr
	e.Payload.NumInstrRange = numInstr
}

func (e *Element) SetLastInstrInfo(exec bool, lastIType InstrType, lastISubtype InstrSubtype, size uint8) {
	e.LastInstrExecuted = exec
	e.LastInstrSize = size & 0x7
	e.LastInstrType = lastIType
	e.LastInstrSubtype = lastISubtype
}

func (e *Element) SetSWTInfo(swtInfo SWTInfo) {
	e.Payload.SWTraceInfo = swtInfo
}

func (e *Element) SetExtendedDataPtr(data []byte) {
	e.ExtendedData = true
	e.ExtendedDataBytes = data
}

func (e *Element) SetITEInfo(swInstrumentation ITEEvent) {
	e.Payload.SWIte = swInstrumentation
}

func (e *Element) SetITMInfo(itmInfo SWTItmInfo) {
	e.Payload.SWTItm = itmInfo
}

func (e *Element) SetSyncMarker(marker TraceMarkerPayload) {
	e.Payload.SyncMarker = marker
}

func (e *Element) CopyPersistentData(src *Element) {
	e.ISA = src.ISA
	e.Context = src.Context
}
