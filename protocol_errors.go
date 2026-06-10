package coresight

import "errors"

var (
	errNotInit         = errors.New("component not initialised")
	errInvalidParamVal = errors.New("invalid value parameter passed to component")
	// ErrDataDecodeFatal is returned when a decoder in the data path has encountered a fatal error.
	ErrDataDecodeFatal     = errors.New("a decoder in the data path has returned a fatal error")
	errDfrmtrBadFhsync     = errors.New("bad frame or half frame sync in trace deformatter")
	errDfrmtrUnaligned     = errors.New("insufficient bytes for aligned frame")
	errDfrmtrBadFsyncReset = errors.New("incorrect FSYNC frame reset pattern")
	errDfrmtrBadHSync      = errors.New("bad HSYNC in frame")
	errDfrmtrBadFsyncStart = errors.New("bad FSYNC start in frame or invalid ID (0x7F)")
	errDfrmtrOddByte       = errors.New("odd trailing byte in frame stream")
	errDfrmtrNotConfigured = errors.New("deformatter not configured")
	errBadPacketSeq        = errors.New("bad packet sequence")
	errInvalidPcktHdr      = errors.New("invalid packet header")
	errPktInterpFail       = errors.New("interpreter failed - cannot recover - bad data or sequence")
	errUnsupportedISA      = errors.New("ISA not supported in decoder")
	errHWCfgUnsupp         = errors.New("programmed trace configuration not supported by decoder")
	errMemNacc             = errors.New("unable to access required memory address")
	errRetStackOverflow    = errors.New("internal return stack overflow checks failed - popped more than we pushed")
	// ErrMemAccOverlap is returned when attempting to register overlapping memory accessors.
	ErrMemAccOverlap        = errors.New("attempted to set an overlapping range in memory access map")
	errMemAccRangeInvalid   = errors.New("address range in accessor set to invalid values")
	errMemAccBadLen         = errors.New("memory accessor returned a bad read length value (larger than requested)")
	errDcdInterfaceUnused   = errors.New("attempt to connect or use and interface not supported by this decoder")
	errInvalidOpcode        = errors.New("illegal Opcode found while decoding program memory")
	errIRangeLimitOverrun   = errors.New("an optional limit on consecutive instructions in range during decode has been exceeded")
	errDfrmtrIncompleteTail = errors.New("incomplete trailing bytes in frame stream at close")

	// ErrNilByteSink is returned when attempting to register a nil sink.
	ErrNilByteSink = errors.New("nil ByteSink not allowed")
	// ErrInvalidTraceID is returned when the trace ID is invalid or too large.
	ErrInvalidTraceID = errors.New("invalid coresight trace ID")
	// ErrDuplicateTraceID is returned when a trace ID is already registered.
	ErrDuplicateTraceID = errors.New("duplicate trace ID in pipeline")
	// ErrMultipleRoutesNonFramed is returned when registering more than one route in a non-framed pipeline.
	ErrMultipleRoutesNonFramed = errors.New("non-framed pipeline only supports a single route")
)
