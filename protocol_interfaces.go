package coresight

// MemoryCallback is the function type used by CallbackAccessor to service
// memory reads from the decoder. address is the target virtual address,
// memSpace is the ARM security/EL space, trcID is the trace source ID,
// reqBytes is the number of bytes requested, and buffer is the destination
// slice. The return value is the number of bytes actually read.
type MemoryCallback func(address VAddr, memSpace MemSpaceAcc, trcID uint8, reqBytes uint32, buffer []byte) uint32

// ByteSink consumes indexed trace bytes through the internal push datapath.
type ByteSink interface {
	Write(index Index, dataBlock []byte) (uint32, error)
	Close() error
	Flush() error
	Reset(index Index) error
}

// ElementSink is the callback type delivered to each decoder for emitting
// decoded trace elements. It is also the public callback type for RegisterXxx
// and NewXxxRoute calls on the Engine.
type ElementSink func(elem Element)

// internalFrameObserver is the callback for observing raw frame bytes.
type internalFrameObserver func(index Index, frameElem RawframeElem, data []byte, traceID uint8) error

// MemoryReader defines the interface for reading target instruction memory
// during trace decode.
type MemoryReader interface {
	Read(address VAddr, trcID uint8, memSpace MemSpaceAcc, reqBytes uint32, buffer []byte) (uint32, error)
}

// internalInstructionDecoder defines the interface for decoding instructions from opcodes.
type internalInstructionDecoder func(instrInfo *instrInfo) error
