package coresight



type internalMemoryCallback func(address VAddr, memSpace MemSpaceAcc, trcID uint8, reqBytes uint32, buffer []byte) uint32

// internalByteSink consumes indexed trace bytes through the internal push datapath.
type internalByteSink interface {
	Write(index Index, dataBlock []byte) (uint32, error)
	Close() error
	Flush() error
	Reset(index Index) error
}

// internalElementSink is the synchronous destination for decoded trace elements.
type internalElementSink func(elem Element)

// internalFrameObserver is the callback for observing raw frame bytes.
type internalFrameObserver func(index Index, frameElem RawframeElem, data []byte, traceID uint8) error

// internalMemoryReader defines the interface for reading memory during trace decode.
type internalMemoryReader interface {
	Read(address VAddr, trcID uint8, memSpace MemSpaceAcc, reqBytes uint32, buffer []byte) (uint32, error)
}

// internalInstructionDecoder defines the interface for decoding instructions from opcodes.
type internalInstructionDecoder func(instrInfo *InstrInfo) error
