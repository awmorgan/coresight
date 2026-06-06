package trace

import (
	"fmt"
)

type MemoryCallback func(address VAddr, memSpace MemSpaceAcc, trcID uint8, reqBytes uint32, buffer []byte) uint32

// ByteSink consumes indexed trace bytes through the internal push datapath.
type ByteSink interface {
	Write(index Index, dataBlock []byte) (uint32, error)
	Close() error
	Flush() error
	Reset(index Index) error
}

// ElementSink is the synchronous destination for decoded trace elements.
type ElementSink func(elem Element)

// PacketObserver observes raw packets off the decode path.
type PacketObserver func(indexSOP Index, pkt fmt.Stringer, rawData []byte)

// FrameObserver is the callback for observing raw frame bytes.
type FrameObserver func(index Index, frameElem RawframeElem, data []byte, traceID uint8) error

// MemoryReader defines the interface for reading memory during trace decode.
type MemoryReader interface {
	Read(address VAddr, trcID uint8, memSpace MemSpaceAcc, reqBytes uint32, buffer []byte) (uint32, error)
}

// InstructionDecoder defines the interface for decoding instructions from opcodes.
type InstructionDecoder func(instrInfo *InstrInfo) error
