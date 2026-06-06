package protocol

import (
	"fmt"

	"github.com/awmorgan/coresight/trace"
)

type MemoryCallback func(address trace.VAddr, memSpace trace.MemSpaceAcc, trcID uint8, reqBytes uint32, buffer []byte) uint32

// ByteSink consumes indexed trace bytes through the internal push datapath.
type ByteSink interface {
	Write(index trace.Index, dataBlock []byte) (uint32, error)
	Close() error
	Flush() error
	Reset(index trace.Index) error
}

// ElementSink is the synchronous destination for decoded trace elements.
type ElementSink func(elem trace.Element)

// PacketObserver observes raw packets off the decode path.
type PacketObserver func(indexSOP trace.Index, pkt fmt.Stringer, rawData []byte)

// FrameObserver is the callback for observing raw frame bytes.
type FrameObserver func(index trace.Index, frameElem trace.RawframeElem, data []byte, traceID uint8) error

// MemoryReader defines the interface for reading memory during trace decode.
type MemoryReader interface {
	Read(address trace.VAddr, trcID uint8, memSpace trace.MemSpaceAcc, reqBytes uint32, buffer []byte) (uint32, error)
}

// InstructionDecoder defines the interface for decoding instructions from opcodes.
type InstructionDecoder func(instrInfo *InstrInfo) error
