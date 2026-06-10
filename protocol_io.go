package coresight

import (
	"fmt"
)

// internalEmitter holds the observers shared by packet decoders.
type internalEmitter struct {
	ElementSink      ElementSink
	PacketObserver   PacketObserver
	TraceEndObserver func()
}

func (o *internalEmitter) SetElementSink(sink ElementSink) {
	o.ElementSink = sink
}

func (o *internalEmitter) SetPacketObserver(observer PacketObserver) {
	o.PacketObserver = observer
}

func (o *internalEmitter) SetTraceEndObserver(observer func()) {
	o.TraceEndObserver = observer
}

func (o *internalEmitter) EmitElement(index Index, traceID uint8, elem Element) {
	elem.Index = index
	elem.TraceID = traceID
	if o.ElementSink != nil {
		o.ElementSink(elem)
	}
}

func (o *internalEmitter) EmitPacket(index Index, pkt fmt.Stringer, rawData []byte) {
	if o.PacketObserver != nil && len(rawData) > 0 {
		o.PacketObserver(uint64(index), pkt, rawData)
	}
}

func (o *internalEmitter) EmitTraceEnd() {
	if o.TraceEndObserver != nil {
		o.TraceEndObserver()
	}
}

// internalByteStream tracks the current input block and packet scratch buffer.
type internalByteStream struct {
	Reader       *ByteReader
	DataBlock    []uint8
	BlockBaseIdx Index
	BlockLen     int
}

func newInternalByteStream() internalByteStream {
	return internalByteStream{Reader: NewByteReader()}
}

func (s *internalByteStream) EnsureReader() {
	if s.Reader == nil {
		s.Reader = NewByteReader()
	}
}

func (s *internalByteStream) Feed(index Index, dataBlock []uint8) {
	s.EnsureReader()
	s.DataBlock = dataBlock
	s.Reader.Feed(dataBlock)
	s.BlockBaseIdx = index
	s.BlockLen = len(dataBlock)
}

func (s *internalByteStream) BytesConsumed() int {
	return s.BlockLen - s.Reader.Len()
}

func (s *internalByteStream) CurrentIndex() Index {
	return s.BlockBaseIdx + Index(s.BytesConsumed())
}

func (s *internalByteStream) ReadByte() (byte, error) {
	return s.Reader.ReadByte()
}
