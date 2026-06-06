package protocol

import (
	"fmt"

	"coresight/internal/utils"
	"coresight/trace"
)

// Emitter holds the observers shared by packet decoders.
type Emitter struct {
	ElementSink      trace.ElementSink
	PacketObserver   trace.PacketObserver
	TraceEndObserver func()
}

func (o *Emitter) SetElementSink(sink trace.ElementSink) {
	o.ElementSink = sink
}

func (o *Emitter) SetPacketObserver(observer trace.PacketObserver) {
	o.PacketObserver = observer
}

func (o *Emitter) SetTraceEndObserver(observer func()) {
	o.TraceEndObserver = observer
}

func (o *Emitter) EmitElement(index trace.Index, traceID uint8, elem trace.Element) {
	elem.Index = index
	elem.TraceID = traceID
	if o.ElementSink != nil {
		o.ElementSink(elem)
	}
}

func (o *Emitter) EmitPacket(index trace.Index, pkt fmt.Stringer, rawData []byte) {
	if o.PacketObserver != nil && len(rawData) > 0 {
		o.PacketObserver(index, pkt, rawData)
	}
}

func (o *Emitter) EmitTraceEnd() {
	if o.TraceEndObserver != nil {
		o.TraceEndObserver()
	}
}

// ByteStream tracks the current input block and packet scratch buffer.
type ByteStream struct {
	Reader       *utils.Reader
	DataBlock    []uint8
	BlockBaseIdx trace.Index
	BlockLen     int
}

func NewByteStream() ByteStream {
	return ByteStream{Reader: utils.NewReader()}
}

func (s *ByteStream) EnsureReader() {
	if s.Reader == nil {
		s.Reader = utils.NewReader()
	}
}

func (s *ByteStream) Feed(index trace.Index, dataBlock []uint8) {
	s.EnsureReader()
	s.DataBlock = dataBlock
	s.Reader.Feed(dataBlock)
	s.BlockBaseIdx = index
	s.BlockLen = len(dataBlock)
}

func (s *ByteStream) BytesConsumed() int {
	return s.BlockLen - s.Reader.Len()
}

func (s *ByteStream) CurrentIndex() trace.Index {
	return s.BlockBaseIdx + trace.Index(s.BytesConsumed())
}

func (s *ByteStream) ReadByte() (byte, error) {
	return s.Reader.ReadByte()
}
