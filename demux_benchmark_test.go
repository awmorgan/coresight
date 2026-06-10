package coresight

import (
	"testing"
)

func BenchmarkDemuxer_Write(b *testing.B) {
	bufMemAlign := []byte{
		idByteID(0x10), 0x01, idByteData(0x02), 0x03,
		idByteData(0x04), 0x05, idByteData(0x06), 0x07,
		idByteID(0x20), 0x08, idByteData(0x09), 0x0A,
		idByteData(0x0B), 0x0C, idByteData(0x0D),
		flagsByte(0, 0, 0, 0, 0, 1, 1, 1),
	}

	streams := make([]ByteSink, 128)
	dec := newDemuxer(streams)
	_ = dec.Configure(DemuxOptions{
		FrameMemAlign: true,
	})

	b.ResetTimer()
	for b.Loop() {
		_, _ = dec.Write(0, bufMemAlign)
	}
}
