package coresight

import (
	"testing"
)

func BenchmarkITMDecoder_Write(b *testing.B) {
	data := buildTest2() // Predefined test suite data with DWT + LTS types
	cfg := &itmConfig{RegTCR: 0}

	b.ResetTimer()
	for b.Loop() {
		decoder, _ := itmNewDecoder(cfg)
		_, _ = decoder.Write(0, data)
		_ = decoder.Close()
	}
}
