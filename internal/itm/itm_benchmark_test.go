package itm_test

import (
	"coresight/internal/itm"
	"testing"
)

func BenchmarkITMDecoder_Write(b *testing.B) {
	data := buildTest2() // Predefined test suite data with DWT + LTS types
	cfg := &itm.Config{RegTCR: 0}

	b.ResetTimer()
	for b.Loop() {
		decoder, _ := itm.NewDecoder(cfg)
		_, _ = decoder.Write(0, data)
		_ = decoder.Close()
	}
}
