package utils

import "testing"

func TestReaderScratchGrowsPastInlineBuffer(t *testing.T) {
	r := NewReader()
	data := make([]byte, 80)
	for i := range data {
		data[i] = byte(i)
	}
	r.Feed(data)

	for range data {
		if _, err := r.ReadByte(); err != nil {
			t.Fatalf("ReadByte() error = %v", err)
		}
	}

	scratch := r.Scratch()
	if len(scratch) != len(data) {
		t.Fatalf("len(Scratch()) = %d, want %d", len(scratch), len(data))
	}
	for i, got := range scratch {
		if want := byte(i); got != want {
			t.Fatalf("Scratch()[%d] = %d, want %d", i, got, want)
		}
	}
}

func TestReaderDiscardScratchPrefix(t *testing.T) {
	r := NewReader()
	data := make([]byte, 80)
	for i := range data {
		data[i] = byte(i)
	}
	r.Feed(data)

	for range data {
		if _, err := r.ReadByte(); err != nil {
			t.Fatalf("ReadByte() error = %v", err)
		}
	}

	r.DiscardScratchPrefix(65)
	scratch := r.Scratch()
	if len(scratch) != 15 {
		t.Fatalf("len(Scratch()) = %d, want 15", len(scratch))
	}
	for i, got := range scratch {
		if want := byte(i + 65); got != want {
			t.Fatalf("Scratch()[%d] = %d, want %d", i, got, want)
		}
	}

	r.DiscardScratchPrefix(100)
	if len(r.Scratch()) != 0 {
		t.Fatalf("len(Scratch()) = %d, want 0", len(r.Scratch()))
	}
}

func BenchmarkReader_ReadByte(b *testing.B) {
	r := NewReader()
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i)
	}
	b.ResetTimer()
	for b.Loop() {
		r.Feed(data)
		for range data {
			_, err := r.ReadByte()
			if err != nil {
				b.Fatal(err)
			}
		}
		r.Reset()
	}
}
