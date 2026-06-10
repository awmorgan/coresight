package coresight

import (
	"errors"
	"io"
)

// ByteReader provides an idiomatic way to read from a stream of data blocks.
// It uses a fixed-size scratch buffer for common packet parsing and grows only
// when malformed or unusually long packets exceed that buffer.
type ByteReader struct {
	data []byte
	off  int

	scratch    [64]byte
	scratchExt []byte
	scratchLen int
}

// NewByteReader creates a new byte stream reader.
func NewByteReader() *ByteReader {
	return &ByteReader{}
}

// Feed sets the next block of data to be processed.
func (r *ByteReader) Feed(data []byte) {
	r.data = data
	r.off = 0
}

// ReadByte returns the next byte from the current block.
// It automatically appends the byte to the internal scratch buffer.
func (r *ByteReader) ReadByte() (byte, error) {
	if r.off >= len(r.data) {
		return 0, io.EOF
	}
	b := r.data[r.off]
	r.off++

	r.appendScratch(b)
	return b, nil
}

// ReadByteRaw returns the next byte from the current block without adding it
// to the internal scratch buffer.
func (r *ByteReader) ReadByteRaw() (byte, error) {
	if r.off >= len(r.data) {
		return 0, io.EOF
	}
	b := r.data[r.off]
	r.off++
	return b, nil
}

// Peek returns the next byte without consuming it or adding it to scratch.
func (r *ByteReader) Peek() (byte, error) {
	if r.off >= len(r.data) {
		return 0, io.EOF
	}
	return r.data[r.off], nil
}

// ReadBytes attempts to read n bytes from the CURRENT block.
// If successful, it returns a slice of the scratch buffer containing those bytes.
// If there are fewer than n bytes available, it returns nil and consumes nothing.
func (r *ByteReader) ReadBytes(n int) []byte {
	if r.off+n > len(r.data) {
		return nil
	}

	start := r.scratchLen
	for range n {
		r.appendScratch(r.data[r.off])
		r.off++
	}
	return r.Scratch()[start:r.scratchLen]
}

// Scratch returns all bytes accumulated since the last Reset.
func (r *ByteReader) Scratch() []byte {
	if len(r.scratchExt) > 0 {
		return r.scratchExt[:r.scratchLen]
	}
	return r.scratch[:r.scratchLen]
}

// Reset clears the scratch buffer for the next operation (e.g. next packet).
func (r *ByteReader) Reset() {
	r.scratchLen = 0
	r.scratchExt = r.scratchExt[:0]
}

// DiscardScratchPrefix removes the first n scratch bytes, preserving the tail.
func (r *ByteReader) DiscardScratchPrefix(n int) {
	if n <= 0 {
		return
	}
	if n >= r.scratchLen {
		r.Reset()
		return
	}
	if len(r.scratchExt) > 0 {
		copy(r.scratchExt, r.scratchExt[n:r.scratchLen])
		r.scratchLen -= n
		r.scratchExt = r.scratchExt[:r.scratchLen]
		return
	}
	copy(r.scratch[:], r.scratch[n:r.scratchLen])
	r.scratchLen -= n
}

// WriteScratch appends b to the scratch buffer without consuming stream data.
func (r *ByteReader) WriteScratch(b byte) {
	r.appendScratch(b)
}

// Len returns the number of bytes remaining in the current block.
func (r *ByteReader) Len() int {
	if r.data == nil {
		return 0
	}
	return len(r.data) - r.off
}

// UnreadByte unreads the last byte read, reversing both the stream offset
// and the internal scratch buffer accumulation.
// It is only valid to call UnreadByte immediately after a successful ReadByte
// within the current data block.
func (r *ByteReader) UnreadByte() error {
	if r.off <= 0 || r.scratchLen <= 0 {
		return errors.New("ByteReader: invalid use of UnreadByte")
	}
	r.off--
	r.scratchLen--
	if len(r.scratchExt) > r.scratchLen {
		r.scratchExt = r.scratchExt[:r.scratchLen]
	}
	return nil
}

func (r *ByteReader) appendScratch(b byte) {
	if r.scratchLen < len(r.scratch) {
		r.scratch[r.scratchLen] = b
		r.scratchLen++
		return
	}

	if cap(r.scratchExt) > 0 {
		if r.scratchLen == len(r.scratch) {
			r.scratchExt = r.scratchExt[:len(r.scratch)]
			copy(r.scratchExt, r.scratch[:])
		}
		r.scratchExt = append(r.scratchExt, b)
		r.scratchLen++
		return
	}

	r.scratchExt = make([]byte, len(r.scratch), len(r.scratch)*2)
	copy(r.scratchExt, r.scratch[:])
	r.scratchExt = append(r.scratchExt, b)
	r.scratchLen++
}
