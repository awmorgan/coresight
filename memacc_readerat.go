package coresight

import (
	"io"
)

// readerAtAccessor implements Accessor using an io.ReaderAt source.
type readerAtAccessor struct {
	baseAccessor
	Source io.ReaderAt
}

// newReaderAtAccessor creates a new readerAtAccessor.
func newReaderAtAccessor(startAddr VAddr, size uint64, source io.ReaderAt, memSpace MemSpaceAcc) *readerAtAccessor {
	var endAddr VAddr
	if size == 0 {
		endAddr = startAddr
	} else {
		endAddr = startAddr + VAddr(size) - 1
	}
	return &readerAtAccessor{
		baseAccessor: baseAccessor{
			StartAddress: startAddr,
			EndAddress:   endAddr,
			MemSpaceAcc:  memSpace,
		},
		Source: source,
	}
}

// ReadBytes implements the Accessor interface.
func (r *readerAtAccessor) ReadBytes(address VAddr, _ MemSpaceAcc, _ uint8, reqBytes uint32, buffer []byte) uint32 {
	if !r.AddrInRange(address) {
		return 0
	}
	avail := uint32(uint64(r.EndAddress) - uint64(address) + 1)
	bytesToRead := min(avail, reqBytes, uint32(len(buffer)))
	if bytesToRead == 0 {
		return 0
	}
	offset := address - r.StartAddress
	n, err := r.Source.ReadAt(buffer[:bytesToRead], int64(offset))
	if err != nil && err != io.EOF && n == 0 {
		return 0
	}
	return uint32(n)
}
