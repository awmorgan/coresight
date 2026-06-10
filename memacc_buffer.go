package coresight

import (
	"fmt"
)

type bufferAccessor struct {
	baseAccessor
	Buffer []byte
	Desc   string
}

// NewBufferAccessor creates a memory accessor backed by a byte slice.
func NewBufferAccessor(startAddr VAddr, buffer []byte, memSpace MemSpaceAcc, desc string) Accessor {
	b := &bufferAccessor{Buffer: buffer, Desc: desc}
	b.baseAccessor = newBaseAccessor(startAddr, endAddress(startAddr, len(buffer)), memSpace)
	return b
}

func (b *bufferAccessor) String() string {
	return fmt.Sprintf("FileAcc; %s\nFilename=%s", b.baseAccessor.String(), b.Desc)
}

func (b *bufferAccessor) ReadBytes(address VAddr, _ MemSpaceAcc, _ uint8, reqBytes uint32, buffer []byte) uint32 {
	if !b.AddrInRange(address) {
		return 0
	}
	avail := uint32(uint64(b.EndAddress) - uint64(address) + 1)
	bytesToRead := min(avail, reqBytes, uint32(len(buffer)))
	if bytesToRead == 0 {
		return 0
	}

	offset := address - b.StartAddress
	copy(buffer, b.Buffer[offset:offset+VAddr(bytesToRead)])
	return bytesToRead
}

func (b *bufferAccessor) Configure(startAddr VAddr, buffer []byte) {
	b.StartAddress = startAddr
	b.EndAddress = endAddress(startAddr, len(buffer))
	b.Buffer = buffer
}

func newBaseAccessor(startAddr, endAddr VAddr, memSpace MemSpaceAcc) baseAccessor {
	return baseAccessor{
		StartAddress: startAddr,
		EndAddress:   endAddr,
		MemSpaceAcc:  memSpace,
	}
}

func endAddress(startAddr VAddr, size int) VAddr {
	if size == 0 {
		return startAddr
	}
	return startAddr + VAddr(size) - 1
}
