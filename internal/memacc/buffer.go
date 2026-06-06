package memacc

import (
	"coresight/trace"
	"fmt"
)

type BufferAccessor struct {
	BaseAccessor
	Buffer []byte
	Desc   string
}

func NewBufferAccessor(startAddr trace.VAddr, buffer []byte, memSpace trace.MemSpaceAcc, desc string) *BufferAccessor {
	b := &BufferAccessor{Buffer: buffer, Desc: desc}
	b.BaseAccessor = newBaseAccessor(startAddr, endAddress(startAddr, len(buffer)), memSpace)
	return b
}

func (b *BufferAccessor) String() string {
	return fmt.Sprintf("FileAcc; %s\nFilename=%s", b.BaseAccessor.String(), b.Desc)
}

func (b *BufferAccessor) ReadBytes(address trace.VAddr, _ trace.MemSpaceAcc, _ uint8, reqBytes uint32, buffer []byte) uint32 {
	if !b.AddrInRange(address) {
		return 0
	}
	avail := uint32(uint64(b.EndAddress) - uint64(address) + 1)
	bytesToRead := min(avail, reqBytes, uint32(len(buffer)))
	if bytesToRead == 0 {
		return 0
	}

	offset := address - b.StartAddress
	copy(buffer, b.Buffer[offset:offset+trace.VAddr(bytesToRead)])
	return bytesToRead
}

func (b *BufferAccessor) Configure(startAddr trace.VAddr, buffer []byte) {
	b.StartAddress = startAddr
	b.EndAddress = endAddress(startAddr, len(buffer))
	b.Buffer = buffer
}

func newBaseAccessor(startAddr, endAddr trace.VAddr, memSpace trace.MemSpaceAcc) BaseAccessor {
	return BaseAccessor{
		StartAddress: startAddr,
		EndAddress:   endAddr,
		MemSpaceAcc:  memSpace,
	}
}

func endAddress(startAddr trace.VAddr, size int) trace.VAddr {
	if size == 0 {
		return startAddr
	}
	return startAddr + trace.VAddr(size) - 1
}
