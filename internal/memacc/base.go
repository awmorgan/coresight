package memacc

import (
	"coresight/trace"
	"fmt"
	"strings"
)

// Accessor defines the interface for a memory range access.
type Accessor interface {
	ReadBytes(address trace.VAddr, memSpace trace.MemSpaceAcc, trcID uint8, reqBytes uint32, buffer []byte) uint32
	AddrInRange(address trace.VAddr) bool
	MemSpace() trace.MemSpaceAcc
	Range() (trace.VAddr, trace.VAddr)
}

// BaseAccessor implements the common logic for memory accessors.
type BaseAccessor struct {
	StartAddress trace.VAddr
	EndAddress   trace.VAddr
	MemSpaceAcc  trace.MemSpaceAcc
}

func (b *BaseAccessor) AddrInRange(address trace.VAddr) bool {
	return address >= b.StartAddress && address <= b.EndAddress
}

func (b *BaseAccessor) MemSpace() trace.MemSpaceAcc {
	return b.MemSpaceAcc
}

func (b *BaseAccessor) Range() (trace.VAddr, trace.VAddr) {
	return b.StartAddress, b.EndAddress
}

func (b *BaseAccessor) String() string {
	return fmt.Sprintf("Range::0x%x:%x; Mem Space::%s", b.StartAddress, b.EndAddress, MemSpaceString(b.MemSpaceAcc))
}

// MemSpaceString formats memSpace using the OpenCSD memory-space names.
func MemSpaceString(memSpace trace.MemSpaceAcc) string {
	if name, ok := namedMemSpace(memSpace); ok {
		return name
	}

	parts := make([]string, 0, len(memSpaceNames))
	msBits := uint8(memSpace)
	for _, named := range memSpaceNames {
		if msBits&uint8(named.space) != 0 {
			parts = append(parts, named.name)
		}
	}
	return strings.Join(parts, ",")
}

func namedMemSpace(memSpace trace.MemSpaceAcc) (string, bool) {
	switch memSpace {
	case trace.MemSpaceNone:
		return "None", true
	case trace.MemSpaceS:
		return "Any S", true
	case trace.MemSpaceN:
		return "Any NS", true
	case trace.MemSpaceR:
		return "Any R", true
	case trace.MemSpaceAny:
		return "Any", true
	}

	for _, named := range memSpaceNames {
		if memSpace == named.space {
			return named.name, true
		}
	}
	return "", false
}

var memSpaceNames = []struct {
	space trace.MemSpaceAcc
	name  string
}{
	{trace.MemSpaceEL1S, "EL1S"},
	{trace.MemSpaceEL1N, "EL1N"},
	{trace.MemSpaceEL2, "EL2N"},
	{trace.MemSpaceEL3, "EL3"},
	{trace.MemSpaceEL2S, "EL2S"},
	{trace.MemSpaceEL1R, "EL1R"},
	{trace.MemSpaceEL2R, "EL2R"},
	{trace.MemSpaceRoot, "Root"},
}
