package coresight

import (
	"fmt"
	"strings"
)

// Accessor defines the interface for a memory range access.
type Accessor interface {
	ReadBytes(address VAddr, memSpace MemSpaceAcc, trcID uint8, reqBytes uint32, buffer []byte) uint32
	AddrInRange(address VAddr) bool
	MemSpace() MemSpaceAcc
	Range() (VAddr, VAddr)
}

// BaseAccessor implements the common logic for memory accessors.
type BaseAccessor struct {
	StartAddress VAddr
	EndAddress   VAddr
	MemSpaceAcc  MemSpaceAcc
}

func (b *BaseAccessor) AddrInRange(address VAddr) bool {
	return address >= b.StartAddress && address <= b.EndAddress
}

func (b *BaseAccessor) MemSpace() MemSpaceAcc {
	return b.MemSpaceAcc
}

func (b *BaseAccessor) Range() (VAddr, VAddr) {
	return b.StartAddress, b.EndAddress
}

func (b *BaseAccessor) String() string {
	return fmt.Sprintf("Range::0x%x:%x; Mem Space::%s", b.StartAddress, b.EndAddress, MemSpaceString(b.MemSpaceAcc))
}

// MemSpaceString formats memSpace using the OpenCSD memory-space names.
func MemSpaceString(memSpace MemSpaceAcc) string {
	if name, ok := namedMemSpace(memSpace); ok {
		return name
	}

	parts := make([]string, 0, len(memaccMemSpaceNames))
	msBits := uint8(memSpace)
	for _, named := range memaccMemSpaceNames {
		if msBits&uint8(named.space) != 0 {
			parts = append(parts, named.name)
		}
	}
	return strings.Join(parts, ",")
}

func namedMemSpace(memSpace MemSpaceAcc) (string, bool) {
	switch memSpace {
	case MemSpaceNone:
		return "None", true
	case MemSpaceS:
		return "Any S", true
	case MemSpaceN:
		return "Any NS", true
	case MemSpaceR:
		return "Any R", true
	case MemSpaceAny:
		return "Any", true
	}

	for _, named := range memaccMemSpaceNames {
		if memSpace == named.space {
			return named.name, true
		}
	}
	return "", false
}

var memaccMemSpaceNames = []struct {
	space MemSpaceAcc
	name  string
}{
	{MemSpaceEL1S, "EL1S"},
	{MemSpaceEL1N, "EL1N"},
	{MemSpaceEL2, "EL2N"},
	{MemSpaceEL3, "EL3"},
	{MemSpaceEL2S, "EL2S"},
	{MemSpaceEL1R, "EL1R"},
	{MemSpaceEL2R, "EL2R"},
	{MemSpaceRoot, "Root"},
}
