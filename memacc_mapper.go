package coresight

import (
	"errors"
	"fmt"
	"math/bits"
	"strings"
)

// Sentinel errors for memory access lookups.
var (
	// ErrNoAccessor indicates no memory accessor can service the request.
	ErrNoAccessor = errors.New("no memory accessor")

	// ErrAddressNotMapped indicates the address is not mapped in any accessor.
	ErrAddressNotMapped = errors.New("address not mapped")
)

// GlobalMapper implements a global registry of memory accessors.
type GlobalMapper struct {
	accessors []Accessor
	last      Accessor
}

func NewGlobalMapper() *GlobalMapper {
	return &GlobalMapper{}
}

// DumpMappings returns a multi-line formatted string describing all registered accessors.
// This matches the legacy gocsd CLI output format.
func (m *GlobalMapper) DumpMappings() string {
	var sb strings.Builder
	sb.WriteString("Gen_Info : Mapped Memory Accessors\n")
	for i := 0; i < len(m.accessors); {
		if bufAcc, ok := m.accessors[i].(*BufferAccessor); ok {
			desc := bufAcc.Desc
			first := true
			for i < len(m.accessors) {
				nextBufAcc, ok := m.accessors[i].(*BufferAccessor)
				if !ok || nextBufAcc.Desc != desc {
					break
				}
				if first {
					fmt.Fprintf(&sb, "Gen_Info : FileAcc; %s\n", nextBufAcc.BaseAccessor.String())
					first = false
				} else {
					fmt.Fprintf(&sb, "FileAcc; %s\n", nextBufAcc.BaseAccessor.String())
				}
				i++
			}
			fmt.Fprintf(&sb, "Filename=%s\n", desc)
			continue
		}

		acc := m.accessors[i]
		if stringer, ok := acc.(fmt.Stringer); ok {
			fmt.Fprintf(&sb, "Gen_Info : %s\n", stringer.String())
		}
		i++
	}
	sb.WriteString("Gen_Info : ========================\n")
	return sb.String()
}

// Read attempts to read reqBytes from target memory at address. Returns number of bytes read and error.
func (m *GlobalMapper) Read(address VAddr, trcID uint8, memSpace MemSpaceAcc, reqBytes uint32, buffer []byte) (uint32, error) {
	bytesToRead := min(reqBytes, uint32(len(buffer)))

	acc, ok := m.findAccessor(address, memSpace)
	if !ok {
		return 0, ErrNoAccessor
	}

	read := acc.ReadBytes(address, memSpace, trcID, bytesToRead, buffer)
	if read > bytesToRead {
		return read, ErrMemAccBadLen
	}
	return read, nil
}

func (m *GlobalMapper) AddAccessor(accessor Accessor, _ uint8) error {
	if accessor == nil {
		return ErrInvalidParamVal
	}
	st, en := accessor.Range()
	if st >= en || st&0x1 != 0 || (en+1)&0x1 != 0 {
		return ErrMemAccRangeInvalid
	}
	if m.overlapsExisting(accessor) {
		return ErrMemAccOverlap
	}

	m.accessors = append(m.accessors, accessor)
	m.last = nil
	return nil
}

func (m *GlobalMapper) overlapsExisting(accessor Accessor) bool {
	stA, enA := accessor.Range()
	for _, existing := range m.accessors {
		stB, enB := existing.Range()
		overlaps := stA <= enB && enA >= stB
		if overlaps && (accessor.MemSpace()&existing.MemSpace() != 0) {
			return true
		}
	}
	return false
}

func (m *GlobalMapper) RemoveAccessor(accessor Accessor) error {
	for i, acc := range m.accessors {
		if acc == accessor {
			m.removeAccessorAt(i)
			return nil
		}
	}
	return ErrInvalidParamVal
}

func (m *GlobalMapper) removeAccessorAt(i int) {
	if m.accessors[i] == m.last {
		m.last = nil
	}
	m.accessors[i] = m.accessors[len(m.accessors)-1]
	m.accessors[len(m.accessors)-1] = nil
	m.accessors = m.accessors[:len(m.accessors)-1]
}

func (m *GlobalMapper) RemoveAllAccessors() {
	clear(m.accessors)
	m.accessors = nil
	m.last = nil
}

func (m *GlobalMapper) findAccessor(address VAddr, memSpace MemSpaceAcc) (Accessor, bool) {
	if m.last != nil && m.last.MemSpace() == memSpace && m.last.AddrInRange(address) {
		return m.last, true
	}

	var best Accessor
	bestScore := maxMemSpaceSpecificity + 1

	for _, acc := range m.accessors {
		if !acc.AddrInRange(address) || (acc.MemSpace()&memSpace == 0) {
			continue
		}
		if acc.MemSpace() == memSpace {
			m.last = acc
			return acc, true
		}
		if score := memSpaceSpecificity(acc.MemSpace()); score < bestScore {
			best = acc
			bestScore = score
		}
	}
	m.last = best
	return best, best != nil
}

const maxMemSpaceSpecificity = 32

func memSpaceSpecificity(memSpace MemSpaceAcc) int {
	return bits.OnesCount32(uint32(memSpace))
}
