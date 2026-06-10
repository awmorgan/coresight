package coresight

import (
	"errors"
	"fmt"
	"math/bits"
	"strings"
)

// Sentinel errors for memory access lookups.
var (
	// errNoAccessor indicates no memory accessor can service the request.
	errNoAccessor = errors.New("no memory accessor")
)

type accessorEntry struct {
	acc      Accessor
	start    VAddr
	end      VAddr
	memSpace MemSpaceAcc
	score    int
}

// GlobalMapper implements a global registry of memory accessors.
type GlobalMapper struct {
	accessors []Accessor
	entries   []accessorEntry
	lastAcc   Accessor
	lastStart VAddr
	lastEnd   VAddr
	lastSpace MemSpaceAcc
}

// NewGlobalMapper creates a new GlobalMapper instance.
func NewGlobalMapper() *GlobalMapper {
	return &GlobalMapper{}
}

// DumpMappings returns a multi-line formatted string describing all registered accessors.
// This matches the legacy gocsd CLI output format.
func (m *GlobalMapper) DumpMappings() string {
	var sb strings.Builder
	sb.WriteString("Gen_Info : Mapped Memory Accessors\n")
	for i := 0; i < len(m.accessors); {
		if bufAcc, ok := m.accessors[i].(*bufferAccessor); ok {
			desc := bufAcc.Desc
			first := true
			for i < len(m.accessors) {
				nextBufAcc, ok := m.accessors[i].(*bufferAccessor)
				if !ok || nextBufAcc.Desc != desc {
					break
				}
				if first {
					fmt.Fprintf(&sb, "Gen_Info : FileAcc; %s\n", nextBufAcc.baseAccessor.String())
					first = false
				} else {
					fmt.Fprintf(&sb, "FileAcc; %s\n", nextBufAcc.baseAccessor.String())
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
		return 0, errNoAccessor
	}

	read := acc.ReadBytes(address, memSpace, trcID, bytesToRead, buffer)
	if read > bytesToRead {
		return read, errMemAccBadLen
	}
	return read, nil
}

// AddAccessor registers a memory accessor with the mapper.
// Returns an error if the accessor overlaps with any existing accessors.
func (m *GlobalMapper) AddAccessor(accessor Accessor) error {
	if accessor == nil {
		return errInvalidParamVal
	}
	st, en := accessor.Range()
	if st >= en || st&0x1 != 0 || (en+1)&0x1 != 0 {
		return errMemAccRangeInvalid
	}
	if m.overlapsExisting(accessor) {
		return ErrMemAccOverlap
	}

	m.accessors = append(m.accessors, accessor)
	m.entries = append(m.entries, accessorEntry{
		acc:      accessor,
		start:    st,
		end:      en,
		memSpace: accessor.MemSpace(),
		score:    memSpaceSpecificity(accessor.MemSpace()),
	})
	m.lastAcc = nil
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

func (m *GlobalMapper) removeAllAccessors() {
	clear(m.accessors)
	m.accessors = nil
	clear(m.entries)
	m.entries = nil
	m.lastAcc = nil
}

func (m *GlobalMapper) findAccessor(address VAddr, memSpace MemSpaceAcc) (Accessor, bool) {
	if m.lastAcc != nil && m.lastSpace == memSpace && address >= m.lastStart && address <= m.lastEnd {
		return m.lastAcc, true
	}

	var best Accessor
	bestScore := maxMemSpaceSpecificity + 1

	for i := range m.entries {
		entry := &m.entries[i]
		if address < entry.start || address > entry.end || (entry.memSpace&memSpace == 0) {
			continue
		}
		if entry.memSpace == memSpace {
			m.lastAcc = entry.acc
			m.lastStart = entry.start
			m.lastEnd = entry.end
			m.lastSpace = entry.memSpace
			return entry.acc, true
		}
		if entry.score < bestScore {
			best = entry.acc
			bestScore = entry.score
		}
	}

	if best != nil {
		st, en := best.Range()
		m.lastAcc = best
		m.lastStart = st
		m.lastEnd = en
		m.lastSpace = best.MemSpace()
	} else {
		m.lastAcc = nil
	}
	return best, best != nil
}

const maxMemSpaceSpecificity = 32

func memSpaceSpecificity(memSpace MemSpaceAcc) int {
	return bits.OnesCount32(uint32(memSpace))
}
