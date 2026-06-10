package snapshot

import (
	"strings"
)

type parsedDevices struct {
	Version           string
	Description       string
	DeviceList        map[string]string
	TraceMetaDataName string
}

// Device represents a CoreSight trace or topology device in the snapshot.
type Device struct {
	Name        string
	Class       string
	Type        string
	regs        map[string]string
	extRegs     map[uint32]uint32
	Memory      []MemoryDump
	foundGlobal bool
	core        string
}

// MemoryDump represents a region of memory dumped into a file as part of the snapshot.
type MemoryDump struct {
	Address uint64
	Path    string
	Length  uint64
	Offset  uint64
	Space   string
}

func (p *Device) regValue(key string) (string, bool) {
	keyLower := strings.ToLower(key)
	if val, ok := p.regs[keyLower]; ok {
		return val, true
	}
	prefix := keyLower + "("
	for k, v := range p.regs {
		if strings.HasPrefix(k, prefix) {
			return v, true
		}
	}
	return "", false
}

// Buffer describes a trace buffer in the snapshot.
type Buffer struct {
	BufferName   string
	DataFileName string
	DataFormat   string
}

// Trace represents the trace metadata configuration in the snapshot.
type Trace struct {
	BufferSectionNames []string
	Buffers            []Buffer
	SourceBufferAssoc  map[string]string
	CPUSourceAssoc     map[string]string
}

// TraceBufferSourceTree associates trace buffers with their source CPU/devices.
type TraceBufferSourceTree struct {
	BufferInfo      *Buffer
	SourceCoreAssoc map[string]string
}
