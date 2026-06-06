package coresight

import "io"

// MemorySpace defines the security and exception level attributes of the target memory.
type MemorySpace uint8

const (
	SpaceSecure    MemorySpace = 0
	SpaceNonSecure MemorySpace = 1
)

// Mapping represents a bounded region of target virtual memory.
// The Source can be an *os.File, a *bytes.Reader, or a custom simulator hook.
type Mapping struct {
	BaseAddress uint64
	Size        uint64
	Space       MemorySpace
	Source      io.ReaderAt
}
