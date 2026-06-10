// Component tests for memory accessor and caching.
package coresight

import (
	"encoding/binary"
	"errors"
	"testing"
)

// Constants mirroring the reference test program.
const (
	numBlocks      = 2
	blockNumWords  = 8192
	blockSizeBytes = 4 * blockNumWords
)

// blockVal mirrors the reference BLOCK_VAL macro:
//
//	(mem_space << 24) | (block_num << 16) | index
func blockVal(memSpace MemSpaceAcc, blockNum, index int) uint32 {
	return (uint32(memSpace) << 24) | (uint32(blockNum) << 16) | uint32(index)
}

// populateBlock fills a word array with deterministic values keyed by
// memory space and block number so reads can be verified.
func populateBlock(memSpace MemSpaceAcc, blockNum int) []byte {
	buf := make([]byte, blockSizeBytes)
	for j := range blockNumWords {
		binary.LittleEndian.PutUint32(buf[j*4:], blockVal(memSpace, blockNum, j))
	}
	return buf
}

// testBlocks holds all pre-populated memory blocks, keyed as in the reference test.
type testBlocks struct {
	el01NS  [numBlocks][]byte
	el2NS   [numBlocks][]byte
	el01S   [numBlocks][]byte
	el2S    [numBlocks][]byte
	el3     [numBlocks][]byte
	el01R   [numBlocks][]byte
	el2R    [numBlocks][]byte
	el3Root [numBlocks][]byte
}

func newTestBlocks() *testBlocks {
	tb := &testBlocks{}
	for i := range numBlocks {
		tb.el01NS[i] = populateBlock(MemSpaceEL1N, i)
		tb.el2NS[i] = populateBlock(MemSpaceEL2, i)
		tb.el01S[i] = populateBlock(MemSpaceEL1S, i)
		tb.el2S[i] = populateBlock(MemSpaceEL2S, i)
		tb.el3[i] = populateBlock(MemSpaceEL3, i)
		tb.el01R[i] = populateBlock(MemSpaceEL1R, i)
		tb.el2R[i] = populateBlock(MemSpaceEL2R, i)
		tb.el3Root[i] = populateBlock(MemSpaceRoot, i)
	}
	return tb
}

// --------------------------------------------------------------------------
// TestOverlapRegions verifies overlapping and non-overlapping regions.
//
// It verifies:
//  1. A single accessor can be added successfully.
//  2. An overlapping accessor in the SAME memory space is rejected.
//  3. A non-overlapping accessor in the same space is accepted.
//  4. An overlapping accessor in a DIFFERENT specific space is accepted.
//  5. An overlapping accessor in a MORE GENERAL space that shares bits
//     with an existing specific space is rejected.
//
// --------------------------------------------------------------------------
func TestOverlapRegions(t *testing.T) {
	tb := newTestBlocks()
	mapper := NewGlobalMapper()

	// 1) Add single accessor: [0x0000 .. 0x7FFF], EL1N — should succeed.
	acc1 := NewBufferAccessor(0x0000, tb.el01NS[0], MemSpaceEL1N, "")
	if err := mapper.AddAccessor(acc1); err != nil {
		t.Fatalf("Adding first accessor should succeed: %v", err)
	}

	// 2) Overlapping region, same memory space — should fail with ErrMemAccOverlap.
	//    Reference: Acc2 at 0x1000, EL1N, overlaps [0x0000..0x7FFF].
	acc2 := NewBufferAccessor(0x1000, tb.el01NS[1], MemSpaceEL1N, "")
	if err := mapper.AddAccessor(acc2); !errors.Is(err, ErrMemAccOverlap) {
		t.Fatalf("Overlapping accessor in same space should return ErrMemAccOverlap, got: %v", err)
	}

	// 3) Non-overlapping region, same memory space — should succeed.
	//    Reference: Acc2 re-ranged to [0x8000 .. 0x8000+BLOCK_SIZE-1].
	acc2NonOverlap := NewBufferAccessor(0x8000, tb.el01NS[1], MemSpaceEL1N, "")
	if err := mapper.AddAccessor(acc2NonOverlap); err != nil {
		t.Fatalf("Non-overlapping accessor in same space should succeed: %v", err)
	}

	// 4) Overlapping region, different specific memory space — should succeed.
	//    Reference: Acc3 at 0x0000, EL1S (different from EL1N already present).
	acc3 := NewBufferAccessor(0x0000, tb.el01S[0], MemSpaceEL1S, "")
	if err := mapper.AddAccessor(acc3); err != nil {
		t.Fatalf("Overlapping accessor in different space should succeed: %v", err)
	}

	// 5) Overlapping region, more general memory space (S) that shares bits with EL1S.
	//    Reference: Acc4 at 0x0000, MemSpaceS — should overlap with EL1S.
	acc4 := NewBufferAccessor(0x0000, tb.el2S[0], MemSpaceS, "")
	if err := mapper.AddAccessor(acc4); !errors.Is(err, ErrMemAccOverlap) {
		t.Fatalf("Overlapping general S accessor should return ErrMemAccOverlap, got: %v", err)
	}

	mapper.removeAllAccessors()
}

// --------------------------------------------------------------------------
// TestTrcIDCallbackDispatch verifies callback dispatch behavior.
//
// It verifies that a callback accessor correctly dispatches reads to
// different data based on trace ID and memory space, by registering a
// single callbackAccessor over the full address range and providing a
// callback that selects data based on trace ID + memory space + address.
// --------------------------------------------------------------------------
func TestTrcIDCallbackDispatch(t *testing.T) {
	tb := newTestBlocks()

	type testRange struct {
		startAddr VAddr
		size      uint32
		buffer    []byte
		memSpace  MemSpaceAcc
		trcID     uint8
	}

	ranges := []testRange{
		{0x0000, blockSizeBytes, tb.el01NS[0], MemSpaceEL1N, 0x10},
		{0x0000, blockSizeBytes, tb.el01NS[1], MemSpaceEL1N, 0x11},
		{0x8000, blockSizeBytes, tb.el2NS[0], MemSpaceEL2, 0x10},
		{0x10000, blockSizeBytes, tb.el2NS[1], MemSpaceEL2, 0x11},
		{0x0000, blockSizeBytes, tb.el01R[0], MemSpaceEL1R, 0x10},
		{0x0000, blockSizeBytes, tb.el2R[0], MemSpaceEL2R, 0x11},
	}

	callbackCount := 0
	callback := func(address VAddr, memSpace MemSpaceAcc, trcID uint8, reqBytes uint32, buffer []byte) uint32 {
		callbackCount++
		for _, r := range ranges {
			if (uint32(memSpace)&uint32(r.memSpace) != 0) && trcID == r.trcID {
				if address >= r.startAddr && address < r.startAddr+VAddr(r.size) {
					offset := uint32(address - r.startAddr)
					bytesRead := min(r.size-offset, reqBytes)
					copy(buffer, r.buffer[offset:offset+bytesRead])
					return bytesRead
				}
			}
		}
		return 0
	}

	mapper := NewGlobalMapper()
	cbAcc := newCallbackAccessor(0, 0xFFFFFFFF, MemSpaceAny)
	cbAcc.SetTraceIDCallback(callback)
	if err := mapper.AddAccessor(cbAcc); err != nil {
		t.Fatalf("Adding callback accessor failed: %v", err)
	}

	// Helper: read 4 bytes from mapper and verify against expected value in range.
	readAndCheck := func(t *testing.T, label string, rangeIdx int, byteOffset uint32) {
		t.Helper()
		r := ranges[rangeIdx]
		addr := r.startAddr + VAddr(byteOffset)
		buf := make([]byte, 4)

		n, err := mapper.Read(addr, r.trcID, MemSpaceEL1N, 4, buf)
		if err != nil {
			t.Fatalf("%s: Read error: %v", label, err)
		}
		if n != 4 {
			t.Fatalf("%s: expected 4 bytes, got %d", label, n)
		}

		expected := binary.LittleEndian.Uint32(r.buffer[byteOffset:])
		got := binary.LittleEndian.Uint32(buf)
		if got != expected {
			t.Fatalf("%s: value mismatch: got 0x%08x, want 0x%08x", label, got, expected)
		}
	}

	// Test 1: Read from range 0, offset 0 — callback should fire.
	prevCount := callbackCount
	readAndCheck(t, "test1: range0 offset=0x0", 0, 0)
	if callbackCount == prevCount {
		t.Fatal("test1: expected callback to fire on initial read")
	}

	// Test 2: Read from range 0, offset 0x10 — callback fires (no caching in Go).
	readAndCheck(t, "test2: range0 offset=0x10", 0, 0x10)

	// Test 3: Read from range 1 (different trcID), offset 0x10 — callback should fire.
	prevCount = callbackCount
	readAndCheck(t, "test3: range1 offset=0x10", 1, 0x10)
	if callbackCount == prevCount {
		t.Fatal("test3: expected callback to fire for different trcID")
	}

	// Test 4: Read from range 1 again.
	readAndCheck(t, "test4: range1 offset=0x10 again", 1, 0x10)

	mapper.removeAllAccessors()
}

// --------------------------------------------------------------------------
// TestMemSpaces verifies memory space separation and fallback logic.
//
// It registers buffer accessors across all 8 specific memory spaces with
// overlapping + non-overlapping address ranges, then verifies that reads
// with a specific memory space return the correct data. It also tests that
// broader space queries (N, S, R, ANY) match accessors registered with
// more specific spaces.
// --------------------------------------------------------------------------
func TestMemSpaces(t *testing.T) {
	tb := newTestBlocks()

	// Address constants from the reference test.
	const (
		addrCommon = VAddr(0x000000)
		addrEL1N   = VAddr(0x008000)
		addrEL2    = VAddr(0x010000)
		addrEL1S   = VAddr(0x018000)
		addrEL2S   = VAddr(0x020000)
		addrEL3    = VAddr(0x028000)
		addrEL1R   = VAddr(0x030000)
		addrEL2R   = VAddr(0x038000)
		addrEL3R   = VAddr(0x040000)
	)

	type accSpec struct {
		addr   VAddr
		buffer []byte
		space  MemSpaceAcc
	}

	// Phase 1: register accessors for each specific memory space (2 per space).
	// Block 0 in each space is at the common address; block 1 is at a unique address.
	specificAccs := []accSpec{
		{addrCommon, tb.el01NS[0], MemSpaceEL1N},
		{addrEL1N, tb.el01NS[1], MemSpaceEL1N},
		{addrCommon, tb.el2NS[0], MemSpaceEL2},
		{addrEL2, tb.el2NS[1], MemSpaceEL2},
		{addrCommon, tb.el01S[0], MemSpaceEL1S},
		{addrEL1S, tb.el01S[1], MemSpaceEL1S},
		{addrCommon, tb.el2S[0], MemSpaceEL2S},
		{addrEL2S, tb.el2S[1], MemSpaceEL2S},
		{addrCommon, tb.el3[0], MemSpaceEL3},
		{addrEL3, tb.el3[1], MemSpaceEL3},
		{addrCommon, tb.el01R[0], MemSpaceEL1R},
		{addrEL1R, tb.el01R[1], MemSpaceEL1R},
		{addrCommon, tb.el2R[0], MemSpaceEL2R},
		{addrEL2R, tb.el2R[1], MemSpaceEL2R},
		{addrCommon, tb.el3Root[0], MemSpaceRoot},
		{addrEL3R, tb.el3Root[1], MemSpaceRoot},
	}

	mapper := NewGlobalMapper()
	for i, spec := range specificAccs {
		acc := NewBufferAccessor(spec.addr, spec.buffer, spec.space, "")
		if err := mapper.AddAccessor(acc); err != nil {
			t.Fatalf("Failed to add accessor %d (addr=0x%x, space=%v): %v", i, spec.addr, spec.space, err)
		}
	}

	// readAndCheckValue reads 4 bytes at addr with the given space and
	// verifies the result against the first 4 bytes of expectedBuf.
	readAndCheckValue := func(t *testing.T, addr VAddr, expectedBuf []byte, space MemSpaceAcc) {
		t.Helper()
		buf := make([]byte, 4)
		n, err := mapper.Read(addr, 0, space, 4, buf)
		if err != nil {
			t.Fatalf("Read(0x%x, space=%v) error: %v", addr, space, err)
		}
		if n != 4 {
			t.Fatalf("Read(0x%x, space=%v): got %d bytes, want 4", addr, space, n)
		}
		expected := binary.LittleEndian.Uint32(expectedBuf)
		got := binary.LittleEndian.Uint32(buf)
		if got != expected {
			t.Fatalf("Read(0x%x, space=%v): got 0x%08x, want 0x%08x", addr, space, got, expected)
		}
	}

	// Test specific space reads and broader-space fallback.
	t.Run("EL1N", func(t *testing.T) {
		readAndCheckValue(t, addrCommon, tb.el01NS[0], MemSpaceEL1N)
		readAndCheckValue(t, addrEL1N, tb.el01NS[1], MemSpaceEL1N)
		readAndCheckValue(t, addrEL1N, tb.el01NS[1], MemSpaceN)
		readAndCheckValue(t, addrEL1N, tb.el01NS[1], MemSpaceAny)
	})

	t.Run("EL2N", func(t *testing.T) {
		readAndCheckValue(t, addrCommon, tb.el2NS[0], MemSpaceEL2)
		readAndCheckValue(t, addrEL2, tb.el2NS[1], MemSpaceEL2)
		readAndCheckValue(t, addrEL2, tb.el2NS[1], MemSpaceN)
		readAndCheckValue(t, addrEL2, tb.el2NS[1], MemSpaceAny)
	})

	t.Run("EL1S", func(t *testing.T) {
		readAndCheckValue(t, addrCommon, tb.el01S[0], MemSpaceEL1S)
		readAndCheckValue(t, addrEL1S, tb.el01S[1], MemSpaceEL1S)
		readAndCheckValue(t, addrEL1S, tb.el01S[1], MemSpaceS)
		readAndCheckValue(t, addrEL1S, tb.el01S[1], MemSpaceAny)
	})

	t.Run("EL2S", func(t *testing.T) {
		readAndCheckValue(t, addrCommon, tb.el2S[0], MemSpaceEL2S)
		readAndCheckValue(t, addrEL2S, tb.el2S[1], MemSpaceEL2S)
		readAndCheckValue(t, addrEL2S, tb.el2S[1], MemSpaceS)
		readAndCheckValue(t, addrEL2S, tb.el2S[1], MemSpaceAny)
	})

	t.Run("EL3", func(t *testing.T) {
		readAndCheckValue(t, addrCommon, tb.el3[0], MemSpaceEL3)
		readAndCheckValue(t, addrEL3, tb.el3[1], MemSpaceEL3)
		readAndCheckValue(t, addrEL3, tb.el3[1], MemSpaceS)
		readAndCheckValue(t, addrEL3, tb.el3[1], MemSpaceAny)
	})

	t.Run("EL1R", func(t *testing.T) {
		readAndCheckValue(t, addrCommon, tb.el01R[0], MemSpaceEL1R)
		readAndCheckValue(t, addrEL1R, tb.el01R[1], MemSpaceEL1R)
		readAndCheckValue(t, addrEL1R, tb.el01R[1], MemSpaceR)
		readAndCheckValue(t, addrEL1R, tb.el01R[1], MemSpaceAny)
	})

	t.Run("EL2R", func(t *testing.T) {
		readAndCheckValue(t, addrCommon, tb.el2R[0], MemSpaceEL2R)
		readAndCheckValue(t, addrEL2R, tb.el2R[1], MemSpaceEL2R)
		readAndCheckValue(t, addrEL2R, tb.el2R[1], MemSpaceR)
		readAndCheckValue(t, addrEL2R, tb.el2R[1], MemSpaceAny)
	})

	t.Run("Root", func(t *testing.T) {
		readAndCheckValue(t, addrCommon, tb.el3Root[0], MemSpaceRoot)
		readAndCheckValue(t, addrEL3R, tb.el3Root[1], MemSpaceRoot)
		readAndCheckValue(t, addrEL3R, tb.el3Root[1], MemSpaceAny)
	})

	// Phase 2: test broader space accessors (ANY, N, S, R) with specific read spaces.
	mapper.removeAllAccessors()

	broaderAccs := []accSpec{
		{addrCommon, tb.el01NS[0], MemSpaceAny},
		{addrEL1N, tb.el01NS[1], MemSpaceN},
		{addrEL2, tb.el2NS[0], MemSpaceS},
		{addrEL3, tb.el2NS[1], MemSpaceR},
	}

	for i, spec := range broaderAccs {
		acc := NewBufferAccessor(spec.addr, spec.buffer, spec.space, "")
		if err := mapper.AddAccessor(acc); err != nil {
			t.Fatalf("Failed to add broader accessor %d: %v", i, err)
		}
	}

	// ANY space at addrCommon should match all specific space queries.
	t.Run("AnyBlock", func(t *testing.T) {
		spacesToTest := []MemSpaceAcc{
			MemSpaceEL1N, MemSpaceEL2,
			MemSpaceEL1S, MemSpaceEL2S,
			MemSpaceEL3,
			MemSpaceEL1R, MemSpaceEL2R,
			MemSpaceS, MemSpaceN, MemSpaceR,
			MemSpaceRoot,
		}
		for i, sp := range spacesToTest {
			offset := uint32(i * 4)
			readAndCheckValue(t, addrCommon+VAddr(offset), tb.el01NS[0][offset:], sp)
		}
	})

	// N space at addrEL1N should match EL1N, EL2, and N queries.
	t.Run("NBlock", func(t *testing.T) {
		for i, sp := range []MemSpaceAcc{MemSpaceEL1N, MemSpaceEL2, MemSpaceN} {
			offset := uint32(i * 4)
			readAndCheckValue(t, addrEL1N+VAddr(offset), tb.el01NS[1][offset:], sp)
		}
	})

	// S space at addrEL2 should match EL1S, EL2S, EL3, and S queries.
	t.Run("SBlock", func(t *testing.T) {
		for i, sp := range []MemSpaceAcc{MemSpaceEL1S, MemSpaceEL2S, MemSpaceEL3, MemSpaceS} {
			offset := uint32(i * 4)
			readAndCheckValue(t, addrEL2+VAddr(offset), tb.el2NS[0][offset:], sp)
		}
	})

	// R space at addrEL3 should match EL1R, EL2R, and R queries.
	t.Run("RBlock", func(t *testing.T) {
		for i, sp := range []MemSpaceAcc{MemSpaceEL1R, MemSpaceEL2R, MemSpaceR} {
			offset := uint32(i * 4)
			readAndCheckValue(t, addrEL3+VAddr(offset), tb.el2NS[1][offset:], sp)
		}
	})

	mapper.removeAllAccessors()
}
