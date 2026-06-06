// Component tests for memory accessor and caching, ported from
// OpenCSD/decoder/tests/source/mem_acc_test.cpp.
package memacc_test

import (
	"encoding/binary"
	"errors"
	"github.com/awmorgan/coresight/internal/memacc"
	"github.com/awmorgan/coresight/internal/protocol"
	"github.com/awmorgan/coresight/trace"
	"testing"
)

// Constants mirroring the C++ test program.
const (
	numBlocks      = 2
	blockNumWords  = 8192
	blockSizeBytes = 4 * blockNumWords
)

// blockVal mirrors the C++ BLOCK_VAL macro:
//
//	(mem_space << 24) | (block_num << 16) | index
func blockVal(memSpace trace.MemSpaceAcc, blockNum, index int) uint32 {
	return (uint32(memSpace) << 24) | (uint32(blockNum) << 16) | uint32(index)
}

// populateBlock fills a word array with deterministic values keyed by
// memory space and block number so reads can be verified.
func populateBlock(memSpace trace.MemSpaceAcc, blockNum int) []byte {
	buf := make([]byte, blockSizeBytes)
	for j := range blockNumWords {
		binary.LittleEndian.PutUint32(buf[j*4:], blockVal(memSpace, blockNum, j))
	}
	return buf
}

// testBlocks holds all pre-populated memory blocks, keyed as in the C++ test.
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
		tb.el01NS[i] = populateBlock(trace.MemSpaceEL1N, i)
		tb.el2NS[i] = populateBlock(trace.MemSpaceEL2, i)
		tb.el01S[i] = populateBlock(trace.MemSpaceEL1S, i)
		tb.el2S[i] = populateBlock(trace.MemSpaceEL2S, i)
		tb.el3[i] = populateBlock(trace.MemSpaceEL3, i)
		tb.el01R[i] = populateBlock(trace.MemSpaceEL1R, i)
		tb.el2R[i] = populateBlock(trace.MemSpaceEL2R, i)
		tb.el3Root[i] = populateBlock(trace.MemSpaceRoot, i)
	}
	return tb
}

// --------------------------------------------------------------------------
// TestOverlapRegions mirrors test_overlap_regions() in mem_acc_test.cpp.
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
	mapper := memacc.NewGlobalMapper()

	// 1) Add single accessor: [0x0000 .. 0x7FFF], EL1N — should succeed.
	acc1 := memacc.NewBufferAccessor(0x0000, tb.el01NS[0], trace.MemSpaceEL1N, "")
	if err := mapper.AddAccessor(acc1, 0); err != nil {
		t.Fatalf("Adding first accessor should succeed: %v", err)
	}

	// 2) Overlapping region, same memory space — should fail with ErrMemAccOverlap.
	//    C++: Acc2 at 0x1000, EL1N, overlaps [0x0000..0x7FFF].
	acc2 := memacc.NewBufferAccessor(0x1000, tb.el01NS[1], trace.MemSpaceEL1N, "")
	if err := mapper.AddAccessor(acc2, 0); !errors.Is(err, protocol.ErrMemAccOverlap) {
		t.Fatalf("Overlapping accessor in same space should return ErrMemAccOverlap, got: %v", err)
	}

	// 3) Non-overlapping region, same memory space — should succeed.
	//    C++: Acc2 re-ranged to [0x8000 .. 0x8000+BLOCK_SIZE-1].
	acc2NonOverlap := memacc.NewBufferAccessor(0x8000, tb.el01NS[1], trace.MemSpaceEL1N, "")
	if err := mapper.AddAccessor(acc2NonOverlap, 0); err != nil {
		t.Fatalf("Non-overlapping accessor in same space should succeed: %v", err)
	}

	// 4) Overlapping region, different specific memory space — should succeed.
	//    C++: Acc3 at 0x0000, EL1S (different from EL1N already present).
	acc3 := memacc.NewBufferAccessor(0x0000, tb.el01S[0], trace.MemSpaceEL1S, "")
	if err := mapper.AddAccessor(acc3, 0); err != nil {
		t.Fatalf("Overlapping accessor in different space should succeed: %v", err)
	}

	// 5) Overlapping region, more general memory space (S) that shares bits with EL1S.
	//    C++: Acc4 at 0x0000, OCSD_MEM_SPACE_S — should overlap with EL1S.
	acc4 := memacc.NewBufferAccessor(0x0000, tb.el2S[0], trace.MemSpaceS, "")
	if err := mapper.AddAccessor(acc4, 0); !errors.Is(err, protocol.ErrMemAccOverlap) {
		t.Fatalf("Overlapping general S accessor should return ErrMemAccOverlap, got: %v", err)
	}

	mapper.RemoveAllAccessors()
}

// --------------------------------------------------------------------------
// TestTrcIDCallbackDispatch mirrors test_trcid_cache_mem_cb() in mem_acc_test.cpp.
//
// It verifies that a callback accessor correctly dispatches reads to
// different data based on trace ID and memory space, by registering a
// single CallbackAccessor over the full address range and providing a
// callback that selects data based on trace ID + memory space + address.
// --------------------------------------------------------------------------
func TestTrcIDCallbackDispatch(t *testing.T) {
	tb := newTestBlocks()

	type testRange struct {
		startAddr trace.VAddr
		size      uint32
		buffer    []byte
		memSpace  trace.MemSpaceAcc
		trcID     uint8
	}

	ranges := []testRange{
		{0x0000, blockSizeBytes, tb.el01NS[0], trace.MemSpaceEL1N, 0x10},
		{0x0000, blockSizeBytes, tb.el01NS[1], trace.MemSpaceEL1N, 0x11},
		{0x8000, blockSizeBytes, tb.el2NS[0], trace.MemSpaceEL2, 0x10},
		{0x10000, blockSizeBytes, tb.el2NS[1], trace.MemSpaceEL2, 0x11},
		{0x0000, blockSizeBytes, tb.el01R[0], trace.MemSpaceEL1R, 0x10},
		{0x0000, blockSizeBytes, tb.el2R[0], trace.MemSpaceEL2R, 0x11},
	}

	callbackCount := 0
	callback := func(address trace.VAddr, memSpace trace.MemSpaceAcc, trcID uint8, reqBytes uint32, buffer []byte) uint32 {
		callbackCount++
		for _, r := range ranges {
			if (uint32(memSpace)&uint32(r.memSpace) != 0) && trcID == r.trcID {
				if address >= r.startAddr && address < r.startAddr+trace.VAddr(r.size) {
					offset := uint32(address - r.startAddr)
					bytesRead := min(r.size-offset, reqBytes)
					copy(buffer, r.buffer[offset:offset+bytesRead])
					return bytesRead
				}
			}
		}
		return 0
	}

	mapper := memacc.NewGlobalMapper()
	cbAcc := memacc.NewCallbackAccessor(0, 0xFFFFFFFF, trace.MemSpaceAny)
	cbAcc.SetTraceIDCallback(callback)
	if err := mapper.AddAccessor(cbAcc, 0); err != nil {
		t.Fatalf("Adding callback accessor failed: %v", err)
	}

	// Helper: read 4 bytes from mapper and verify against expected value in range.
	readAndCheck := func(t *testing.T, label string, rangeIdx int, byteOffset uint32) {
		t.Helper()
		r := ranges[rangeIdx]
		addr := r.startAddr + trace.VAddr(byteOffset)
		buf := make([]byte, 4)

		n, err := mapper.Read(addr, r.trcID, trace.MemSpaceEL1N, 4, buf)
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

	mapper.RemoveAllAccessors()
}

// --------------------------------------------------------------------------
// TestMemSpaces mirrors test_mem_spaces() in mem_acc_test.cpp.
//
// It registers buffer accessors across all 8 specific memory spaces with
// overlapping + non-overlapping address ranges, then verifies that reads
// with a specific memory space return the correct data. It also tests that
// broader space queries (N, S, R, ANY) match accessors registered with
// more specific spaces.
// --------------------------------------------------------------------------
func TestMemSpaces(t *testing.T) {
	tb := newTestBlocks()

	// Address constants from C++.
	const (
		addrCommon = trace.VAddr(0x000000)
		addrEL1N   = trace.VAddr(0x008000)
		addrEL2    = trace.VAddr(0x010000)
		addrEL1S   = trace.VAddr(0x018000)
		addrEL2S   = trace.VAddr(0x020000)
		addrEL3    = trace.VAddr(0x028000)
		addrEL1R   = trace.VAddr(0x030000)
		addrEL2R   = trace.VAddr(0x038000)
		addrEL3R   = trace.VAddr(0x040000)
	)

	type accSpec struct {
		addr   trace.VAddr
		buffer []byte
		space  trace.MemSpaceAcc
	}

	// Phase 1: register accessors for each specific memory space (2 per space).
	// Block 0 in each space is at the common address; block 1 is at a unique address.
	specificAccs := []accSpec{
		{addrCommon, tb.el01NS[0], trace.MemSpaceEL1N},
		{addrEL1N, tb.el01NS[1], trace.MemSpaceEL1N},
		{addrCommon, tb.el2NS[0], trace.MemSpaceEL2},
		{addrEL2, tb.el2NS[1], trace.MemSpaceEL2},
		{addrCommon, tb.el01S[0], trace.MemSpaceEL1S},
		{addrEL1S, tb.el01S[1], trace.MemSpaceEL1S},
		{addrCommon, tb.el2S[0], trace.MemSpaceEL2S},
		{addrEL2S, tb.el2S[1], trace.MemSpaceEL2S},
		{addrCommon, tb.el3[0], trace.MemSpaceEL3},
		{addrEL3, tb.el3[1], trace.MemSpaceEL3},
		{addrCommon, tb.el01R[0], trace.MemSpaceEL1R},
		{addrEL1R, tb.el01R[1], trace.MemSpaceEL1R},
		{addrCommon, tb.el2R[0], trace.MemSpaceEL2R},
		{addrEL2R, tb.el2R[1], trace.MemSpaceEL2R},
		{addrCommon, tb.el3Root[0], trace.MemSpaceRoot},
		{addrEL3R, tb.el3Root[1], trace.MemSpaceRoot},
	}

	mapper := memacc.NewGlobalMapper()
	for i, spec := range specificAccs {
		acc := memacc.NewBufferAccessor(spec.addr, spec.buffer, spec.space, "")
		if err := mapper.AddAccessor(acc, 0); err != nil {
			t.Fatalf("Failed to add accessor %d (addr=0x%x, space=%v): %v", i, spec.addr, spec.space, err)
		}
	}

	// readAndCheckValue reads 4 bytes at addr with the given space and
	// verifies the result against the first 4 bytes of expectedBuf.
	readAndCheckValue := func(t *testing.T, addr trace.VAddr, expectedBuf []byte, space trace.MemSpaceAcc) {
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
		readAndCheckValue(t, addrCommon, tb.el01NS[0], trace.MemSpaceEL1N)
		readAndCheckValue(t, addrEL1N, tb.el01NS[1], trace.MemSpaceEL1N)
		readAndCheckValue(t, addrEL1N, tb.el01NS[1], trace.MemSpaceN)
		readAndCheckValue(t, addrEL1N, tb.el01NS[1], trace.MemSpaceAny)
	})

	t.Run("EL2N", func(t *testing.T) {
		readAndCheckValue(t, addrCommon, tb.el2NS[0], trace.MemSpaceEL2)
		readAndCheckValue(t, addrEL2, tb.el2NS[1], trace.MemSpaceEL2)
		readAndCheckValue(t, addrEL2, tb.el2NS[1], trace.MemSpaceN)
		readAndCheckValue(t, addrEL2, tb.el2NS[1], trace.MemSpaceAny)
	})

	t.Run("EL1S", func(t *testing.T) {
		readAndCheckValue(t, addrCommon, tb.el01S[0], trace.MemSpaceEL1S)
		readAndCheckValue(t, addrEL1S, tb.el01S[1], trace.MemSpaceEL1S)
		readAndCheckValue(t, addrEL1S, tb.el01S[1], trace.MemSpaceS)
		readAndCheckValue(t, addrEL1S, tb.el01S[1], trace.MemSpaceAny)
	})

	t.Run("EL2S", func(t *testing.T) {
		readAndCheckValue(t, addrCommon, tb.el2S[0], trace.MemSpaceEL2S)
		readAndCheckValue(t, addrEL2S, tb.el2S[1], trace.MemSpaceEL2S)
		readAndCheckValue(t, addrEL2S, tb.el2S[1], trace.MemSpaceS)
		readAndCheckValue(t, addrEL2S, tb.el2S[1], trace.MemSpaceAny)
	})

	t.Run("EL3", func(t *testing.T) {
		readAndCheckValue(t, addrCommon, tb.el3[0], trace.MemSpaceEL3)
		readAndCheckValue(t, addrEL3, tb.el3[1], trace.MemSpaceEL3)
		readAndCheckValue(t, addrEL3, tb.el3[1], trace.MemSpaceS)
		readAndCheckValue(t, addrEL3, tb.el3[1], trace.MemSpaceAny)
	})

	t.Run("EL1R", func(t *testing.T) {
		readAndCheckValue(t, addrCommon, tb.el01R[0], trace.MemSpaceEL1R)
		readAndCheckValue(t, addrEL1R, tb.el01R[1], trace.MemSpaceEL1R)
		readAndCheckValue(t, addrEL1R, tb.el01R[1], trace.MemSpaceR)
		readAndCheckValue(t, addrEL1R, tb.el01R[1], trace.MemSpaceAny)
	})

	t.Run("EL2R", func(t *testing.T) {
		readAndCheckValue(t, addrCommon, tb.el2R[0], trace.MemSpaceEL2R)
		readAndCheckValue(t, addrEL2R, tb.el2R[1], trace.MemSpaceEL2R)
		readAndCheckValue(t, addrEL2R, tb.el2R[1], trace.MemSpaceR)
		readAndCheckValue(t, addrEL2R, tb.el2R[1], trace.MemSpaceAny)
	})

	t.Run("Root", func(t *testing.T) {
		readAndCheckValue(t, addrCommon, tb.el3Root[0], trace.MemSpaceRoot)
		readAndCheckValue(t, addrEL3R, tb.el3Root[1], trace.MemSpaceRoot)
		readAndCheckValue(t, addrEL3R, tb.el3Root[1], trace.MemSpaceAny)
	})

	// Phase 2: test broader space accessors (ANY, N, S, R) with specific read spaces.
	mapper.RemoveAllAccessors()

	broaderAccs := []accSpec{
		{addrCommon, tb.el01NS[0], trace.MemSpaceAny},
		{addrEL1N, tb.el01NS[1], trace.MemSpaceN},
		{addrEL2, tb.el2NS[0], trace.MemSpaceS},
		{addrEL3, tb.el2NS[1], trace.MemSpaceR},
	}

	for i, spec := range broaderAccs {
		acc := memacc.NewBufferAccessor(spec.addr, spec.buffer, spec.space, "")
		if err := mapper.AddAccessor(acc, 0); err != nil {
			t.Fatalf("Failed to add broader accessor %d: %v", i, err)
		}
	}

	// ANY space at addrCommon should match all specific space queries.
	t.Run("AnyBlock", func(t *testing.T) {
		spacesToTest := []trace.MemSpaceAcc{
			trace.MemSpaceEL1N, trace.MemSpaceEL2,
			trace.MemSpaceEL1S, trace.MemSpaceEL2S,
			trace.MemSpaceEL3,
			trace.MemSpaceEL1R, trace.MemSpaceEL2R,
			trace.MemSpaceS, trace.MemSpaceN, trace.MemSpaceR,
			trace.MemSpaceRoot,
		}
		for i, sp := range spacesToTest {
			offset := uint32(i * 4)
			readAndCheckValue(t, addrCommon+trace.VAddr(offset), tb.el01NS[0][offset:], sp)
		}
	})

	// N space at addrEL1N should match EL1N, EL2, and N queries.
	t.Run("NBlock", func(t *testing.T) {
		for i, sp := range []trace.MemSpaceAcc{trace.MemSpaceEL1N, trace.MemSpaceEL2, trace.MemSpaceN} {
			offset := uint32(i * 4)
			readAndCheckValue(t, addrEL1N+trace.VAddr(offset), tb.el01NS[1][offset:], sp)
		}
	})

	// S space at addrEL2 should match EL1S, EL2S, EL3, and S queries.
	t.Run("SBlock", func(t *testing.T) {
		for i, sp := range []trace.MemSpaceAcc{trace.MemSpaceEL1S, trace.MemSpaceEL2S, trace.MemSpaceEL3, trace.MemSpaceS} {
			offset := uint32(i * 4)
			readAndCheckValue(t, addrEL2+trace.VAddr(offset), tb.el2NS[0][offset:], sp)
		}
	})

	// R space at addrEL3 should match EL1R, EL2R, and R queries.
	t.Run("RBlock", func(t *testing.T) {
		for i, sp := range []trace.MemSpaceAcc{trace.MemSpaceEL1R, trace.MemSpaceEL2R, trace.MemSpaceR} {
			offset := uint32(i * 4)
			readAndCheckValue(t, addrEL3+trace.VAddr(offset), tb.el2NS[1][offset:], sp)
		}
	})

	mapper.RemoveAllAccessors()
}
