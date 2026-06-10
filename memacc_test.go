package coresight

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"testing"
)

var memaccWindowsTestExePathRE = regexp.MustCompile(`(?m)[A-Za-z]:\\[^\r\n]*\\(mem-buffer-eg\.exe)`)

// memBuffDemoConfig returns the ETMv4 config for the memory buffer demo test.
// trace_config.reg_traceidr = 0x00000010, etc.
func memBuffDemoConfig() *etmv4Config {
	return etmv4ParseConfig(
		0x00000010, // reg_traceidr  → trace ID 0x10
		0x000000C1, // reg_configr
		0x28000EA1, // reg_idr0
		0x4100F403, // reg_idr1
		0x00000488, // reg_idr2
		0x0,        // reg_idr8
		0x0,        // reg_idr9
		0x0,        // reg_idr10
		0x0,        // reg_idr11
		0x0,        // reg_idr12
		0x0,        // reg_idr13
		ArchV8,
		ProfileCortexA,
	)
}

const (
	// memDumpAddress is the memory dump address for the test.
	memDumpAddress = VAddr(0xFFFFFFC000081000)
	// snapshot files relative to this package directory (internal/memacc)
	snapshotDir = "cmd/trc_pkt_lister/testdata/juno_r1_1"
)

// runMemBuffDemo builds and runs a complete ETMv4 full-decode pipeline
// using the supplied mapper, processes cstrace.bin in 2048-byte chunks,
// and writes all output to sb.  Returns total bytes processed.
func runMemBuffDemo(t *testing.T, sb *strings.Builder, mapper *GlobalMapper) uint32 {
	t.Helper()

	cfg := memBuffDemoConfig()
	dec, err := etmv4NewDecoder(cfg, mapper, decodeInstruction)
	if err != nil {
		t.Fatalf("NewDecoder: %v", err)
	}

	pipe, err := NewPipeline(true, DemuxOptions{
		FrameMemAlign: true,
	})
	if err != nil {
		t.Fatalf("NewPipeline: %v", err)
	}
	if err := pipe.AddRoute(Route{
		TraceID:  cfg.TraceID(),
		Protocol: ProtocolETMV4I,
		ByteSink: dec,
	}); err != nil {
		t.Fatalf("AddRoute: %v", err)
	}

	elemPrinter := NewGenericElementPrinter(sb)
	pipe.SetElementSink(elemPrinter.PrintElement)

	// Open the trace binary
	traceFile, err := os.Open(snapshotDir + "/cstrace.bin")
	if err != nil {
		t.Fatalf("open cstrace.bin: %v", err)
	}
	defer traceFile.Close()

	const chunkSize = 2048
	buf := make([]byte, chunkSize)
	var totalBytes uint32

	for {
		n, readErr := traceFile.Read(buf)
		if n > 0 {
			_, writeErr := pipe.Write(Index(totalBytes), buf[:n])
			totalBytes += uint32(n)
			if writeErr != nil {
				break
			}
		}
		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}
		if readErr != nil {
			t.Fatalf("reading cstrace.bin: %v", readErr)
		}
	}

	_ = pipe.Close()
	return totalBytes
}

// TestMemBuffDemoGoldens tests both buffer and callback memory accessor modes
// against their golden reference files.
func TestMemBuffDemoGoldens(t *testing.T) {
	// Load the kernel memory dump once; used by both sub-tests.
	kernelDump, err := os.ReadFile(snapshotDir + "/kernel_dump.bin")
	if err != nil {
		t.Fatalf("read kernel_dump.bin: %v", err)
	}
	programImageSize := uint32(len(kernelDump))

	t.Run("mem_buff_demo", func(t *testing.T) {
		var sb strings.Builder

		// Emit header exactly as the reference mem_buff_demo does.
		sb.WriteString("MemBuffDemo\n--------------\n\n\n")
		sb.WriteString("Test Command Line:-\n")
		sb.WriteString("mem-buffer-eg.exe   -logfile  -ss_path  ./snapshots  -noprint  \n\n")

		// Buffer mode: split the kernel dump into two contiguous buffers
		// (mirroring the buffer configuration in the reference test).
		block1Sz := programImageSize / 2
		block1Sz &^= 0x3 // 4-byte align
		block2Sz := programImageSize - block1Sz
		block1St := memDumpAddress
		block2St := memDumpAddress + VAddr(block1Sz)

		mapper := NewGlobalMapper()

		acc1 := NewBufferAccessor(block1St, kernelDump[:block1Sz], MemSpaceAny, "")
		if err := mapper.AddAccessor(acc1); err != nil {
			t.Fatalf("AddAccessor block1: %v", err)
		}
		acc2 := NewBufferAccessor(block2St, kernelDump[block1Sz:block1Sz+block2Sz], MemSpaceAny, "")
		if err := mapper.AddAccessor(acc2); err != nil {
			t.Fatalf("AddAccessor block2: %v", err)
		}

		totalBytes := runMemBuffDemo(t, &sb, mapper)
		fmt.Fprintf(&sb, "Processed %d bytes out of %d\n", totalBytes, totalBytes)

		compareAgainstGolden(t, &sb, "testdata/mem_buff_demo.ppl")
	})

	t.Run("mem_buff_demo_cb", func(t *testing.T) {
		var sb strings.Builder

		// Emit header exactly as the reference mem_buff_demo -callback does.
		sb.WriteString("MemBuffDemo\n--------------\n\n\n")
		sb.WriteString("Test Command Line:-\n")
		sb.WriteString("mem-buffer-eg.exe   -logfile  -ss_path  ./snapshots  -noprint  -callback  \n\n")

		// Callback mode: single callbackAccessor backed by the full kernel dump.
		mapper := NewGlobalMapper()
		endAddr := memDumpAddress + VAddr(programImageSize) - 1
		cbAcc := newCallbackAccessor(memDumpAddress, endAddr, MemSpaceAny)

		// The callback copies from program_image_buffer.
		// We replicate this with a simple Go closure.
		cbAcc.SetCallback(func(address VAddr, _ MemSpaceAcc, _ uint8, reqBytes uint32, buffer []byte) uint32 {
			bufEndAddress := memDumpAddress + VAddr(programImageSize) - 1
			if address < memDumpAddress || address > bufEndAddress {
				return 0
			}
			readBytes := reqBytes
			if address+VAddr(reqBytes)-1 > bufEndAddress {
				readBytes = uint32(bufEndAddress - (address - 1))
			}
			copy(buffer, kernelDump[address-memDumpAddress:])
			return readBytes
		})

		if err := mapper.AddAccessor(cbAcc); err != nil {
			t.Fatalf("AddAccessor cb: %v", err)
		}

		totalBytes := runMemBuffDemo(t, &sb, mapper)
		fmt.Fprintf(&sb, "Processed %d bytes out of %d\n", totalBytes, totalBytes)

		compareAgainstGolden(t, &sb, "testdata/mem_buff_demo_cb.ppl")
	})
}

func compareAgainstGolden(t *testing.T, sb *strings.Builder, goldenPath string) {
	t.Helper()

	expectedData, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden %s: %v", goldenPath, err)
	}

	actualNormalized := normalizeMemaccGoldenText(sb.String())
	expectedNormalized := normalizeMemaccGoldenText(string(expectedData))

	if actualNormalized == expectedNormalized {
		return
	}

	actualLines := strings.Split(actualNormalized, "\n")
	expectedLines := strings.Split(expectedNormalized, "\n")

	for i := 0; i < len(actualLines) && i < len(expectedLines); i++ {
		if actualLines[i] != expectedLines[i] {
			t.Fatalf("First line mismatch at line %d:\nExpected: %q\nActual:   %q",
				i+1, expectedLines[i], actualLines[i])
		}
	}
	if len(actualLines) != len(expectedLines) {
		t.Fatalf("Line count mismatch. Expected %d lines, got %d",
			len(expectedLines), len(actualLines))
	}
}

func normalizeMemaccGoldenText(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return memaccWindowsTestExePathRE.ReplaceAllString(s, "$1")
}
