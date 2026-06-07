package coresight

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"testing"
)

const cAPISnapshotDir = "cmd/trc_pkt_lister/testdata/juno_r1_1"

var cAPIWindowsTestExePathRE = regexp.MustCompile(`(?m)[A-Za-z]:\\[^\r\n]*\\(c_api_pkt_print_test\.exe)`)

func TestCAPIPacketPrintGolden(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("C-API packet print test\n")
	sb.WriteString("c_api_pkt_print_test.exe -ss_path ./snapshots -decode \n\n")

	mapper := NewGlobalMapper()
	kernelDump, err := os.ReadFile(cAPISnapshotDir + "/kernel_dump.bin")
	if err != nil {
		t.Fatalf("read kernel dump: %v", err)
	}
	acc := NewBufferAccessor(
		VAddr(0xffffffc000081000),
		kernelDump,
		MemSpaceAny,
		"./snapshots\\juno_r1_1\\kernel_dump.bin",
	)
	if err := mapper.AddAccessor(acc, BadCSSrcID); err != nil {
		t.Fatalf("add kernel dump accessor: %v", err)
	}
	sb.WriteString(mapper.DumpMappings())

	cfg := etmv4ParseConfig(
		0x00000010,
		0x000000c1,
		0x28000ea1,
		0x4100f402,
		0x00000488,
		0,
		0,
		0,
		0,
		0,
		0,
		ArchV8,
		ProfileCortexA,
	)
	dec, err := etmv4NewDecoder(cfg, mapper, DecodeInstruction)
	if err != nil {
		t.Fatalf("new ETMv4 decoder: %v", err)
	}

	pipe, err := NewPipeline(true, DemuxOptions{FrameMemAlign: true})
	if err != nil {
		t.Fatalf("new pipeline: %v", err)
	}
	pipe.AddRoute(Route{
		TraceID:  cfg.TraceID(),
		Protocol: ProtocolETMV4I,
		ByteSink: dec,
	})

	printer := cAPITracePrinter{writer: &sb}
	dec.SetPacketObserver(printer.ObservePacket)
	dec.SetTraceEndObserver(printer.ObserveTraceEnd)
	dec.SetElementSink(printer.PrintElement)

	total := runTrace(t, pipe, cAPISnapshotDir+"/cstrace.bin")
	if total != 65536 {
		t.Fatalf("processed trace bytes: got %d, want 65536", total)
	}

	compareGolden(t, sb.String(), "testdata/c_api_test.ppl")
}

type cAPITracePrinter struct {
	writer *strings.Builder
	elems  ElementFormatter
}

func (p cAPITracePrinter) ObservePacket(index uint64, pkt fmt.Stringer, rawData []byte) {
	if len(rawData) == 0 {
		return
	}
	formatted := pkt.String()
	if formatted == "" {
		return
	}
	fmt.Fprintf(p.writer, "Idx:%d;[", index)
	for _, b := range rawData {
		fmt.Fprintf(p.writer, " 0x%02X", b)
	}
	fmt.Fprintf(p.writer, " ];%s\n", formatted)
}

func (p cAPITracePrinter) PrintElement(elem Element) {
	fmt.Fprintf(p.writer, "Idx:%d; TrcID:0x%02X; %s\n", elem.Index, elem.TraceID, p.elems.FormatElement(elem))
}

func (p cAPITracePrinter) ObserveTraceEnd() {
	p.writer.WriteString("**** END OF TRACE ****\n")
}

func runTrace(t *testing.T, pipe *Pipeline, tracePath string) uint32 {
	t.Helper()

	traceFile, err := os.Open(tracePath)
	if err != nil {
		t.Fatalf("open trace file: %v", err)
	}
	defer traceFile.Close()

	const chunkSize = 2048
	buf := make([]byte, chunkSize)
	var total uint32
	for {
		n, readErr := traceFile.Read(buf)
		if n > 0 {
			if _, err := pipe.Write(Index(total), buf[:n]); err != nil {
				t.Fatalf("write trace chunk at %d: %v", total, err)
			}
			total += uint32(n)
		}
		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}
		if readErr != nil {
			t.Fatalf("read trace file: %v", readErr)
		}
	}
	if err := pipe.Close(); err != nil {
		t.Fatalf("close pipeline: %v", err)
	}
	return total
}

func filterEmptyLines(s string) string {
	lines := strings.Split(s, "\n")
	var filtered []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		filtered = append(filtered, line)
	}
	return strings.Join(filtered, "\n")
}

func compareGolden(t *testing.T, actual, goldenPath string) {
	t.Helper()

	expectedData, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden %s: %v", goldenPath, err)
	}

	actual = filterEmptyLines(normalizeCAPIGoldenText(actual))
	expected := filterEmptyLines(normalizeCAPIGoldenText(string(expectedData)))
	if actual == expected {
		return
	}

	actualLines := strings.Split(actual, "\n")
	expectedLines := strings.Split(expected, "\n")
	for i := 0; i < len(actualLines) && i < len(expectedLines); i++ {
		if actualLines[i] != expectedLines[i] {
			t.Fatalf("first line mismatch at line %d:\nexpected: %q\nactual:   %q", i+1, expectedLines[i], actualLines[i])
		}
	}
	t.Fatalf("line count mismatch: expected %d lines, got %d", len(expectedLines), len(actualLines))
}

func normalizeCAPIGoldenText(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return cAPIWindowsTestExePathRE.ReplaceAllString(s, "$1")
}
