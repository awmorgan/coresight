package itm_test

import (
	"fmt"
	"github.com/awmorgan/coresight/internal/itm"
	"github.com/awmorgan/coresight/internal/printers"
	"github.com/awmorgan/coresight/trace"
	"io"
	"os"
	"strings"
	"testing"
)

type byteBuilder struct {
	data []byte
}

func (b *byteBuilder) append(bytes ...byte) {
	b.data = append(b.data, bytes...)
}

func (b *byteBuilder) async() {
	b.append(0x00, 0x00, 0x00, 0x00, 0x00, 0x80)
}

func (b *byteBuilder) overflow() {
	b.append(0x70)
}

func (b *byteBuilder) swit1(chanNum byte, val byte) {
	hdr := ((chanNum & 0x1F) << 3) | 0x1
	b.append(byte(hdr), val)
}

func (b *byteBuilder) swit2(chanNum byte, val uint16) {
	hdr := ((chanNum & 0x1F) << 3) | 0x2
	b.append(byte(hdr), byte(val), byte(val>>8))
}

func (b *byteBuilder) swit4(chanNum byte, val uint32) {
	hdr := ((chanNum & 0x1F) << 3) | 0x3
	b.append(byte(hdr), byte(val), byte(val>>8), byte(val>>16), byte(val>>24))
}

func (b *byteBuilder) dwtEventCnt(flags byte) {
	hdr := ((0 & 0x1F) << 3) | 0x04 | 0x1
	b.append(byte(hdr), flags&0x3F)
}

func (b *byteBuilder) dwtExcepTrc(excepNum uint16, excepFn byte) {
	hdr := ((1 & 0x1F) << 3) | 0x04 | 0x2
	b.append(byte(hdr), byte(excepNum), byte(excepNum>>8)&0x1|(excepFn&0x3)<<4)
}

func (b *byteBuilder) dwtPCSample(pcVal uint32) {
	hdr := ((2 & 0x1F) << 3) | 0x04 | 0x3
	b.append(byte(hdr), byte(pcVal), byte(pcVal>>8), byte(pcVal>>16), byte(pcVal>>24))
}

func (b *byteBuilder) dwtPCSleep() {
	hdr := ((2 & 0x1F) << 3) | 0x04 | 0x1
	b.append(byte(hdr), 0)
}

func (b *byteBuilder) dwtDTPCVal(cmpn byte, pcVal uint32) {
	discID := ((cmpn & 0x3) << 1) | 0x4
	hdr := ((discID & 0x1F) << 3) | 0x04 | 0x3
	b.append(byte(hdr), byte(pcVal), byte(pcVal>>8), byte(pcVal>>16), byte(pcVal>>24))
}

func (b *byteBuilder) dwtDTAddr(cmpn byte, addrVal uint32) {
	discID := ((cmpn & 0x3) << 1) | 0x5
	hdr := ((discID & 0x1F) << 3) | 0x04 | 0x2
	b.append(byte(hdr), byte(addrVal), byte(addrVal>>8))
}

func (b *byteBuilder) dwtDTDataR8(cmpn byte, val byte) {
	discID := ((cmpn & 0x3) << 1) | 0x10
	hdr := ((discID & 0x1F) << 3) | 0x04 | 0x1
	b.append(byte(hdr), val)
}

func (b *byteBuilder) dwtDTDataR16(cmpn byte, val uint16) {
	discID := ((cmpn & 0x3) << 1) | 0x10
	hdr := ((discID & 0x1F) << 3) | 0x04 | 0x2
	b.append(byte(hdr), byte(val), byte(val>>8))
}

func (b *byteBuilder) dwtDTDataR32(cmpn byte, val uint32) {
	discID := ((cmpn & 0x3) << 1) | 0x10
	hdr := ((discID & 0x1F) << 3) | 0x04 | 0x3
	b.append(byte(hdr), byte(val), byte(val>>8), byte(val>>16), byte(val>>24))
}

func (b *byteBuilder) dwtDTDataW8(cmpn byte, val byte) {
	discID := ((cmpn & 0x3) << 1) | 0x11
	hdr := ((discID & 0x1F) << 3) | 0x04 | 0x1
	b.append(byte(hdr), val)
}

func (b *byteBuilder) dwtDTDataW16(cmpn byte, val uint16) {
	discID := ((cmpn & 0x3) << 1) | 0x11
	hdr := ((discID & 0x1F) << 3) | 0x04 | 0x2
	b.append(byte(hdr), byte(val), byte(val>>8))
}

func (b *byteBuilder) dwtDTDataW32(cmpn byte, val uint32) {
	discID := ((cmpn & 0x3) << 1) | 0x11
	hdr := ((discID & 0x1F) << 3) | 0x04 | 0x3
	b.append(byte(hdr), byte(val), byte(val>>8), byte(val>>16), byte(val>>24))
}

func (b *byteBuilder) ltsHdr20Sync(val byte) {
	b.append((val & 0x7) << 4)
}

func (b *byteBuilder) lts60(val uint32, tc byte) {
	hdr := ((tc & 0x3) << 4) | 0x80 | 0x40
	b.append(byte(hdr), byte(val&0x7F))
}

func (b *byteBuilder) lts130(val uint32, tc byte) {
	hdr := ((tc & 0x3) << 4) | 0x80 | 0x40
	b.append(byte(hdr), byte(val&0x7F)|0x80, byte((val>>7)&0x7F))
}

func (b *byteBuilder) lts200(val uint32, tc byte) {
	hdr := ((tc & 0x3) << 4) | 0x80 | 0x40
	b.append(byte(hdr), byte(val&0x7F)|0x80, byte((val>>7)&0x7F)|0x80, byte((val>>14)&0x7F))
}

func (b *byteBuilder) lts270(val uint32, tc byte) {
	hdr := ((tc & 0x3) << 4) | 0x80 | 0x40
	b.append(byte(hdr), byte(val&0x7F)|0x80, byte((val>>7)&0x7F)|0x80, byte((val>>14)&0x7F)|0x80, byte((val>>21)&0x7F))
}

func (b *byteBuilder) gts160(time uint32) {
	b.append(0x94, byte(time&0x7F))
}

func (b *byteBuilder) gts1130(time uint32) {
	b.append(0x94, byte(time&0x7F)|0x80, byte((time>>7)&0x7F))
}

func (b *byteBuilder) gts1200(time uint32) {
	b.append(0x94, byte(time&0x7F)|0x80, byte((time>>7)&0x7F)|0x80, byte((time>>14)&0x7F))
}

func (b *byteBuilder) gts1250Flags(time uint32, wrap, clkChange byte) {
	b.append(0x94,
		byte(time&0x7F)|0x80,
		byte((time>>7)&0x7F)|0x80,
		byte((time>>14)&0x7F)|0x80,
		byte((time>>21)&0x1F)|(wrap&0x1)<<6|(clkChange&0x1)<<5,
	)
}

func (b *byteBuilder) gts1250(time uint32) {
	b.gts1250Flags(time, 0, 0)
}

func (b *byteBuilder) gts248(time uint64) {
	b.append(0xB4,
		byte((time>>26)&0x7F)|0x80,
		byte((time>>33)&0x7F)|0x80,
		byte((time>>40)&0x7F)|0x80,
		byte((time>>47)&0x1),
	)
}

func (b *byteBuilder) gts264(time uint64) {
	b.append(0xB4,
		byte((time>>26)&0x7F)|0x80,
		byte((time>>33)&0x7F)|0x80,
		byte((time>>40)&0x7F)|0x80,
		byte((time>>47)&0x7F)|0x80,
		byte((time>>54)&0x7F)|0x80,
		byte((time>>61)&0x7),
	)
}

func (b *byteBuilder) extSwitPage(page byte) {
	b.append(((page & 0x7) << 4) | 0x08)
}

func buildTest0() []byte {
	b := &byteBuilder{data: []byte{
		0xF0, 0x00, 0x00, 0x34,
		0x00, 0x12, 0x33, 0x44,
		0x12, 0x43, 0x55, 0x66,
		0x22, 0x77, 0x88, 0x99,
	}}
	b.async()
	b.overflow()
	b.swit1(3, 0xBB)
	b.ltsHdr20Sync(2)
	return b.data
}

func buildTest1() []byte {
	b := &byteBuilder{}
	b.async()
	b.swit1(1, 0xAC)
	b.ltsHdr20Sync(2)
	b.swit2(1, 0x2345)
	b.swit4(1, 0x67890123)
	b.lts60(13, 1)
	return b.data
}

func buildTest2() []byte {
	b := &byteBuilder{}
	b.async()
	b.dwtEventCnt(0x15)
	b.lts200(0x12402, 0)
	b.dwtExcepTrc(4, 1)
	b.lts130(0x3220, 1)
	b.dwtPCSample(0x1000)
	b.lts130(0x1342, 2)
	b.dwtPCSample(0x1080)
	b.dwtPCSleep()
	b.overflow()
	b.dwtDTDataR8(1, 0x44)
	b.lts270(0x7543F5E, 3)
	b.dwtDTDataR16(0, 0x5566)
	b.lts60(0x78, 0)
	b.dwtDTDataR32(2, 0x778899AA)
	b.ltsHdr20Sync(6)
	b.dwtExcepTrc(0x123, 2)
	b.ltsHdr20Sync(3)
	b.dwtExcepTrc(3, 3)
	b.dwtDTPCVal(3, 0x2000)
	b.dwtDTAddr(0, 0x12340322)
	b.dwtDTDataW8(0, 0x11)
	b.ltsHdr20Sync(4)
	b.dwtDTDataW16(1, 0x2233)
	b.ltsHdr20Sync(3)
	b.dwtDTDataW32(2, 0x44556677)
	b.ltsHdr20Sync(2)
	return b.data
}

func buildTest3() []byte {
	b := &byteBuilder{}
	b.async()
	b.overflow()
	b.swit1(0xA, 0xAC)
	b.ltsHdr20Sync(2)
	b.extSwitPage(2)
	b.swit2(0xA, 0x2345)
	b.extSwitPage(4)
	b.swit4(0xB, 0x67890123)
	b.extSwitPage(0)
	b.swit2(0xA, 0x32FE)
	return b.data
}

func buildTest4() []byte {
	b := &byteBuilder{}
	b.async()
	b.overflow()
	b.gts1250(0xF23456)
	b.gts264(0x1020304C000000)
	b.swit2(0x10, 0x1234)
	b.gts160(0x7A)
	b.swit4(0x10, 0x56789ABC)
	b.gts1130(0x16712)
	b.swit2(0x11, 0x9876)
	b.gts1200(0x42353)
	b.swit4(0x11, 0x54321ADC)
	b.gts1250(0x2FEA782)
	b.swit2(0x11, 0xA5A5)
	b.gts1250Flags(0x2FEA782, 1, 1)
	b.swit2(0x11, 0xB6B6)
	b.gts264(0x1020304F000000)
	b.swit2(0x11, 0xC7C7)
	b.gts1250Flags(0x343923A, 1, 0)
	b.swit2(0x11, 0xC7C7)
	b.gts160(0xDD)
	b.swit2(0x11, 0xD8D8)
	b.gts264(0x10203050000000)
	b.swit2(0x11, 0xE9E9)
	b.gts1130(0x3451)
	b.swit2(0x10, 0xF0F0)
	b.gts1250Flags(0x03AFE32, 1, 0)
	b.gts248(0x123458000000)
	b.swit2(0x10, 0x0101)
	return b.data
}

type itmRawPrinter struct {
	writer io.Writer
	id     uint8
}

func (p *itmRawPrinter) ObservePacket(indexSOP trace.Index, pkt fmt.Stringer, rawData []byte) {
	if len(rawData) == 0 {
		return
	}
	formattedPkt := pkt.String()
	if formattedPkt == "" {
		return
	}
	fmt.Fprintf(p.writer, "Idx:%d; ID:%d; [", indexSOP, p.id)
	for _, b := range rawData {
		fmt.Fprintf(p.writer, "0x%02x ", b)
	}
	fmt.Fprintf(p.writer, "];\t%s\n", formattedPkt)
}

func (p *itmRawPrinter) ObserveTraceEnd() {
	fmt.Fprintf(p.writer, "ID:%d\tEND OF TRACE DATA\n", p.id)
}

func (p *itmRawPrinter) PrintTraceReset() {
	fmt.Fprintf(p.writer, "ID:%d\tRESET operation on trace decode path\n", p.id)
}

func TestTraceItmGoldens(t *testing.T) {
	var sb strings.Builder
	logMsg := func(format string, a ...any) {
		fmt.Fprintf(&sb, format, a...)
	}

	logMsg("ITM decode test\n")
	logMsg("-----------------------------------------------\n\n")

	type testCase struct {
		name string
		desc string
		data []byte
	}

	tests := []testCase{
		{"test0", "Test arbitrary data before ASYNC, short sequence after", buildTest0()},
		{"test1", "test of various SWIT and local TS packets", buildTest1()},
		{"test2", "test DWT packets and LTS types.", buildTest2()},
		{"test3", "test SWIT with channel extension", buildTest3()},
		{"test4", "test GTS clock packets in SWIT sequence", buildTest4()},
	}

	var traceIndex trace.Index = 0

	cfg := &itm.Config{RegTCR: 0}
	decoder, err := itm.NewDecoder(cfg)
	if err != nil {
		t.Fatalf("Failed to create decoder: %v", err)
	}

	mon := &itmRawPrinter{writer: &sb, id: 0}
	decoder.SetPacketObserver(mon.ObservePacket)
	decoder.SetTraceEndObserver(mon.ObserveTraceEnd)

	elemPrinter := printers.NewGenericElementPrinter(&sb)
	decoder.SetElementSink(elemPrinter.PrintElement)

	for _, tc := range tests {
		logMsg("\nRunning test %s - %s;...\n", tc.name, tc.desc)

		// Process trace data block
		var processed uint32
		processed, err = decoder.Write(traceIndex, tc.data)
		if err != nil {
			t.Fatalf("Error writing data for test %s: %v", tc.name, err)
		}
		traceIndex += trace.Index(processed)

		// OP_EOT
		_ = decoder.Close()
		mon.PrintTraceReset()

		// OP_RESET
		_ = decoder.Reset(0)

		logMsg("\nTest %s complete.\n", tc.name)
	}

	logMsg("All tests complete\n")

	// Read and verify against golden file
	expectedData, err := os.ReadFile("testdata/itm-decode-test.ppl")
	if err != nil {
		t.Fatalf("Failed to read golden file: %v", err)
	}

	expectedStr := string(expectedData)
	filterEmptyLines := func(s string) string {
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
	actualNormalized := filterEmptyLines(strings.ReplaceAll(sb.String(), "\r\n", "\n"))
	expectedNormalized := filterEmptyLines(strings.ReplaceAll(expectedStr, "\r\n", "\n"))

	if actualNormalized != expectedNormalized {
		t.Errorf("Output mismatch.\n=== EXPECTED ===\n%s\n=== ACTUAL ===\n%s\n", expectedNormalized, actualNormalized)
		actualLines := strings.Split(actualNormalized, "\n")
		expectedLines := strings.Split(expectedNormalized, "\n")
		for i := 0; i < len(actualLines) && i < len(expectedLines); i++ {
			if actualLines[i] != expectedLines[i] {
				t.Fatalf("First line mismatch at line %d:\nExpected: %q\nActual:   %q", i+1, expectedLines[i], actualLines[i])
			}
		}
		if len(actualLines) != len(expectedLines) {
			t.Fatalf("Line count mismatch. Expected %d lines, got %d", len(expectedLines), len(actualLines))
		}
	}
}
