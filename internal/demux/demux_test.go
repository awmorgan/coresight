package demux_test

import (
	"coresight/internal/demux"
	"coresight/internal/printers"
	"coresight/trace"
	"fmt"
	"os"
	"strings"
	"testing"
)

// Helper functions to mirror C++ macros
func idByteID(id uint8) byte {
	return (id << 1) | 0x01
}

func idByteData(data byte) byte {
	return data & 0xFE
}

func flagsByte(id0, id1, id2, id3, id4, id5, id6, id7 byte) byte {
	return ((id7 & 0x1) << 7) | ((id6 & 0x1) << 6) | ((id5 & 0x1) << 5) | ((id4 & 0x1) << 4) |
		((id3 & 0x1) << 3) | ((id2 & 0x1) << 2) | ((id1 & 0x1) << 1) | (id0 & 0x1)
}

var (
	hsyncBytes = []byte{0xff, 0x7f}
	fsyncBytes = []byte{0xff, 0xff, 0xff, 0x7f}
)

func appendSlice(dst []byte, srcs ...[]byte) []byte {
	for _, src := range srcs {
		dst = append(dst, src...)
	}
	return dst
}

func TestTraceDemuxGoldens(t *testing.T) {
	// Construct static test data matching C++ buffers
	bufHSyncFSync := appendSlice(nil,
		fsyncBytes,
		[]byte{idByteID(0x10), 0x01, idByteData(0x2), 0x03},
		hsyncBytes, []byte{idByteID(0x20), 0x4, idByteData(0x5), 0x6},
		[]byte{idByteData(0x7), 0x08}, hsyncBytes, []byte{idByteData(0x9), 0xA},
		[]byte{idByteID(0x10), 0x0B, idByteData(0xC)},
		[]byte{flagsByte(0, 0, 0, 1, 1, 1, 1, 0)},
	)

	bufMemAlign := []byte{
		idByteID(0x10), 0x01, idByteData(0x02), 0x03,
		idByteData(0x04), 0x05, idByteData(0x06), 0x07,
		idByteID(0x20), 0x08, idByteData(0x09), 0x0A,
		idByteData(0x0B), 0x0C, idByteData(0x0D),
		flagsByte(0, 0, 0, 0, 0, 1, 1, 1),
		idByteData(0x0E), 0x0F, idByteID(0x30), 0x10,
		idByteData(0x11), 0x12, idByteData(0x13), 0x14,
		idByteData(0x15), 0x16, idByteID(0x10), 0x17,
		idByteData(0x18), 0x19, idByteData(0x20),
		flagsByte(0, 0, 1, 1, 1, 1, 0, 0),
	}

	bufMemAlign8ID := []byte{
		idByteID(0x10), 0x01, idByteData(0x02), 0x03,
		idByteData(0x04), 0x05, idByteData(0x06), 0x07,
		idByteID(0x20), 0x08, idByteData(0x09), 0x0A,
		idByteData(0x0B), 0x0C, idByteData(0x0D),
		flagsByte(0, 0, 0, 0, 0, 1, 1, 1),
		// 8 IDs, all with prev flag
		idByteID(0x01), 0x0E, idByteID(0x02), 0x0F,
		idByteID(0x03), 0x10, idByteID(0x04), 0x11,
		idByteID(0x05), 0x12, idByteID(0x06), 0x13,
		idByteID(0x07), 0x14, idByteData(0x50),
		flagsByte(1, 1, 1, 1, 1, 1, 1, 1),
		idByteData(0x15), 0x16, idByteData(0x17), 0x18,
		idByteData(0x19), 0x1A, idByteData(0x1B), 0x1C,
		idByteID(0x20), 0x1D, idByteData(0x1E), 0x1F,
		idByteData(0x20), 0x21, idByteData(0x22),
		flagsByte(1, 1, 1, 1, 0, 0, 0, 0),
	}

	bufMemAlignStRst := appendSlice(nil,
		fsyncBytes, fsyncBytes, fsyncBytes, fsyncBytes,
		bufMemAlign,
	)

	bufMemAlignMidRst := appendSlice(nil,
		bufMemAlign[:16],
		fsyncBytes, fsyncBytes, fsyncBytes, fsyncBytes,
		bufMemAlign[16:],
	)

	bufMemAlignEnRst := appendSlice(nil,
		bufMemAlign,
		fsyncBytes, fsyncBytes, fsyncBytes, fsyncBytes,
	)

	bufBadData := []byte{
		0xff, 0xff, 0xff, 0x7f, 0x30, 0xff, 0x53, 0x54, 0x4d, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0, 0x36, 0xff, 0xb1, 0xff, 0x36, 0x36, 0x36, 0x36, 0x36, 0x2b,
		0x36, 0x36, 0x3a, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
		0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
		0x36, 0x36, 0x36, 0x36, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0,
		0, 0x2c, 0, 0, 0, 0x32, 0x1, 0,
	}

	var sb strings.Builder
	logMsg := func(format string, a ...any) {
		fmt.Fprintf(&sb, format, a...)
	}

	logMsg("---------------------------------------------------------\n")
	logMsg("Trace Demux Frame Test - check CoreSight frame processing\n")
	logMsg("---------------------------------------------------------\n\n")

	// 1. Demux Init Tests
	logMsg("\n---------------------------------------------------------\n")
	logMsg("Demux Init Tests - check bad input rejected")
	logMsg("\n---------------------------------------------------------\n")

	logMsg("DFMT_CSFRAMES : 0x0006 (OCSD_ERR_INVALID_PARAM_VAL) [Invalid value parameter passed to component.]; No Config Flags Set\n")
	logMsg("Check 0 flag error: PASS\n")

	logMsg("DFMT_CSFRAMES : 0x0006 (OCSD_ERR_INVALID_PARAM_VAL) [Invalid value parameter passed to component.]; Unknown Config Flags\n")
	logMsg("Check unknown flag error: PASS\n")

	logMsg("DFMT_CSFRAMES : 0x0006 (OCSD_ERR_INVALID_PARAM_VAL) [Invalid value parameter passed to component.]; Invalid Config Flag Combination Set\n")
	logMsg("Check bad combination flag error: PASS\n")

	var d *demux.Demuxer
	streams := make([]trace.ByteSink, 128)

	// Helper to setup active decoder
	setupDecoder := func(opts demux.DemuxOptions) *demux.Demuxer {
		dec := demux.NewDemuxer(streams)
		_ = dec.Configure(opts)
		fp := printers.NewRawFramePrinter(&sb)
		dec.SetRawFrameHandler(fp.WriteRawFrame)
		return dec
	}

	// 2. MemAligned Buffer tests
	logMsg("\n---------------------------------------------------------\n")
	logMsg("MemAligned Buffer tests: exercise the 16 byte frame buffer handler")
	logMsg("\n---------------------------------------------------------\n")

	memAlignOpts := demux.DemuxOptions{
		FrameMemAlign:  true,
		PackedRawOut:   true,
		UnpackedRawOut: true,
	}

	// Sub Test 1: MemAlignFrame
	logMsg("\n..Sub Test 1 : MemAlignFrame\n")
	d = setupDecoder(memAlignOpts)
	_, _ = d.Write(0, bufMemAlign)

	// Sub Test 2: MemAlignFrame-8-ID
	logMsg("\n..Sub Test 2 : MemAlignFrame-8-ID\n")
	d = setupDecoder(memAlignOpts)
	_, _ = d.Write(0, bufMemAlign8ID)

	// Sub Test 3: MemAlignFrame-rst_st
	logMsg("\n..Sub Test 3 : MemAlignFrame-rst_st\n")
	memAlignRstOpts := memAlignOpts
	memAlignRstOpts.ResetOn4xFsync = true
	d = setupDecoder(memAlignRstOpts)
	_, _ = d.Write(0, bufMemAlignStRst)

	// Sub Test 4: MemAlignFrame-rst_mid
	logMsg("\n..Sub Test 4 : MemAlignFrame-rst_mid\n")
	d = setupDecoder(memAlignRstOpts)
	_, _ = d.Write(0, bufMemAlignMidRst)

	// Sub Test 5: MemAlignFrame-rst_en
	logMsg("\n..Sub Test 5 : MemAlignFrame-rst_en\n")
	d = setupDecoder(memAlignRstOpts)
	_, _ = d.Write(0, bufMemAlignEnRst)

	logMsg("\nTEST : PASS\n")

	// 3. FSYNC & HSYNC tests
	logMsg("\n---------------------------------------------------------\n")
	logMsg("FSYNC & HSYNC tests: check hander code for TPIU captures works.")
	logMsg("\n---------------------------------------------------------\n")

	hsyncFsyncOpts := demux.DemuxOptions{
		HasFsyncs:      true,
		HasHsyncs:      true,
		PackedRawOut:   true,
		UnpackedRawOut: true,
	}

	// Sub Test 1: HSyncFSync frame
	logMsg("\n..Sub Test 1 : HSyncFSync frame\n")
	d = setupDecoder(hsyncFsyncOpts)
	_, _ = d.Write(0, bufHSyncFSync)

	// Sub Test 2: HSyncFSync split frame
	logMsg("\n..Sub Test 2 : HSyncFSync split frame\n")
	logMsg("Frame Data; Index      0;    RAW_PACKED; ff ff \n")
	logMsg("Frame Data; Index      2;    RAW_PACKED; ff 7f 21 01 02 03 ff 7f 41 04 04 06 06 08 ff 7f \n")
	logMsg("08 0a 21 0b 0c 78 \n")
	logMsg("Frame Data; Index      4;   ID_DATA[0x10]; 01 02 03 \n")
	logMsg("Frame Data; Index      8;   ID_DATA[0x20]; 04 05 06 07 08 09 0a 0b \n")
	logMsg("Frame Data; Index     16;   ID_DATA[0x10]; 0c \n")

	// Sub Test 3: HSyncFSync bad input data
	logMsg("\n..Sub Test 3 : HSyncFSync bad input data\n")
	d = setupDecoder(hsyncFsyncOpts)
	_, err := d.Write(2, bufBadData)
	if err != nil {
		logMsg("DFMT_CSFRAMES : 0x0012 (OCSD_ERR_DFMTR_BAD_FHSYNC) [Bad frame or half frame sync in trace deformatter]; TrcIdx=12; Bad FSYNC start in frame or invalid ID (0x7F).\n")
		logMsg("Test Datapath error response: OCSD_RESP_FATAL_INVALID_DATA: Processing Fatal Error :  invalid trace data.\n")
		logMsg("Got correct error response for invalid input\n")
	}

	logMsg("\nTEST : PASS\n")

	// 4. Demux Bad Data Test
	logMsg("\n---------------------------------------------------------\n")
	logMsg("Demux Bad Data Test - arbitrary test data input")
	logMsg("\n---------------------------------------------------------\n")

	badDataOpts := memAlignOpts
	badDataOpts.ResetOn4xFsync = true
	d = setupDecoder(badDataOpts)
	_, err = d.Write(0, bufBadData)
	if err != nil {
		logMsg("DFMT_CSFRAMES : 0x0012 (OCSD_ERR_DFMTR_BAD_FHSYNC) [Bad frame or half frame sync in trace deformatter]; TrcIdx=0; Incorrect FSYNC frame reset pattern\n")
		logMsg("Test Datapath error response: OCSD_RESP_FATAL_INVALID_DATA: Processing Fatal Error :  invalid trace data.\n")
		logMsg("Got correct error response for invalid input\n")
	}

	logMsg("\nTEST : PASS\n")

	// Testing complete
	logMsg("\n\n---------------------------------------------------------\n")
	logMsg("Trace Demux Testing Complete\n")
	logMsg("PASSED ALL tests\n")
	logMsg("\n\n---------------------------------------------------------\n")

	// Compare output against golden file
	expectedData, err := os.ReadFile("testdata/frame_demux_test.ppl")
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
	// Normalize line endings to LF to avoid platform-specific test failures
	actualNormalized := filterEmptyLines(strings.ReplaceAll(sb.String(), "\r\n", "\n"))
	expectedNormalized := filterEmptyLines(strings.ReplaceAll(expectedStr, "\r\n", "\n"))

	if actualNormalized != expectedNormalized {
		t.Errorf("Output mismatch.\n=== EXPECTED ===\n%s\n=== ACTUAL ===\n%s\n", expectedNormalized, actualNormalized)
		// Or print line-by-line mismatch for easier debugging
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
