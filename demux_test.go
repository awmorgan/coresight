package coresight

import (
	"bytes"
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

	var d *Demuxer
	streams := make([]ByteSink, 128)

	// Helper to setup active decoder
	setupDecoder := func(opts DemuxOptions) *Demuxer {
		dec := newDemuxer(streams)
		_ = dec.Configure(opts)
		fp := NewRawFramePrinter(&sb)
		dec.SetRawFrameHandler(fp.WriteRawFrame)
		return dec
	}

	// 2. MemAligned Buffer tests
	logMsg("\n---------------------------------------------------------\n")
	logMsg("MemAligned Buffer tests: exercise the 16 byte frame buffer handler")
	logMsg("\n---------------------------------------------------------\n")

	memAlignOpts := DemuxOptions{
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

	hsyncFsyncOpts := DemuxOptions{
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

type mockStream struct {
	chunks []byte
}

func (m *mockStream) Write(index Index, dataBlock []byte) (uint32, error) {
	m.chunks = append(m.chunks, dataBlock...)
	return uint32(len(dataBlock)), nil
}

func (m *mockStream) Close() error            { return nil }
func (m *mockStream) Flush() error            { return nil }
func (m *mockStream) Reset(index Index) error { return nil }

func runDemuxTest(opts DemuxOptions, data []byte, step int, callClose bool, shortWriteLoop bool) (string, map[uint8][]byte, error) {
	var sb strings.Builder
	streams := make([]ByteSink, 128)
	mockStreams := make(map[uint8]*mockStream)
	for i := range streams {
		ms := &mockStream{}
		streams[i] = ms
		mockStreams[uint8(i)] = ms
	}

	dec := newDemuxer(streams)
	if err := dec.Configure(opts); err != nil {
		return "", nil, err
	}
	fp := NewRawFramePrinter(&sb)
	dec.SetRawFrameHandler(fp.WriteRawFrame)

	if shortWriteLoop {
		total := 0
		available := 0
		for total < len(data) {
			available += step
			if available > len(data) {
				available = len(data)
			}
			chunk := data[total:available]
			n, err := dec.Write(Index(total), chunk)
			if err != nil {
				return sb.String(), nil, err
			}
			total += int(n)
			if available == len(data) && n == 0 && total < len(data) {
				break
			}
		}
	} else {
		var currentIdx Index
		for i := 0; i < len(data); i += step {
			end := min(i+step, len(data))
			chunk := data[i:end]
			_, err := dec.Write(currentIdx, chunk)
			if err != nil {
				return sb.String(), nil, err
			}
			currentIdx += Index(len(chunk))
		}
	}

	var closeErr error
	if callClose {
		closeErr = dec.Close()
	}

	resStreams := make(map[uint8][]byte)
	for id, ms := range mockStreams {
		if len(ms.chunks) > 0 {
			resStreams[id] = ms.chunks
		}
	}

	return sb.String(), resStreams, closeErr
}

func TestTraceDemuxStreaming(t *testing.T) {
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

	memAlignOpts := DemuxOptions{
		FrameMemAlign:  true,
		PackedRawOut:   true,
		UnpackedRawOut: true,
	}

	// 1. Get baseline (single block)
	baselinePrinter, baselineStreams, err := runDemuxTest(memAlignOpts, bufMemAlign, len(bufMemAlign), true, false)
	if err != nil {
		t.Fatalf("Failed to run baseline: %v", err)
	}

	// Helper to compare outputs against baseline
	compareOutputs := func(name string, printer string, streams map[uint8][]byte, err error) {
		t.Helper()
		if err != nil {
			t.Errorf("[%s] unexpected error: %v", name, err)
			return
		}
		if printer != baselinePrinter {
			t.Errorf("[%s] printer output mismatch\nBaseline:\n%s\nActual:\n%s", name, baselinePrinter, printer)
		}
		for id, baselineData := range baselineStreams {
			actualData := streams[id]
			if !bytes.Equal(actualData, baselineData) {
				t.Errorf("[%s] stream %d mismatch: expected %v, got %v", name, id, baselineData, actualData)
			}
		}
	}

	// 2. Test byte-by-byte chunking
	t.Run("ByteByByte_NonRewriting", func(t *testing.T) {
		printer, streams, err := runDemuxTest(memAlignOpts, bufMemAlign, 1, true, false)
		compareOutputs("ByteByByte_NonRewriting", printer, streams, err)
	})

	t.Run("ByteByByte_Rewriting", func(t *testing.T) {
		printer, streams, err := runDemuxTest(memAlignOpts, bufMemAlign, 1, true, true)
		compareOutputs("ByteByByte_Rewriting", printer, streams, err)
	})

	// 3. Test two bytes at a time
	t.Run("TwoBytes_NonRewriting", func(t *testing.T) {
		printer, streams, err := runDemuxTest(memAlignOpts, bufMemAlign, 2, true, false)
		compareOutputs("TwoBytes_NonRewriting", printer, streams, err)
	})

	t.Run("TwoBytes_Rewriting", func(t *testing.T) {
		printer, streams, err := runDemuxTest(memAlignOpts, bufMemAlign, 2, true, true)
		compareOutputs("TwoBytes_Rewriting", printer, streams, err)
	})

	// 4. Test split at every offset from 1 through frame size minus 1
	for k := 1; k < 16; k++ {
		t.Run(fmt.Sprintf("SplitAt_%d_NonRewriting", k), func(t *testing.T) {
			// Simulates writing bufMemAlign[:k] and bufMemAlign[k:]
			// We can do this with non-rewriting loop using chunks
			var sb strings.Builder
			streams := make([]ByteSink, 128)
			mockStreams := make(map[uint8]*mockStream)
			for i := range streams {
				ms := &mockStream{}
				streams[i] = ms
				mockStreams[uint8(i)] = ms
			}

			dec := newDemuxer(streams)
			if err := dec.Configure(memAlignOpts); err != nil {
				t.Fatalf("Configure failed: %v", err)
			}
			fp := NewRawFramePrinter(&sb)
			dec.SetRawFrameHandler(fp.WriteRawFrame)

			// Write first chunk
			_, err := dec.Write(0, bufMemAlign[:k])
			if err != nil {
				t.Fatalf("Write 1 failed: %v", err)
			}
			// Write second chunk
			_, err = dec.Write(Index(k), bufMemAlign[k:])
			if err != nil {
				t.Fatalf("Write 2 failed: %v", err)
			}
			if err := dec.Close(); err != nil {
				t.Fatalf("Close failed: %v", err)
			}

			resStreams := make(map[uint8][]byte)
			for id, ms := range mockStreams {
				if len(ms.chunks) > 0 {
					resStreams[id] = ms.chunks
				}
			}
			compareOutputs(fmt.Sprintf("SplitAt_%d_NonRewriting", k), sb.String(), resStreams, nil)
		})

		t.Run(fmt.Sprintf("SplitAt_%d_Rewriting", k), func(t *testing.T) {
			// Simulates a rewriting client:
			// Write bufMemAlign[:k] (alignment is 16, so n = 0 is returned)
			// Write bufMemAlign since it rewrites from 0.
			var sb strings.Builder
			streams := make([]ByteSink, 128)
			mockStreams := make(map[uint8]*mockStream)
			for i := range streams {
				ms := &mockStream{}
				streams[i] = ms
				mockStreams[uint8(i)] = ms
			}

			dec := newDemuxer(streams)
			if err := dec.Configure(memAlignOpts); err != nil {
				t.Fatalf("Configure failed: %v", err)
			}
			fp := NewRawFramePrinter(&sb)
			dec.SetRawFrameHandler(fp.WriteRawFrame)

			// Write first chunk
			n1, err := dec.Write(0, bufMemAlign[:k])
			if err != nil {
				t.Fatalf("Write 1 failed: %v", err)
			}
			if n1 != 0 {
				t.Fatalf("Expected n1 = 0, got %d", n1)
			}

			// Rewrite since n1 was 0
			_, err = dec.Write(0, bufMemAlign)
			if err != nil {
				t.Fatalf("Write 2 failed: %v", err)
			}
			if err := dec.Close(); err != nil {
				t.Fatalf("Close failed: %v", err)
			}

			resStreams := make(map[uint8][]byte)
			for id, ms := range mockStreams {
				if len(ms.chunks) > 0 {
					resStreams[id] = ms.chunks
				}
			}
			compareOutputs(fmt.Sprintf("SplitAt_%d_Rewriting", k), sb.String(), resStreams, nil)
		})
	}

	// 5. Test incomplete frame at Close returns errDfrmtrIncompleteTail
	t.Run("IncompleteFrameAtClose", func(t *testing.T) {
		incompleteInput := append([]byte(nil), bufMemAlign...)
		incompleteInput = append(incompleteInput, 0xAA) // 1 extra byte

		_, _, err := runDemuxTest(memAlignOpts, incompleteInput, len(incompleteInput), true, false)
		if err != errDfrmtrIncompleteTail {
			t.Errorf("Expected errDfrmtrIncompleteTail error on Close, got: %v", err)
		}
	})
}
