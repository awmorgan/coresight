package main

import (
	"bufio"
	"compress/gzip"
	"github.com/awmorgan/coresight/internal/memacc"
	"github.com/awmorgan/coresight/internal/snapshot"
	"github.com/awmorgan/coresight/internal/testutil"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

var (
	reDeviceSuffix = regexp.MustCompile(`(?i)(?:_|-dcd-)0x([0-9a-f]+)$`)
)

// goldenBoolFlags is the canonical set of boolean behavioral flags that
// parseOptionsFromGolden recognises and forwards verbatim into extraFlags.
// It mirrors every boolean flag in parseOptions that materially affects decode
// output and should therefore be re-applied when replaying a golden test case.
var goldenBoolFlags = map[string]struct{}{
	"-multi_session":   {},
	"-dstream_format":  {},
	"-tpiu":            {},
	"-tpiu_hsync":      {},
	"-aa64_opcode_chk": {},
	"-o_raw_packed":    {},
	"-o_raw_unpacked":  {},
	"-pkt_mon":         {},
	"-src_addr_n":      {},
}

// goldenValueFlags is the canonical set of flags that take a single value
// argument and should be forwarded as "flag value" pairs into extraFlags.
var goldenValueFlags = map[string]struct{}{
	"-instr_range_limit": {},
}

type listerGoldenCase struct {
	name        string
	goldenPath  string
	snapshotDir string
	sourceName  string
	id          string
	decode      bool
	extraFlags  []string
}

type listerGoldenManifestEntry struct {
	decoder      string
	goldenName   string
	snapshotName string
}

func TestTraceListerGoldens(t *testing.T) {
	testCases := explicitTraceListerGoldenCases(t)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			args := []string{
				"-ss_dir", tc.snapshotDir,
				"-logfilename", filepath.Join(t.TempDir(), "out.ppl"),
				"-no_time_print",
			}
			if tc.sourceName != "" {
				args = append(args, "-src_name", tc.sourceName)
			}
			if tc.id != "" {
				args = append(args, "-id", tc.id)
			}
			args = append(args, tc.extraFlags...)
			if tc.decode {
				args = append(args, "-decode")
			}

			outPath := args[3]
			err := run(args)
			if err != nil {
				t.Fatalf("run(%v) failed: %v", args, err)
			}

			gotLines, err := comparableTraceListerOutputFromFile(outPath)
			if err != nil {
				t.Fatalf("parse generated output %s: %v", outPath, err)
			}
			wantLines, err := comparableTraceListerOutputFromFile(tc.goldenPath)
			if err != nil {
				t.Fatalf("parse golden %s: %v", tc.goldenPath, err)
			}

			if diffIdx, gotLine, wantLine := testutil.FirstDiff(gotLines, wantLines); diffIdx != 0 {
				t.Errorf("Output mismatch at line %d\nwant: %s\n got: %s", diffIdx, wantLine, gotLine)
				// output files for debugging and comparing files
				repoRoot := filepath.Join("..", "..")
				gotBytes, err := os.ReadFile(outPath)
				if err != nil {
					t.Fatalf("read generated output %s: %v", outPath, err)
				}
				wantBytes, err := os.ReadFile(tc.goldenPath)
				if err != nil {
					t.Fatalf("read golden %s: %v", tc.goldenPath, err)
				}
				if err := os.WriteFile(filepath.Join(repoRoot, "got.txt"), gotBytes, 0644); err != nil {
					t.Fatalf("copy generated output %s to got.txt: %v", outPath, err)
				}
				if err := os.WriteFile(filepath.Join(repoRoot, "want.txt"), wantBytes, 0644); err != nil {
					t.Fatalf("copy golden %s to want.txt: %v", tc.goldenPath, err)
				}
			}

			if t.Failed() {
				t.FailNow()
			}
		})
	}
}

func explicitTraceListerGoldenCases(t *testing.T) []listerGoldenCase {
	t.Helper()

	manifest := []listerGoldenManifestEntry{
		{decoder: "ete", goldenName: "001-ack_test", snapshotName: "001-ack_test"},
		{decoder: "ete", goldenName: "002-ack_test_scr", snapshotName: "002-ack_test_scr"},
		{decoder: "ete", goldenName: "002-ack_test_scr_src_addr_N", snapshotName: "002-ack_test_scr"},
		{decoder: "ete", goldenName: "ete-bc-instr", snapshotName: "ete-bc-instr"},
		{decoder: "ete", goldenName: "ete-ite-instr", snapshotName: "ete-ite-instr"},
		{decoder: "ete", goldenName: "ete-ite-instr_multi_sess", snapshotName: "ete-ite-instr"},
		{decoder: "ete", goldenName: "ete-wfet", snapshotName: "ete-wfet"},
		{decoder: "ete", goldenName: "ete_ip", snapshotName: "ete_ip"},
		{decoder: "ete", goldenName: "ete_ip_src_addr_N", snapshotName: "ete_ip"},
		{decoder: "ete", goldenName: "ete_mem", snapshotName: "ete_mem"},
		{decoder: "ete", goldenName: "ete_spec_1", snapshotName: "ete_spec_1"},
		{decoder: "ete", goldenName: "ete_spec_2", snapshotName: "ete_spec_2"},
		{decoder: "ete", goldenName: "ete_spec_3", snapshotName: "ete_spec_3"},
		{decoder: "ete", goldenName: "event_test", snapshotName: "event_test"},
		{decoder: "ete", goldenName: "feat_cmpbr", snapshotName: "feat_cmpbr"},
		{decoder: "ete", goldenName: "infrastructure", snapshotName: "infrastructure"},
		{decoder: "ete", goldenName: "maxspec0_commopt1", snapshotName: "maxspec0_commopt1"},
		{decoder: "ete", goldenName: "maxspec78_commopt0", snapshotName: "maxspec78_commopt0"},
		{decoder: "ete", goldenName: "pauth_lr", snapshotName: "pauth_lr"},
		{decoder: "ete", goldenName: "pauth_lr_Rm", snapshotName: "pauth_lr_Rm"},
		{decoder: "ete", goldenName: "pauth_lr_Rm_multi_sess", snapshotName: "pauth_lr_Rm"},
		{decoder: "ete", goldenName: "pauth_lr_multi_sess", snapshotName: "pauth_lr"},
		{decoder: "ete", goldenName: "q_elem", snapshotName: "q_elem"},
		{decoder: "ete", goldenName: "q_elem_multi_sess", snapshotName: "q_elem"},
		{decoder: "ete", goldenName: "rme_test", snapshotName: "rme_test"},
		{decoder: "ete", goldenName: "rme_test_multi_sess", snapshotName: "rme_test"},
		{decoder: "ete", goldenName: "s_9001", snapshotName: "s_9001"},
		{decoder: "ete", goldenName: "s_9001_multi_sess", snapshotName: "s_9001"},
		{decoder: "ete", goldenName: "src_addr", snapshotName: "src_addr"},
		{decoder: "ete", goldenName: "src_addr_src_addr_N", snapshotName: "src_addr"},
		{decoder: "ete", goldenName: "ss_ib_el1ns", snapshotName: "ss_ib_el1ns"},
		{decoder: "ete", goldenName: "ss_ib_el1ns_multi_sess", snapshotName: "ss_ib_el1ns"},
		{decoder: "ete", goldenName: "texit-poe2", snapshotName: "texit-poe2"},
		{decoder: "ete", goldenName: "tme_simple", snapshotName: "tme_simple"},
		{decoder: "ete", goldenName: "tme_tcancel", snapshotName: "tme_tcancel"},
		{decoder: "ete", goldenName: "tme_test", snapshotName: "tme_test"},
		{decoder: "ete", goldenName: "trace_file_cid_vmid", snapshotName: "trace_file_cid_vmid"},
		{decoder: "ete", goldenName: "trace_file_vmid", snapshotName: "trace_file_vmid"},
		{decoder: "ete", goldenName: "ts_bit64_set", snapshotName: "ts_bit64_set"},
		{decoder: "ete", goldenName: "ts_marker", snapshotName: "ts_marker"},
		{decoder: "etmv3", goldenName: "TC2", snapshotName: "TC2"},
		{decoder: "etmv4", goldenName: "a55-test-tpiu", snapshotName: "a55-test-tpiu"},
		{decoder: "etmv4", goldenName: "a57_single_step", snapshotName: "a57_single_step"},
		{decoder: "etmv4", goldenName: "armv8_1m_branches", snapshotName: "armv8_1m_branches"},
		{decoder: "etmv4", goldenName: "init-short-addr", snapshotName: "init-short-addr"},
		{decoder: "etmv4", goldenName: "juno-ret-stck", snapshotName: "juno-ret-stck"},
		{decoder: "etmv4", goldenName: "juno-uname-001", snapshotName: "juno-uname-001"},
		{decoder: "etmv4", goldenName: "juno-uname-002", snapshotName: "juno-uname-002"},
		{decoder: "etmv4", goldenName: "juno_r1_1", snapshotName: "juno_r1_1"},
		{decoder: "etmv4", goldenName: "juno_r1_1_badopcode", snapshotName: "juno_r1_1"},
		{decoder: "etmv4", goldenName: "juno_r1_1_badopcode_flag", snapshotName: "juno_r1_1"},
		{decoder: "etmv4", goldenName: "juno_r1_1_rangelimit", snapshotName: "juno_r1_1"},
		{decoder: "etmv4", goldenName: "test-file-mem-offsets", snapshotName: "test-file-mem-offsets"},
		{decoder: "etmv4", goldenName: "bugfix-exact-match", snapshotName: "bugfix-exact-match"},
		{decoder: "itm", goldenName: "itm_only_csformat", snapshotName: "itm_only_csformat"},
		{decoder: "itm", goldenName: "itm_only_raw", snapshotName: "itm_only_raw"},
		{decoder: "ptm", goldenName: "Snowball", snapshotName: "Snowball"},
		{decoder: "ptm", goldenName: "TC2", snapshotName: "TC2"},
		{decoder: "ptm", goldenName: "tc2-ptm-rstk-t32", snapshotName: "tc2-ptm-rstk-t32"},
		{decoder: "ptm", goldenName: "trace_cov_a15", snapshotName: "trace_cov_a15"},
		{decoder: "stm", goldenName: "stm-issue-27", snapshotName: "stm-issue-27"},
		{decoder: "stm", goldenName: "stm_only-2", snapshotName: "stm_only-2"},
		{decoder: "stm", goldenName: "stm_only-juno", snapshotName: "stm_only-juno"},
		{decoder: "stm", goldenName: "stm_only", snapshotName: "stm_only"},
	}

	testCases := make([]listerGoldenCase, 0, len(manifest))
	for _, entry := range manifest {
		goldenPath := filepath.Join("testdata", entry.goldenName+".ppl")
		snapshotDir := filepath.Join("testdata", entry.snapshotName)

		if entry.goldenName == "bugfix-exact-match" {
			extractPPLGz(t, goldenPath)
		}

		headerText, err := readGoldenHeader(goldenPath)
		if err != nil {
			t.Fatalf("read golden header %s: %v", goldenPath, err)
		}
		if stat, err := os.Stat(snapshotDir); err != nil || !stat.IsDir() {
			t.Fatalf("missing snapshot dir %s", snapshotDir)
		}

		id, decode, extraFlags := parseOptionsFromGolden(entry.goldenName, headerText)
		testCases = append(testCases, listerGoldenCase{
			name:        filepath.ToSlash(filepath.Join(entry.decoder, entry.snapshotName, entry.goldenName+".ppl")),
			goldenPath:  goldenPath,
			snapshotDir: snapshotDir,
			sourceName:  extractSourceName(headerText),
			id:          id,
			decode:      decode,
			extraFlags:  extraFlags,
		})
	}

	return testCases
}

func extractPPLGz(t *testing.T, targetPath string) {
	t.Helper()
	gzPath := targetPath + ".gz"

	// If the decompressed file already exists, do nothing.
	if _, err := os.Stat(targetPath); err == nil {
		return
	}

	t.Logf("Extracting %s from %s...", targetPath, gzPath)

	gzFile, err := os.Open(gzPath)
	if err != nil {
		t.Fatalf("failed to open compressed file %s: %v", gzPath, err)
	}
	defer gzFile.Close()

	gzReader, err := gzip.NewReader(gzFile)
	if err != nil {
		t.Fatalf("failed to create gzip reader for %s: %v", gzPath, err)
	}
	defer gzReader.Close()

	outFile, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		t.Fatalf("failed to create target file %s: %v", targetPath, err)
	}
	defer outFile.Close()

	if _, err := io.Copy(outFile, gzReader); err != nil {
		t.Fatalf("failed to decompress %s: %v", targetPath, err)
	}
}

// parseOptionsFromGolden extracts behavioural replay arguments from a golden
// .ppl file. It returns the trace-source ID (if any), whether full decode was
// requested, and all extra flags that must be re-applied when running the
// golden test case.
//
// Flag recognition is table-driven: goldenBoolFlags and goldenValueFlags are
// the authoritative sets, so adding a new flag here is a one-line change.
// Flags that are either handled through other fields (e.g. -id, -src_name) or
// irrelevant to output comparison (-ss_dir, -logfilename, …) are consumed but
// not forwarded to extraFlags.
func parseOptionsFromGolden(name, ppl string) (string, bool, []string) {
	decode := strings.Contains(strings.ToLower(name), "-dcd-")
	id := ""
	var extraFlags []string

	if m := reDeviceSuffix.FindStringSubmatch(name); len(m) == 2 {
		id = "0x" + strings.ToLower(m[1])
	}
	if strings.Contains(strings.ToLower(name), "badopcode") {
		extraFlags = append(extraFlags, "-aa64_opcode_chk")
	}
	if strings.Contains(strings.ToLower(name), "rangelimit") {
		extraFlags = append(extraFlags, "-instr_range_limit", "100")
	}

	cmdLine := extractGoldenCommandLine(ppl)
	if cmdLine == "" {
		return id, decode, extraFlags
	}

	skipValueFlags := map[string]struct{}{
		"-ss_dir":      {},
		"-src_name":    {},
		"-logfilename": {},
		"-test_waits":  {},
	}

	fields := strings.Fields(cmdLine)
	for i := 0; i < len(fields); i++ {
		tok := fields[i]
		switch tok {
		case "-decode", "-decode_only":
			decode = true

		case "-id":
			if i+1 < len(fields) {
				i++
				parsed := strings.ToLower(strings.TrimSuffix(fields[i], ","))
				if parsed != "" {
					if _, err := strconv.ParseUint(parsed, 0, 8); err == nil {
						id = parsed
					}
				}
			}

		default:
			if _, ok := goldenBoolFlags[tok]; ok {
				extraFlags = append(extraFlags, tok)
			} else if _, ok := goldenValueFlags[tok]; ok {
				if i+1 < len(fields) {
					i++
					extraFlags = append(extraFlags, tok, fields[i])
				}
			} else if _, ok := skipValueFlags[tok]; ok {
				if i+1 < len(fields) {
					i++
				}
			}
			// Unknown/non-behavioural flags (e.g. -stats, -profile) are silently
			// ignored; they do not affect decode output.
		}
	}

	return id, decode, extraFlags
}

func extractGoldenCommandLine(ppl string) string {
	lines := strings.Split(normalizeNewlines(ppl), "\n")
	for i, line := range lines {
		if strings.TrimSpace(line) != "Test Command Line:-" {
			continue
		}

		var b strings.Builder
		for j := i + 1; j < len(lines); j++ {
			curr := strings.TrimSpace(lines[j])
			if curr == "" {
				if b.Len() > 0 {
					break
				}
				continue
			}
			if strings.HasPrefix(curr, "Trace Packet Lister :") {
				break
			}
			if b.Len() > 0 {
				b.WriteByte(' ')
			}
			b.WriteString(curr)
		}
		return b.String()
	}
	return ""
}

func extractSourceName(ppl string) string {
	for line := range strings.SplitSeq(normalizeNewlines(ppl), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "Using ") || !strings.HasSuffix(line, " as trace source") {
			continue
		}
		line = strings.TrimPrefix(line, "Using ")
		line = strings.TrimSuffix(line, " as trace source")
		return strings.TrimSpace(line)
	}
	return ""
}

func readGoldenHeader(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	buf := make([]byte, 64*1024)
	n, err := file.Read(buf)
	if err != nil && err != io.EOF {
		return "", err
	}
	return string(buf[:n]), nil
}

func comparableTraceListerOutputFromFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var out []string
	inCommandLine := false

	scanner := bufio.NewScanner(file)
	const maxCapacity = 10 * 1024 * 1024
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, maxCapacity)

	for scanner.Scan() {
		line := scanner.Text()
		line = strings.ReplaceAll(line, "./snapshots/", "testdata/")
		line = strings.ReplaceAll(line, "./snapshots-ete/", "testdata/")
		text := strings.TrimSpace(line)

		if text == "" {
			inCommandLine = false
			continue
		}

		if text == "Test Command Line:-" {
			inCommandLine = true
			continue
		}
		if inCommandLine {
			continue
		}

		if strings.HasPrefix(text, "Trace Packet Lister : reading snapshot from path ") {
			continue
		}

		if filename, ok := strings.CutPrefix(text, "Filename="); ok {
			out = append(out, "Filename="+filepath.Base(filepath.ToSlash(filename)))
			continue
		}

		records := testutil.SplitIdxRecords(line)
		if len(records) > 1 {
			out = append(out, records...)
			continue
		}
		out = append(out, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func normalizeNewlines(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return s
}

// TestParseOptionsFromGoldenAllBehavioralFlags verifies that every flag listed
// in goldenBoolFlags and goldenValueFlags is actually recognised and forwarded
// by parseOptionsFromGolden. If a new flag is added to either table but the
// parser loop is not updated, this test will catch the regression.
func TestParseOptionsFromGoldenAllBehavioralFlags(t *testing.T) {
	cmdParts := []string{
		"trc_pkt_lister",
		"-ss_dir", "testdir",
		"-decode",
		"-decode_only", // also sets decode; harmless duplicate
		"-id", "0x10",
		"-src_name", "ETM_0", // should be consumed-but-not-forwarded
	}
	for flag := range goldenBoolFlags {
		cmdParts = append(cmdParts, flag)
	}
	for flag := range goldenValueFlags {
		cmdParts = append(cmdParts, flag, "42")
	}

	ppl := "Test Command Line:-\n" + strings.Join(cmdParts, " ") + "\n\nTrace Packet Lister : stub\n"

	id, decode, extraFlags := parseOptionsFromGolden("golden-test", ppl)

	if !decode {
		t.Errorf("expected decode=true from -decode flag in synthetic command line")
	}
	if id != "0x10" {
		t.Errorf("expected id=0x10, got %q", id)
	}

	extraIndex := make(map[string]int, len(extraFlags))
	for i, f := range extraFlags {
		extraIndex[f] = i
	}

	for flag := range goldenBoolFlags {
		if _, ok := extraIndex[flag]; !ok {
			t.Errorf("parseOptionsFromGolden did not forward bool flag %s", flag)
		}
	}

	for flag := range goldenValueFlags {
		pos, ok := extraIndex[flag]
		if !ok {
			t.Errorf("parseOptionsFromGolden did not forward value flag %s", flag)
			continue
		}
		if pos+1 >= len(extraFlags) || extraFlags[pos+1] != "42" {
			t.Errorf("parseOptionsFromGolden did not forward value for flag %s (extraFlags=%v)", flag, extraFlags)
		}
	}

	for _, f := range extraFlags {
		if f == "-src_name" {
			t.Errorf("parseOptionsFromGolden forwarded -src_name into extraFlags; it should be consumed but not forwarded")
		}
	}
}

func TestParseOptionsCompositeFlags(t *testing.T) {
	opts, err := parseOptions([]string{
		"-decode_only",
		"-tpiu_hsync",
		"-id", "0x10",
		"-id", "0x20",
	})
	if err != nil {
		t.Fatalf("parseOptions failed: %v", err)
	}

	if !opts.decodeOnly || !opts.decode {
		t.Fatalf("expected decode_only to imply decode; decodeOnly=%v decode=%v", opts.decodeOnly, opts.decode)
	}
	if !opts.tpiuFormat || !opts.hasHSync {
		t.Fatalf("expected tpiu_hsync to set tpiuFormat+hasHSync; tpiuFormat=%v hasHSync=%v", opts.tpiuFormat, opts.hasHSync)
	}

	if opts.allSourceIDs {
		t.Fatal("expected allSourceIDs=false when -id is provided")
	}
	if len(opts.idList) != 2 || opts.idList[0] != 0x10 || opts.idList[1] != 0x20 {
		t.Fatalf("unexpected idList: %v", opts.idList)
	}
}

func TestParseOptionsLoggingPrecedence(t *testing.T) {
	defaultOpts, err := parseOptions(nil)
	if err != nil {
		t.Fatalf("parseOptions default failed: %v", err)
	}
	if !defaultOpts.logStdout || defaultOpts.logStderr || !defaultOpts.logFile || defaultOpts.logFileName != defaultLogFile {
		t.Fatalf("unexpected default logging options: stdout=%v stderr=%v file=%v fileName=%q", defaultOpts.logStdout, defaultOpts.logStderr, defaultOpts.logFile, defaultOpts.logFileName)
	}

	stdoutWins, err := parseOptions([]string{"-logfile", "-logfilename", "custom.ppl", "-logstderr", "-logstdout"})
	if err != nil {
		t.Fatalf("parseOptions precedence failed: %v", err)
	}
	if !stdoutWins.logStdout || stdoutWins.logStderr || stdoutWins.logFile {
		t.Fatalf("expected logstdout precedence, got stdout=%v stderr=%v file=%v", stdoutWins.logStdout, stdoutWins.logStderr, stdoutWins.logFile)
	}
	if stdoutWins.logFileName != defaultLogFile {
		t.Fatalf("expected default logfile name to remain, got %q", stdoutWins.logFileName)
	}

	fileNameWins, err := parseOptions([]string{"-logfile", "-logfilename", "named-output.ppl"})
	if err != nil {
		t.Fatalf("parseOptions logfilename failed: %v", err)
	}
	if fileNameWins.logStdout || fileNameWins.logStderr || !fileNameWins.logFile || fileNameWins.logFileName != "named-output.ppl" {
		t.Fatalf("expected logfilename behavior, got stdout=%v stderr=%v file=%v fileName=%q", fileNameWins.logStdout, fileNameWins.logStderr, fileNameWins.logFile, fileNameWins.logFileName)
	}
}

func TestRunUnknownSourceNameReturnsError(t *testing.T) {
	snapshotDir := filepath.Join("testdata", "trace_cov_a15")
	outPath := filepath.Join(t.TempDir(), "out.ppl")

	err := run([]string{
		"-ss_dir", snapshotDir,
		"-src_name", "__definitely_not_a_real_source__",
		"-logfilename", outPath,
		"-no_time_print",
	})
	if err == nil {
		t.Fatal("expected error for unknown source name, got nil")
	}
	if !strings.Contains(err.Error(), `trace source name "__definitely_not_a_real_source__" not found`) {
		t.Fatalf("unexpected error: %v", err)
	}

	gotBytes, readErr := os.ReadFile(outPath)
	if readErr != nil {
		t.Fatalf("read output %s: %v", outPath, readErr)
	}
	got := string(gotBytes)
	if !strings.Contains(got, "Valid source names are:-") {
		t.Fatalf("expected valid-source list in output, got:\n%s", got)
	}
}

func TestMapMemoryRangesSameFileDifferentOffsetsBothMapped(t *testing.T) {
	dir := t.TempDir()
	memFile := filepath.Join(dir, "mem.bin")
	if err := os.WriteFile(memFile, []byte{0, 1, 2, 3, 4, 5, 6, 7}, 0o644); err != nil {
		t.Fatalf("write memory file: %v", err)
	}

	reader := &snapshot.Reader{
		ParsedDeviceList: map[string]*snapshot.Device{
			"cpu_0": {
				Name:  "cpu_0",
				Class: "core",
				Memory: []snapshot.MemoryDump{
					{
						Path:    "mem.bin",
						Address: 0x1000,
						Offset:  0,
						Length:  4,
						Space:   "N",
					},
					{
						Path:    "mem.bin",
						Address: 0x2000,
						Offset:  4,
						Length:  4,
						Space:   "N",
					},
				},
			},
		},
	}

	mapper := memacc.NewGlobalMapper()
	err := mapMemoryRanges(mapper, dir, reader)
	if err != nil {
		t.Fatalf("mapMemoryRanges returned error: %v", err)
	}

	mappings := mapper.DumpMappings()
	if !strings.Contains(mappings, "Range::0x1000:1003") {
		t.Errorf("expected range 0x1000:1003 in mappings, got:\n%s", mappings)
	}
	if !strings.Contains(mappings, "Range::0x2000:2003") {
		t.Errorf("expected range 0x2000:2003 in mappings, got:\n%s", mappings)
	}
}

func TestMapMemoryRangesBadOffsetReturnsError(t *testing.T) {
	dir := t.TempDir()
	memFile := filepath.Join(dir, "mem.bin")
	if err := os.WriteFile(memFile, []byte{0, 1, 2, 3}, 0o644); err != nil {
		t.Fatalf("write memory file: %v", err)
	}

	reader := &snapshot.Reader{
		ParsedDeviceList: map[string]*snapshot.Device{
			"cpu_0": {
				Name:  "cpu_0",
				Class: "core",
				Memory: []snapshot.MemoryDump{
					{
						Path:    "mem.bin",
						Address: 0x1000,
						Offset:  99,
						Length:  4,
						Space:   "N",
					},
				},
			},
		},
	}

	mapper := memacc.NewGlobalMapper()
	err := mapMemoryRanges(mapper, dir, reader)
	if err == nil {
		t.Fatal("expected error for bad offset, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "offset beyond EOF") {
		t.Fatalf("expected offset error, got: %v", err)
	}
	if !strings.Contains(msg, "requested_offset=99") {
		t.Fatalf("expected requested offset in error, got: %v", err)
	}
	if !strings.Contains(msg, "file_size=4") {
		t.Fatalf("expected file size in error, got: %v", err)
	}
	if !strings.Contains(msg, "mem.bin") {
		t.Fatalf("expected file path in error, got: %v", err)
	}
}

func TestMapMemoryRangesUnreadableFileIgnored(t *testing.T) {
	dir := t.TempDir()

	reader := &snapshot.Reader{
		ParsedDeviceList: map[string]*snapshot.Device{
			"cpu_0": {
				Name:  "cpu_0",
				Class: "core",
				Memory: []snapshot.MemoryDump{
					{
						Path:    "missing.bin",
						Address: 0x1000,
						Offset:  0,
						Length:  4,
						Space:   "N",
					},
				},
			},
		},
	}

	mapper := memacc.NewGlobalMapper()
	err := mapMemoryRanges(mapper, dir, reader)
	if err != nil {
		t.Fatalf("expected missing dump file to be ignored, got error: %v", err)
	}
	mappings := mapper.DumpMappings()
	if strings.Contains(mappings, "FileAcc;") {
		t.Fatalf("expected no mapped ranges, got:\n%s", mappings)
	}
}

func TestMapMemoryRangesDuplicateSemanticMappingIgnored(t *testing.T) {
	dir := t.TempDir()
	memFile := filepath.Join(dir, "mem.bin")
	if err := os.WriteFile(memFile, []byte{0, 1, 2, 3}, 0o644); err != nil {
		t.Fatalf("write memory file: %v", err)
	}

	reader := &snapshot.Reader{
		ParsedDeviceList: map[string]*snapshot.Device{
			"cpu_0": {
				Name:  "cpu_0",
				Class: "core",
				Memory: []snapshot.MemoryDump{
					{
						Path:    "mem.bin",
						Address: 0x1000,
						Offset:  0,
						Length:  4,
						Space:   "N",
					},
					{
						Path:    "mem.bin",
						Address: 0x1000,
						Offset:  0,
						Length:  4,
						Space:   "N",
					},
				},
			},
		},
	}

	mapper := memacc.NewGlobalMapper()
	err := mapMemoryRanges(mapper, dir, reader)
	if err != nil {
		t.Fatalf("mapMemoryRanges returned error: %v", err)
	}
	mappings := mapper.DumpMappings()
	count := strings.Count(mappings, "Range::")
	if count != 1 {
		t.Fatalf("expected 1 mapped range after semantic dedupe, got %d. Mappings:\n%s", count, mappings)
	}
	if !strings.Contains(mappings, "0x1000:1003") {
		t.Fatalf("unexpected mapped range: %s", mappings)
	}
}
