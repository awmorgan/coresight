package main

import (
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func BenchmarkBugfixExactMatch(b *testing.B) {
	ensureBugfixExactMatchTrace(b)
	tmpDir := b.TempDir()
	outPath := filepath.Join(tmpDir, "bench.ppl")

	for b.Loop() {
		args := []string{
			"-ss_dir", filepath.Join("testdata", "bugfix-exact-match"),
			"-logfilename", outPath,
			"-no_time_print",
			"-decode",
		}
		err := run(args)
		if err != nil {
			b.Fatalf("run failed: %v", err)
		}
	}
}

func BenchmarkBugfixExactMatchDecodeOnly(b *testing.B) {
	ensureBugfixExactMatchTrace(b)
	tmpDir := b.TempDir()
	outPath := filepath.Join(tmpDir, "bench.ppl")

	for b.Loop() {
		args := []string{
			"-ss_dir", filepath.Join("testdata", "bugfix-exact-match"),
			"-logfilename", outPath,
			"-no_time_print",
			"-decode_only",
		}
		err := run(args)
		if err != nil {
			b.Fatalf("run failed: %v", err)
		}
	}
}

func BenchmarkBugfixExactMatchPacketMonitorOnly(b *testing.B) {
	ensureBugfixExactMatchTrace(b)
	benchmarkTraceListerSnapshot(b, "bugfix-exact-match", "-pkt_mon")
}

func BenchmarkTraceListerPTM_Snowball_DecodeOnly(b *testing.B) {
	benchmarkTraceListerSnapshot(b, "Snowball", "-decode_only")
}

func BenchmarkTraceListerPTM_Snowball_PacketMonitorOnly(b *testing.B) {
	benchmarkTraceListerSnapshot(b, "Snowball", "-pkt_mon")
}

func BenchmarkTraceListerETMv3_TC2_DecodeOnly(b *testing.B) {
	benchmarkTraceListerSnapshot(b, "TC2", "-decode_only")
}

func BenchmarkTraceListerETMv3_TC2_PacketMonitorOnly(b *testing.B) {
	benchmarkTraceListerSnapshot(b, "TC2", "-pkt_mon")
}

func BenchmarkTraceListerITM_Raw_DecodeOnly(b *testing.B) {
	benchmarkTraceListerSnapshot(b, "itm_only_raw", "-decode_only")
}

func BenchmarkTraceListerITM_Raw_PacketMonitorOnly(b *testing.B) {
	benchmarkTraceListerSnapshot(b, "itm_only_raw", "-pkt_mon")
}

func BenchmarkTraceListerSTM_Only_DecodeOnly(b *testing.B) {
	benchmarkTraceListerSnapshot(b, "stm_only", "-decode_only")
}

func BenchmarkTraceListerSTM_Only_PacketMonitorOnly(b *testing.B) {
	benchmarkTraceListerSnapshot(b, "stm_only", "-pkt_mon")
}

func ensureBugfixExactMatchTrace(b *testing.B) {
	b.Helper()
	targetPath := filepath.Join("testdata", "bugfix-exact-match.ppl")
	gzPath := targetPath + ".gz"
	if _, err := os.Stat(targetPath); err != nil {
		gzFile, err := os.Open(gzPath)
		if err != nil {
			b.Fatalf("failed to open compressed file %s: %v", gzPath, err)
		}
		defer gzFile.Close()

		gzReader, err := gzip.NewReader(gzFile)
		if err != nil {
			b.Fatalf("failed to create gzip reader for %s: %v", gzPath, err)
		}
		defer gzReader.Close()

		outFile, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			b.Fatalf("failed to create target file %s: %v", targetPath, err)
		}
		defer outFile.Close()

		if _, err := io.Copy(outFile, gzReader); err != nil {
			b.Fatalf("failed to decompress %s: %v", targetPath, err)
		}
	}
}

func benchmarkTraceListerSnapshot(b *testing.B, snapshot string, flags ...string) {
	b.Helper()
	tmpDir := b.TempDir()
	outPath := filepath.Join(tmpDir, "bench.ppl")
	snapshotDir := filepath.Join("testdata", snapshot)
	if stat, err := os.Stat(snapshotDir); err != nil || !stat.IsDir() {
		b.Fatalf("missing snapshot dir %s", snapshotDir)
	}

	args := []string{
		"-ss_dir", snapshotDir,
		"-logfilename", outPath,
		"-no_time_print",
	}
	args = append(args, flags...)

	for b.Loop() {
		if err := run(args); err != nil {
			b.Fatalf("run failed: %v", err)
		}
	}
}
