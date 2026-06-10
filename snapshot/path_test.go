package snapshot

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSafeRelativePath(t *testing.T) {
	testCases := []struct {
		path      string
		expectErr bool
	}{
		// Valid cases
		{"device_0.ini", false},
		{"subdir/device_0.ini", false},
		{"subdir\\device_0.ini", false}, // Windows-style separator normalized to slash
		{"a/b/c.ini", false},

		// Invalid cases: empty
		{"", true},
		{"   ", true},

		// Invalid cases: absolute paths
		{"/tmp/outside.ini", true},
		{"C:\\outside.ini", true},
		{"\\\\server\\share\\outside.ini", true},

		// Invalid cases: escaping snapshot directory
		{"../outside.ini", true},
		{"../../outside.ini", true},
		{"a/../../outside.ini", true},
		{"a/b/../../../outside.ini", true},
	}

	for _, tc := range testCases {
		res, err := SafeRelativePath(tc.path)
		if tc.expectErr {
			if err == nil {
				t.Errorf("expected error for path %q, got nil", tc.path)
			}
		} else {
			if err != nil {
				t.Errorf("unexpected error for path %q: %v", tc.path, err)
			}
			// check that separators are normalized to slash
			if strings.Contains(res, "\\") {
				t.Errorf("path %q was not normalized: %q", tc.path, res)
			}
		}
	}
}

func TestIntegrationSnapshotPathContainment(t *testing.T) {
	// Create snapshot dir
	tmpDir := t.TempDir()

	// Create outside file
	outsideFile := filepath.Join(tmpDir, "..", "outside.ini")
	if err := os.WriteFile(outsideFile, []byte("[device]\nname=outside\n"), 0644); err != nil {
		t.Fatalf("failed to write outside file: %v", err)
	}

	// Test 1: Device ini file escaping containment
	t.Run("DeviceIniEscapes", func(t *testing.T) {
		r := NewSnapshotReader()
		r.SnapshotPath = tmpDir

		// Write a snapshot.ini referencing the outside file
		snapshotIniData := []byte(`
[snapshot]
version=0.1

[device_list]
cpu0=../outside.ini
`)
		if err := os.WriteFile(filepath.Join(tmpDir, "snapshot.ini"), snapshotIniData, 0644); err != nil {
			t.Fatalf("failed to write snapshot.ini: %v", err)
		}

		err := r.Read()
		var targetErr error
		if err != nil {
			targetErr = err
		} else if len(r.Warnings) > 0 {
			targetErr = r.Warnings[0]
		}

		if targetErr == nil {
			t.Fatal("expected error or warning, got nil")
		}
		if !strings.Contains(targetErr.Error(), "escapes snapshot directory") && !strings.Contains(targetErr.Error(), "invalid device ini path") {
			t.Fatalf("expected path containment error, got: %v", targetErr)
		}
	})

	// Test 2: Trace metadata data file escaping containment
	t.Run("TraceDataFileEscapes", func(t *testing.T) {
		r := NewSnapshotReader()
		r.SnapshotPath = tmpDir

		snapshotIniData := []byte(`
[snapshot]
version=0.1

[device_list]

[trace]
metadata=trace.ini
`)
		if err := os.WriteFile(filepath.Join(tmpDir, "snapshot.ini"), snapshotIniData, 0644); err != nil {
			t.Fatalf("failed to write snapshot.ini: %v", err)
		}

		traceIniData := []byte(`
[trace_buffers]
buffers=buffer0

[buffer0]
name=ETB_0
file=../outside.bin
format=coresight
`)
		if err := os.WriteFile(filepath.Join(tmpDir, "trace.ini"), traceIniData, 0644); err != nil {
			t.Fatalf("failed to write trace.ini: %v", err)
		}

		err := r.Read()
		var targetErr error
		if err != nil {
			targetErr = err
		} else if len(r.Warnings) > 0 {
			targetErr = r.Warnings[0]
		}

		if targetErr == nil {
			t.Fatal("expected error or warning, got nil")
		}
		if !strings.Contains(targetErr.Error(), "escapes snapshot directory") && !strings.Contains(targetErr.Error(), "invalid trace buffer data file path") {
			t.Fatalf("expected path containment error, got: %v", targetErr)
		}
	})
}
