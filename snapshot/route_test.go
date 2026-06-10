package snapshot

import (
	"strings"
	"testing"
	"testing/fstest"
)

func TestRouteTraceIDValidation(t *testing.T) {
	testCases := []struct {
		deviceType string
		regName    string
		traceIDStr string
		expectErr  bool
		errSubstr  string
	}{
		// ETM4 tests
		{"ETM4", "TRCTRACEIDR", "0x11", false, ""},
		{"ETM4", "TRCTRACEIDR", "0x7f", false, ""},
		{"ETM4", "TRCTRACEIDR", "0x80", true, "invalid trace ID in register TRCTRACEIDR: 128"},
		{"ETM4", "TRCTRACEIDR", "0xff", true, "invalid trace ID in register TRCTRACEIDR: 255"},
		{"ETM4", "TRCTRACEIDR", "0x100", true, "invalid trace ID in register TRCTRACEIDR: 256"},

		// ETE tests
		{"ETE", "TRCTRACEIDR", "0x11", false, ""},
		{"ETE", "TRCTRACEIDR", "0x7f", false, ""},
		{"ETE", "TRCTRACEIDR", "0x80", true, "invalid trace ID in register TRCTRACEIDR: 128"},
		{"ETE", "TRCTRACEIDR", "0xff", true, "invalid trace ID in register TRCTRACEIDR: 255"},
		{"ETE", "TRCTRACEIDR", "0x100", true, "invalid trace ID in register TRCTRACEIDR: 256"},

		// ETM3 tests
		{"ETM3", "ETMTRACEIDR", "0x11", false, ""},
		{"ETM3", "ETMTRACEIDR", "0x7f", false, ""},
		{"ETM3", "ETMTRACEIDR", "0x80", true, "invalid trace ID in register ETMTRACEIDR: 128"},
		{"ETM3", "ETMTRACEIDR", "0xff", true, "invalid trace ID in register ETMTRACEIDR: 255"},
		{"ETM3", "ETMTRACEIDR", "0x100", true, "invalid trace ID in register ETMTRACEIDR: 256"},

		// PTM1 tests
		{"PTM1", "ETMTRACEIDR", "0x11", false, ""},
		{"PTM1", "ETMTRACEIDR", "0x7f", false, ""},
		{"PTM1", "ETMTRACEIDR", "0x80", true, "invalid trace ID in register ETMTRACEIDR: 128"},
		{"PTM1", "ETMTRACEIDR", "0xff", true, "invalid trace ID in register ETMTRACEIDR: 255"},
		{"PTM1", "ETMTRACEIDR", "0x100", true, "invalid trace ID in register ETMTRACEIDR: 256"},
	}

	for _, tc := range testCases {
		t.Run(tc.deviceType+"_"+tc.traceIDStr, func(t *testing.T) {
			reader := NewSnapshotReader()
			reader.FS = fstest.MapFS{
				"snap/snapshot.ini": &fstest.MapFile{Data: []byte(`
[snapshot]
version=0.1

[device_list]
cpu0=cpu0.ini
core0=core0.ini

[trace]
metadata=trace.ini
`)},
				"snap/cpu0.ini": &fstest.MapFile{Data: []byte(`
[device]
name=cpu0
class=source
type=` + tc.deviceType + `

[regs]
` + tc.regName + `=` + tc.traceIDStr + `
`)},
				"snap/core0.ini": &fstest.MapFile{Data: []byte(`
[device]
name=core0
class=core
type=Cortex-A57
`)},
				"snap/trace.ini": &fstest.MapFile{Data: []byte(`
[trace_buffers]
buffers=buffer0

[buffer0]
name=ETB_0
file=bin
format=coresight

[source_buffers]
cpu0=ETB_0

[core_trace_sources]
core0=cpu0
`)},
			}
			reader.SnapshotPath = "snap"

			if err := reader.Read(); err != nil {
				t.Fatalf("Read() error = %v", err)
			}

			builder := NewPipelineBuilder(reader)
			_, err := builder.Build("ETB_0", true)
			if tc.expectErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.errSubstr)
				}
				if !strings.Contains(err.Error(), tc.errSubstr) {
					t.Fatalf("expected error containing %q, got: %v", tc.errSubstr, err)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}
