package snapshot

import (
	"testing"
	"testing/fstest"
)

func TestReaderReadsFromFS(t *testing.T) {
	reader := NewReader()
	reader.FS = fstest.MapFS{
		"snap/snapshot.ini": &fstest.MapFile{Data: []byte(`
[snapshot]
version=0.1

[device_list]
cpu0=cpu0.ini

[trace]
metadata=trace.ini
`)},
		"snap/cpu0.ini": &fstest.MapFile{Data: []byte(`
[device]
name=cpu0
class=source
type=ETM4

[regs]
TRCTRACEIDR=0x11
`)},
		"snap/trace.ini": &fstest.MapFile{Data: []byte(`
[trace_buffers]
buffers=buffer0

[buffer0]
name=ETB_0
file=trace.bin
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
	if !reader.ReadOK {
		t.Fatal("ReadOK = false, want true")
	}
	if _, ok := reader.ParsedDeviceList["cpu0"]; !ok {
		t.Fatalf("ParsedDeviceList missing cpu0: %#v", reader.ParsedDeviceList)
	}
	if len(reader.Trace.Buffers) != 1 || reader.Trace.Buffers[0].BufferName != "ETB_0" {
		t.Fatalf("Trace.Buffers = %#v, want one ETB_0 buffer", reader.Trace.Buffers)
	}
	if _, ok := reader.SourceTrees["ETB_0"]; !ok {
		t.Fatalf("SourceTrees missing ETB_0: %#v", reader.SourceTrees)
	}
}
