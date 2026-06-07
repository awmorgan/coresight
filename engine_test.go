package coresight_test

import (
	"bytes"
	"github.com/awmorgan/coresight"
	"os"
	"testing"
)

const junoSnapshotDir = "cmd/trc_pkt_lister/testdata/juno_r1_1"

func TestEngineETMv4Golden(t *testing.T) {
	// 1. Load kernel dump memory
	kernelDump, err := os.ReadFile(junoSnapshotDir + "/kernel_dump.bin")
	if err != nil {
		t.Fatalf("failed to read kernel dump: %v", err)
	}

	// 2. Set up mappings using bytes.Reader as our io.ReaderAt source
	mappings := []coresight.Mapping{
		{
			BaseAddress: 0xffffffc000081000,
			Size:        uint64(len(kernelDump)),
			Space:       coresight.SpaceNonSecure,
			Source:      bytes.NewReader(kernelDump),
		},
	}

	// 3. Create the programmatic engine using structured config
	engine, err := coresight.NewEngine(coresight.EngineConfig{
		FramedInput: true,
		Mappings:    mappings,
	})
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	defer engine.Close()

	// 4. Register ETMv4 decoder using typed method
	var decodedElements []coresight.Element
	etmConfig := coresight.ETMv4Config{
		IDR0:        0x28000ea1,
		IDR1:        0x4100f402,
		IDR2:        0x00000488,
		ConfigR:     0x000000c1,
		ArchVersion: coresight.ArchV8,
		CoreProfile: coresight.ProfileCortexA,
	}

	err = engine.RegisterETMv4(0x10, etmConfig, func(elem coresight.Element) {
		decodedElements = append(decodedElements, elem)
	})
	if err != nil {
		t.Fatalf("failed to register ETMv4 decoder: %v", err)
	}

	// 5. Ingest trace data
	traceBytes, err := os.ReadFile(junoSnapshotDir + "/cstrace.bin")
	if err != nil {
		t.Fatalf("failed to read cstrace: %v", err)
	}

	// Feed in chunks
	const chunkSize = 2048
	var total int
	for total < len(traceBytes) {
		end := min(total+chunkSize, len(traceBytes))
		n, err := engine.Write(traceBytes[total:end])
		if err != nil {
			t.Fatalf("failed to write trace chunk at %d: %v", total, err)
		}
		total += n
	}

	if err := engine.Close(); err != nil {
		t.Fatalf("failed to close engine: %v", err)
	}

	// 6. Basic assertions on decoded elements
	if len(decodedElements) == 0 {
		t.Fatal("expected to decode trace elements, got 0")
	}

	// Ensure we decoded some instruction ranges
	var instrRangeCount int
	for _, elem := range decodedElements {
		if elem.ElemType == 5 { // GenElemInstrRange is 5
			instrRangeCount++
		}
	}
	if instrRangeCount == 0 {
		t.Error("expected to decode instruction range elements, got 0")
	}
}

func TestEngineRegisterAllDecoders(t *testing.T) {
	engine, err := coresight.NewEngine(coresight.EngineConfig{
		FramedInput: false,
	})
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	// ITM
	itmConfig := coresight.ITMConfig{ControlRegister: 0x00010000} // trace ID 1
	err = engine.RegisterITM(1, itmConfig, func(elem coresight.Element) {})
	if err != nil {
		t.Errorf("failed to register ITM: %v", err)
	}

	// STM
	stmConfig := coresight.STMConfig{ControlRegister: 0x00020000} // trace ID 2
	err = engine.RegisterSTM(2, stmConfig, func(elem coresight.Element) {})
	if err != nil {
		t.Errorf("failed to register STM: %v", err)
	}

	// ETMv3
	etmv3Config := coresight.ETMv3Config{
		Control:     0x1000,
		IDR:         0x4100F240,
		ArchVersion: coresight.ArchV7,
		CoreProfile: coresight.ProfileCortexA,
	}
	err = engine.RegisterETMv3(3, etmv3Config, func(elem coresight.Element) {})
	if err != nil {
		t.Errorf("failed to register ETMv3: %v", err)
	}

	// PTM
	ptmConfig := coresight.PTMConfig{
		Control:     0,
		IDR:         0x4100F310,
		ArchVersion: coresight.ArchV7,
		CoreProfile: coresight.ProfileCortexA,
	}
	err = engine.RegisterPTM(4, ptmConfig, func(elem coresight.Element) {})
	if err != nil {
		t.Errorf("failed to register PTM: %v", err)
	}
}
