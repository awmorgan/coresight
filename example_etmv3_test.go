package coresight_test

import (
	"bytes"
	"coresight"
	"coresight/trace"
	"fmt"
)

// This example demonstrates how to configure and register an ETMv3 (Embedded Trace Macrocell v3)
// instruction decoder, map target memory, ingest raw trace bytes, and capture initialization/termination events.
func ExampleEngine_RegisterETMv3() {
	// Mock target memory: A dummy 4-byte instruction section.
	mockV7Code := []byte{
		0x00, 0x00, 0x00, 0x00,
	}

	// Configure the engine with memory mapping space matching ETMv3 secure EL1.
	cfg := coresight.EngineConfig{
		FramedInput: false,
		Mappings: []coresight.Mapping{
			{
				BaseAddress: 0x8000,
				Size:        uint64(len(mockV7Code)),
				Source:      bytes.NewReader(mockV7Code),
				Space:       coresight.SpaceSecure,
			},
		},
	}

	engine, err := coresight.NewEngine(cfg)
	if err != nil {
		fmt.Printf("failed to create engine: %v\n", err)
		return
	}
	defer engine.Close()

	// Configure the ETMv3 register parameters matching typical Cortex-A profile.
	etmv3Cfg := coresight.ETMv3Config{
		IDR:         0x4100F240,
		Control:     0x00001000,
		ArchVersion: trace.ArchV7,
		CoreProfile: trace.ProfileCortexA,
	}

	// Register ETMv3 on Trace ID 3.
	err = engine.RegisterETMv3(3, etmv3Cfg, func(elem trace.Element) {
		switch elem.ElemType {
		case trace.GenElemNoSync:
			fmt.Printf("ETMv3: Decoder initialized\n")
		case trace.GenElemEOTrace:
			fmt.Printf("ETMv3: End of trace\n")
		}
	})
	if err != nil {
		fmt.Printf("failed to register ETMv3: %v\n", err)
		return
	}

	// Ingest raw ETMv3 bytes.
	if _, err := engine.Write([]byte{0x00, 0x00}); err != nil {
		fmt.Printf("failed to write trace: %v\n", err)
		return
	}

	// Close the engine to flush the decoder.
	if err := engine.Close(); err != nil {
		fmt.Printf("failed to close engine: %v\n", err)
	}

	// Output:
	// ETMv3: Decoder initialized
	// ETMv3: End of trace
}
