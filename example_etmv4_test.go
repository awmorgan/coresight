package coresight_test

import (
	"bytes"
	"coresight"
	"coresight/trace"
	"fmt"
)

func ExampleEngine_etmv4Decode() {
	// Mock target memory: A snippet representing 4 instructions (16 bytes)
	// For an actual integration, this would read from an ELF section or memory dump.
	mockProgramELF := []byte{
		0x20, 0x00, 0x80, 0xD2, // MOV X0, #1
		0x20, 0x00, 0x80, 0xD2, // MOV X0, #1
		0x20, 0x00, 0x80, 0xD2, // MOV X0, #1
		0xC0, 0x03, 0x5F, 0xD6, // RET
	}
	elfReader := bytes.NewReader(mockProgramELF)

	// Configure engine with program mappings so instruction tracking functions
	// can retrieve opcodes at target virtual addresses during trace processing.
	cfg := coresight.EngineConfig{
		FramedInput: false,
		Mappings: []coresight.Mapping{
			{
				BaseAddress: 0x00100000,
				Size:        uint64(len(mockProgramELF)),
				Source:      elfReader,
				Space:       coresight.SpaceSecure,
			},
		},
	}

	engine, err := coresight.NewEngine(cfg)
	if err != nil {
		fmt.Printf("Engine initialization failed: %v\n", err)
		return
	}
	defer engine.Close()

	// Set up ETMv4 decoding configuration matching target hardware profile
	etmCfg := coresight.ETMv4Config{
		IDR0:        0x28000EA1, // ID Register profile
		ConfigR:     0x000000C1, // Trace configuration state
		ArchVersion: trace.ArchAA64,
		CoreProfile: trace.ProfileCortexA,
		PacketObserver: func(index uint64, pkt fmt.Stringer, rawData []byte) {
			// Optional: Inspect raw protocol packets prior to range reconstruction
		},
	}

	// Connect decoder context to Trace ID 0x10
	err = engine.RegisterETMv4(0x10, etmCfg, func(elem trace.Element) {
		if elem.ElemType == trace.GenElemInstrRange {
			fmt.Printf("Executed instruction block from 0x%08X to 0x%08X (Instructions: %d)\n",
				elem.StartAddr, elem.EndAddr, elem.Payload.NumInstrRange)
		}
	})
	if err != nil {
		fmt.Printf("ETMv4 registration failed: %v\n", err)
		return
	}

	// Stream packets into the engine: An example snippet starting with sync frames
	// followed by trace info, context, target address, and atom structures.
	etmStreamBytes := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // Sync sequence
		0x01, 0x00, // Trace Info
		0x81, 0x12, // Context: SF=1 (AArch64), EL=2, Secure
		0x9A, 0x00, 0x00, 0x10, 0x00, // Address packet targeting 0x00100000
		0xF7, // Atom packet (1 E atom)
	}

	_, err = engine.Write(etmStreamBytes)
	if err != nil {
		fmt.Printf("Processing fault: %v\n", err)
		return
	}

	// Finalize block validation and clean state channels
	if err := engine.Close(); err != nil {
		fmt.Printf("Close operational error: %v\n", err)
	}

	// Output:
	// Executed instruction block from 0x00100000 to 0x00100010 (Instructions: 4)
}
