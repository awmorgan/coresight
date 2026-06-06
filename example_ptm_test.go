package coresight_test

import (
	"bytes"
	"coresight"
	"coresight/trace"
	"fmt"
)

// This example demonstrates how to configure and initialize a PTM (Program Trace Macrocell)
// instruction-decoder pipeline using programmatic virtual memory maps and custom out-of-band sinks.
func ExampleEngine_RegisterPTM() {
	// Simulated target binary block representing ARMv7 instructions.
	// In production, this data represents decoded bytes extracted from an ELF file or hardware dump.
	mockV7BinaryImage := []byte{
		0x02, 0x00, 0x00, 0xEA, // B #8 (Branch past instructions)
		0x01, 0x10, 0xA0, 0xE1, // MOV R1, R1
		0x0E, 0xF0, 0xA0, 0xE1, // MOV PC, LR (Subroutine Return)
		0x14, 0x00, 0x00, 0xEB, // BL Subroutine
	}
	binaryReader := bytes.NewReader(mockV7BinaryImage)

	// Configure the engine context. PTM is an instruction-tracing module
	// that requires access to a mapped virtual address space to track branches.
	cfg := coresight.EngineConfig{
		FramedInput: false, // Ingesting a direct raw source stream
		Mappings: []coresight.Mapping{
			{
				BaseAddress: 0x8000,
				Size:        uint64(len(mockV7BinaryImage)),
				Source:      binaryReader,
				Space:       coresight.SpaceSecure,
			},
		},
	}

	engine, err := coresight.NewEngine(cfg)
	if err != nil {
		fmt.Printf("PTM pipeline initialization failed: %v\n", err)
		return
	}
	defer engine.Close()

	// Establish register parameters matching the target hardware's execution profile.
	// We pass typical ARMv7-A identification register states and enable the hardware return stack.
	ptmCfg := coresight.PTMConfig{
		IDR:         0x4100F310, // Standard PTM version identification signature
		Control:     0x20001000, // Enable Return Stack logic and baseline tracing
		CCER:        0x00400000, // Configure Waypoint generation behavior
		ArchVersion: trace.ArchV7,
		CoreProfile: trace.ProfileCortexA,
		PacketObserver: func(index uint64, pkt fmt.Stringer, rawData []byte) {
			// Optional callback to trace or inspect protocol packets at low levels
		},
	}

	// Register the PTM module for CoreSight Trace ID 0x1A
	err = engine.RegisterPTM(0x1A, ptmCfg, func(elem trace.Element) {
		switch elem.ElemType {
		case trace.GenElemTraceOn:
			fmt.Printf("[PTM] Trace streaming started (Reason: %d)\n", elem.Payload.UnsyncEOTInfo)
		case trace.GenElemInstrRange:
			fmt.Printf("[PTM] Range executed: 0x%04X -> 0x%04X (Instructions: %d, LastType: %d)\n",
				elem.StartAddr, elem.EndAddr, elem.Payload.NumInstrRange, elem.LastInstrType)
		case trace.GenElemAddrNacc:
			fmt.Printf("[PTM] Memory access error at address: 0x%04X\n", elem.StartAddr)
		}
	})
	if err != nil {
		fmt.Printf("PTM configuration registration failed: %v\n", err)
		return
	}

	// Programmatic stream packet sequence containing:
	// 1. An alignment synchronization marker
	// 2. An I_SYNC instruction pointer synchronization target targeting 0x8000
	// 3. An Atom packet capturing the execution branches
	ptmStreamBytes := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // A_SYNC block pattern
		0x08, 0x00, 0x80, 0x00, 0x00, 0x01, // I_SYNC initialization packet to address 0x8000
		0x82, // ATOM sequence indicating instruction evaluations
	}

	// Synchronously drive the trace block down the decoder pipeline
	_, err = engine.Write(ptmStreamBytes)
	if err != nil {
		fmt.Printf("Stream ingestion failure: %v\n", err)
		return
	}

	// Flush trailing states and validate pipeline termination boundaries
	if err := engine.Close(); err != nil {
		fmt.Printf("Pipeline termination warning: %v\n", err)
	}

	// Output:
	// [PTM] Trace streaming started (Reason: 0)
	// [PTM] Range executed: 0x8000 -> 0x8004 (Instructions: 1, LastType: 1)
}
