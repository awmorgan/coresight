package coresight_test

import (
	"bytes"
	"coresight"
	"coresight/trace"
	"fmt"
)

// This example demonstrates how to initialize the CoreSight engine,
// register an STM (System Trace Macrocell) decoder, ingest raw trace data,
// and capture decoded generic trace elements in a callback.
func ExampleEngine_basic() {
	// 1. Create a programmatic CoreSight decoding engine.
	// We set FramedInput to false as we are directly writing raw STM bytes.
	engine, err := coresight.NewEngine(coresight.EngineConfig{
		FramedInput: false,
	})
	if err != nil {
		fmt.Printf("failed to create engine: %v\n", err)
		return
	}
	defer engine.Close()

	// 2. Configure the STM decoder.
	// Since STM operates purely on trace packets without needing target instruction memory access,
	// we only need to provide basic hardware control registers.
	stmConfig := coresight.STMConfig{
		ControlRegister: 0x00000000,
	}

	// 3. Register the STM decoder on Trace ID 2.
	err = engine.RegisterSTM(2, stmConfig, func(elem trace.Element) {
		switch elem.ElemType {
		case trace.GenElemNoSync:
			fmt.Printf("STM Trace: Decoder initialized (reason: %d)\n", elem.Payload.UnsyncEOTInfo)
		case trace.GenElemEOTrace:
			fmt.Printf("STM Trace: Decoder reached end-of-trace (reason: %d)\n", elem.Payload.UnsyncEOTInfo)
		default:
			fmt.Printf("STM Trace: Decoded element: %d\n", elem.ElemType)
		}
	})
	if err != nil {
		fmt.Printf("failed to register STM decoder: %v\n", err)
		return
	}

	// 4. Feed a block of raw STM trace bytes.
	traceData := []byte{0x00, 0x00, 0x00}
	if _, err := engine.Write(traceData); err != nil {
		fmt.Printf("failed to write trace data: %v\n", err)
		return
	}

	// 5. Close the engine to flush decoders and trigger final callbacks.
	if err := engine.Close(); err != nil {
		fmt.Printf("failed to close engine: %v\n", err)
	}

	// Output:
	// STM Trace: Decoder initialized (reason: 1)
	// STM Trace: Decoder reached end-of-trace (reason: 7)
}

// This example demonstrates how to set up an ITM (Instrumentation Trace Macrocell) decoder
// and monitor the decoded software trace packets using Go closures.
func ExampleEngine_RegisterITM() {
	engine, err := coresight.NewEngine(coresight.EngineConfig{
		FramedInput: false,
	})
	if err != nil {
		fmt.Printf("failed to create engine: %v\n", err)
		return
	}
	defer engine.Close()

	// Configure the ITM decoder with a control register setting.
	itmConfig := coresight.ITMConfig{
		ControlRegister: 0x00010000, // Enable trace generation control
	}

	// Register the ITM decoder on Trace ID 1.
	err = engine.RegisterITM(1, itmConfig, func(elem trace.Element) {
		switch elem.ElemType {
		case trace.GenElemNoSync:
			fmt.Printf("ITM Trace: Decoder initialized (reason: %d)\n", elem.Payload.UnsyncEOTInfo)
		case trace.GenElemEOTrace:
			fmt.Printf("ITM Trace: Decoder reached end-of-trace (reason: %d)\n", elem.Payload.UnsyncEOTInfo)
		default:
			fmt.Printf("ITM Trace: Decoded element: %d\n", elem.ElemType)
		}
	})
	if err != nil {
		fmt.Printf("failed to register ITM decoder: %v\n", err)
		return
	}

	// Ingest raw ITM bytes.
	if _, err := engine.Write([]byte{0x00, 0x00}); err != nil {
		fmt.Printf("failed to write trace data: %v\n", err)
		return
	}

	if err := engine.Close(); err != nil {
		fmt.Printf("failed to close engine: %v\n", err)
	}

	// Output:
	// ITM Trace: Decoder initialized (reason: 1)
	// ITM Trace: Decoder reached end-of-trace (reason: 7)
}

// This example demonstrates how to configure an ETMv4 decoder.
// ETMv4 trace decoding requires mapping the target program's instruction memory
// (e.g. elf segments or RAM dumps) so the decoder can follow jump targets and opcodes.
func ExampleEngine_RegisterETMv4() {
	// 1. Define target virtual memory mappings.
	// We mock target instruction memory containing a small section of code.
	mockKernelCode := []byte{
		0x00, 0x00, 0x00, 0x14, // B +0 (dummy branch instruction)
	}

	mappings := []coresight.Mapping{
		{
			BaseAddress: 0xffffffc000081000,
			Size:        uint64(len(mockKernelCode)),
			Space:       coresight.SpaceNonSecure,
			Source:      bytes.NewReader(mockKernelCode), // io.ReaderAt source
		},
	}

	// 2. Initialize the engine with the memory mappings.
	engine, err := coresight.NewEngine(coresight.EngineConfig{
		FramedInput: false,
		Mappings:    mappings,
	})
	if err != nil {
		fmt.Printf("failed to create engine: %v\n", err)
		return
	}
	defer engine.Close()

	// 3. Configure the ETMv4 decoder with registers representing hardware state.
	etmConfig := coresight.ETMv4Config{
		IDR0:        0x28000ea1,
		IDR1:        0x4100f402,
		IDR2:        0x00000488,
		ConfigR:     0x000000c1,
		ArchVersion: trace.ArchV8,
		CoreProfile: trace.ProfileCortexA,
	}

	// 4. Register ETMv4 on Trace ID 0x10.
	err = engine.RegisterETMv4(0x10, etmConfig, func(elem trace.Element) {
		switch elem.ElemType {
		case trace.GenElemNoSync:
			fmt.Printf("ETMv4 Trace: Decoder initialized (reason: %d)\n", elem.Payload.UnsyncEOTInfo)
		case trace.GenElemEOTrace:
			fmt.Printf("ETMv4 Trace: Decoder reached end-of-trace (reason: %d)\n", elem.Payload.UnsyncEOTInfo)
		default:
			fmt.Printf("ETMv4 Trace: Decoded element: %d\n", elem.ElemType)
		}
	})
	if err != nil {
		fmt.Printf("failed to register ETMv4 decoder: %v\n", err)
		return
	}

	// 5. Ingest ETMv4 trace bytes.
	if _, err := engine.Write([]byte{0x00, 0x00}); err != nil {
		fmt.Printf("failed to write trace data: %v\n", err)
		return
	}

	if err := engine.Close(); err != nil {
		fmt.Printf("failed to close engine: %v\n", err)
	}

	// Output:
	// ETMv4 Trace: Decoder initialized (reason: 1)
}

// This example demonstrates how to process a framed trace stream
// (e.g. from a TPIU formatter) by setting FramedInput to true and
// using a custom DemuxConfig with a RawFrameHandler to intercept individual frame packets.
func ExampleEngine_framed() {
	// 1. Configure the demuxer options.
	demuxCfg := &coresight.DemuxConfig{
		FrameMemAlign: true,
		RawFrameHandler: func(index uint64, elem trace.RawframeElem, data []byte, traceID uint8) error {
			// Print details of intercepted raw frame bytes.
			fmt.Printf("Frame: index=%d traceID=0x%02x len=%d\n", index, traceID, len(data))
			return nil
		},
	}

	// 2. Initialize the engine with framed input enabled.
	engine, err := coresight.NewEngine(coresight.EngineConfig{
		FramedInput: true,
		Demux:       demuxCfg,
	})
	if err != nil {
		fmt.Printf("failed to create engine: %v\n", err)
		return
	}
	defer engine.Close()

	// 3. Register STM decoder to consume demuxed stream for Trace ID 2.
	stmConfig := coresight.STMConfig{
		ControlRegister: 0,
	}
	err = engine.RegisterSTM(2, stmConfig, func(elem trace.Element) {
		// Decoded STM elements from the framed stream will end up here.
	})
	if err != nil {
		fmt.Printf("failed to register STM: %v\n", err)
		return
	}

	// 4. Ingest framed bytes.
	// In TPIU format, bytes are grouped into frames.
	// Write raw formatted bytes into the engine.
	mockFramedBytes := []byte{
		0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	if _, err := engine.Write(mockFramedBytes); err != nil {
		fmt.Printf("failed to write framed trace: %v\n", err)
		return
	}

	if err := engine.Close(); err != nil {
		fmt.Printf("failed to close engine: %v\n", err)
	}

	// Output:
}

func ExampleEngine_multiSourceDemux() {
	// Initialize configuration indicating the incoming byte stream uses
	// standard CoreSight frame structure alignment protocols.
	cfg := coresight.EngineConfig{
		FramedInput: true,
		Demux: &coresight.DemuxConfig{
			FrameMemAlign: true,
			RawFrameHandler: func(index uint64, elem trace.RawframeElem, data []byte, traceID uint8) error {
				// Optional hook to audit raw interleaved channels
				return nil
			},
		},
	}

	engine, err := coresight.NewEngine(cfg)
	if err != nil {
		fmt.Printf("Failed to generate hardware pipeline: %v\n", err)
		return
	}
	defer engine.Close()

	// Bind an ITM module to route events coming from Source ID 1
	itmCfg := coresight.ITMConfig{ControlRegister: 0x1}
	err = engine.RegisterITM(1, itmCfg, func(elem trace.Element) {
		if elem.ElemType == trace.GenElemInstrumentation {
			fmt.Printf("[Source ID 1 - ITM] Instrumentation value parsed\n")
		}
	})
	if err != nil {
		fmt.Printf("ITM channel routing setup failed: %v\n", err)
		return
	}

	// Bind an STM module to simultaneously extract trace data assigned to Source ID 2
	stmCfg := coresight.STMConfig{ControlRegister: 0x0}
	err = engine.RegisterSTM(2, stmCfg, func(elem trace.Element) {
		fmt.Printf("[Source ID 2 - STM] Captured system trace element: %d\n", elem.ElemType)
	})
	if err != nil {
		fmt.Printf("STM channel routing setup failed: %v\n", err)
		return
	}

	// Construct a programmatic sample of formatted trace bytes.
	// In the standard CoreSight formatter protocol, bytes are grouped into 16-byte frames
	// containing embedded channel identifiers, multiplexing data cleanly.
	packedTraceFrames := []byte{
		0x03, 0x11, 0x22, 0x33, 0x05, 0x44, 0x55, 0x66,
		0x07, 0x77, 0x88, 0x99, 0x09, 0xAA, 0xBB, 0xCC,
	}

	_, err = engine.Write(packedTraceFrames)
	if err != nil {
		fmt.Printf("Demux pipe write processing failed: %v\n", err)
		return
	}

	// Flush and close the formatting processing pipeline
	if err := engine.Close(); err != nil {
		fmt.Printf("Pipeline flush failure: %v\n", err)
	}

	// Output:
	// [Source ID 2 - STM] Captured system trace element: 1
	// [Source ID 2 - STM] Captured system trace element: 3
}
