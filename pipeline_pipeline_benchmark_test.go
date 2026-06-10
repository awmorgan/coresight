package coresight

import (
	"os"
	"testing"
)

func BenchmarkPTM_PipelineDecode_Snowball(b *testing.B) {
	kernelDump, err := os.ReadFile("cmd/trc_pkt_lister/testdata/Snowball/kernel_dump.bin")
	if err != nil {
		b.Fatalf("read kernel dump: %v", err)
	}
	traceData, err := os.ReadFile("cmd/trc_pkt_lister/testdata/Snowball/cstrace.bin")
	if err != nil {
		b.Fatalf("read trace data: %v", err)
	}

	mapper := NewGlobalMapper()
	acc := NewBufferAccessor(
		VAddr(0xC0008000), // Start address of kernel dump in Snowball
		kernelDump,
		MemSpaceAny,
		"",
	)
	if err := mapper.AddAccessor(acc); err != nil {
		b.Fatalf("add kernel dump accessor: %v", err)
	}

	cfg := ptmParseConfig(
		0x10,
		0x411CF301,
		0x10001000,
		0x000008EA,
		ArchV7,
		ProfileCortexA,
	)

	b.ResetTimer()
	for b.Loop() {
		dec, err := ptmNewDecoder(cfg, mapper, decodeInstruction)
		if err != nil {
			b.Fatal(err)
		}
		pipe, err := NewPipeline(true, DemuxOptions{FrameMemAlign: true})
		if err != nil {
			b.Fatal(err)
		}
		pipe.AddRoute(Route{
			TraceID:  cfg.TraceID,
			Protocol: ProtocolPTM,
			ByteSink: dec,
		})

		_, _ = pipe.Write(0, traceData)
		_ = pipe.Close()
	}
}

func BenchmarkETMv4_PipelineDecode_Juno(b *testing.B) {
	kernelDump, err := os.ReadFile("cmd/trc_pkt_lister/testdata/juno_r1_1/kernel_dump.bin")
	if err != nil {
		b.Fatalf("read kernel dump: %v", err)
	}
	traceData, err := os.ReadFile("cmd/trc_pkt_lister/testdata/juno_r1_1/cstrace.bin")
	if err != nil {
		b.Fatalf("read trace data: %v", err)
	}

	mapper := NewGlobalMapper()
	acc := NewBufferAccessor(
		VAddr(0xffffffc000081000),
		kernelDump,
		MemSpaceAny,
		"",
	)
	if err := mapper.AddAccessor(acc); err != nil {
		b.Fatalf("add kernel dump accessor: %v", err)
	}

	cfg := etmv4ParseConfig(
		0x00000010, 0x000000c1, 0x28000ea1, 0x4100f402, 0x00000488,
		0, 0, 0, 0, 0, 0, ArchV8, ProfileCortexA,
	)

	b.ResetTimer()
	for b.Loop() {
		dec, err := etmv4NewDecoder(cfg, mapper, decodeInstruction)
		if err != nil {
			b.Fatal(err)
		}
		pipe, err := NewPipeline(true, DemuxOptions{FrameMemAlign: true})
		if err != nil {
			b.Fatal(err)
		}
		pipe.AddRoute(Route{
			TraceID:  cfg.TraceID(),
			Protocol: ProtocolETMV4I,
			ByteSink: dec,
		})

		_, _ = pipe.Write(0, traceData)
		_ = pipe.Close()
	}
}
