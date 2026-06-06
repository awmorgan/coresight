package pipeline_test

import (
	"coresight/internal/demux"
	"coresight/internal/etmv4"
	"coresight/internal/idec"
	"coresight/internal/memacc"
	"coresight/internal/pipeline"
	"coresight/internal/ptm"
	"coresight/trace"
	"os"
	"testing"
)

func BenchmarkPTM_PipelineDecode_Snowball(b *testing.B) {
	kernelDump, err := os.ReadFile("../../cmd/trc_pkt_lister/testdata/Snowball/kernel_dump.bin")
	if err != nil {
		b.Fatalf("read kernel dump: %v", err)
	}
	traceData, err := os.ReadFile("../../cmd/trc_pkt_lister/testdata/Snowball/cstrace.bin")
	if err != nil {
		b.Fatalf("read trace data: %v", err)
	}

	mapper := memacc.NewGlobalMapper()
	acc := memacc.NewBufferAccessor(
		trace.VAddr(0xC0008000), // Start address of kernel dump in Snowball
		kernelDump,
		trace.MemSpaceAny,
		"",
	)
	if err := mapper.AddAccessor(acc, trace.BadCSSrcID); err != nil {
		b.Fatalf("add kernel dump accessor: %v", err)
	}

	cfg := ptm.ParseConfig(
		0x10,
		0x411CF301,
		0x10001000,
		0x000008EA,
		trace.ArchV7,
		trace.ProfileCortexA,
	)

	b.ResetTimer()
	for b.Loop() {
		dec, err := ptm.NewDecoder(cfg, mapper, idec.DecodeInstruction)
		if err != nil {
			b.Fatal(err)
		}
		pipe, err := pipeline.NewPipeline(true, demux.DemuxOptions{FrameMemAlign: true})
		if err != nil {
			b.Fatal(err)
		}
		pipe.AddRoute(pipeline.Route{
			TraceID:  cfg.TraceID,
			Protocol: trace.ProtocolPTM,
			ByteSink: dec,
		})

		_, _ = pipe.Write(0, traceData)
		_ = pipe.Close()
	}
}

func BenchmarkETMv4_PipelineDecode_Juno(b *testing.B) {
	kernelDump, err := os.ReadFile("../../cmd/trc_pkt_lister/testdata/juno_r1_1/kernel_dump.bin")
	if err != nil {
		b.Fatalf("read kernel dump: %v", err)
	}
	traceData, err := os.ReadFile("../../cmd/trc_pkt_lister/testdata/juno_r1_1/cstrace.bin")
	if err != nil {
		b.Fatalf("read trace data: %v", err)
	}

	mapper := memacc.NewGlobalMapper()
	acc := memacc.NewBufferAccessor(
		trace.VAddr(0xffffffc000081000),
		kernelDump,
		trace.MemSpaceAny,
		"",
	)
	if err := mapper.AddAccessor(acc, trace.BadCSSrcID); err != nil {
		b.Fatalf("add kernel dump accessor: %v", err)
	}

	cfg := etmv4.ParseConfig(
		0x00000010, 0x000000c1, 0x28000ea1, 0x4100f402, 0x00000488,
		0, 0, 0, 0, 0, 0, trace.ArchV8, trace.ProfileCortexA,
	)

	b.ResetTimer()
	for b.Loop() {
		dec, err := etmv4.NewDecoder(cfg, mapper, idec.DecodeInstruction)
		if err != nil {
			b.Fatal(err)
		}
		pipe, err := pipeline.NewPipeline(true, demux.DemuxOptions{FrameMemAlign: true})
		if err != nil {
			b.Fatal(err)
		}
		pipe.AddRoute(pipeline.Route{
			TraceID:  cfg.TraceID(),
			Protocol: trace.ProtocolETMV4I,
			ByteSink: dec,
		})

		_, _ = pipe.Write(0, traceData)
		_ = pipe.Close()
	}
}
