package snapshot

import (
	"fmt"

	"github.com/awmorgan/coresight/internal/etmv3"
	"github.com/awmorgan/coresight/internal/pipeline"
	"github.com/awmorgan/coresight/trace"
)

func (b *PipelineBuilder) buildETMv3Route(spec sourceRouteSpec) (pipeline.Route, error) {
	cfg, err := newETMv3Config(spec.sourceDevice.Type, spec.sourceDevice)
	if err != nil {
		return pipeline.Route{}, err
	}

	mem, instr := b.decodeInterfaces()
	dec, err := etmv3.NewDecoder(cfg, mem, instr)
	if err != nil {
		return pipeline.Route{}, fmt.Errorf("ETMv3 decoder creation failed: %w", err)
	}

	return pipeline.Route{
		TraceID:  cfg.TraceID(),
		Protocol: trace.ProtocolETMV3,
		ByteSink: dec,
	}, nil
}

func newETMv3Config(coreName string, devSrc *Device) (*etmv3.Config, error) {
	regs, err := etmPTMDeviceRegs(devSrc, 0)
	if err != nil {
		return nil, err
	}

	arch, prof := getCoreProfile(coreName)
	return etmv3.ParseConfig(regs.trcID, regs.idr, regs.ctrl, regs.ccer, arch, prof), nil
}
