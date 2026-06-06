package snapshot

import (
	"fmt"

	"coresight/internal/pipeline"
	"coresight/internal/ptm"
	"coresight/trace"
)

func (b *PipelineBuilder) buildPTMRoute(spec sourceRouteSpec) (pipeline.Route, error) {
	cfg, err := newPTMConfig(spec.sourceDevice.Type, spec.sourceDevice)
	if err != nil {
		return pipeline.Route{}, err
	}

	mem, instr := b.decodeInterfaces()
	dec, err := ptm.NewDecoder(cfg, mem, instr)
	if err != nil {
		return pipeline.Route{}, fmt.Errorf("PTM decoder creation failed: %w", err)
	}

	return pipeline.Route{
		TraceID:  cfg.TraceID,
		Protocol: trace.ProtocolPTM,
		ByteSink: dec,
	}, nil
}

func newPTMConfig(coreName string, devSrc *Device) (*ptm.Config, error) {
	regs, err := etmPTMDeviceRegs(devSrc, 0x4100F310)
	if err != nil {
		return nil, err
	}

	arch, prof := getCoreProfile(coreName)
	return ptm.ParseConfig(regs.trcID, regs.idr, regs.ctrl, regs.ccer, arch, prof), nil
}
