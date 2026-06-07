package coresight

import (
	"fmt"

)

func (b *PipelineBuilder) buildPTMRoute(spec sourceRouteSpec) (Route, error) {
	cfg, err := newPTMConfig(spec.sourceDevice.Type, spec.sourceDevice)
	if err != nil {
		return Route{}, err
	}

	mem, instr := b.decodeInterfaces()
	dec, err := ptmNewDecoder(cfg, mem, instr)
	if err != nil {
		return Route{}, fmt.Errorf("PTM decoder creation failed: %w", err)
	}

	return Route{
		TraceID:  cfg.TraceID,
		Protocol: ProtocolPTM,
		ByteSink: dec,
	}, nil
}

func newPTMConfig(coreName string, devSrc *Device) (*ptmConfig, error) {
	regs, err := etmPTMDeviceRegs(devSrc, 0x4100F310)
	if err != nil {
		return nil, err
	}

	arch, prof := getCoreProfile(coreName)
	return ptmParseConfig(regs.trcID, regs.idr, regs.ctrl, regs.ccer, arch, prof), nil
}
