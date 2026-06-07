package coresight

import (
	"fmt"

)

func (b *PipelineBuilder) buildETMv3Route(spec sourceRouteSpec) (Route, error) {
	cfg, err := newETMv3Config(spec.sourceDevice.Type, spec.sourceDevice)
	if err != nil {
		return Route{}, err
	}

	mem, instr := b.decodeInterfaces()
	dec, err := etmv3NewDecoder(cfg, mem, instr)
	if err != nil {
		return Route{}, fmt.Errorf("ETMv3 decoder creation failed: %w", err)
	}

	return Route{
		TraceID:  cfg.TraceID(),
		Protocol: ProtocolETMV3,
		ByteSink: dec,
	}, nil
}

func newETMv3Config(coreName string, devSrc *Device) (*etmv3Config, error) {
	regs, err := etmPTMDeviceRegs(devSrc, 0)
	if err != nil {
		return nil, err
	}

	arch, prof := getCoreProfile(coreName)
	return etmv3ParseConfig(regs.trcID, regs.idr, regs.ctrl, regs.ccer, arch, prof), nil
}
