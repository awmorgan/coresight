package coresight

import (
	"github.com/awmorgan/coresight/snapshot"

	
	"fmt"

)

type eteRegs struct {
	etmv4Regs
	devarch uint32
}

func (b *PipelineBuilder) buildETERoute(spec sourceRouteSpec) (Route, error) {
	cfg, err := newETEConfig(spec.coreDevice.Type, spec.sourceDevice)
	if err != nil {
		return Route{}, err
	}
	cfg.errOnAA64BadOpcode = b.errOnAA64BadOpcode
	cfg.InstrRangeLimit = b.instrRangeLimit
	cfg.SrcAddrNAtoms = b.srcAddrNAtoms

	mem, instr := b.decodeInterfaces()
	dec, err := eteNewDecoder(cfg, mem, instr)
	if err != nil {
		return Route{}, fmt.Errorf("ETE decoder creation failed: %w", err)
	}

	return Route{
		TraceID:  cfg.TraceID(),
		Protocol: ProtocolETE,
		ByteSink: dec,
	}, nil
}

func newETEConfig(coreName string, devSrc *snapshot.Device) (*eteConfig, error) {
	regs, err := eteDeviceRegs(devSrc)
	if err != nil {
		return nil, err
	}
	arch, prof := getCoreProfile(coreName)

	return eteParseConfig(
		regs.traceIDR,
		regs.configr,
		regs.idr0,
		regs.idr1,
		regs.idr2,
		regs.idr8,
		regs.devarch,
		arch,
		prof,
	), nil
}

func eteDeviceRegs(dev *snapshot.Device) (eteRegs, error) {
	v4regs, err := etmv4DeviceRegs(dev)
	if err != nil {
		return eteRegs{}, err
	}
	regs := eteRegs{
		etmv4Regs: v4regs,
		devarch:   0x47705A13,
	}
	if err := setReg32(dev, snapshot.EteRegDevArch, &regs.devarch); err != nil {
		return eteRegs{}, err
	}
	return regs, nil
}
