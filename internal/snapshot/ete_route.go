package snapshot

import (
	"fmt"

	"coresight/internal/ete"
	"coresight/internal/pipeline"
	"coresight/trace"
)

type eteRegs struct {
	etmv4Regs
	devarch uint32
}

func (b *PipelineBuilder) buildETERoute(spec sourceRouteSpec) (pipeline.Route, error) {
	cfg, err := newETEConfig(spec.coreDevice.Type, spec.sourceDevice)
	if err != nil {
		return pipeline.Route{}, err
	}
	cfg.ErrOnAA64BadOpcode = b.errOnAA64BadOpcode
	cfg.InstrRangeLimit = b.instrRangeLimit
	cfg.SrcAddrNAtoms = b.srcAddrNAtoms

	mem, instr := b.decodeInterfaces()
	dec, err := ete.NewDecoder(cfg, mem, instr)
	if err != nil {
		return pipeline.Route{}, fmt.Errorf("ETE decoder creation failed: %w", err)
	}

	return pipeline.Route{
		TraceID:  cfg.TraceID(),
		Protocol: trace.ProtocolETE,
		ByteSink: dec,
	}, nil
}

func newETEConfig(coreName string, devSrc *Device) (*ete.Config, error) {
	regs, err := eteDeviceRegs(devSrc)
	if err != nil {
		return nil, err
	}
	arch, prof := getCoreProfile(coreName)

	return ete.ParseConfig(
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

func eteDeviceRegs(dev *Device) (eteRegs, error) {
	v4regs, err := etmv4DeviceRegs(dev)
	if err != nil {
		return eteRegs{}, err
	}
	regs := eteRegs{
		etmv4Regs: v4regs,
		devarch:   0x47705A13,
	}
	if err := setReg32(dev, ETERegDevArch, &regs.devarch); err != nil {
		return eteRegs{}, err
	}
	return regs, nil
}
