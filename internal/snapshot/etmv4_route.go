package snapshot

import (
	"fmt"

	"github.com/awmorgan/coresight/internal/etmv4"
	"github.com/awmorgan/coresight/internal/pipeline"
	"github.com/awmorgan/coresight/trace"
)

type etmv4Regs struct {
	configr  uint32
	traceIDR uint32
	idr0     uint32
	idr1     uint32
	idr2     uint32
	idr8     uint32
	idr9     uint32
	idr10    uint32
	idr11    uint32
	idr12    uint32
	idr13    uint32
}

func (b *PipelineBuilder) buildETMv4Route(spec sourceRouteSpec) (pipeline.Route, error) {
	cfg, err := newETMv4Config(spec.sourceDevice.Type, spec.sourceDevice)
	if err != nil {
		return pipeline.Route{}, err
	}
	cfg.ErrOnAA64BadOpcode = b.errOnAA64BadOpcode
	cfg.InstrRangeLimit = b.instrRangeLimit
	cfg.SrcAddrNAtoms = b.srcAddrNAtoms

	mem, instr := b.decodeInterfaces()
	dec, err := etmv4.NewDecoder(cfg, mem, instr)
	if err != nil {
		return pipeline.Route{}, fmt.Errorf("ETMv4 decoder creation failed: %w", err)
	}

	return pipeline.Route{
		TraceID:  cfg.TraceID(),
		Protocol: trace.ProtocolETMV4I,
		ByteSink: dec,
	}, nil
}

func newETMv4Config(coreName string, devSrc *Device) (*etmv4.Config, error) {
	regs, err := etmv4DeviceRegs(devSrc)
	if err != nil {
		return nil, err
	}
	arch, prof := getCoreProfile(coreName)
	return etmv4.ParseConfig(
		regs.traceIDR,
		regs.configr,
		regs.idr0,
		regs.idr1,
		regs.idr2,
		regs.idr8,
		regs.idr9,
		regs.idr10,
		regs.idr11,
		regs.idr12,
		regs.idr13,
		arch,
		prof,
	), nil
}

func etmv4DeviceRegs(dev *Device) (etmv4Regs, error) {
	regs := etmv4Regs{
		idr0:    0x28000EA1,
		idr1:    0x4100F403,
		idr2:    0x00000488,
		configr: 0xC1,
	}
	for _, reg := range []struct {
		name string
		dst  *uint32
	}{
		{ETMv4RegCfg, &regs.configr},
		{ETMv4RegIDR, &regs.traceIDR},
		{ETMv4RegIDR0, &regs.idr0},
		{ETMv4RegIDR1, &regs.idr1},
		{ETMv4RegIDR2, &regs.idr2},
		{ETMv4RegIDR8, &regs.idr8},
		{ETMv4RegIDR9, &regs.idr9},
		{ETMv4RegIDR10, &regs.idr10},
		{ETMv4RegIDR11, &regs.idr11},
		{ETMv4RegIDR12, &regs.idr12},
		{ETMv4RegIDR13, &regs.idr13},
	} {
		if err := setReg32(dev, reg.name, reg.dst); err != nil {
			return etmv4Regs{}, err
		}
	}
	return regs, nil
}
