package snapshot

import (
	"fmt"

	"github.com/awmorgan/coresight"
)

// etmv4Regs holds the raw ETMv4 hardware register values parsed from a device INI.
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

// buildETMv4Route parses device registers and creates an ETMv4 route.
func (b *PipelineBuilder) buildETMv4Route(spec sourceRouteSpec) (coresight.Route, error) {
	regs, err := etmv4DeviceRegs(spec.sourceDevice)
	if err != nil {
		return coresight.Route{}, err
	}
	arch, prof := coresight.LookupCoreProfile(spec.coreDevice.Type)
	cfg := coresight.ETMv4Config{
		IDR0:               regs.idr0,
		IDR1:               regs.idr1,
		IDR2:               regs.idr2,
		ConfigR:            regs.configr,
		IDR8:               regs.idr8,
		IDR9:               regs.idr9,
		IDR10:              regs.idr10,
		IDR11:              regs.idr11,
		IDR12:              regs.idr12,
		IDR13:              regs.idr13,
		ArchVersion:        arch,
		CoreProfile:        prof,
		ErrOnAA64BadOpcode: b.errOnAA64BadOpcode,
		InstrRangeLimit:    b.instrRangeLimit,
		SrcAddrNAtoms:      b.srcAddrNAtoms,
	}
	mem := b.decodeInterfaces()
	traceID, err := validateTraceID(etmv4RegIDR, regs.traceIDR)
	if err != nil {
		return coresight.Route{}, fmt.Errorf("ETMv4 route creation failed: %w", err)
	}
	route, err := coresight.NewETMv4Route(traceID, cfg, mem, nil)
	if err != nil {
		return coresight.Route{}, fmt.Errorf("ETMv4 route creation failed: %w", err)
	}
	return route, nil
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
		{etmv4RegCfg, &regs.configr},
		{etmv4RegIDR, &regs.traceIDR},
		{etmv4RegIDR0, &regs.idr0},
		{etmv4RegIDR1, &regs.idr1},
		{etmv4RegIDR2, &regs.idr2},
		{etmv4RegIDR8, &regs.idr8},
		{etmv4RegIDR9, &regs.idr9},
		{etmv4RegIDR10, &regs.idr10},
		{etmv4RegIDR11, &regs.idr11},
		{etmv4RegIDR12, &regs.idr12},
		{etmv4RegIDR13, &regs.idr13},
	} {
		if err := setReg32(dev, reg.name, reg.dst); err != nil {
			return etmv4Regs{}, err
		}
	}
	return regs, nil
}
