package snapshot

import (
	"fmt"

	"github.com/awmorgan/coresight"
)

// eteRegs extends etmv4Regs with the DEVARCH register.
type eteRegs struct {
	etmv4Regs
	devarch uint32
}

// buildETERoute parses device registers and creates an ETE route.
func (b *PipelineBuilder) buildETERoute(spec sourceRouteSpec) (coresight.Route, error) {
	regs, err := eteDeviceRegs(spec.sourceDevice)
	if err != nil {
		return coresight.Route{}, err
	}
	arch, prof := coresight.LookupCoreProfile(spec.coreDevice.Type)
	cfg := coresight.ETEConfig{
		IDR0:               regs.idr0,
		IDR1:               regs.idr1,
		IDR2:               regs.idr2,
		ConfigR:            regs.configr,
		IDR8:               regs.idr8,
		DevArch:            regs.devarch,
		ArchVersion:        arch,
		CoreProfile:        prof,
		ErrOnAA64BadOpcode: b.errOnAA64BadOpcode,
		InstrRangeLimit:    b.instrRangeLimit,
		SrcAddrNAtoms:      b.srcAddrNAtoms,
	}
	mem := b.decodeInterfaces()
	route, err := coresight.NewETERoute(uint8(regs.traceIDR), cfg, mem, nil)
	if err != nil {
		return coresight.Route{}, fmt.Errorf("ETE route creation failed: %w", err)
	}
	return route, nil
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
	if err := setReg32(dev, EteRegDevArch, &regs.devarch); err != nil {
		return eteRegs{}, err
	}
	return regs, nil
}
