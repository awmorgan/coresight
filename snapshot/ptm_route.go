package snapshot

import (
	"fmt"

	"github.com/awmorgan/coresight"
)

// buildPTMRoute parses device registers and creates a PTM route.
func (b *PipelineBuilder) buildPTMRoute(spec sourceRouteSpec) (coresight.Route, error) {
	regs, err := etmPTMDeviceRegs(spec.sourceDevice, 0x4100F310)
	if err != nil {
		return coresight.Route{}, err
	}
	arch, prof := coresight.LookupCoreProfile(spec.coreDevice.Type)
	cfg := coresight.PTMConfig{
		IDR:         regs.idr,
		Control:     regs.ctrl,
		CCER:        regs.ccer,
		ArchVersion: arch,
		CoreProfile: prof,
	}
	mem := b.decodeInterfaces()
	traceID, err := validateTraceID(Etmv3PTMRegTraceIDR, regs.trcID)
	if err != nil {
		return coresight.Route{}, fmt.Errorf("PTM route creation failed: %w", err)
	}
	route, err := coresight.NewPTMRoute(traceID, cfg, mem, nil)
	if err != nil {
		return coresight.Route{}, fmt.Errorf("PTM route creation failed: %w", err)
	}
	return route, nil
}
