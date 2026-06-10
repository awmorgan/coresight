package snapshot

import (
	"fmt"

	"github.com/awmorgan/coresight"
)

// buildETMv3Route parses device registers and creates an ETMv3 route.
func (b *PipelineBuilder) buildETMv3Route(spec sourceRouteSpec) (coresight.Route, error) {
	regs, err := etmPTMDeviceRegs(spec.sourceDevice, 0)
	if err != nil {
		return coresight.Route{}, err
	}
	arch, prof := coresight.LookupCoreProfile(spec.coreDevice.Type)
	cfg := coresight.ETMv3Config{
		IDR:         regs.idr,
		Control:     regs.ctrl,
		CCER:        regs.ccer,
		ArchVersion: arch,
		CoreProfile: prof,
	}
	mem := b.decodeInterfaces()
	traceID, err := validateTraceID(Etmv3PTMRegTraceIDR, regs.trcID)
	if err != nil {
		return coresight.Route{}, fmt.Errorf("ETMv3 route creation failed: %w", err)
	}
	route, err := coresight.NewETMv3Route(traceID, cfg, mem, nil)
	if err != nil {
		return coresight.Route{}, fmt.Errorf("ETMv3 route creation failed: %w", err)
	}
	return route, nil
}
