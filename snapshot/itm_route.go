package snapshot

import (
	"fmt"

	"github.com/awmorgan/coresight"
)

// buildITMRoute parses device registers and creates an ITM route.
func (b *PipelineBuilder) buildITMRoute(spec sourceRouteSpec) (coresight.Route, error) {
	var tcr uint32
	if err := setReg32(spec.sourceDevice, itmRegTCR, &tcr); err != nil {
		return coresight.Route{}, err
	}
	traceID := uint8((tcr & 0x007F0000) >> 16)
	cfg := coresight.ITMConfig{ControlRegister: tcr}
	route, err := coresight.NewITMRoute(traceID, cfg, nil)
	if err != nil {
		return coresight.Route{}, fmt.Errorf("ITM route creation failed: %w", err)
	}
	return route, nil
}
