package snapshot

import (
	"fmt"

	"github.com/awmorgan/coresight"
)

// buildSTMRoute parses device registers and creates an STM route.
func (b *PipelineBuilder) buildSTMRoute(spec sourceRouteSpec) (coresight.Route, error) {
	var tcsr uint32
	if err := setReg32(spec.sourceDevice, stmRegTCSR, &tcsr); err != nil {
		return coresight.Route{}, err
	}
	traceID := uint8((tcsr & 0x007F0000) >> 16)
	cfg := coresight.STMConfig{ControlRegister: tcsr}
	route, err := coresight.NewSTMRoute(traceID, cfg, nil)
	if err != nil {
		return coresight.Route{}, fmt.Errorf("STM route creation failed: %w", err)
	}
	return route, nil
}
