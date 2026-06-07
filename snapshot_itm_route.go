package coresight

import (
	"fmt"

)

func (b *PipelineBuilder) buildITMRoute(spec sourceRouteSpec) (Route, error) {
	var tcr uint32

	if err := setReg32(spec.sourceDevice, ITMRegTCR, &tcr); err != nil {
		return Route{}, err
	}

	cfg := &itmConfig{RegTCR: tcr}

	dec, err := itmNewDecoder(cfg)
	if err != nil {
		return Route{}, fmt.Errorf("ITM decoder creation failed: %w", err)
	}

	return Route{
		TraceID:  cfg.TraceID(),
		Protocol: ProtocolITM,
		ByteSink: dec,
	}, nil
}
