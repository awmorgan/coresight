package coresight

import (
	"github.com/awmorgan/coresight/snapshot"

	
	"fmt"

)

func (b *PipelineBuilder) buildITMRoute(spec sourceRouteSpec) (Route, error) {
	var tcr uint32

	if err := setReg32(spec.sourceDevice, snapshot.ItmRegTCR, &tcr); err != nil {
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
