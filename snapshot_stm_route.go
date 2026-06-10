package coresight

import (
	"fmt"

)

func (b *PipelineBuilder) buildSTMRoute(spec sourceRouteSpec) (Route, error) {
	var tcsr uint32

	if err := setReg32(spec.sourceDevice, stmRegTCSR, &tcsr); err != nil {
		return Route{}, err
	}

	cfg := &stmConfig{RegTCSR: tcsr}

	dec, err := stmNewDecoder(cfg)
	if err != nil {
		return Route{}, fmt.Errorf("STM decoder creation failed: %w", err)
	}

	return Route{
		TraceID:  cfg.TraceID(),
		Protocol: ProtocolSTM,
		ByteSink: dec,
	}, nil
}
