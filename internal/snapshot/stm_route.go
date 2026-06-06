package snapshot

import (
	"fmt"

	"coresight/internal/pipeline"
	"coresight/internal/stm"
	"coresight/trace"
)

func (b *PipelineBuilder) buildSTMRoute(spec sourceRouteSpec) (pipeline.Route, error) {
	var tcsr uint32

	if err := setReg32(spec.sourceDevice, STMRegTCSR, &tcsr); err != nil {
		return pipeline.Route{}, err
	}

	cfg := &stm.Config{RegTCSR: tcsr}

	dec, err := stm.NewDecoder(cfg)
	if err != nil {
		return pipeline.Route{}, fmt.Errorf("STM decoder creation failed: %w", err)
	}

	return pipeline.Route{
		TraceID:  cfg.TraceID(),
		Protocol: trace.ProtocolSTM,
		ByteSink: dec,
	}, nil
}
