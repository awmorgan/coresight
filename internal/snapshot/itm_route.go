package snapshot

import (
	"fmt"

	"coresight/internal/itm"
	"coresight/internal/pipeline"
	"coresight/trace"
)

func (b *PipelineBuilder) buildITMRoute(spec sourceRouteSpec) (pipeline.Route, error) {
	var tcr uint32

	if err := setReg32(spec.sourceDevice, ITMRegTCR, &tcr); err != nil {
		return pipeline.Route{}, err
	}

	cfg := &itm.Config{RegTCR: tcr}

	dec, err := itm.NewDecoder(cfg)
	if err != nil {
		return pipeline.Route{}, fmt.Errorf("ITM decoder creation failed: %w", err)
	}

	return pipeline.Route{
		TraceID:  cfg.TraceID(),
		Protocol: trace.ProtocolITM,
		ByteSink: dec,
	}, nil
}
