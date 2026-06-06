package pipeline

import (
	"github.com/awmorgan/coresight/internal/demux"
	"github.com/awmorgan/coresight/trace"
)

// Route links a Trace ID to its processors.
type Route struct {
	TraceID  uint8
	Protocol trace.TraceProtocol
	ByteSink trace.ByteSink
}

// Pipeline orchestrates the demuxer and registered decoders.
type Pipeline struct {
	Demuxer        *demux.Demuxer
	Routes         []Route
	sinksByTraceID [trace.MaxTraceID]trace.ByteSink
	FramedInput    bool
}

func NewPipeline(framedInput bool, opts demux.DemuxOptions) (*Pipeline, error) {
	p := &Pipeline{FramedInput: framedInput}
	if framedInput {
		p.Demuxer = demux.NewDemuxer(p.sinksByTraceID[:])
		if err := p.Demuxer.Configure(opts); err != nil {
			return nil, err
		}
	}
	return p, nil
}

func (p *Pipeline) AddRoute(route Route) {
	// For non-framed pipelines there is only one stream, so the trace ID is
	// irrelevant for routing purposes. Force it to 0 to match the behaviour
	// of the old DecodeTree.normalizedRouteID and keep golden output stable.
	if !p.FramedInput {
		route.TraceID = 0
	}
	p.Routes = append(p.Routes, route)
	if route.TraceID < trace.MaxTraceID {
		p.sinksByTraceID[route.TraceID] = route.ByteSink
	}
}

func (p *Pipeline) Write(index trace.Index, data []byte) (uint32, error) {
	if p.FramedInput && p.Demuxer != nil {
		return p.Demuxer.Write(index, data)
	}
	if len(p.Routes) > 0 && p.Routes[0].ByteSink != nil {
		return p.Routes[0].ByteSink.Write(index, data)
	}
	return 0, trace.ErrNotInit
}

func (p *Pipeline) Close() error {
	if p.FramedInput && p.Demuxer != nil {
		return p.Demuxer.Close()
	}
	return p.controlRoutes(func(s trace.ByteSink) error { return s.Close() })
}

func (p *Pipeline) Reset(index trace.Index) error {
	if p.FramedInput && p.Demuxer != nil {
		return p.Demuxer.Reset(index)
	}
	return p.controlRoutes(func(s trace.ByteSink) error { return s.Reset(index) })
}

func (p *Pipeline) controlRoutes(op func(trace.ByteSink) error) error {
	var outErr error
	for _, r := range p.Routes {
		if r.ByteSink == nil {
			continue
		}
		if err := op(r.ByteSink); err != nil && outErr == nil {
			outErr = err
		}
	}
	return outErr
}

// SetElementSink attaches the sink to all decoders that support it.
func (p *Pipeline) SetElementSink(sink trace.ElementSink) {
	for _, r := range p.Routes {
		if s, ok := r.ByteSink.(interface{ SetElementSink(trace.ElementSink) }); ok {
			s.SetElementSink(sink)
		}
	}
}
