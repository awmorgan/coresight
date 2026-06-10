package coresight


// Route links a Trace ID to its protocol decoder.
type Route struct {
	TraceID  uint8
	Protocol TraceProtocol
	ByteSink ByteSink
}

// Pipeline orchestrates the demuxer and registered decoders.
type Pipeline struct {
	Demuxer        *Demuxer
	Routes         []Route
	sinksByTraceID [MaxTraceID]ByteSink
	FramedInput    bool
}

// NewPipeline creates a configured Pipeline. framedInput selects TPIU
// frame demultiplexing; opts configures the demuxer when framedInput is true.
func NewPipeline(framedInput bool, opts DemuxOptions) (*Pipeline, error) {
	p := &Pipeline{FramedInput: framedInput}
	if framedInput {
		p.Demuxer = newDemuxer(p.sinksByTraceID[:])
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
	if route.TraceID < MaxTraceID {
		p.sinksByTraceID[route.TraceID] = route.ByteSink
	}
}

func (p *Pipeline) Write(index Index, data []byte) (uint32, error) {
	if p.FramedInput && p.Demuxer != nil {
		return p.Demuxer.Write(index, data)
	}
	if len(p.Routes) > 0 && p.Routes[0].ByteSink != nil {
		return p.Routes[0].ByteSink.Write(index, data)
	}
	return 0, errNotInit
}

func (p *Pipeline) Close() error {
	if p.FramedInput && p.Demuxer != nil {
		return p.Demuxer.Close()
	}
	return p.controlRoutes(func(s ByteSink) error { return s.Close() })
}

func (p *Pipeline) Reset(index Index) error {
	if p.FramedInput && p.Demuxer != nil {
		return p.Demuxer.Reset(index)
	}
	return p.controlRoutes(func(s ByteSink) error { return s.Reset(index) })
}

func (p *Pipeline) controlRoutes(op func(ByteSink) error) error {
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
func (p *Pipeline) SetElementSink(sink ElementSink) {
	for _, r := range p.Routes {
		if s, ok := r.ByteSink.(interface{ SetElementSink(ElementSink) }); ok {
			s.SetElementSink(sink)
		}
	}
}
