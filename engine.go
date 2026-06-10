package coresight

import (
	"fmt"
)

// RawFrameHandler is the callback type for observing raw frame bytes.
type RawFrameHandler func(index uint64, elem RawframeElem, data []byte, traceID uint8) error

// DemuxConfig holds the framing demuxer options.
type DemuxConfig struct {
	HasFsyncs       bool
	HasHsyncs       bool
	FrameMemAlign   bool
	PackedRawOut    bool
	UnpackedRawOut  bool
	ResetOn4xFsync  bool
	RawFrameHandler RawFrameHandler
}

// EngineConfig holds options for creating a new Engine.
type EngineConfig struct {
	FramedInput bool
	Mappings    []Mapping
	Demux       *DemuxConfig
}

type Engine struct {
	pipe        *Pipeline
	framedInput bool
	mapper      *GlobalMapper
	index       Index
}

// NewEngine creates a programmatic instance of the CoreSight decoding framework.
func NewEngine(cfg EngineConfig) (*Engine, error) {
	// 1. Initialize internal memory mapper.
	mapper := NewGlobalMapper()
	for _, m := range cfg.Mappings {
		var space MemSpaceAcc
		switch m.Space {
		case SpaceSecure:
			space = MemSpaceS
		case SpaceNonSecure:
			space = MemSpaceN
		default:
			space = MemSpaceAny
		}
		acc := NewReaderAtAccessor(VAddr(m.BaseAddress), m.Size, m.Source, space)
		if err := mapper.AddAccessor(acc); err != nil {
			return nil, fmt.Errorf("failed to add memory accessor: %w", err)
		}
	}

	// 2. Map demux options.
	var demuxOpts DemuxOptions
	if cfg.FramedInput {
		if cfg.Demux != nil {
			demuxOpts = DemuxOptions{
				HasFsyncs:      cfg.Demux.HasFsyncs,
				HasHsyncs:      cfg.Demux.HasHsyncs,
				FrameMemAlign:  cfg.Demux.FrameMemAlign,
				PackedRawOut:   cfg.Demux.PackedRawOut,
				UnpackedRawOut: cfg.Demux.UnpackedRawOut,
				ResetOn4xFsync: cfg.Demux.ResetOn4xFsync,
			}
		} else {
			demuxOpts = DemuxOptions{FrameMemAlign: true}
		}
	}

	p, err := NewPipeline(cfg.FramedInput, demuxOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to create pipeline: %w", err)
	}

	if cfg.FramedInput && cfg.Demux != nil && cfg.Demux.RawFrameHandler != nil {
		p.Demuxer.SetRawFrameHandler(func(idx Index, elem RawframeElem, data []byte, traceID uint8) error {
			return cfg.Demux.RawFrameHandler(uint64(idx), elem, data, traceID)
		})
	}

	return &Engine{
		pipe:        p,
		framedInput: cfg.FramedInput,
		mapper:      mapper,
	}, nil
}

// Write feeds a block of raw binary trace data directly into the decoding pipeline.
// Execution is entirely synchronous and runs down the call chain to the registered sinks.
func (e *Engine) Write(p []byte) (int, error) {
	n, err := e.pipe.Write(e.index, p)
	e.index += Index(n)
	return int(n), err
}

// Reset resets the engine and internal decoders.
func (e *Engine) Reset() error {
	e.index = 0
	return e.pipe.Reset(0)
}

// Close flushes and closes the engine.
func (e *Engine) Close() error {
	return e.pipe.Close()
}

// DumpMappings returns a string representation of the mapped memory accessors,
// matching the format expected by the package diagnostics.
func (e *Engine) DumpMappings() string {
	return e.mapper.DumpMappings()
}

// Mapper returns the GlobalMapper used by this engine.
// Callers can use it to add additional memory accessors after construction.
func (e *Engine) Mapper() *GlobalMapper {
	return e.mapper
}

// RegisterETMv3 registers an ETMv3 macrocell decoder on a Trace ID.
func (e *Engine) RegisterETMv3(traceID uint8, cfg ETMv3Config, sink ElementSink) error {
	route, err := NewETMv3Route(traceID, cfg, e.mapper, sink)
	if err != nil {
		return err
	}
	e.pipe.AddRoute(route)
	return nil
}

// RegisterETMv4 registers an ETMv4 macrocell decoder on a Trace ID.
func (e *Engine) RegisterETMv4(traceID uint8, cfg ETMv4Config, sink ElementSink) error {
	route, err := NewETMv4Route(traceID, cfg, e.mapper, sink)
	if err != nil {
		return err
	}
	e.pipe.AddRoute(route)
	return nil
}

// RegisterPTM registers a PTM macrocell decoder on a Trace ID.
func (e *Engine) RegisterPTM(traceID uint8, cfg PTMConfig, sink ElementSink) error {
	route, err := NewPTMRoute(traceID, cfg, e.mapper, sink)
	if err != nil {
		return err
	}
	e.pipe.AddRoute(route)
	return nil
}

// RegisterSTM registers an STM macrocell decoder on a Trace ID.
func (e *Engine) RegisterSTM(traceID uint8, cfg STMConfig, sink ElementSink) error {
	route, err := NewSTMRoute(traceID, cfg, sink)
	if err != nil {
		return err
	}
	e.pipe.AddRoute(route)
	return nil
}

// RegisterITM registers an ITM macrocell decoder on a Trace ID.
func (e *Engine) RegisterITM(traceID uint8, cfg ITMConfig, sink ElementSink) error {
	route, err := NewITMRoute(traceID, cfg, sink)
	if err != nil {
		return err
	}
	e.pipe.AddRoute(route)
	return nil
}

// RegisterETE registers an ETE macrocell decoder on a Trace ID.
// ETE is a superset of ETMv4; use ETEConfig (which aliases ETMv4Config) to configure it.
func (e *Engine) RegisterETE(traceID uint8, cfg ETEConfig, sink ElementSink) error {
	route, err := NewETERoute(traceID, cfg, e.mapper, sink)
	if err != nil {
		return err
	}
	e.pipe.AddRoute(route)
	return nil
}

func setupObservers(dec any, pktObs PacketObserver, endObs func(), sink ElementSink) {
	if s, ok := any(dec).(interface{ SetElementSink(ElementSink) }); ok {
		s.SetElementSink(sink)
	}
	if pktObs != nil {
		if s, ok := any(dec).(interface{ SetPacketObserver(PacketObserver) }); ok {
			s.SetPacketObserver(func(idx uint64, pkt fmt.Stringer, raw []byte) {
				pktObs(idx, pkt, raw)
			})
		}
	}
	if endObs != nil {
		if s, ok := any(dec).(interface{ SetTraceEndObserver(func()) }); ok {
			s.SetTraceEndObserver(endObs)
		}
	}
}

func makeETMv4Config(traceID uint8, c ETMv4Config) *etmv4Config {
	cfg := etmv4NewDefaultConfig()
	cfg.RegTraceIDR = uint32(traceID)
	if c.IDR0 != 0 {
		cfg.RegIDR0 = c.IDR0
	}
	if c.IDR1 != 0 {
		cfg.RegIDR1 = c.IDR1
	}
	if c.IDR2 != 0 {
		cfg.RegIDR2 = c.IDR2
	}
	if c.ConfigR != 0 {
		cfg.RegConfigR = c.ConfigR
	}
	cfg.RegIDR8 = c.IDR8
	cfg.RegIDR9 = c.IDR9
	cfg.RegIDR10 = c.IDR10
	cfg.RegIDR11 = c.IDR11
	cfg.RegIDR12 = c.IDR12
	cfg.RegIDR13 = c.IDR13
	cfg.RegDevArch = c.DevArch
	if c.ArchVersion != ArchUnknown {
		cfg.ArchVer = c.ArchVersion
	}
	if c.CoreProfile != ProfileUnknown {
		cfg.CoreProf = c.CoreProfile
	}
	cfg.errOnAA64BadOpcode = c.ErrOnAA64BadOpcode
	cfg.InstrRangeLimit = c.InstrRangeLimit
	cfg.SrcAddrNAtoms = c.SrcAddrNAtoms
	return cfg
}

func makeETMv3Config(traceID uint8, c ETMv3Config) *etmv3Config {
	cfg := etmv3NewDefaultConfig()
	cfg.RegTrcID = uint32(traceID)
	if c.IDR != 0 {
		cfg.RegIDR = c.IDR
	}
	if c.Control != 0 {
		cfg.RegCtrl = c.Control
	}
	if c.CCER != 0 {
		cfg.RegCCER = c.CCER
	}
	if c.ArchVersion != ArchUnknown {
		cfg.ArchVer = c.ArchVersion
	}
	if c.CoreProfile != ProfileUnknown {
		cfg.CoreProf = c.CoreProfile
	}
	return cfg
}

func makePTMConfig(traceID uint8, c PTMConfig) *ptmConfig {
	idr := c.IDR
	if idr == 0 {
		idr = 0x4100F310
	}
	arch := c.ArchVersion
	if arch == ArchUnknown {
		arch = ArchV7
	}
	prof := c.CoreProfile
	if prof == ProfileUnknown {
		prof = ProfileCortexA
	}
	return ptmParseConfig(uint32(traceID), idr, c.Control, c.CCER, arch, prof)
}

func makeSTMConfig(traceID uint8, c STMConfig) *stmConfig {
	cfg := &stmConfig{RegTCSR: c.ControlRegister}
	cfg.SetTraceID(traceID)
	return cfg
}

func makeITMConfig(traceID uint8, c ITMConfig) *itmConfig {
	cfg := &itmConfig{RegTCR: c.ControlRegister}
	cfg.SetTraceID(traceID)
	return cfg
}
