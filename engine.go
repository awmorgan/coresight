package coresight

import (
	"fmt"

)

// ElementSink is the public callback type. Because it is route-specific,
// users can use Go closures to capture core-specific context out-of-band.
type ElementSink func(elem Element)

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
		if err := mapper.AddAccessor(acc, BadCSSrcID); err != nil {
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

// Write feeds a block of raw binary trace data directly into the decoding 
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

// RegisterETMv3 registers an ETMv3 macrocell decoder on a Trace ID.
func (e *Engine) RegisterETMv3(traceID uint8, cfg ETMv3Config, sink ElementSink) error {
	if traceID >= 128 {
		return fmt.Errorf("invalid coresight trace ID: %d", traceID)
	}
	internalSink := func(elem Element) { sink(elem) }
	c := makeETMv3Config(traceID, cfg)
	dec, err := etmv3NewDecoder(c, e.mapper, DecodeInstruction)
	if err != nil {
		return fmt.Errorf("failed to create ETMv3 decoder: %w", err)
	}
	setupObservers(dec, cfg.PacketObserver, cfg.TraceEndObserver, internalSink)
	e.pipe.AddRoute(Route{
		TraceID:  traceID,
		Protocol: ProtocolETMV3,
		ByteSink: dec,
	})
	return nil
}

// RegisterETMv4 registers an ETMv4 macrocell decoder on a Trace ID.
func (e *Engine) RegisterETMv4(traceID uint8, cfg ETMv4Config, sink ElementSink) error {
	if traceID >= 128 {
		return fmt.Errorf("invalid coresight trace ID: %d", traceID)
	}
	internalSink := func(elem Element) { sink(elem) }
	c := makeETMv4Config(traceID, cfg)
	dec, err := etmv4NewDecoder(c, e.mapper, DecodeInstruction)
	if err != nil {
		return fmt.Errorf("failed to create ETMv4 decoder: %w", err)
	}
	setupObservers(dec, cfg.PacketObserver, cfg.TraceEndObserver, internalSink)
	e.pipe.AddRoute(Route{
		TraceID:  traceID,
		Protocol: ProtocolETMV4I,
		ByteSink: dec,
	})
	return nil
}

// RegisterPTM registers a PTM macrocell decoder on a Trace ID.
func (e *Engine) RegisterPTM(traceID uint8, cfg PTMConfig, sink ElementSink) error {
	if traceID >= 128 {
		return fmt.Errorf("invalid coresight trace ID: %d", traceID)
	}
	internalSink := func(elem Element) { sink(elem) }
	c := makePTMConfig(traceID, cfg)
	dec, err := ptmNewDecoder(c, e.mapper, DecodeInstruction)
	if err != nil {
		return fmt.Errorf("failed to create PTM decoder: %w", err)
	}
	setupObservers(dec, cfg.PacketObserver, cfg.TraceEndObserver, internalSink)
	e.pipe.AddRoute(Route{
		TraceID:  traceID,
		Protocol: ProtocolPTM,
		ByteSink: dec,
	})
	return nil
}

// RegisterSTM registers an STM macrocell decoder on a Trace ID.
func (e *Engine) RegisterSTM(traceID uint8, cfg STMConfig, sink ElementSink) error {
	if traceID >= 128 {
		return fmt.Errorf("invalid coresight trace ID: %d", traceID)
	}
	internalSink := func(elem Element) { sink(elem) }
	c := makeSTMConfig(traceID, cfg)
	dec, err := stmNewDecoder(c)
	if err != nil {
		return fmt.Errorf("failed to create STM decoder: %w", err)
	}
	setupObservers(dec, cfg.PacketObserver, cfg.TraceEndObserver, internalSink)
	e.pipe.AddRoute(Route{
		TraceID:  traceID,
		Protocol: ProtocolSTM,
		ByteSink: dec,
	})
	return nil
}

// RegisterITM registers an ITM macrocell decoder on a Trace ID.
func (e *Engine) RegisterITM(traceID uint8, cfg ITMConfig, sink ElementSink) error {
	if traceID >= 128 {
		return fmt.Errorf("invalid coresight trace ID: %d", traceID)
	}
	internalSink := func(elem Element) { sink(elem) }
	c := makeITMConfig(traceID, cfg)
	dec, err := itmNewDecoder(c)
	if err != nil {
		return fmt.Errorf("failed to create ITM decoder: %w", err)
	}
	setupObservers(dec, cfg.PacketObserver, cfg.TraceEndObserver, internalSink)
	e.pipe.AddRoute(Route{
		TraceID:  traceID,
		Protocol: ProtocolITM,
		ByteSink: dec,
	})
	return nil
}

func setupObservers(dec any, pktObs PacketObserver, endObs func(), sink internalElementSink) {
	if s, ok := any(dec).(interface{ SetElementSink(internalElementSink) }); ok {
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
	cfg.ErrOnAA64BadOpcode = c.ErrOnAA64BadOpcode
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
