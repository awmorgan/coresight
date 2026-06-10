package coresight

import "fmt"

// NewETMv3Route creates a configured ETMv3 decoder and returns a Route ready
// to be added to a Pipeline. mem must be non-nil for full instruction decode;
// pass nil for packet-only mode.
func NewETMv3Route(traceID uint8, cfg ETMv3Config, mem MemoryReader, sink ElementSink) (Route, error) {
	if traceID >= 128 {
		return Route{}, fmt.Errorf("invalid coresight trace ID: %d", traceID)
	}
	c := makeETMv3Config(traceID, cfg)
	var instr internalInstructionDecoder
	if mem != nil {
		instr = decodeInstruction
	}
	dec, err := etmv3NewDecoder(c, mem, instr)
	if err != nil {
		return Route{}, fmt.Errorf("failed to create ETMv3 decoder: %w", err)
	}
	setupObservers(dec, cfg.PacketObserver, cfg.TraceEndObserver, sink)
	return Route{TraceID: traceID, Protocol: ProtocolETMV3, ByteSink: dec}, nil
}

// NewETMv4Route creates a configured ETMv4 decoder and returns a Route ready
// to be added to a Pipeline.
func NewETMv4Route(traceID uint8, cfg ETMv4Config, mem MemoryReader, sink ElementSink) (Route, error) {
	if traceID >= 128 {
		return Route{}, fmt.Errorf("invalid coresight trace ID: %d", traceID)
	}
	c := makeETMv4Config(traceID, cfg)
	var instr internalInstructionDecoder
	if mem != nil {
		instr = decodeInstruction
	}
	dec, err := etmv4NewDecoder(c, mem, instr)
	if err != nil {
		return Route{}, fmt.Errorf("failed to create ETMv4 decoder: %w", err)
	}
	setupObservers(dec, cfg.PacketObserver, cfg.TraceEndObserver, sink)
	return Route{TraceID: traceID, Protocol: ProtocolETMV4I, ByteSink: dec}, nil
}

// NewPTMRoute creates a configured PTM decoder and returns a Route ready
// to be added to a Pipeline.
func NewPTMRoute(traceID uint8, cfg PTMConfig, mem MemoryReader, sink ElementSink) (Route, error) {
	if traceID >= 128 {
		return Route{}, fmt.Errorf("invalid coresight trace ID: %d", traceID)
	}
	c := makePTMConfig(traceID, cfg)
	var instr internalInstructionDecoder
	if mem != nil {
		instr = decodeInstruction
	}
	dec, err := ptmNewDecoder(c, mem, instr)
	if err != nil {
		return Route{}, fmt.Errorf("failed to create PTM decoder: %w", err)
	}
	setupObservers(dec, cfg.PacketObserver, cfg.TraceEndObserver, sink)
	return Route{TraceID: traceID, Protocol: ProtocolPTM, ByteSink: dec}, nil
}

// NewSTMRoute creates a configured STM decoder and returns a Route ready
// to be added to a Pipeline. STM decoders do not require memory access.
func NewSTMRoute(traceID uint8, cfg STMConfig, sink ElementSink) (Route, error) {
	if traceID >= 128 {
		return Route{}, fmt.Errorf("invalid coresight trace ID: %d", traceID)
	}
	c := makeSTMConfig(traceID, cfg)
	dec, err := stmNewDecoder(c)
	if err != nil {
		return Route{}, fmt.Errorf("failed to create STM decoder: %w", err)
	}
	setupObservers(dec, cfg.PacketObserver, cfg.TraceEndObserver, sink)
	return Route{TraceID: traceID, Protocol: ProtocolSTM, ByteSink: dec}, nil
}

// NewITMRoute creates a configured ITM decoder and returns a Route ready
// to be added to a Pipeline. ITM decoders do not require memory access.
func NewITMRoute(traceID uint8, cfg ITMConfig, sink ElementSink) (Route, error) {
	if traceID >= 128 {
		return Route{}, fmt.Errorf("invalid coresight trace ID: %d", traceID)
	}
	c := makeITMConfig(traceID, cfg)
	dec, err := itmNewDecoder(c)
	if err != nil {
		return Route{}, fmt.Errorf("failed to create ITM decoder: %w", err)
	}
	setupObservers(dec, cfg.PacketObserver, cfg.TraceEndObserver, sink)
	return Route{TraceID: traceID, Protocol: ProtocolITM, ByteSink: dec}, nil
}

// ETEConfig holds the hardware register state required to initialise an ETE decoder.
// ETE is a superset of ETMv4 and shares the same register layout.
type ETEConfig = ETMv4Config

// NewETERoute creates a configured ETE decoder and returns a Route ready
// to be added to a Pipeline.
func NewETERoute(traceID uint8, cfg ETEConfig, mem MemoryReader, sink ElementSink) (Route, error) {
	if traceID >= 128 {
		return Route{}, fmt.Errorf("invalid coresight trace ID: %d", traceID)
	}
	etmCfg := makeETMv4Config(traceID, cfg)
	eteCfg := &eteConfig{etmv4Config: etmCfg}
	var instr internalInstructionDecoder
	if mem != nil {
		instr = decodeInstruction
	}
	dec, err := eteNewDecoder(eteCfg, mem, instr)
	if err != nil {
		return Route{}, fmt.Errorf("failed to create ETE decoder: %w", err)
	}
	setupObservers(dec, cfg.PacketObserver, cfg.TraceEndObserver, sink)
	return Route{TraceID: traceID, Protocol: ProtocolETE, ByteSink: dec}, nil
}
