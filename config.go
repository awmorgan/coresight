package coresight

import (
	"fmt"

)

// PacketObserver is the public type for observing raw packets off the decode path.
type PacketObserver func(index uint64, pkt fmt.Stringer, rawData []byte)

// ETMv4Config holds the hardware register state required to initialize an ETMv4 decoder.
type ETMv4Config struct {
	IDR0               uint32
	IDR1               uint32
	IDR2               uint32
	ConfigR            uint32
	IDR8               uint32
	IDR9               uint32
	IDR10              uint32
	IDR11              uint32
	IDR12              uint32
	IDR13              uint32
	DevArch            uint32
	ArchVersion        ArchVersion
	CoreProfile        CoreProfile
	errOnAA64BadOpcode bool
	InstrRangeLimit    uint32
	SrcAddrNAtoms      bool

	PacketObserver   PacketObserver
	TraceEndObserver func()
}

// ETMv3Config holds the hardware configuration for an ETMv3 trace macrocell.
type ETMv3Config struct {
	IDR         uint32
	Control     uint32
	CCER        uint32
	ArchVersion ArchVersion
	CoreProfile CoreProfile

	PacketObserver   PacketObserver
	TraceEndObserver func()
}

// PTMConfig holds the hardware configuration for a Program Trace Macrocell.
type PTMConfig struct {
	IDR         uint32
	Control     uint32
	CCER        uint32
	ArchVersion ArchVersion
	CoreProfile CoreProfile

	PacketObserver   PacketObserver
	TraceEndObserver func()
}

// ITMConfig holds the hardware configuration for an Instrumentation Trace Macrocell.
type ITMConfig struct {
	ControlRegister uint32

	PacketObserver   PacketObserver
	TraceEndObserver func()
}

// STMConfig holds the hardware configuration for a System Trace Macrocell.
type STMConfig struct {
	ControlRegister uint32

	PacketObserver   PacketObserver
	TraceEndObserver func()
}
