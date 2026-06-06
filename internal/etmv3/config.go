package etmv3

import (
	"fmt"
	"github.com/awmorgan/coresight/trace"
)

// Config represents the hardware configuration for an ETMv3 trace macrocell.
type Config struct {
	RegIDR   uint32
	RegCtrl  uint32
	RegCCER  uint32
	RegTrcID uint32
	ArchVer  trace.ArchVersion
	CoreProf trace.CoreProfile
}

// Register bit constants
const (
	ctrlDataVal  uint32 = 0x4
	ctrlDataAddr uint32 = 0x8
	ctrlCycleAcc uint32 = 0x1000
	ctrlDataOnly uint32 = 0x100000
	ctrlTsEna    uint32 = 0x1 << 28
	ctrlVmidEna  uint32 = 0x1 << 30

	ccerHasTs   uint32 = 0x1 << 22
	ccerVirtExt uint32 = 0x1 << 26
	ccerTs64Bit uint32 = 0x1 << 29

	idrAltBranch uint32 = 0x100000
)

type TraceMode int

const (
	TMInstrOnly TraceMode = iota
	TMIDataVal
	TMIDataAddr
	TMIDataValAddr
	TMDataOnlyVal
	TMDataOnlyAddr
	TMDataOnlyValAddr
)

// TraceMode returns the combination enum describing the trace mode.
func (c *Config) TraceMode() TraceMode {
	mode := 0
	if c.DataValTrace() {
		mode += 1
	}
	if c.DataAddrTrace() {
		mode += 2
	}
	if !c.InstrTrace() {
		mode += 3
	}
	return TraceMode(mode)
}

func (c *Config) InstrTrace() bool    { return (c.RegCtrl & ctrlDataOnly) == 0 }
func (c *Config) DataValTrace() bool  { return (c.RegCtrl & ctrlDataVal) != 0 }
func (c *Config) DataAddrTrace() bool { return (c.RegCtrl & ctrlDataAddr) != 0 }
func (c *Config) DataTrace() bool     { return (c.RegCtrl & (ctrlDataAddr | ctrlDataVal)) != 0 }
func (c *Config) CycleAcc() bool      { return (c.RegCtrl & ctrlCycleAcc) != 0 }
func (c *Config) MinorRev() int       { return int((c.RegIDR & 0xF0) >> 4) }
func (c *Config) V7MArch() bool {
	return c.ArchVer == trace.ArchV7 && c.CoreProf == trace.ProfileCortexM
}
func (c *Config) AltBranch() bool { return (c.RegIDR&idrAltBranch) != 0 && c.MinorRev() >= 4 }

var ctxtIDByteCounts = [...]int{0, 1, 2, 4}

func (c *Config) CtxtIDBytes() int { return ctxtIDByteCounts[(c.RegCtrl>>14)&0x3] }
func (c *Config) HasVirtExt() bool { return (c.RegCCER & ccerVirtExt) != 0 }
func (c *Config) VMIDTrace() bool  { return (c.RegCtrl & ctrlVmidEna) != 0 }
func (c *Config) HasTS() bool      { return (c.RegCCER & ccerHasTs) != 0 }
func (c *Config) TSEnabled() bool  { return (c.RegCtrl & ctrlTsEna) != 0 }
func (c *Config) TSPkt64() bool    { return (c.RegCCER & ccerTs64Bit) != 0 }
func (c *Config) TraceID() uint8   { return uint8(c.RegTrcID & 0x7F) }

func (c *Config) String() string {
	return fmt.Sprintf("ETMv3 Config [ID=0x%02x, IDR=0x%08x, CTRL=0x%08x]", c.TraceID(), c.RegIDR, c.RegCtrl)
}

// ParseConfig creates a Config from raw hardware register values.
func ParseConfig(traceID, idr, ctrl, ccer uint32, arch trace.ArchVersion, prof trace.CoreProfile) *Config {
	return &Config{
		RegTrcID: traceID,
		RegIDR:   idr,
		RegCtrl:  ctrl,
		RegCCER:  ccer,
		ArchVer:  arch,
		CoreProf: prof,
	}
}

// NewDefaultConfig creates a Config with the default ETMv3.4, V7A, instruction only setup.
func NewDefaultConfig() *Config {
	return &Config{
		ArchVer:  trace.ArchV7,
		CoreProf: trace.ProfileCortexA,
		RegIDR:   0x4100F240,
	}
}
