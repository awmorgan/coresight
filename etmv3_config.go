package coresight

import (
	"fmt"
)

// etmv3Config represents the hardware configuration for an ETMv3 trace macrocell.
type etmv3Config struct {
	RegIDR   uint32
	RegCtrl  uint32
	RegCCER  uint32
	RegTrcID uint32
	ArchVer  ArchVersion
	CoreProf CoreProfile
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

func (c *etmv3Config) InstrTrace() bool    { return (c.RegCtrl & ctrlDataOnly) == 0 }
func (c *etmv3Config) DataValTrace() bool  { return (c.RegCtrl & ctrlDataVal) != 0 }
func (c *etmv3Config) DataAddrTrace() bool { return (c.RegCtrl & ctrlDataAddr) != 0 }
func (c *etmv3Config) DataTrace() bool     { return (c.RegCtrl & (ctrlDataAddr | ctrlDataVal)) != 0 }
func (c *etmv3Config) CycleAcc() bool      { return (c.RegCtrl & ctrlCycleAcc) != 0 }
func (c *etmv3Config) MinorRev() int       { return int((c.RegIDR & 0xF0) >> 4) }
func (c *etmv3Config) V7MArch() bool {
	return c.ArchVer == ArchV7 && c.CoreProf == ProfileCortexM
}
func (c *etmv3Config) AltBranch() bool { return (c.RegIDR&idrAltBranch) != 0 && c.MinorRev() >= 4 }

var ctxtIDByteCounts = [...]int{0, 1, 2, 4}

func (c *etmv3Config) CtxtIDBytes() int { return ctxtIDByteCounts[(c.RegCtrl>>14)&0x3] }
func (c *etmv3Config) HasVirtExt() bool { return (c.RegCCER & ccerVirtExt) != 0 }
func (c *etmv3Config) VMIDTrace() bool  { return (c.RegCtrl & ctrlVmidEna) != 0 }
func (c *etmv3Config) HasTS() bool      { return (c.RegCCER & ccerHasTs) != 0 }
func (c *etmv3Config) TSEnabled() bool  { return (c.RegCtrl & ctrlTsEna) != 0 }
func (c *etmv3Config) TSPkt64() bool    { return (c.RegCCER & ccerTs64Bit) != 0 }
func (c *etmv3Config) TraceID() uint8   { return uint8(c.RegTrcID & 0x7F) }

func (c *etmv3Config) String() string {
	return fmt.Sprintf("ETMv3 etmv3Config [ID=0x%02x, IDR=0x%08x, CTRL=0x%08x]", c.TraceID(), c.RegIDR, c.RegCtrl)
}

// etmv3ParseConfig creates a etmv3Config from raw hardware register values.
func etmv3ParseConfig(traceID, idr, ctrl, ccer uint32, arch ArchVersion, prof CoreProfile) *etmv3Config {
	return &etmv3Config{
		RegTrcID: traceID,
		RegIDR:   idr,
		RegCtrl:  ctrl,
		RegCCER:  ccer,
		ArchVer:  arch,
		CoreProf: prof,
	}
}

// etmv3NewDefaultConfig creates a etmv3Config with the default ETMv3.4, V7A, instruction only setup.
func etmv3NewDefaultConfig() *etmv3Config {
	return &etmv3Config{
		ArchVer:  ArchV7,
		CoreProf: ProfileCortexA,
		RegIDR:   0x4100F240,
	}
}
