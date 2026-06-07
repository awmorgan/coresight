package coresight

import (
	"fmt"

)

type QSuppType int

const (
	QNone QSuppType = iota
	QICountOnly
	QNoICountOnly
	QFull
)

type CondITrace int

const (
	CondTraceDisabled CondITrace = iota
	CondTraceLoad
	CondTraceStore
	CondTraceLoadStore
	CondTraceAll
)

// etmv4Config represents the ETMv4 instruction trace register configuration.
type etmv4Config struct {
	RegIDR0     uint32
	RegIDR1     uint32
	RegIDR2     uint32
	RegIDR8     uint32
	RegIDR9     uint32
	RegIDR10    uint32
	RegIDR11    uint32
	RegIDR12    uint32
	RegIDR13    uint32
	RegDevArch  uint32
	RegConfigR  uint32
	RegTraceIDR uint32
	ArchVer     ArchVersion
	CoreProf    CoreProfile

	ErrOnAA64BadOpcode bool
	InstrRangeLimit    uint32
	SrcAddrNAtoms      bool
}

func etmv4ParseConfig(traceID, configr, idr0, idr1, idr2, idr8, idr9, idr10, idr11, idr12, idr13 uint32, arch ArchVersion, prof CoreProfile) *etmv4Config {
	return &etmv4Config{
		RegTraceIDR: traceID,
		RegConfigR:  configr,
		RegIDR0:     idr0,
		RegIDR1:     idr1,
		RegIDR2:     idr2,
		RegIDR8:     idr8,
		RegIDR9:     idr9,
		RegIDR10:    idr10,
		RegIDR11:    idr11,
		RegIDR12:    idr12,
		RegIDR13:    idr13,
		ArchVer:     arch,
		CoreProf:    prof,
	}
}

func etmv4NewDefaultConfig() *etmv4Config {
	return &etmv4Config{
		RegIDR0:    0x28000EA1,
		RegIDR1:    0x4100F403,
		RegIDR2:    0x00000488,
		RegConfigR: 0xC1,
		ArchVer:    ArchV7,
		CoreProf:   ProfileCortexA,
	}
}

func (c *etmv4Config) TraceID() uint8 { return uint8(c.RegTraceIDR & 0x7F) }
func (c *etmv4Config) MajorVersion() uint8 {
	if c.RegDevArch != 0 {
		return uint8((c.RegDevArch >> 12) & 0xF)
	}
	return uint8((c.RegIDR1 >> 8) & 0xF)
}
func (c *etmv4Config) MinorVersion() uint8 {
	if c.RegDevArch != 0 {
		return uint8((c.RegDevArch >> 16) & 0xF)
	}
	return uint8((c.RegIDR1 >> 4) & 0xF)
}
func (c *etmv4Config) FullVersion() uint8 { return (c.MajorVersion() << 4) | c.MinorVersion() }
func (c *etmv4Config) IsETE() bool        { return c.MajorVersion() >= 5 }

func (c *etmv4Config) HasDataTrace() bool   { return (c.RegIDR0 & 0x18) == 0x18 }
func (c *etmv4Config) HasCondTrace() bool   { return (c.RegIDR0 & 0x40) == 0x40 }
func (c *etmv4Config) HasCycleCountI() bool { return (c.RegIDR0 & 0x80) == 0x80 }
func (c *etmv4Config) HasRetStack() bool    { return (c.RegIDR0 & 0x200) == 0x200 }
func (c *etmv4Config) HasTrcExcpData() bool { return (c.RegIDR0 & 0x20000) == 0x20000 }
func (c *etmv4Config) TimeStampSize() uint32 {
	switch (c.RegIDR0 >> 24) & 0x1F {
	case 0x6:
		return 48
	case 0x8:
		return 64
	default:
		return 0
	}
}
func (c *etmv4Config) CommitOpt1() bool  { return (c.RegIDR0&0x20000000) != 0 && c.HasCycleCountI() }
func (c *etmv4Config) CommTransP0() bool { return (c.RegIDR0 & 0x40000000) == 0 }

func (c *etmv4Config) QSuppType() QSuppType {
	return [...]QSuppType{QNone, QICountOnly, QNoICountOnly, QFull}[(c.RegIDR0>>15)&0x3]
}
func (c *etmv4Config) HasQElem() bool { return c.QSuppType() != QNone }

func (c *etmv4Config) IASizeMax() uint32 {
	if c.RegIDR2&0x1F == 0x8 {
		return 64
	}
	return 32
}
func (c *etmv4Config) CIDSize() uint32 {
	if ((c.RegIDR2 >> 5) & 0x1F) == 0x4 {
		return 32
	}
	return 0
}
func (c *etmv4Config) VMIDSize() uint32 {
	vmidsz := (c.RegIDR2 >> 10) & 0x1F
	if vmidsz == 1 {
		return 8
	}
	if c.FullVersion() > 0x40 {
		if vmidsz == 2 {
			return 16
		}
		if vmidsz == 4 {
			return 32
		}
	}
	return 0
}
func (c *etmv4Config) CCSize() uint32 { return ((c.RegIDR2 >> 25) & 0xF) + 12 }
func (c *etmv4Config) MaxSpecDepth() uint32 {
	return c.RegIDR8
}
func (c *etmv4Config) WfiWfeBranch() bool {
	return (c.RegIDR2&0x80000000 != 0) && (c.FullVersion() >= 0x43)
}
func (c *etmv4Config) EnabledLSP0Trace() bool { return (c.RegConfigR & 0x6) != 0 }
func (c *etmv4Config) EnabledDATrace() bool {
	return c.HasDataTrace() && c.EnabledLSP0Trace() && (c.RegConfigR&(1<<16)) != 0
}
func (c *etmv4Config) EnabledDVTrace() bool {
	return c.HasDataTrace() && c.EnabledLSP0Trace() && (c.RegConfigR&(1<<17)) != 0
}
func (c *etmv4Config) EnabledDataTrace() bool { return c.EnabledDATrace() || c.EnabledDVTrace() }
func (c *etmv4Config) EnabledCCI() bool       { return (c.RegConfigR & (1 << 4)) != 0 }
func (c *etmv4Config) EnabledCID() bool       { return (c.RegConfigR & (1 << 6)) != 0 }
func (c *etmv4Config) EnabledVMID() bool      { return (c.RegConfigR & (1 << 7)) != 0 }
func (c *etmv4Config) EnabledTS() bool        { return (c.RegConfigR & (1 << 11)) != 0 }
func (c *etmv4Config) EnabledRetStack() bool  { return (c.RegConfigR & (1 << 12)) != 0 }
func (c *etmv4Config) EnabledQE() bool        { return (c.RegConfigR & (0x3 << 13)) != 0 }

func (c *etmv4Config) EnabledCondITrace() CondITrace {
	switch (c.RegConfigR >> 8) & 0x7 {
	case 1:
		return CondTraceLoad
	case 2:
		return CondTraceStore
	case 3:
		return CondTraceLoadStore
	case 7:
		return CondTraceAll
	default:
		return CondTraceDisabled
	}
}

func (c *etmv4Config) String() string {
	return fmt.Sprintf("ETMv4 etmv4Config [ID=0x%02x, IDR0=0x%08x, IDR1=0x%08x, CONFIGR=0x%08x]", c.TraceID(), c.RegIDR0, c.RegIDR1, c.RegConfigR)
}
