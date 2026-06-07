package coresight

import (
	"fmt"

)

type eteConfig struct {
	*etmv4Config
}

func eteParseConfig(traceID, configr, idr0, idr1, idr2, idr8, devarch uint32, arch ArchVersion, prof CoreProfile) *eteConfig {
	cfg := etmv4ParseConfig(
		traceID,
		configr,
		idr0,
		idr1,
		idr2,
		idr8,
		0,
		0,
		0,
		0,
		0,
		arch,
		prof,
	)
	cfg.RegDevArch = devarch
	return &eteConfig{etmv4Config: cfg}
}

func eteNewDefaultConfig() *eteConfig {
	return eteParseConfig(
		0,
		0xC1,
		0x28000EA1,
		0x4100FFF3,
		0x00000488,
		0,
		0x47705A13,
		ArchAA64,
		ProfileCortexA,
	)
}

func (c *eteConfig) String() string {
	if c == nil || c.etmv4Config == nil {
		return "ETE eteConfig <nil>"
	}
	return fmt.Sprintf("ETE eteConfig [ID=0x%02x, IDR0=0x%08x, IDR1=0x%08x, DEVARCH=0x%08x, CONFIGR=0x%08x]", c.TraceID(), c.RegIDR0, c.RegIDR1, c.RegDevArch, c.RegConfigR)
}
