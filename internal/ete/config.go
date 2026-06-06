package ete

import (
	"fmt"

	"coresight/internal/etmv4"
	"coresight/trace"
)

type Config struct {
	*etmv4.Config
}

func ParseConfig(traceID, configr, idr0, idr1, idr2, idr8, devarch uint32, arch trace.ArchVersion, prof trace.CoreProfile) *Config {
	cfg := etmv4.ParseConfig(
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
	return &Config{Config: cfg}
}

func NewDefaultConfig() *Config {
	return ParseConfig(
		0,
		0xC1,
		0x28000EA1,
		0x4100FFF3,
		0x00000488,
		0,
		0x47705A13,
		trace.ArchAA64,
		trace.ProfileCortexA,
	)
}

func (c *Config) String() string {
	if c == nil || c.Config == nil {
		return "ETE Config <nil>"
	}
	return fmt.Sprintf("ETE Config [ID=0x%02x, IDR0=0x%08x, IDR1=0x%08x, DEVARCH=0x%08x, CONFIGR=0x%08x]", c.TraceID(), c.RegIDR0, c.RegIDR1, c.RegDevArch, c.RegConfigR)
}
