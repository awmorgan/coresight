package coresight

import (
	"fmt"
)

type eteConfig struct {
	*etmv4Config
}

func (c *eteConfig) String() string {
	if c == nil || c.etmv4Config == nil {
		return "ETE eteConfig <nil>"
	}
	return fmt.Sprintf("ETE eteConfig [ID=0x%02x, IDR0=0x%08x, IDR1=0x%08x, DEVARCH=0x%08x, CONFIGR=0x%08x]", c.TraceID(), c.RegIDR0, c.RegIDR1, c.RegDevArch, c.RegConfigR)
}
