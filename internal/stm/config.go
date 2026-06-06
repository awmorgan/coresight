package stm

const (
	traceIDMask  uint32 = 0x007F0000
	traceIDShift uint32 = 16
)

// Config represents STM hardware configuration data.
type Config struct {
	RegTCSR uint32
}

// TraceID gets the CoreSight trace ID.
func (c *Config) TraceID() uint8 {
	return uint8((c.RegTCSR & traceIDMask) >> traceIDShift)
}

// SetTraceID sets the CoreSight trace ID.
func (c *Config) SetTraceID(traceID uint8) {
	c.RegTCSR &= ^traceIDMask
	c.RegTCSR |= (uint32(traceID) << traceIDShift) & traceIDMask
}
