package coresight

const (
	stmTraceIDMask  uint32 = 0x007F0000
	stmTraceIDShift uint32 = 16
)

// stmConfig represents STM hardware configuration data.
type stmConfig struct {
	RegTCSR uint32
}

// TraceID gets the CoreSight trace ID.
func (c *stmConfig) TraceID() uint8 {
	return uint8((c.RegTCSR & stmTraceIDMask) >> stmTraceIDShift)
}

// SetTraceID sets the CoreSight trace ID.
func (c *stmConfig) SetTraceID(traceID uint8) {
	c.RegTCSR &= ^stmTraceIDMask
	c.RegTCSR |= (uint32(traceID) << stmTraceIDShift) & stmTraceIDMask
}
