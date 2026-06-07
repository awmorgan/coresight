package coresight

const (
	itmTraceIDMask        uint32 = 0x007F0000
	itmTraceIDShift              = 16
	tcrSWOEnable       uint32 = 0x10
	tcrTSPrescaleShift        = 8
)

var tsPrescaleValues = [...]uint32{1, 4, 16, 64}

// itmConfig represents ITM hardware configuration data.
type itmConfig struct {
	RegTCR uint32 // Contains CoreSight trace ID, TS prescaler
}

// TraceID gets the CoreSight trace ID.
func (c *itmConfig) TraceID() uint8 {
	return uint8((c.RegTCR & itmTraceIDMask) >> itmTraceIDShift)
}

// TSPrescaleValue gets the prescaler for the local ts clock.
func (c *itmConfig) TSPrescaleValue() uint32 {
	if c.RegTCR&tcrSWOEnable == 0 {
		return tsPrescaleValues[0]
	}
	idx := (c.RegTCR >> tcrTSPrescaleShift) & 0x3
	return tsPrescaleValues[idx]
}

// SetTraceID sets the CoreSight trace ID.
func (c *itmConfig) SetTraceID(traceID uint8) {
	c.RegTCR &= ^itmTraceIDMask
	c.RegTCR |= (uint32(traceID) << itmTraceIDShift) & itmTraceIDMask
}
