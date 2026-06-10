package coresight

import (
	"fmt"
)

// callbackAccessor represents a callback trace memory accessor.
type callbackAccessor struct {
	baseAccessor
	callback        memoryCallback
	traceIDCallback memoryCallback
}

func newCallbackAccessor(startAddr VAddr, endAddr VAddr, memSpace MemSpaceAcc) *callbackAccessor {
	return &callbackAccessor{
		baseAccessor: newBaseAccessor(startAddr, endAddr, memSpace),
	}
}

func (c *callbackAccessor) String() string {
	return fmt.Sprintf("CB  Acc; %s", c.baseAccessor.String())
}

// ReadBytes implements the Accessor interface.
func (c *callbackAccessor) ReadBytes(address VAddr, memSpace MemSpaceAcc, trcID uint8, reqBytes uint32, buffer []byte) uint32 {
	switch {
	case c.traceIDCallback != nil:
		return c.traceIDCallback(address, memSpace, trcID, reqBytes, buffer)
	case c.callback != nil:
		return c.callback(address, memSpace, trcID, reqBytes, buffer)
	default:
		return 0
	}
}

// SetCallback sets a callback function that does not take a trace ID.
func (c *callbackAccessor) SetCallback(fn memoryCallback) {
	c.callback = fn
	c.traceIDCallback = nil
}

// SetTraceIDCallback sets a callback function that includes trace ID.
func (c *callbackAccessor) SetTraceIDCallback(fn memoryCallback) {
	c.traceIDCallback = fn
	c.callback = nil
}

// Configure updates accessor range and memory-space routing.
func (c *callbackAccessor) Configure(startAddr VAddr, endAddr VAddr, memSpace MemSpaceAcc) {
	c.StartAddress = startAddr
	c.EndAddress = endAddr
	c.MemSpaceAcc = memSpace
}
