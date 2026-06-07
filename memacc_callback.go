package coresight

import (
	"fmt"
)

// CallbackAccessor represents a callback trace memory accessor.
type CallbackAccessor struct {
	BaseAccessor
	callback        internalMemoryCallback
	traceIDCallback internalMemoryCallback
}

func NewCallbackAccessor(startAddr VAddr, endAddr VAddr, memSpace MemSpaceAcc) *CallbackAccessor {
	return &CallbackAccessor{
		BaseAccessor: newBaseAccessor(startAddr, endAddr, memSpace),
	}
}

func (c *CallbackAccessor) String() string {
	return fmt.Sprintf("CB  Acc; %s", c.BaseAccessor.String())
}

// ReadBytes implements the Accessor interface.
func (c *CallbackAccessor) ReadBytes(address VAddr, memSpace MemSpaceAcc, trcID uint8, reqBytes uint32, buffer []byte) uint32 {
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
func (c *CallbackAccessor) SetCallback(fn internalMemoryCallback) {
	c.callback = fn
	c.traceIDCallback = nil
}

// SetTraceIDCallback sets a callback function that includes trace ID.
func (c *CallbackAccessor) SetTraceIDCallback(fn internalMemoryCallback) {
	c.traceIDCallback = fn
	c.callback = nil
}

// Configure updates accessor range and memory-space routing.
func (c *CallbackAccessor) Configure(startAddr VAddr, endAddr VAddr, memSpace MemSpaceAcc) {
	c.StartAddress = startAddr
	c.EndAddress = endAddr
	c.MemSpaceAcc = memSpace
}
