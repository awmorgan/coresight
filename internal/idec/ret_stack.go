package idec

import "github.com/awmorgan/coresight/trace"

type RetStackElement struct {
	RetAddr trace.VAddr
	RetISA  trace.ISA
}

const retStackCap = 16

// AddrReturnStack tracks return addresses for branch instructions.
type AddrReturnStack struct {
	Active bool
	Stack  []RetStackElement
}

// Push adds an address/ISA pair to the stack, dropping the oldest if at capacity.
func (s *AddrReturnStack) Push(addr trace.VAddr, isa trace.ISA) {
	if !s.Active {
		return
	}
	if len(s.Stack) == retStackCap {
		// Shift left to drop the oldest element
		copy(s.Stack, s.Stack[1:])
		s.Stack = s.Stack[:retStackCap-1]
	}
	s.Stack = append(s.Stack, RetStackElement{RetAddr: addr, RetISA: isa})
}

// Pop removes and returns the top entry.
func (s *AddrReturnStack) Pop() (trace.VAddr, trace.ISA, bool) {
	if !s.Active || len(s.Stack) == 0 {
		return trace.VAddr(trace.VAMask), 0, false
	}
	top := len(s.Stack) - 1
	elem := s.Stack[top]
	s.Stack = s.Stack[:top]
	return elem.RetAddr, elem.RetISA, true
}

// Flush clears the stack state.
func (s *AddrReturnStack) Flush() {
	s.Stack = s.Stack[:0]
}
