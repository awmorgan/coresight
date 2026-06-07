package coresight


type retStackElement struct {
	RetAddr VAddr
	RetISA  ISA
}

const retStackCap = 16

// addrReturnStack tracks return addresses for branch instructions.
type addrReturnStack struct {
	Active bool
	Stack  []retStackElement
}

// push adds an address/ISA pair to the stack, dropping the oldest if at capacity.
func (s *addrReturnStack) push(addr VAddr, isa ISA) {
	if !s.Active {
		return
	}
	if len(s.Stack) == retStackCap {
		// Shift left to drop the oldest element
		copy(s.Stack, s.Stack[1:])
		s.Stack = s.Stack[:retStackCap-1]
	}
	s.Stack = append(s.Stack, retStackElement{RetAddr: addr, RetISA: isa})
}

// pop removes and returns the top entry.
func (s *addrReturnStack) pop() (VAddr, ISA, bool) {
	if !s.Active || len(s.Stack) == 0 {
		return VAddr(VAMask), 0, false
	}
	top := len(s.Stack) - 1
	elem := s.Stack[top]
	s.Stack = s.Stack[:top]
	return elem.RetAddr, elem.RetISA, true
}

// flush clears the stack state.
func (s *addrReturnStack) flush() {
	s.Stack = s.Stack[:0]
}
