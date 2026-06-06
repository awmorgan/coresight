package ptm

import (
	"errors"
	"fmt"

	"coresight/internal/idec"
	"coresight/internal/memacc"
	"coresight/internal/protocol"
	"coresight/trace"
)

type decodeState int

const (
	decodeNoSync decodeState = iota
	decodeWaitSync
	decodeWaitISync
	decodePkts
)

type waypointTraceOp int

const (
	traceWaypoint waypointTraceOp = iota
	traceToAddrExcl
	traceToAddrIncl
)

type peAddrState struct {
	isa       trace.ISA
	instrAddr trace.VAddr
	valid     bool
}

// Decoder processes raw trace bytes into packets, then decodes them into Elements.
type Decoder struct {
	Config *Config

	// Byte processing state
	ctx parseContext

	// Packet decoding state
	MemAccess      trace.MemoryReader
	InstrDecode    trace.InstructionDecoder
	IndexCurrPkt   trace.Index
	CurrPacketIn   *Packet
	currState      decodeState
	unsyncInfo     trace.UnsyncInfo
	peContext      trace.PEContext
	currPeState    peAddrState
	needIsync      bool
	instrInfo      trace.InstrInfo
	memNaccPending bool
	naccAddr       trace.VAddr
	iSyncPeCtxt    bool
	atoms          AtomPkt
	returnStack    idec.AddrReturnStack

	// Observational Sinks
	protocol.Emitter
	isClosed bool

	fetchBuf [4]byte
}

func NewDecoder(cfg *Config, mem trace.MemoryReader, instr trace.InstructionDecoder) (*Decoder, error) {
	if cfg == nil {
		return nil, fmt.Errorf("%w: PTM config cannot be nil", trace.ErrInvalidParamVal)
	}

	d := &Decoder{
		Config:      cfg,
		MemAccess:   mem,
		InstrDecode: instr,
	}
	d.ctx.ByteStream = protocol.NewByteStream()

	d.resetProcessorState()
	d.configureDecoder()
	if d.Config.HasRetStack {
		d.returnStack.Active = d.Config.EnaRetStack
	}

	d.instrInfo.PeType.Profile = d.Config.CoreProf
	d.instrInfo.PeType.Arch = d.Config.ArchVer
	if d.Config.DmsbWayPt {
		d.instrInfo.DsbDmbWaypoints = 1
	}

	return d, nil
}

// OutputTraceElement sends an element using IndexCurrPkt.
func (d *Decoder) OutputTraceElement(elem trace.Element) {
	d.EmitElement(d.IndexCurrPkt, d.Config.TraceID, elem)
}

// OutputTraceElementIdx sends an element at an explicit index.
func (d *Decoder) OutputTraceElementIdx(idx trace.Index, elem trace.Element) {
	d.EmitElement(idx, d.Config.TraceID, elem)
}

// AccessMemory reads target memory.
func (d *Decoder) AccessMemory(address trace.VAddr, traceID uint8, memSpace trace.MemSpaceAcc, reqBytes uint32, buffer []byte) (uint32, error) {
	if d.MemAccess != nil {
		return d.MemAccess.Read(address, traceID, memSpace, reqBytes, buffer)
	}
	return 0, trace.ErrDcdInterfaceUnused
}

// InstrDecodeCall calls the attached instruction decoder.
func (d *Decoder) InstrDecodeCall(instrInfo *trace.InstrInfo) error {
	if d.InstrDecode != nil {
		return d.InstrDecode(instrInfo)
	}
	return trace.ErrDcdInterfaceUnused
}

func (d *Decoder) Close() error {
	if d.isClosed {
		return nil
	}
	d.isClosed = true

	// Processor shutdown
	if len(d.ctx.Reader.Scratch()) > 0 {
		d.ctx.currPacket.Type = PacketIncompleteEOT
		_ = d.outputPacket()
	}

	// Decoder shutdown
	var err error
	for err == nil && (d.memNaccPending || d.atoms.Num > 0) {
		if d.atoms.Num > 0 {
			if d.currPeState.valid {
				err = d.processAtom()
			} else {
				d.atoms.Num = 0
			}
			continue
		}
		d.checkPendingNacc()
	}

	if err != nil {
		return err
	}

	elem := trace.Element{ElemType: trace.GenElemEOTrace}
	elem.SetUnsyncEndReason(trace.UnsyncEOT)
	d.OutputTraceElement(elem)
	d.EmitTraceEnd()
	return nil
}

func (d *Decoder) Reset(index trace.Index) error {
	d.isClosed = false
	d.resetProcessorState()

	d.unsyncInfo = trace.UnsyncResetDecoder
	d.resetDecoder()
	return nil
}

func (d *Decoder) Flush() error {
	if d.Config == nil {
		return trace.ErrNotInit
	}
	return nil
}

func (d *Decoder) configureDecoder() {
	d.instrInfo.PeType.Profile = trace.ProfileUnknown
	d.instrInfo.PeType.Arch = trace.ArchUnknown
	d.instrInfo.DsbDmbWaypoints = 0
	d.unsyncInfo = trace.UnsyncInitDecoder
	d.resetDecoder()
}

func (d *Decoder) resetDecoder() {
	d.currState = decodeNoSync
	d.needIsync = true

	d.instrInfo.ISA = trace.ISAUnknown
	d.memNaccPending = false

	d.peContext.ContextIDValid = false
	d.peContext.Bits64 = false
	d.peContext.VMIDValid = false
	d.peContext.ExceptionLevel = trace.ELUnknown
	d.peContext.SecurityLevel = trace.SecSecure
	d.peContext.ELValid = false

	d.currPeState.instrAddr = 0
	d.currPeState.isa = trace.ISAUnknown
	d.currPeState.valid = false

	d.atoms.Num = 0
}

// processPacket encapsulates the core state machine for decoding a single packet.
func (d *Decoder) processPacket(pktIn *Packet) error {
	if pktIn == nil {
		return trace.ErrInvalidParamVal
	}
	d.CurrPacketIn = pktIn
	d.IndexCurrPkt = pktIn.Index

	switch d.currState {
	case decodeNoSync:
		elem := trace.Element{ElemType: trace.GenElemNoSync}
		elem.SetUnsyncEndReason(trace.UnsyncInfo(d.unsyncInfo))
		d.OutputTraceElement(elem)

		if pktIn.Type == PacketASync {
			d.currState = decodeWaitISync
		} else {
			d.currState = decodeWaitSync
		}
		return nil

	case decodeWaitSync:
		if pktIn.Type == PacketASync {
			d.currState = decodeWaitISync
		}
		return nil

	case decodeWaitISync:
		if pktIn.Type == PacketISync {
			d.currState = decodePkts
			return d.decodePacket()
		}
		return nil

	case decodePkts:
		return d.decodePacket()

	default:
		return nil
	}
}

func (d *Decoder) decodePacket() error {
	var err error

	pkt := d.CurrPacketIn
	switch pkt.Type {
	case PacketIncompleteEOT:
		return nil
	case PacketBadSequence, PacketReserved:
		d.currState = decodeWaitSync
		d.needIsync = true
		d.OutputTraceElement(trace.Element{ElemType: trace.GenElemNoSync})
		return nil
	}

	switch pkt.Type {
	case PacketNotSync, PacketASync, PacketIgnore:
		// ignore
	case PacketISync:
		err = d.processIsync()
	case PacketBranchAddress:
		err = d.processBranch()
	case PacketTrigger:
		elem := trace.Element{ElemType: trace.GenElemEvent}
		elem.SetEvent(trace.EventTrigger, 0)
		d.OutputTraceElement(elem)
	case PacketWPointUpdate:
		err = d.processWPUpdate()
	case PacketContextID:
		update := true
		if d.peContext.ContextIDValid && d.peContext.ContextID == pkt.Context.CtxtID {
			update = false
		}
		if update {
			d.peContext.ContextID = pkt.Context.CtxtID
			d.peContext.ContextIDValid = true
			elem := trace.Element{ElemType: trace.GenElemPeContext}
			elem.SetContext(d.peContext)
			d.OutputTraceElement(elem)
		}
	case PacketVMID:
		update := true
		if d.peContext.VMIDValid && d.peContext.VMID == uint32(pkt.Context.VMID) {
			update = false
		}
		if update {
			d.peContext.VMID = uint32(pkt.Context.VMID)
			d.peContext.VMIDValid = true
			elem := trace.Element{ElemType: trace.GenElemPeContext}
			elem.SetContext(d.peContext)
			d.OutputTraceElement(elem)
		}
	case PacketAtom:
		if d.currPeState.valid {
			d.atoms = pkt.Atom
			err = d.processAtom()
		} else {
			// warning, ignored
		}
	case PacketTimestamp:
		elem := trace.Element{
			ElemType:  trace.GenElemTimestamp,
			Timestamp: pkt.Timestamp,
		}
		if pkt.CCValid {
			elem.SetCycleCount(pkt.CycleCount)
		}
		d.OutputTraceElement(elem)
	case PacketExceptionRet:
		d.OutputTraceElement(trace.Element{ElemType: trace.GenElemExceptionRet})
	}
	return err
}

func (d *Decoder) processIsync() error {
	pkt := d.CurrPacketIn

	if d.currState == decodePkts {
		d.currPeState.instrAddr = pkt.AddrVal
		d.currPeState.isa = pkt.CurrISA
		d.currPeState.valid = true

		d.iSyncPeCtxt = pkt.CurrISA != pkt.PrevISA
		if pkt.Context.UpdatedC {
			d.peContext.ContextID = pkt.Context.CtxtID
			d.peContext.ContextIDValid = true
			d.iSyncPeCtxt = true
		}

		if pkt.Context.UpdatedV {
			d.peContext.VMID = uint32(pkt.Context.VMID)
			d.peContext.VMIDValid = true
			d.iSyncPeCtxt = true
		}
		if pkt.Context.CurrNS {
			d.peContext.SecurityLevel = trace.SecNonsecure
		} else {
			d.peContext.SecurityLevel = trace.SecSecure
		}

		if d.needIsync || pkt.ISyncReason != trace.ISyncPeriodic {
			elem := trace.Element{ElemType: trace.GenElemTraceOn}
			elem.SetTraceOnReason(trace.TraceOnNormal)
			switch pkt.ISyncReason {
			case trace.ISyncTraceRestartAfterOverflow:
				elem.SetTraceOnReason(trace.TraceOnOverflow)
			case trace.ISyncDebugExit:
				elem.SetTraceOnReason(trace.TraceOnExDebug)
			}
			if pkt.CCValid {
				elem.SetCycleCount(pkt.CycleCount)
			}
			d.OutputTraceElement(elem)
		} else {
			d.iSyncPeCtxt = false
		}
		d.needIsync = false
		d.returnStack.Flush()
	}

	if d.iSyncPeCtxt {
		elemCtx := trace.Element{
			ElemType: trace.GenElemPeContext,
			ISA:      d.currPeState.isa,
		}
		elemCtx.SetContext(d.peContext)
		d.OutputTraceElement(elemCtx)
		d.iSyncPeCtxt = false
	}

	return nil
}

func (d *Decoder) processBranch() error {
	var err error

	pkt := d.CurrPacketIn

	if d.currState == decodePkts {
		if pkt.Exception.Present {
			elem := trace.Element{ElemType: trace.GenElemException}
			elem.SetExceptionNum(uint32(pkt.Exception.Number))
			if d.currPeState.valid {
				elem.ExceptionRetAddr = true
				elem.EndAddr = d.currPeState.instrAddr
			}
			if pkt.CCValid {
				elem.SetCycleCount(pkt.CycleCount)
			}
			d.OutputTraceElement(elem)
		} else {
			if d.currPeState.valid {
				err = d.processAtomRange(trace.AtomE, traceWaypoint, 0)
			}
		}

		d.currPeState.isa = pkt.CurrISA
		d.currPeState.instrAddr = pkt.AddrVal
		d.currPeState.valid = true
	}

	d.checkPendingNacc()
	return err
}

func (d *Decoder) processWPUpdate() error {
	var err error

	if d.currPeState.valid {
		err = d.processAtomRange(trace.AtomE, traceToAddrIncl, d.CurrPacketIn.AddrVal)
	}

	d.checkPendingNacc()
	return err
}

func (d *Decoder) processAtom() error {
	var err error

	for d.atoms.Num > 0 && d.currPeState.valid && err == nil {
		err = d.processAtomRange(d.atoms.Pop(), traceWaypoint, 0)
		if !d.currPeState.valid {
			d.atoms.Num = 0
		}
	}

	d.checkPendingNacc()
	return err
}

func (d *Decoder) checkPendingNacc() {
	if d.memNaccPending {
		elem := trace.Element{
			ElemType:  trace.GenElemAddrNacc,
			StartAddr: d.naccAddr,
		}
		if d.peContext.SecurityLevel == trace.SecSecure {
			elem.SetExceptionNum(uint32(trace.MemSpaceS))
		} else {
			elem.SetExceptionNum(uint32(trace.MemSpaceN))
		}
		d.OutputTraceElementIdx(d.IndexCurrPkt, elem)
		d.memNaccPending = false
	}
}

func (d *Decoder) processAtomRange(A trace.AtmVal, traceWPOp waypointTraceOp, nextAddrMatch trace.VAddr) error {
	d.instrInfo.InstrAddr = d.currPeState.instrAddr
	d.instrInfo.ISA = d.currPeState.isa

	elem := trace.Element{
		ElemType: trace.GenElemInstrRange,
		ISA:      d.currPeState.isa,
	}

	wpFound, err := d.traceInstrToWP(traceWPOp, nextAddrMatch, &elem)
	if err != nil {
		if errors.Is(err, trace.ErrUnsupportedISA) {
			d.currPeState.valid = false
			return nil // Warning
		}
		return err
	}

	if wpFound {
		nextAddr := d.instrInfo.InstrAddr

		switch d.instrInfo.Type {
		case trace.InstrBr:
			if A == trace.AtomE {
				d.instrInfo.InstrAddr = d.instrInfo.BranchAddr
				if d.instrInfo.IsLink {
					d.returnStack.Push(nextAddr, d.instrInfo.ISA)
				}
			}
		case trace.InstrBrIndirect:
			if A == trace.AtomE {
				d.currPeState.valid = false

				// Match PTM OpenCSD: any indirect branch resulting in an ATOM E is treated as a ReturnStack Pop
				if d.returnStack.Active && d.CurrPacketIn.Type == PacketAtom {
					popAddr, nextIsa, ok := d.returnStack.Pop()
					if !ok {
						return trace.ErrRetStackOverflow // fatal
					} else {
						d.instrInfo.InstrAddr = popAddr
						d.instrInfo.NextISA = nextIsa
						d.currPeState.valid = true
					}
				}

				if d.instrInfo.IsLink {
					d.returnStack.Push(nextAddr, d.instrInfo.ISA)
				}
			}
		}

		elem.SetLastInstrInfo(A == trace.AtomE, d.instrInfo.Type, d.instrInfo.Subtype, d.instrInfo.InstrSize)
		if d.CurrPacketIn.CCValid {
			elem.SetCycleCount(d.CurrPacketIn.CycleCount)
		}
		elem.LastInstrCond = d.instrInfo.IsConditional
		d.OutputTraceElementIdx(d.IndexCurrPkt, elem)

		d.currPeState.instrAddr = d.instrInfo.InstrAddr
		d.currPeState.isa = d.instrInfo.NextISA
	} else {
		d.currPeState.valid = false
		if elem.StartAddr != elem.EndAddr {
			elem.SetLastInstrInfo(true, d.instrInfo.Type, d.instrInfo.Subtype, d.instrInfo.InstrSize)
			elem.LastInstrCond = d.instrInfo.IsConditional
			d.OutputTraceElementIdx(d.IndexCurrPkt, elem)
		}
	}
	return nil
}

func (d *Decoder) traceInstrToWP(traceWPOp waypointTraceOp, nextAddrMatch trace.VAddr, elem *trace.Element) (wpFound bool, err error) {
	elem.StartAddr = d.instrInfo.InstrAddr
	elem.EndAddr = d.instrInfo.InstrAddr
	elem.Payload.NumInstrRange = 0

	wpFound = false

	for !wpFound && !d.memNaccPending {
		currOpAddress := d.instrInfo.InstrAddr
		opcode, size, errFetch := d.fetchAndDecodeOpcode(currOpAddress, d.instrInfo.ISA)
		if errFetch != nil {
			if errors.Is(errFetch, memacc.ErrNoAccessor) || errors.Is(errFetch, trace.ErrMemNacc) {
				d.memNaccPending = true
				d.naccAddr = currOpAddress
				break
			}
			err = errFetch
			break
		}

		d.instrInfo.Opcode = opcode
		d.instrInfo.InstrAddr += trace.VAddr(size)
		elem.EndAddr = d.instrInfo.InstrAddr
		elem.Payload.NumInstrRange++
		elem.LastInstrType = d.instrInfo.Type

		if traceWPOp != traceWaypoint {
			if traceWPOp == traceToAddrExcl {
				wpFound = elem.EndAddr == nextAddrMatch
			} else {
				wpFound = currOpAddress == nextAddrMatch
			}
		} else {
			wpFound = d.instrInfo.Type != trace.InstrOther
		}
	}
	return wpFound, err
}

func (d *Decoder) fetchAndDecodeOpcode(addr trace.VAddr, isa trace.ISA) (uint32, int, error) {
	memSpace := trace.MemSpaceEL1N
	if d.peContext.SecurityLevel == trace.SecSecure {
		memSpace = trace.MemSpaceEL1S
	}

	bytesRead, err := d.AccessMemory(addr, d.Config.TraceID, memSpace, 4, d.fetchBuf[:])
	if err != nil {
		return 0, 0, err
	}

	// Match OpenCSD PTM: strictly requires 4 bytes returned or assumes NACC
	if bytesRead != 4 {
		return 0, 0, trace.ErrMemNacc
	}

	opcode := uint32(d.fetchBuf[0])
	opcode |= uint32(d.fetchBuf[1]) << 8
	opcode |= uint32(d.fetchBuf[2]) << 16
	opcode |= uint32(d.fetchBuf[3]) << 24

	d.instrInfo.Opcode = opcode
	d.instrInfo.ISA = isa
	d.instrInfo.InstrAddr = addr
	if err := d.InstrDecodeCall(&d.instrInfo); err != nil {
		return 0, 0, err
	}

	return opcode, int(d.instrInfo.InstrSize), nil
}
