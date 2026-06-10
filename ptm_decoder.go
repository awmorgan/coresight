package coresight

import (
	"errors"
	"fmt"

)

type ptmDecodeState int

const (
	ptmDecodeNoSync ptmDecodeState = iota
	ptmDecodeWaitSync
	ptmDecodeWaitISync
	ptmDecodePkts
)

type waypointTraceOp int

const (
	traceWaypoint waypointTraceOp = iota
	traceToAddrExcl
	traceToAddrIncl
)

type peAddrState struct {
	isa       ISA
	instrAddr VAddr
	valid     bool
}

// ptmDecoder processes raw trace bytes into packets, then decodes them into Elements.
type ptmDecoder struct {
	Config *ptmConfig

	// Byte processing state
	ctx ptmParseContext

	// ptmPacket decoding state
	MemAccess      internalMemoryReader
	InstrDecode    internalInstructionDecoder
	IndexCurrPkt   Index
	CurrPacketIn   *ptmPacket
	currState      ptmDecodeState
	unsyncInfo     UnsyncInfo
	peContext      PEContext
	currPeState    peAddrState
	needIsync      bool
	instrInfo      instrInfo
	memNaccPending bool
	naccAddr       VAddr
	iSyncPeCtxt    bool
	atoms          ptmAtomPkt
	returnStack    addrReturnStack

	// Observational Sinks
	internalEmitter
	isClosed bool

	fetchBuf [4]byte
}

func ptmNewDecoder(cfg *ptmConfig, mem internalMemoryReader, instr internalInstructionDecoder) (*ptmDecoder, error) {
	if cfg == nil {
		return nil, fmt.Errorf("%w: PTM config cannot be nil", errInvalidParamVal)
	}

	d := &ptmDecoder{
		Config:      cfg,
		MemAccess:   mem,
		InstrDecode: instr,
	}
	d.ctx.internalByteStream = newInternalByteStream()

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
func (d *ptmDecoder) OutputTraceElement(elem Element) {
	d.EmitElement(d.IndexCurrPkt, d.Config.TraceID, elem)
}

// OutputTraceElementIdx sends an element at an explicit index.
func (d *ptmDecoder) OutputTraceElementIdx(idx Index, elem Element) {
	d.EmitElement(idx, d.Config.TraceID, elem)
}

// AccessMemory reads target memory.
func (d *ptmDecoder) AccessMemory(address VAddr, traceID uint8, memSpace MemSpaceAcc, reqBytes uint32, buffer []byte) (uint32, error) {
	if d.MemAccess != nil {
		return d.MemAccess.Read(address, traceID, memSpace, reqBytes, buffer)
	}
	return 0, errDcdInterfaceUnused
}

// InstrDecodeCall calls the attached instruction decoder.
func (d *ptmDecoder) InstrDecodeCall(instrInfo *instrInfo) error {
	if d.InstrDecode != nil {
		return d.InstrDecode(instrInfo)
	}
	return errDcdInterfaceUnused
}

func (d *ptmDecoder) Close() error {
	if d.isClosed {
		return nil
	}
	d.isClosed = true

	// Processor shutdown
	if len(d.ctx.Reader.Scratch()) > 0 {
		d.ctx.currPacket.Type = PacketIncompleteEOT
		_ = d.outputPacket()
	}

	// ptmDecoder shutdown
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

	elem := Element{ElemType: GenElemEOTrace}
	elem.SetUnsyncEndReason(UnsyncEOT)
	d.OutputTraceElement(elem)
	d.EmitTraceEnd()
	return nil
}

func (d *ptmDecoder) Reset(index Index) error {
	d.isClosed = false
	d.resetProcessorState()

	d.unsyncInfo = UnsyncResetDecoder
	d.resetDecoder()
	return nil
}

func (d *ptmDecoder) Flush() error {
	if d.Config == nil {
		return errNotInit
	}
	return nil
}

func (d *ptmDecoder) configureDecoder() {
	d.instrInfo.PeType.Profile = ProfileUnknown
	d.instrInfo.PeType.Arch = ArchUnknown
	d.instrInfo.DsbDmbWaypoints = 0
	d.unsyncInfo = UnsyncInitDecoder
	d.resetDecoder()
}

func (d *ptmDecoder) resetDecoder() {
	d.currState = ptmDecodeNoSync
	d.needIsync = true

	d.instrInfo.ISA = ISAUnknown
	d.memNaccPending = false

	d.peContext.ContextIDValid = false
	d.peContext.Bits64 = false
	d.peContext.VMIDValid = false
	d.peContext.ExceptionLevel = ELUnknown
	d.peContext.SecurityLevel = SecSecure
	d.peContext.ELValid = false

	d.currPeState.instrAddr = 0
	d.currPeState.isa = ISAUnknown
	d.currPeState.valid = false

	d.atoms.Num = 0
}

// processPacket encapsulates the core state machine for decoding a single packet.
func (d *ptmDecoder) processPacket(pktIn *ptmPacket) error {
	if pktIn == nil {
		return errInvalidParamVal
	}
	d.CurrPacketIn = pktIn
	d.IndexCurrPkt = pktIn.Index

	switch d.currState {
	case ptmDecodeNoSync:
		elem := Element{ElemType: GenElemNoSync}
		elem.SetUnsyncEndReason(UnsyncInfo(d.unsyncInfo))
		d.OutputTraceElement(elem)

		if pktIn.Type == PacketASync {
			d.currState = ptmDecodeWaitISync
		} else {
			d.currState = ptmDecodeWaitSync
		}
		return nil

	case ptmDecodeWaitSync:
		if pktIn.Type == PacketASync {
			d.currState = ptmDecodeWaitISync
		}
		return nil

	case ptmDecodeWaitISync:
		if pktIn.Type == PacketISync {
			d.currState = ptmDecodePkts
			return d.decodePacket()
		}
		return nil

	case ptmDecodePkts:
		return d.decodePacket()

	default:
		return nil
	}
}

func (d *ptmDecoder) decodePacket() error {
	var err error

	pkt := d.CurrPacketIn
	switch pkt.Type {
	case PacketIncompleteEOT:
		return nil
	case PacketBadSequence, PacketReserved:
		d.currState = ptmDecodeWaitSync
		d.needIsync = true
		d.OutputTraceElement(Element{ElemType: GenElemNoSync})
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
		elem := Element{ElemType: GenElemEvent}
		elem.SetEvent(EventTrigger, 0)
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
			elem := Element{ElemType: GenElemPeContext}
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
			elem := Element{ElemType: GenElemPeContext}
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
		elem := Element{
			ElemType:  GenElemTimestamp,
			Timestamp: pkt.Timestamp,
		}
		if pkt.CCValid {
			elem.SetCycleCount(pkt.CycleCount)
		}
		d.OutputTraceElement(elem)
	case PacketExceptionRet:
		d.OutputTraceElement(Element{ElemType: GenElemExceptionRet})
	}
	return err
}

func (d *ptmDecoder) processIsync() error {
	pkt := d.CurrPacketIn

	if d.currState == ptmDecodePkts {
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
			d.peContext.SecurityLevel = SecNonsecure
		} else {
			d.peContext.SecurityLevel = SecSecure
		}

		if d.needIsync || pkt.ISyncReason != iSyncPeriodic {
			elem := Element{ElemType: GenElemTraceOn}
			elem.SetTraceOnReason(TraceOnNormal)
			switch pkt.ISyncReason {
			case iSyncTraceRestartAfterOverflow:
				elem.SetTraceOnReason(TraceOnOverflow)
			case iSyncDebugExit:
				elem.SetTraceOnReason(TraceOnExDebug)
			}
			if pkt.CCValid {
				elem.SetCycleCount(pkt.CycleCount)
			}
			d.OutputTraceElement(elem)
		} else {
			d.iSyncPeCtxt = false
		}
		d.needIsync = false
		d.returnStack.flush()
	}

	if d.iSyncPeCtxt {
		elemCtx := Element{
			ElemType: GenElemPeContext,
			ISA:      d.currPeState.isa,
		}
		elemCtx.SetContext(d.peContext)
		d.OutputTraceElement(elemCtx)
		d.iSyncPeCtxt = false
	}

	return nil
}

func (d *ptmDecoder) processBranch() error {
	var err error

	pkt := d.CurrPacketIn

	if d.currState == ptmDecodePkts {
		if pkt.Exception.Present {
			elem := Element{ElemType: GenElemException}
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
				err = d.processAtomRange(atomE, traceWaypoint, 0)
			}
		}

		d.currPeState.isa = pkt.CurrISA
		d.currPeState.instrAddr = pkt.AddrVal
		d.currPeState.valid = true
	}

	d.checkPendingNacc()
	return err
}

func (d *ptmDecoder) processWPUpdate() error {
	var err error

	if d.currPeState.valid {
		err = d.processAtomRange(atomE, traceToAddrIncl, d.CurrPacketIn.AddrVal)
	}

	d.checkPendingNacc()
	return err
}

func (d *ptmDecoder) processAtom() error {
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

func (d *ptmDecoder) checkPendingNacc() {
	if d.memNaccPending {
		elem := Element{
			ElemType:  GenElemAddrNacc,
			StartAddr: d.naccAddr,
		}
		if d.peContext.SecurityLevel == SecSecure {
			elem.SetExceptionNum(uint32(MemSpaceS))
		} else {
			elem.SetExceptionNum(uint32(MemSpaceN))
		}
		d.OutputTraceElementIdx(d.IndexCurrPkt, elem)
		d.memNaccPending = false
	}
}

func (d *ptmDecoder) processAtomRange(A atmVal, traceWPOp waypointTraceOp, nextAddrMatch VAddr) error {
	d.instrInfo.InstrAddr = d.currPeState.instrAddr
	d.instrInfo.ISA = d.currPeState.isa

	elem := Element{
		ElemType: GenElemInstrRange,
		ISA:      d.currPeState.isa,
	}

	wpFound, err := d.traceInstrToWP(traceWPOp, nextAddrMatch, &elem)
	if err != nil {
		if errors.Is(err, errUnsupportedISA) {
			d.currPeState.valid = false
			return nil // Warning
		}
		return err
	}

	if wpFound {
		nextAddr := d.instrInfo.InstrAddr

		switch d.instrInfo.Type {
		case InstrBr:
			if A == atomE {
				d.instrInfo.InstrAddr = d.instrInfo.BranchAddr
				if d.instrInfo.IsLink {
					d.returnStack.push(nextAddr, d.instrInfo.ISA)
				}
			}
		case InstrBrIndirect:
			if A == atomE {
				d.currPeState.valid = false

				// Match PTM OpenCSD: any indirect branch resulting in an ATOM E is treated as a ReturnStack Pop
				if d.returnStack.Active && d.CurrPacketIn.Type == PacketAtom {
					popAddr, nextIsa, ok := d.returnStack.pop()
					if !ok {
						return errRetStackOverflow // fatal
					} else {
						d.instrInfo.InstrAddr = popAddr
						d.instrInfo.NextISA = nextIsa
						d.currPeState.valid = true
					}
				}

				if d.instrInfo.IsLink {
					d.returnStack.push(nextAddr, d.instrInfo.ISA)
				}
			}
		}

		elem.SetLastInstrInfo(A == atomE, d.instrInfo.Type, d.instrInfo.Subtype, d.instrInfo.InstrSize)
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

func (d *ptmDecoder) traceInstrToWP(traceWPOp waypointTraceOp, nextAddrMatch VAddr, elem *Element) (wpFound bool, err error) {
	elem.StartAddr = d.instrInfo.InstrAddr
	elem.EndAddr = d.instrInfo.InstrAddr
	elem.Payload.NumInstrRange = 0

	wpFound = false

	for !wpFound && !d.memNaccPending {
		currOpAddress := d.instrInfo.InstrAddr
		opcode, size, errFetch := d.fetchAndDecodeOpcode(currOpAddress, d.instrInfo.ISA)
		if errFetch != nil {
			if errors.Is(errFetch, errNoAccessor) || errors.Is(errFetch, errMemNacc) {
				d.memNaccPending = true
				d.naccAddr = currOpAddress
				break
			}
			err = errFetch
			break
		}

		d.instrInfo.Opcode = opcode
		d.instrInfo.InstrAddr += VAddr(size)
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
			wpFound = d.instrInfo.Type != InstrOther
		}
	}
	return wpFound, err
}

func (d *ptmDecoder) fetchAndDecodeOpcode(addr VAddr, isa ISA) (uint32, int, error) {
	memSpace := MemSpaceEL1N
	if d.peContext.SecurityLevel == SecSecure {
		memSpace = MemSpaceEL1S
	}

	bytesRead, err := d.AccessMemory(addr, d.Config.TraceID, memSpace, 4, d.fetchBuf[:])
	if err != nil {
		return 0, 0, err
	}

	// Match OpenCSD PTM: strictly requires 4 bytes returned or assumes NACC
	if bytesRead != 4 {
		return 0, 0, errMemNacc
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
