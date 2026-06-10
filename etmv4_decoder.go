package coresight

import (
	"errors"
	"fmt"
	"slices"

)

type etmv4DecodeState int

const (
	etmv4DecodeNoSync etmv4DecodeState = iota
	etmv4DecodeWaitSync
	etmv4DecodeWaitTInfo
	etmv4DecodePkts
)

type pendingP0Kind int

const (
	pendingP0Atom pendingP0Kind = iota
	pendingP0Exception
	pendingP0Address
	pendingP0CycleCount
	pendingP0Context
	pendingP0TraceOn
	pendingP0Q
	pendingP0MemTrans
)

type pendingP0 struct {
	kind      pendingP0Kind
	index     Index
	atom      atmVal
	exception *etmv4Packet
	packet    *etmv4Packet
	element   *Element
	retAddr   VAddr
	startAddr VAddr
	lastIS    uint8
	needAddr  bool
}

type etmv4Decoder struct {
	Config      *etmv4Config
	MemAccess   internalMemoryReader
	InstrDecode internalInstructionDecoder
	internalEmitter

	ctx etmv4ParseContext

	currState    etmv4DecodeState
	unsync       UnsyncInfo
	peContext    PEContext
	iAddr        VAddr
	needAddr     bool
	needCtxt     bool
	lastIS       uint8
	is64         bool
	isClosed     bool
	seenData     bool
	prevOverflow bool
	eotPending   bool
	specDepth    uint32
	unseenSpec   uint32

	pendingTraceOn    *Element
	pendingContexts   []Element
	pendingElements   []Element
	pendingITE        *Element
	pendingExceptRet  *Element
	pendingCycleCount *Element
	pendingException  *etmv4Packet
	pendingDiagnostic string
	pendingRawPrefix  string
	pendingP0         []pendingP0

	codeFollower       *codeFollower
	returnStack        addrReturnStack
	retStackPopPending bool
	flushBuf           []Element
}

func etmv4NewDecoder(cfg *etmv4Config, mem internalMemoryReader, instr internalInstructionDecoder) (*etmv4Decoder, error) {
	if cfg == nil {
		return nil, fmt.Errorf("%w: ETMv4 config cannot be nil", errInvalidParamVal)
	}
	pendingP0Cap := min(max(64, int(cfg.MaxSpecDepth())+32), 512)
	d := &etmv4Decoder{
		Config:      cfg,
		MemAccess:   mem,
		InstrDecode: instr,
		codeFollower: &codeFollower{
			MemAccess:          mem,
			IdDecode:           instr,
			TraceID:            cfg.TraceID(),
			errOnAA64BadOpcode: cfg.errOnAA64BadOpcode,
			InstrRangeLimit:    cfg.InstrRangeLimit,
			Arch: archProfile{
				Arch:    cfg.ArchVer,
				Profile: cfg.CoreProf,
			},
		},
		pendingP0: make([]pendingP0, 0, pendingP0Cap),
	}
	d.codeFollower.InstrInfo.PeType = d.codeFollower.Arch
	d.codeFollower.InstrInfo.TrackItBlock = 1

	if d.Config.WfiWfeBranch() {
		d.codeFollower.InstrInfo.WfiWfeBranch = 1
	} else {
		d.codeFollower.InstrInfo.WfiWfeBranch = 0
	}
	d.returnStack.Active = cfg.EnabledRetStack()
	d.ctx.internalByteStream = newInternalByteStream()
	d.unsync = UnsyncInitDecoder
	d.resetDecoder()
	d.initProcessorState()
	return d, nil
}

func (d *etmv4Decoder) IsElementSource() bool {
	return d.canDecodeElements()
}

func (d *etmv4Decoder) Write(index Index, dataBlock []byte) (uint32, error) {
	if len(dataBlock) == 0 {
		return 0, fmt.Errorf("%w: packet processor: zero length data block", errInvalidParamVal)
	}
	d.seenData = true
	return d.processData(index, dataBlock)
}

func (d *etmv4Decoder) Close() error {
	if d.isClosed {
		return nil
	}
	d.isClosed = true
	if len(d.ctx.raw) > 0 {
		d.ctx.currPacket.updateErr(etmv4PktIncompleteEOT, errBadPacketSeq)
		_ = d.outputPacket()
	}

	if err := d.commitElemOnEOT(); err != nil {
		return err
	}

	d.flushPendingStandaloneElements()

	if d.pendingCycleCount != nil {
		d.outputTraceElementAt(d.pendingCycleCount.Index, *d.pendingCycleCount)
		d.pendingCycleCount = nil
	}

	if (d.currState == etmv4DecodePkts && d.ctx.isSync) || (d.Config.IsETE() && d.ctx.isSync && d.seenData) || d.prevOverflow || d.eotPending || !d.seenData {
		elem := Element{ElemType: GenElemEOTrace}
		if d.prevOverflow {
			elem.SetUnsyncEndReason(UnsyncOverflow)
		} else {
			elem.SetUnsyncEndReason(UnsyncEOT)
		}
		elem.Diagnostic = d.pendingDiagnostic
		d.pendingDiagnostic = ""
		d.outputTraceElementAt(d.ctx.packetIndex, elem)
	}
	d.EmitTraceEnd()
	return nil
}

func (d *etmv4Decoder) Reset(index Index) error {
	d.isClosed = false
	d.seenData = false
	d.prevOverflow = false
	d.eotPending = false
	d.unsync = UnsyncResetDecoder
	d.resetDecoder()
	d.initProcessorState()
	return nil
}

func (d *etmv4Decoder) Flush() error { return nil }

func (d *etmv4Decoder) resetDecoder() {
	d.currState = etmv4DecodeNoSync
	d.peContext = PEContext{SecurityLevel: SecSecure, ExceptionLevel: ELUnknown}
	d.iAddr = 0
	d.needAddr = true
	d.needCtxt = true
	d.lastIS = 0
	d.is64 = false
	d.specDepth = 0
	d.unseenSpec = 0
	d.pendingTraceOn = nil
	d.pendingContexts = d.pendingContexts[:0]
	d.pendingElements = d.pendingElements[:0]
	d.pendingITE = nil
	d.pendingExceptRet = nil
	d.pendingCycleCount = nil
	d.pendingException = nil
	d.pendingDiagnostic = ""
	d.pendingRawPrefix = ""
	clear(d.pendingP0)
	d.pendingP0 = d.pendingP0[:0]
	d.returnStack.flush()
	d.retStackPopPending = false
}

func (d *etmv4Decoder) OutputTraceElement(elem Element) {
	d.outputTraceElementAt(d.ctx.currPacket.Index, elem)
}

func (d *etmv4Decoder) outputTraceElementAt(index Index, elem Element) {
	elem.Index = index
	elem.TraceID = d.Config.TraceID()
	d.EmitElement(elem.Index, elem.TraceID, elem)
}

func (d *etmv4Decoder) processPacket(pkt *etmv4Packet) error {
	if !d.canDecodeElements() {
		return nil
	}

	switch d.currState {
	case etmv4DecodeNoSync:
		elem := Element{ElemType: GenElemNoSync}
		elem.SetUnsyncEndReason(d.unsync)
		d.OutputTraceElement(elem)
		d.currState = etmv4DecodeWaitSync
		fallthrough
	case etmv4DecodeWaitSync:
		if pkt.Type == etmv4PktASync {
			d.currState = etmv4DecodeWaitTInfo
		}
		return nil
	case etmv4DecodeWaitTInfo:
		d.needAddr = true
		d.needCtxt = true
		if pkt.Type == PktTraceInfo {
			d.currState = etmv4DecodePkts
			return d.decodePacket(pkt)
		}
		if pkt.Type == PktEvent {
			return d.decodePacket(pkt)
		}
		return nil
	case etmv4DecodePkts:
		return d.decodePacket(pkt)
	}
	return nil
}

func (d *etmv4Decoder) canDecodeElements() bool {
	return d.MemAccess != nil && d.InstrDecode != nil && d.codeFollower != nil
}

func (d *etmv4Decoder) decodePacket(pkt *etmv4Packet) error {
	if pkt.IsBadPacket() {
		if pkt.Type == etmv4PktIncompleteEOT {
			return nil
		}
		if errors.Is(pkt.Err, errBadPacketSeq) || errors.Is(pkt.Err, errInvalidPcktHdr) {
			reason := "Unknown packet type."
			switch pkt.Type {
			case PktReservedCfg:
				reason = "Packet header reserved for current configuration."
			case etmv4PktReserved:
				reason = "Reserved packet header"
			}
			diagnostic := d.badDecodePacketDiagnostic(pkt.Index, reason)
			d.unsync = UnsyncBadPacket
			d.resetDecoder()
			d.pendingRawPrefix = diagnostic
		}
		return nil
	}
	switch pkt.Type {
	case etmv4PktASync, etmv4PktIgnore, etmv4PktNotSync:
	case PktTraceInfo:
		if pkt.TraceInfo.SpecFieldPresent {
			d.specDepth = pkt.CurrSpecDepth
			d.unseenSpec = pkt.CurrSpecDepth
		}
		if pkt.IsETE && pkt.TraceInfo.InTransState {
			elem := Element{ElemType: GenElemMemTrans}
			elem.SetTransactionType(MemTransTraceInit)
			elem.Index = pkt.Index
			if d.shouldQueueControl() {
				d.queueElement(pendingP0MemTrans, pkt.Index, elem)
			} else {
				d.OutputTraceElement(elem)
			}
		}
	case PktTransStart, PktTransCommit, PktTransFail:
		transType := MemTransStart
		switch pkt.Type {
		case PktTransCommit:
			transType = MemTransCommit
		case PktTransFail:
			transType = MemTransFail
		}

		elem := Element{ElemType: GenElemMemTrans}
		elem.SetTransactionType(transType)
		elem.Index = pkt.Index

		if d.usesP0CommitStack() {
			d.queueElement(pendingP0MemTrans, pkt.Index, elem)
			if pkt.Type == PktTransStart && d.Config.CommTransP0() {
				d.specDepth++
			}
			return d.commitOverSpecDepth()
		}
		d.OutputTraceElement(elem)
	case PktPEReset:
		elem := Element{ElemType: GenElemException}
		elem.Payload.ExceptionNum = uint32(pkt.Exception.Type)
		elem.EndAddr = 0
		elem.ExceptionRetAddr = true
		elem.ExceptionRetAddrBrTgt = false
		elem.Index = pkt.Index
		if d.shouldQueueControl() {
			d.queueElement(pendingP0MemTrans, pkt.Index, elem)
			return d.commitOverSpecDepth()
		}
		d.OutputTraceElement(elem)
	case PktTraceOn:
		elem := Element{ElemType: GenElemTraceOn}
		if d.prevOverflow {
			elem.SetTraceOnReason(TraceOnOverflow)
			d.prevOverflow = false
		} else {
			elem.SetTraceOnReason(TraceOnNormal)
		}
		elem.Index = pkt.Index
		if d.shouldQueueControl() {
			d.queueElement(pendingP0TraceOn, pkt.Index, elem)
			return nil
		}
		d.pendingTraceOn = &elem
	case PktContext:
		if d.shouldQueueControl() {
			d.queueContext(pkt)
			return nil
		}
		d.updateContext(pkt)
	case PktAddrCtxtL32IS0, PktAddrCtxtL32IS1, PktAddrCtxtL64IS0, PktAddrCtxtL64IS1:
		if d.pendingException != nil {
			if err := d.resolvePendingExceptionAddress(pkt.Addr.Val); err != nil {
				return err
			}
		}
		if d.shouldQueueAddress() {
			d.queueAddress(pkt)
			return nil
		}
		d.updateAddress(pkt)
		d.updateContext(pkt)
	case PktAddrMatch, PktAddrL32IS0, PktAddrL32IS1, PktAddrL64IS0, PktAddrL64IS1, PktAddrSIS0, PktAddrSIS1:
		if d.pendingException != nil {
			if err := d.resolvePendingExceptionAddress(pkt.Addr.Val); err != nil {
				return err
			}
		}
		if d.shouldQueueAddress() {
			d.queueAddress(pkt)
			return nil
		}
		d.updateAddress(pkt)
	case PktSrcAddrMatch, PktSrcAddrL32IS0, PktSrcAddrL32IS1, PktSrcAddrL64IS0, PktSrcAddrL64IS1, PktSrcAddrSIS0, PktSrcAddrSIS1:
		return d.processSourceAddress(pkt)
	case PktAtomF1, PktAtomF2, PktAtomF3, PktAtomF4, PktAtomF5, PktAtomF6:
		return d.processAtoms(pkt)
	case PktCommit:
		if pkt.CommitValid {
			return d.commitPendingAtoms(pkt.Commit)
		}
	case PktCancelF1, PktCancelF1Mispred, PktMispredict, PktCancelF2, PktCancelF3:
		return d.resolveSpeculation(pkt)
	case PktException:
		if pkt.Exception.AddrInterp == 1 || pkt.Exception.AddrInterp == 2 {
			exception := *pkt
			d.pendingException = &exception
		} else {
			elem := Element{ElemType: GenElemException}
			elem.Payload.ExceptionNum = uint32(pkt.Exception.Type)
			d.OutputTraceElement(elem)
		}
	case PktExceptionReturn, PktFuncRet:
		elem := Element{ElemType: GenElemExceptionRet}
		elem.Index = pkt.Index
		d.pendingExceptRet = &elem
	case PktITE:
		elem := Element{ElemType: GenElemInstrumentation}
		elem.SetITEInfo(ITEEvent{EL: pkt.ITE.EL, Value: pkt.ITE.Value})
		elem.Index = pkt.Index
		d.pendingITE = &elem
	case etmv4PktTimestamp:
		elem := Element{ElemType: GenElemTimestamp}
		elem.SetTimestamp(pkt.Timestamp, false)
		if pkt.CCValid {
			elem.SetCycleCount(pkt.CycleCount)
		}
		elem.Index = pkt.Index
		d.pendingElements = append(d.pendingElements, elem)
	case PktTSMarker:
		elem := Element{ElemType: GenElemSyncMarker}
		elem.SetSyncMarker(TraceMarkerPayload{Type: ElemMarkerTS})
		elem.Index = pkt.Index
		d.pendingElements = append(d.pendingElements, elem)
	case PktCycleCountF1, PktCycleCountF2, PktCycleCountF3:
		elem := Element{ElemType: GenElemCycleCount}
		elem.SetCycleCount(pkt.CycleCount)
		elem.Index = pkt.Index
		if d.usesP0CommitStack() && !d.Config.CommitOpt1() {
			if pkt.CommitValid {
				if err := d.commitPendingAtoms(pkt.Commit); err != nil {
					return err
				}
			}
			d.queueElement(pendingP0CycleCount, pkt.Index, elem)
			return nil
		}
		d.pendingCycleCount = &elem
		if pkt.CommitValid {
			return d.commitPendingAtoms(pkt.Commit)
		}
	case PktEvent:
		elem := Element{ElemType: GenElemEvent}
		elem.SetEvent(EventNumbered, uint16(pkt.EventVal))
		d.OutputTraceElement(elem)
		d.eotPending = true
	case PktOverflow:
		d.unsync = UnsyncOverflow
		d.resetDecoder()
		d.prevOverflow = true
		elem := Element{ElemType: GenElemNoSync}
		elem.SetUnsyncEndReason(UnsyncOverflow)
		d.OutputTraceElement(elem)
		d.currState = etmv4DecodeWaitSync
	case PktDiscard:
		d.unsync = UnsyncDiscard
		d.resetDecoder()
		elem := Element{ElemType: GenElemNoSync}
		elem.SetUnsyncEndReason(UnsyncDiscard)
		d.OutputTraceElement(elem)
		d.currState = etmv4DecodeWaitSync
		d.eotPending = true
	case PktQ:
		if d.usesP0CommitStack() {
			d.queueQElement(pkt)
			return d.commitOverSpecDepth()
		}
		return d.processQElement(pkt)
	}
	return nil
}

func (d *etmv4Decoder) resolvePendingExceptionAddress(retAddr VAddr) error {
	pkt := d.pendingException
	d.pendingException = nil
	if pkt == nil {
		return nil
	}
	if d.usesP0CommitStack() && d.Config.MaxSpecDepth() > 0 {
		d.pendingP0 = append(d.pendingP0, pendingP0{
			kind:      pendingP0Exception,
			index:     pkt.Index,
			exception: clonePacket(pkt),
			retAddr:   retAddr,
			startAddr: d.iAddr,
			lastIS:    d.lastIS,
			needAddr:  d.needAddr,
		})
		d.specDepth++
		return d.commitOverSpecDepth()
	}
	return d.processExceptionPacket(pkt, retAddr, true)
}

func (d *etmv4Decoder) processExceptionPacket(pkt *etmv4Packet, retAddr VAddr, flushPending bool) error {
	if pkt == nil {
		return nil
	}
	if flushPending {
		d.flushPendingElements()
	}
	if d.needAddr && d.retStackPopPending {
		if retAddr, retISA, ok := d.returnStack.pop(); ok {
			d.iAddr = retAddr
			d.lastIS = isaToIS(retISA)
			d.codeFollower.InstrInfo.ISA = retISA
			d.needAddr = false
		}
		d.retStackPopPending = false
	}
	if pkt.Exception.AddrInterp != 2 && d.iAddr < retAddr {
		memSpace := d.currMemSpace()
		d.codeFollower.MemSpace = memSpace
		isa := d.calcISA(d.lastIS)
		d.codeFollower.Isa = isa
		d.codeFollower.InstrInfo.ISA = isa

		rangeStart := d.iAddr
		rangeEnd := d.iAddr
		var numInstr uint32
		var lastInfo instrInfo
		for rangeEnd < retAddr {
			d.codeFollower.TempInstr = d.codeFollower.InstrInfo
			d.codeFollower.TempInstr.ISA = isa
			d.codeFollower.TempInstr.InstrAddr = rangeEnd
			d.codeFollower.TempInstr.PeType = d.codeFollower.Arch
			err := d.codeFollower.decodeSingleOpCode(&d.codeFollower.TempInstr, d.Config.TraceID(), memSpace)
			if err != nil && !errors.Is(err, errMemNacc) {
				return err
			}
			if errors.Is(err, errMemNacc) {
				elem := Element{ElemType: GenElemAddrNacc}
				elem.StartAddr = rangeEnd
				elem.Payload.ExceptionNum = uint32(memSpace)
				d.outputTraceElementAt(pkt.Index, elem)
				d.needAddr = true
				break
			}
			numInstr++
			rangeEnd += VAddr(d.codeFollower.TempInstr.InstrSize)
			lastInfo = d.codeFollower.TempInstr
			isa = d.codeFollower.TempInstr.NextISA
		}
		if numInstr > 0 {
			elem := Element{ElemType: GenElemInstrRange}
			elem.StartAddr = rangeStart
			elem.EndAddr = rangeEnd
			elem.ISA = isa
			elem.Payload.NumInstrRange = numInstr
			elem.SetLastInstrInfo(true, lastInfo.Type, lastInfo.Subtype, lastInfo.InstrSize)
			elem.LastInstrCond = lastInfo.IsConditional
			d.outputTraceElementAt(pkt.Index, elem)
		}
	}

	elem := Element{ElemType: GenElemException}
	elem.Payload.ExceptionNum = uint32(pkt.Exception.Type)
	elem.EndAddr = retAddr
	elem.ExceptionRetAddr = true
	elem.ExceptionRetAddrBrTgt = pkt.Exception.AddrInterp == 2
	d.outputTraceElementAt(pkt.Index, elem)
	return nil
}

func (d *etmv4Decoder) updateContext(pkt *etmv4Packet) {
	if !pkt.Context.Updated && !pkt.Context.UpdatedC && !pkt.Context.UpdatedV {
		return
	}
	d.is64 = pkt.Context.SF
	d.peContext.Bits64 = pkt.Context.SF
	d.peContext.ExceptionLevel = ExLevel(pkt.Context.EL)
	d.peContext.ELValid = true
	if pkt.Context.NSE {
		if pkt.Context.NS {
			d.peContext.SecurityLevel = SecRealm
		} else {
			d.peContext.SecurityLevel = SecRoot
		}
	} else if pkt.Context.NS {
		d.peContext.SecurityLevel = SecNonsecure
	} else {
		d.peContext.SecurityLevel = SecSecure
	}
	if pkt.Context.UpdatedC {
		d.peContext.ContextID = pkt.Context.CtxtID
		d.peContext.ContextIDValid = true
	}
	if pkt.Context.UpdatedV {
		d.peContext.VMID = pkt.Context.VMID
		d.peContext.VMIDValid = true
	}
	elem := Element{ElemType: GenElemPeContext, Context: d.peContext}
	elem.ISA = d.calcISA(d.lastIS)
	elem.Index = pkt.Index
	d.pendingContexts = append(d.pendingContexts, elem)
	d.needCtxt = false
}

func (d *etmv4Decoder) updateAddress(pkt *etmv4Packet) {
	d.retStackPopPending = false
	d.lastIS = pkt.Addr.IS
	d.iAddr = pkt.Addr.Val
	d.needAddr = false
	isa := d.calcISA(pkt.Addr.IS)
	d.codeFollower.Isa = isa
	d.codeFollower.InstrInfo.ISA = isa
}

func (d *etmv4Decoder) processAtoms(pkt *etmv4Packet) error {
	if d.usesP0CommitStack() {
		d.queueAtoms(pkt)
		return d.commitOverSpecDepth()
	}
	return d.processatomEntries(d.packetAtoms(pkt))
}

func (d *etmv4Decoder) packetAtoms(pkt *etmv4Packet) []pendingP0 {
	atoms := make([]pendingP0, 0, pkt.Atom.Num)
	bits := pkt.Atom.EnBits
	for range int(pkt.Atom.Num) {
		val := atomN
		if bits&1 != 0 {
			val = atomE
		}
		bits >>= 1
		atoms = append(atoms, pendingP0{kind: pendingP0Atom, index: pkt.Index, atom: val})
	}
	return atoms
}

func (d *etmv4Decoder) queueAtoms(pkt *etmv4Packet) {
	bits := pkt.Atom.EnBits
	for range int(pkt.Atom.Num) {
		val := atomN
		if bits&1 != 0 {
			val = atomE
		}
		bits >>= 1
		d.pendingP0 = append(d.pendingP0, pendingP0{kind: pendingP0Atom, index: pkt.Index, atom: val})
	}
	d.specDepth += uint32(pkt.Atom.Num)
}

func clonePacket(pkt *etmv4Packet) *etmv4Packet {
	cp := *pkt
	return &cp
}

func cloneElement(elem Element) *Element {
	cp := elem
	return &cp
}

func (d *etmv4Decoder) queueElement(kind pendingP0Kind, index Index, elem Element) {
	d.pendingP0 = append(d.pendingP0, pendingP0{kind: kind, index: index, element: cloneElement(elem)})
}

func (d *etmv4Decoder) shouldQueueAddress() bool {
	return d.usesP0CommitStack() && d.Config.MaxSpecDepth() > 0 && len(d.pendingP0) > 0
}

func (d *etmv4Decoder) queueAddress(pkt *etmv4Packet) {
	d.pendingP0 = append(d.pendingP0, pendingP0{kind: pendingP0Address, index: pkt.Index, packet: clonePacket(pkt)})
}

func (d *etmv4Decoder) shouldQueueControl() bool {
	return d.usesP0CommitStack() && d.Config.MaxSpecDepth() > 0 && len(d.pendingP0) > 0
}

func (d *etmv4Decoder) queueContext(pkt *etmv4Packet) {
	d.pendingP0 = append(d.pendingP0, pendingP0{kind: pendingP0Context, index: pkt.Index, packet: clonePacket(pkt)})
}

func (d *etmv4Decoder) commitOverSpecDepth() error {
	if d.specDepth <= d.Config.MaxSpecDepth() {
		return nil
	}
	return d.commitPendingAtoms(d.specDepth - d.Config.MaxSpecDepth())
}

func (d *etmv4Decoder) commitPendingAtoms(count uint32) error {
	if !d.usesP0CommitStack() {
		return nil
	}
	if d.Config.CommitOpt1() {
		if count > d.unseenSpec {
			count -= d.unseenSpec
			d.specDepth -= d.unseenSpec
			d.unseenSpec = 0
		} else {
			d.unseenSpec -= count
			d.specDepth -= count
			return nil
		}
	}
	committed := uint32(0)
	var endIdx int
	for endIdx < len(d.pendingP0) && committed < count {
		entry := &d.pendingP0[endIdx]
		if entry.kind == pendingP0Atom || entry.kind == pendingP0Exception || (entry.kind == pendingP0Q && entry.packet.Q.AddrPresent) || (entry.kind == pendingP0MemTrans && entry.element.Payload.MemTrans == MemTransStart && d.Config.CommTransP0()) {
			committed++
		}
		endIdx++
	}
	if endIdx == 0 {
		return nil
	}

	d.specDepth -= committed
	entries := d.pendingP0[:endIdx]
	err := d.processPendingP0Entries(entries)

	if len(d.pendingP0) < endIdx {
		// etmv4Decoder was reset or pendingP0 was cleared during processing.
		return err
	}

	copy(d.pendingP0, d.pendingP0[endIdx:])
	clear(d.pendingP0[len(d.pendingP0)-endIdx:])
	d.pendingP0 = d.pendingP0[:len(d.pendingP0)-endIdx]

	return err
}

func (d *etmv4Decoder) resolveSpeculation(pkt *etmv4Packet) error {
	if !d.usesP0CommitStack() {
		return nil
	}
	d.queueAtoms(pkt)
	if pkt.CancelValid {
		for cancel := int(pkt.Cancel); cancel > 0; {
			found := false
			for i := len(d.pendingP0) - 1; i >= 0; i-- {
				if d.pendingP0[i].kind == pendingP0Atom || d.pendingP0[i].kind == pendingP0Exception || (d.pendingP0[i].kind == pendingP0Q && d.pendingP0[i].packet.Q.AddrPresent) || (d.pendingP0[i].kind == pendingP0MemTrans && d.pendingP0[i].element.Payload.MemTrans == MemTransStart && d.Config.CommTransP0()) {
					d.pendingP0 = append(d.pendingP0[:i], d.pendingP0[i+1:]...)
					d.specDepth--
					cancel--
					found = true
					break
				}
			}
			if !found {
				break
			}
		}
	}
	switch pkt.Type {
	case PktMispredict, PktCancelF1Mispred, PktCancelF2, PktCancelF3:
		for i := len(d.pendingP0) - 1; i >= 0; i-- {
			newest := &d.pendingP0[i]
			if newest.kind == pendingP0Address {
				d.pendingP0 = append(d.pendingP0[:i], d.pendingP0[i+1:]...)
				continue
			}
			if newest.kind == pendingP0Atom {
				if newest.atom == atomE {
					newest.atom = atomN
				} else {
					newest.atom = atomE
				}
				break
			}
		}
	}
	return d.commitOverSpecDepth()
}

func (d *etmv4Decoder) usesP0CommitStack() bool {
	return true
}

func (d *etmv4Decoder) processPendingP0Entries(entries []pendingP0) error {
	for i := 0; i < len(entries); {
		switch entries[i].kind {
		case pendingP0Atom:
			j := i + 1
			for j < len(entries) && entries[j].kind == pendingP0Atom {
				j++
			}
			if err := d.processatomEntries(entries[i:j]); err != nil {
				return err
			}
			i = j
		case pendingP0Exception:
			d.flushPendingElements()
			if d.Config.CommitOpt1() {
				savedAddr, savedIS, savedNeedAddr := d.iAddr, d.lastIS, d.needAddr
				d.iAddr, d.lastIS, d.needAddr = entries[i].startAddr, entries[i].lastIS, entries[i].needAddr
				isa := d.calcISA(d.lastIS)
				d.codeFollower.Isa = isa
				d.codeFollower.InstrInfo.ISA = isa
				if err := d.processExceptionPacket(entries[i].exception, entries[i].retAddr, false); err != nil {
					return err
				}
				d.iAddr, d.lastIS, d.needAddr = savedAddr, savedIS, savedNeedAddr
				isa = d.calcISA(d.lastIS)
				d.codeFollower.Isa = isa
				d.codeFollower.InstrInfo.ISA = isa
			} else if err := d.processExceptionPacket(entries[i].exception, entries[i].retAddr, false); err != nil {
				return err
			}
			i++
		case pendingP0Address:
			d.updateAddress(entries[i].packet)
			switch entries[i].packet.Type {
			case PktAddrCtxtL32IS0, PktAddrCtxtL32IS1, PktAddrCtxtL64IS0, PktAddrCtxtL64IS1:
				d.updateContext(entries[i].packet)
			}
			i++
		case pendingP0CycleCount:
			d.flushPendingElements()
			d.outputTraceElementAt(entries[i].element.Index, *entries[i].element)
			i++
		case pendingP0Context:
			d.updateContext(entries[i].packet)
			i++
		case pendingP0TraceOn:
			d.flushPendingElements()
			d.outputTraceElementAt(entries[i].element.Index, *entries[i].element)
			i++
		case pendingP0Q:
			if err := d.processQElement(entries[i].packet); err != nil {
				return err
			}
			i++
		case pendingP0MemTrans:
			d.flushPendingElements()
			d.outputTraceElementAt(entries[i].element.Index, *entries[i].element)
			i++
		default:
			i++
		}
	}
	return nil
}

func (d *etmv4Decoder) processatomEntries(atoms []pendingP0) error {
	if len(atoms) == 0 {
		return nil
	}
	d.flushPendingElements()
	if d.needAddr && d.retStackPopPending {
		if retAddr, retISA, ok := d.returnStack.pop(); ok {
			d.iAddr = retAddr
			d.lastIS = isaToIS(retISA)
			d.codeFollower.InstrInfo.ISA = retISA
			d.needAddr = false
		}
		d.retStackPopPending = false
	}
	if d.needAddr {
		return nil
	}
	memSpace := d.currMemSpace()
	d.codeFollower.MemSpace = memSpace
	isa := d.calcISA(d.lastIS)
	d.codeFollower.Isa = isa
	d.codeFollower.InstrInfo.ISA = isa
	for i, atom := range atoms {
		val := atom.atom
		res, err := d.codeFollower.followAtomWaypoint(d.iAddr, val)
		if err != nil && !errors.Is(err, errMemNacc) {
			d.handlePacketSequenceError(atom.index, err, "Error processing atom packet.")
			return nil
		}
		elem := Element{ElemType: GenElemInstrRange}
		if errors.Is(err, errMemNacc) {
			elem.ElemType = GenElemAddrNacc
			elem.StartAddr = res.NaccAddr
			elem.Payload.ExceptionNum = uint32(memSpace)
			d.needAddr = true
			d.outputTraceElementAt(atom.index, elem)
			return nil
		}
		elem.StartAddr = res.RangeSt
		elem.EndAddr = res.RangeEn
		elem.ISA = isa
		elem.Payload.NumInstrRange = res.NumInstr
		elem.SetLastInstrInfo(val == atomE, res.InstrInfo.Type, res.InstrInfo.Subtype, res.InstrInfo.InstrSize)
		elem.LastInstrCond = res.InstrInfo.IsConditional
		d.outputTraceElementAt(atom.index, elem)
		if d.Config.IsETE() && val == atomE && res.InstrInfo.Subtype == SInstrV8Eret {
			d.outputTraceElementAt(atom.index, Element{ElemType: GenElemExceptionRet})
		}

		if d.returnStack.Active && val == atomE && res.InstrInfo.IsLink {
			d.returnStack.push(res.RangeEn, res.InstrInfo.ISA)
		}
		if d.returnStack.Active && val == atomE && res.InstrInfo.Type == InstrBrIndirect {
			d.retStackPopPending = true
		}
		if d.retStackPopPending && i+1 < len(atoms) {
			if retAddr, retISA, ok := d.returnStack.pop(); ok {
				res.NextAddr = retAddr
				res.HasNext = true
				res.InstrInfo.NextISA = retISA
			}
			d.retStackPopPending = false
		}

		d.iAddr = res.NextAddr
		d.lastIS = isaToIS(res.InstrInfo.NextISA)
		if !res.HasNext {
			d.needAddr = true
			return nil
		}
	}
	return nil
}

func (d *etmv4Decoder) processSourceAddress(pkt *etmv4Packet) error {
	d.flushPendingElements()

	memSpace := d.currMemSpace()
	isa := d.calcISA(d.lastIS)
	srcInstrInfo, err := d.decodeSourceAddressInstr(pkt.Addr.Val, isa, memSpace)
	if err != nil {
		if errors.Is(err, errMemNacc) {
			elem := Element{ElemType: GenElemAddrNacc}
			elem.StartAddr = pkt.Addr.Val
			elem.Payload.ExceptionNum = uint32(memSpace)
			d.OutputTraceElement(elem)
			d.needAddr = true
			return nil
		}
		d.handlePacketSequenceError(pkt.Index, err, "Error processing source address packet.")
		return nil
	}

	start := d.iAddr
	if d.needAddr || start > pkt.Addr.Val {
		start = pkt.Addr.Val
		d.needAddr = false
	}
	end := srcInstrInfo.InstrAddr + VAddr(srcInstrInfo.InstrSize)
	if d.Config.SrcAddrNAtoms {
		if err := d.outputSplitSourceAddressRanges(pkt.Index, start, end, isa, memSpace, srcInstrInfo); err != nil {
			return err
		}
	} else {
		d.outputSourceAddressRange(pkt.Index, start, end, isa, true, srcInstrInfo)
	}
	if srcInstrInfo.Subtype == SInstrV8Eret {
		d.OutputTraceElement(Element{ElemType: GenElemExceptionRet})
	}

	d.iAddr = end
	d.lastIS = isaToIS(srcInstrInfo.NextISA)
	d.codeFollower.Isa = srcInstrInfo.NextISA
	d.codeFollower.InstrInfo = srcInstrInfo
	switch srcInstrInfo.Type {
	case InstrBr:
		if srcInstrInfo.IsLink && d.returnStack.Active {
			d.returnStack.push(end, isa)
		}
		d.iAddr = srcInstrInfo.BranchAddr
	case InstrBrIndirect:
		if srcInstrInfo.IsLink && d.returnStack.Active {
			d.returnStack.push(end, isa)
		}
		d.needAddr = true
		if d.returnStack.Active {
			d.retStackPopPending = true
		}
	}
	return nil
}

func (d *etmv4Decoder) decodeSourceAddressInstr(addr VAddr, isa ISA, memSpace MemSpaceAcc) (instrInfo, error) {
	d.codeFollower.TempInstr = d.codeFollower.InstrInfo
	d.codeFollower.TempInstr.ISA = isa
	d.codeFollower.TempInstr.InstrAddr = addr
	d.codeFollower.TempInstr.PeType = d.codeFollower.Arch
	err := d.codeFollower.decodeSingleOpCode(&d.codeFollower.TempInstr, d.Config.TraceID(), memSpace)
	return d.codeFollower.TempInstr, err
}

func (d *etmv4Decoder) outputSplitSourceAddressRanges(index Index, start, end VAddr, isa ISA, memSpace MemSpaceAcc, srcInstrInfo instrInfo) error {
	rangeStart := start
	var numInstr uint32
	for addr := start; addr < end; {
		instrInfo := srcInstrInfo
		if addr != srcInstrInfo.InstrAddr {
			var err error
			instrInfo, err = d.decodeSourceAddressInstr(addr, isa, memSpace)
			if err != nil {
				if errors.Is(err, errMemNacc) {
					elem := Element{ElemType: GenElemAddrNacc}
					elem.StartAddr = addr
					elem.Payload.ExceptionNum = uint32(memSpace)
					d.outputTraceElementAt(index, elem)
					return nil
				}
				d.handlePacketSequenceError(index, err, "Error processing source address packet.")
				return err
			}
		}
		addr += VAddr(instrInfo.InstrSize)
		numInstr++
		isFinal := addr >= end
		if !isFinal && instrInfo.Type == InstrOther {
			continue
		}
		d.outputSourceAddressRangeWithCount(index, rangeStart, addr, isa, numInstr, isFinal, instrInfo)
		rangeStart = addr
		numInstr = 0
	}
	return nil
}

func (d *etmv4Decoder) outputSourceAddressRange(index Index, start, end VAddr, isa ISA, executed bool, instrInfo instrInfo) {
	numInstr := uint32(1)
	if isa != ISAThumb2 && end > start {
		numInstr = uint32((end - start) / 4)
	}
	d.outputSourceAddressRangeWithCount(index, start, end, isa, numInstr, executed, instrInfo)
}

func (d *etmv4Decoder) outputSourceAddressRangeWithCount(index Index, start, end VAddr, isa ISA, numInstr uint32, executed bool, instrInfo instrInfo) {
	elem := Element{ElemType: GenElemInstrRange}
	elem.StartAddr = start
	elem.EndAddr = end
	elem.ISA = isa
	elem.Payload.NumInstrRange = numInstr
	elem.SetLastInstrInfo(executed, instrInfo.Type, instrInfo.Subtype, instrInfo.InstrSize)
	elem.LastInstrCond = instrInfo.IsConditional
	d.outputTraceElementAt(index, elem)
}

func (d *etmv4Decoder) handlePacketSequenceError(index Index, err error, reason string) {
	diagnostic := d.packetSequenceDiagnostic(index, err, reason)
	d.unsync = UnsyncBadPacket
	d.resetDecoder()
	elem := Element{ElemType: GenElemNoSync, Diagnostic: diagnostic}
	elem.SetUnsyncEndReason(UnsyncBadPacket)
	d.outputTraceElementAt(index, elem)
	d.currState = etmv4DecodeWaitSync
}

func (d *etmv4Decoder) packetSequenceDiagnostic(index Index, err error, reason string) string {
	if errors.Is(err, errInvalidOpcode) {
		return fmt.Sprintf("DCD_ETMV4_0016 : 0x002c (OCSD_ERR_INVALID_OPCODE) [Illegal Opode found while decoding program memory.]; TrcIdx=%d; CS ID=%x; %s", index, d.Config.TraceID(), reason)
	}
	if errors.Is(err, errIRangeLimitOverrun) {
		errText := "An optional limit on consecutive instructions in range during decode has been exceeded."
		return fmt.Sprintf("DCD_ETMV4_0016 : 0x002d (OCSD_ERR_I_RANGE_LIMIT_OVERRUN) [%s]; Decode Instruction Range Limit OverrunDCD_ETMV4_0016 : 0x002d (OCSD_ERR_I_RANGE_LIMIT_OVERRUN) [%s]; TrcIdx=%d; CS ID=%x; %s", errText, errText, index, d.Config.TraceID(), reason)
	}
	return fmt.Sprintf("DCD_ETMV4_0016 : 0x0000 (OCSD_ERR_UNKNOWN) [%s]; TrcIdx=%d; CS ID=%x; %s", err.Error(), index, d.Config.TraceID(), reason)
}

func (d *etmv4Decoder) badDecodePacketDiagnostic(index Index, reason string) string {
	return fmt.Sprintf("DCD_ETMV4_%04d : 0x0019 (OCSD_ERR_BAD_DECODE_PKT) [Reserved or unknown packet in decoder.]; TrcIdx=%d; CS ID=%x; %s", d.Config.TraceID(), index, d.Config.TraceID(), reason)
}

func (d *etmv4Decoder) flushPendingElements() {
	count := 0
	if d.pendingTraceOn != nil {
		count++
	}
	count += len(d.pendingContexts)
	count += len(d.pendingElements)
	if d.pendingITE != nil {
		count++
	}
	if d.pendingExceptRet != nil {
		count++
	}
	if d.pendingCycleCount != nil {
		count++
	}

	if count == 0 {
		return
	}

	if count == 1 {
		var elem Element
		if d.pendingTraceOn != nil {
			elem = *d.pendingTraceOn
			d.pendingTraceOn = nil
		} else if len(d.pendingContexts) > 0 {
			elem = d.pendingContexts[0]
			d.pendingContexts = d.pendingContexts[:0]
		} else if len(d.pendingElements) > 0 {
			elem = d.pendingElements[0]
			d.pendingElements = d.pendingElements[:0]
		} else if d.pendingITE != nil {
			elem = *d.pendingITE
			d.pendingITE = nil
		} else if d.pendingExceptRet != nil {
			elem = *d.pendingExceptRet
			d.pendingExceptRet = nil
		} else if d.pendingCycleCount != nil {
			elem = *d.pendingCycleCount
			d.pendingCycleCount = nil
		}
		d.outputTraceElementAt(elem.Index, elem)
		return
	}

	d.flushBuf = d.flushBuf[:0]
	if d.pendingTraceOn != nil {
		d.flushBuf = append(d.flushBuf, *d.pendingTraceOn)
		d.pendingTraceOn = nil
	}
	d.flushBuf = append(d.flushBuf, d.pendingContexts...)
	d.pendingContexts = d.pendingContexts[:0]
	d.flushBuf = append(d.flushBuf, d.pendingElements...)
	d.pendingElements = d.pendingElements[:0]
	if d.pendingITE != nil {
		d.flushBuf = append(d.flushBuf, *d.pendingITE)
		d.pendingITE = nil
	}
	if d.pendingExceptRet != nil {
		d.flushBuf = append(d.flushBuf, *d.pendingExceptRet)
		d.pendingExceptRet = nil
	}
	if d.pendingCycleCount != nil {
		d.flushBuf = append(d.flushBuf, *d.pendingCycleCount)
		d.pendingCycleCount = nil
	}

	slices.SortStableFunc(d.flushBuf, func(a, b Element) int {
		if a.Index < b.Index {
			return -1
		}
		if a.Index > b.Index {
			return 1
		}
		return 0
	})

	for _, elem := range d.flushBuf {
		d.outputTraceElementAt(elem.Index, elem)
	}
}

func (d *etmv4Decoder) flushPendingStandaloneElements() {
	pending := d.pendingElements
	d.pendingElements = nil
	if len(pending) == 0 {
		return
	}
	if len(pending) > 1 {
		slices.SortStableFunc(pending, func(a, b Element) int {
			if a.Index < b.Index {
				return -1
			}
			if a.Index > b.Index {
				return 1
			}
			return 0
		})
	}
	for _, elem := range pending {
		d.outputTraceElementAt(elem.Index, elem)
	}
}

func (d *etmv4Decoder) calcISA(is uint8) ISA {
	if d.is64 {
		return ISAAArch64
	}
	if is == 0 {
		return ISAArm
	}
	return ISAThumb2
}

func isaToIS(isa ISA) uint8 {
	if isa == ISAThumb2 {
		return 1
	}
	return 0
}

func (d *etmv4Decoder) currMemSpace() MemSpaceAcc {
	el := int(d.peContext.ExceptionLevel) & 0x3
	if !d.peContext.ELValid {
		if d.peContext.SecurityLevel == SecSecure {
			return MemSpaceS
		}
		return MemSpaceN
	}
	switch d.peContext.SecurityLevel {
	case SecRoot:
		return MemSpaceRoot
	case SecRealm:
		return [...]MemSpaceAcc{MemSpaceEL1R, MemSpaceEL1R, MemSpaceEL2R, MemSpaceRoot}[el]
	case SecNonsecure:
		return [...]MemSpaceAcc{MemSpaceEL1N, MemSpaceEL1N, MemSpaceEL2, MemSpaceEL3}[el]
	default:
		return [...]MemSpaceAcc{MemSpaceEL1S, MemSpaceEL1S, MemSpaceEL2S, MemSpaceEL3}[el]
	}
}

func (d *etmv4Decoder) queueQElement(pkt *etmv4Packet) {
	d.pendingP0 = append(d.pendingP0, pendingP0{kind: pendingP0Q, index: pkt.Index, packet: clonePacket(pkt)})
	if pkt.Q.AddrPresent {
		d.specDepth++
	}
}

func (d *etmv4Decoder) processQElement(pkt *etmv4Packet) error {
	d.flushPendingElements()

	var qAddr VAddr
	var qISA uint8

	if pkt.Q.AddrPresent {
		qAddr = pkt.Addr.Val
		qISA = pkt.Addr.IS
	} else {
		qAddr = pkt.Addr.Val
		qISA = pkt.Addr.IS
	}

	iCount := pkt.Q.Count

	// walk iCount instructions
	memSpace := d.currMemSpace()
	d.codeFollower.MemSpace = memSpace
	isa := d.calcISA(d.lastIS)
	d.codeFollower.Isa = isa
	d.codeFollower.InstrInfo.ISA = isa

	var rangeStart = d.iAddr
	var rangeEnd = d.iAddr
	var numInstr uint32
	var lastInfo instrInfo
	var isBranch bool
	var err error

	for range iCount {
		d.codeFollower.TempInstr = d.codeFollower.InstrInfo
		d.codeFollower.TempInstr.ISA = isa
		d.codeFollower.TempInstr.InstrAddr = rangeEnd
		d.codeFollower.TempInstr.PeType = d.codeFollower.Arch
		err = d.codeFollower.decodeSingleOpCode(&d.codeFollower.TempInstr, d.Config.TraceID(), memSpace)
		if err != nil {
			break
		}

		rangeEnd += VAddr(d.codeFollower.TempInstr.InstrSize)
		numInstr++
		lastInfo = d.codeFollower.TempInstr
		isa = d.codeFollower.TempInstr.NextISA

		isBranch = d.codeFollower.TempInstr.Type == InstrBr || d.codeFollower.TempInstr.Type == InstrBrIndirect

		if isBranch {
			break
		}
	}

	inCompleteRange := true
	if err == nil {
		if iCount > 0 && numInstr == iCount {
			if rangeEnd == qAddr || isBranch {
				inCompleteRange = false
				elem := Element{ElemType: GenElemInstrRange}
				elem.StartAddr = rangeStart
				elem.EndAddr = rangeEnd
				elem.ISA = isa
				elem.Payload.NumInstrRange = numInstr
				elem.SetLastInstrInfo(true, lastInfo.Type, lastInfo.Subtype, lastInfo.InstrSize)
				elem.LastInstrCond = lastInfo.IsConditional
				d.outputTraceElementAt(pkt.Index, elem)
			}
		}
	}

	if inCompleteRange {
		elem := Element{ElemType: GenElemIRangeNopath}
		elem.StartAddr = rangeStart
		elem.EndAddr = qAddr
		elem.Payload.NumInstrRange = iCount
		elem.ISA = d.calcISA(qISA)
		d.outputTraceElementAt(pkt.Index, elem)
	}

	// after the Q element, tracing resumes at the address supplied
	d.iAddr = qAddr
	d.lastIS = qISA
	d.needAddr = false
	d.codeFollower.Isa = d.calcISA(qISA)
	d.codeFollower.InstrInfo.ISA = d.calcISA(qISA)

	return nil
}

func (d *etmv4Decoder) commitElemOnEOT() error {
	for len(d.pendingP0) > 0 {
		entry := d.pendingP0[0]
		switch entry.kind {
		case pendingP0Atom, pendingP0Exception, pendingP0TraceOn, pendingP0Q:
			d.pendingP0 = nil
			return nil
		case pendingP0MemTrans:
			if entry.element.Payload.MemTrans == MemTransStart {
				d.pendingP0 = nil
				return nil
			}
			d.outputTraceElementAt(entry.index, *entry.element)
			d.pendingP0 = d.pendingP0[1:]
		case pendingP0Address, pendingP0Context:
			d.pendingP0 = d.pendingP0[1:]
		case pendingP0CycleCount:
			d.outputTraceElementAt(entry.index, *entry.element)
			d.pendingP0 = d.pendingP0[1:]
		default:
			d.pendingP0 = d.pendingP0[1:]
		}
	}
	return nil
}
