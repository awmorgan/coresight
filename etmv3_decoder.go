package coresight

import (
	"errors"
	"fmt"
)

type etmv3DecodeState int

const (
	etmv3DecodeNoSync etmv3DecodeState = iota
	etmv3DecodeWaitSync
	etmv3DecodeWaitISync
	etmv3DecodePkts
)

// etmv3Decoder processes raw trace bytes into ETMv3 packets, then decodes them into Elements.
type etmv3Decoder struct {
	Config      *etmv3Config
	MemAccess   MemoryReader
	InstrDecode internalInstructionDecoder
	internalEmitter

	ctx etmv3ParseContext

	// State for element generation
	IndexCurrPkt Index
	CurrPacketIn *etmv3Packet
	currState    etmv3DecodeState
	unsyncInfo   UnsyncInfo

	codeFollower *codeFollower

	peContext   PEContext
	iAddr       uint64
	needAddr    bool
	sentUnknown bool
	needIsync   bool

	hasPendElem bool
	pendElem    Element

	hasPendEret bool
	pendEret    Element

	committedPendThisPacket bool

	isClosed bool
}

// etmv3NewDecoder creates a new ETMv3 decoder instance.
func etmv3NewDecoder(cfg *etmv3Config, mem MemoryReader, instr internalInstructionDecoder) (*etmv3Decoder, error) {
	if cfg == nil {
		return nil, fmt.Errorf("%w: ETMv3 config cannot be nil", errInvalidParamVal)
	}

	d := &etmv3Decoder{
		Config:      cfg,
		MemAccess:   mem,
		InstrDecode: instr,
		codeFollower: &codeFollower{
			MemAccess: mem,
			IdDecode:  instr,
			TraceID:   cfg.TraceID(),
			Arch: archProfile{
				Arch:    cfg.ArchVer,
				Profile: cfg.CoreProf,
			},
		},
	}

	d.codeFollower.InstrInfo.PeType = d.codeFollower.Arch
	d.ctx.internalByteStream = newInternalByteStream()

	d.resetProcessorState()
	d.configureDecoder()

	return d, nil
}

func (d *etmv3Decoder) flushPendElem() {
	if d.hasPendElem {
		d.EmitElement(d.pendElem.Index, d.Config.TraceID(), d.pendElem)
		d.hasPendElem = false
	}
	if d.hasPendEret {
		d.EmitElement(d.pendEret.Index, d.Config.TraceID(), d.pendEret)
		d.hasPendEret = false
	}
}

func (d *etmv3Decoder) cancelPendElem() {
	// Drop all pending elements due to Exception Cancel
	d.hasPendElem = false
	d.hasPendEret = false
}

func (d *etmv3Decoder) OutputTraceElement(elem Element) {
	elem.Index = d.IndexCurrPkt
	elem.TraceID = d.Config.TraceID()

	switch elem.ElemType {
	case GenElemInstrRange:
		d.flushPendElem()
		d.pendElem = elem
		d.hasPendElem = true
	case GenElemExceptionRet:
		// If not Cortex-M, pend the ERET alongside the InstrRange
		if d.Config.CoreProf != ProfileCortexM {
			d.pendEret = elem
			d.hasPendEret = true
		} else {
			// Cortex-M: flush any ranges and pend the ERET directly
			d.flushPendElem()
			d.pendEret = elem
			d.hasPendEret = true
		}
	default:
		d.flushPendElem()
		d.EmitElement(elem.Index, elem.TraceID, elem)
	}
}

func (d *etmv3Decoder) OutputTraceElementIdx(idx Index, elem Element) {
	elem.Index = idx
	elem.TraceID = d.Config.TraceID()
	d.flushPendElem()
	d.EmitElement(elem.Index, elem.TraceID, elem)
}

// Write consumes trace data from the demuxer.
func (d *etmv3Decoder) Write(index Index, dataBlock []byte) (uint32, error) {
	if len(dataBlock) == 0 {
		return 0, fmt.Errorf("%w: packet processor: zero length data block", errInvalidParamVal)
	}
	processed, err := d.processData(index, dataBlock)
	if err != nil {
		return processed, err
	}
	return processed, nil
}

func (d *etmv3Decoder) Close() error {
	if d.isClosed {
		return nil
	}
	d.isClosed = true

	// Flush any incomplete bytes
	if len(d.ctx.Reader.Scratch()) > 0 {
		d.ctx.currPacket.Type = pktIncompleteEOT
		_ = d.outputPacket()
	}

	d.flushPendElem()

	elem := Element{ElemType: GenElemEOTrace}
	elem.setUnsyncEndReason(UnsyncEOT)
	d.OutputTraceElement(elem)
	d.EmitTraceEnd()
	return nil
}

func (d *etmv3Decoder) Reset(index Index) error {
	d.isClosed = false
	d.resetProcessorState()
	d.unsyncInfo = UnsyncResetDecoder
	d.resetDecoder()
	return nil
}

func (d *etmv3Decoder) Flush() error {
	return nil
}

func (d *etmv3Decoder) configureDecoder() {
	d.unsyncInfo = UnsyncInitDecoder
	d.resetDecoder()
}

func (d *etmv3Decoder) resetDecoder() {
	d.currState = etmv3DecodeNoSync
	d.needIsync = true
	d.needAddr = true
	d.sentUnknown = false

	d.peContext = PEContext{
		SecurityLevel:  SecSecure,
		ExceptionLevel: ELUnknown,
	}
	d.iAddr = 0
}

func (d *etmv3Decoder) resetProcessorState() {
	d.ctx.processState = etmv3StateWaitSync
	d.ctx.waitASyncSOPacket = false
	d.ctx.bAsyncRawOp = false
	d.ctx.unsyncedRaw = nil
	d.resetPacketState()
}

// processPacket is the entrypoint for the Step 5 decoder logic.
func (d *etmv3Decoder) processPacket(pkt *etmv3Packet) error {
	if pkt == nil {
		return errInvalidParamVal
	}
	if !d.canDecodeElements() {
		return nil
	}
	d.CurrPacketIn = pkt
	d.IndexCurrPkt = pkt.Index

	switch d.currState {
	case etmv3DecodeNoSync:
		elem := Element{ElemType: GenElemNoSync}
		elem.setUnsyncEndReason(d.unsyncInfo)
		d.OutputTraceElement(elem)

		if pkt.Type == pktASync {
			d.currState = etmv3DecodeWaitISync
		} else {
			d.currState = etmv3DecodeWaitSync
		}
		return nil

	case etmv3DecodeWaitSync:
		if pkt.Type == pktASync {
			d.currState = etmv3DecodeWaitISync
		}
		return nil

	case etmv3DecodeWaitISync:
		if pkt.Type == pktISync || pkt.Type == pktISyncCycle {
			d.currState = etmv3DecodePkts
			return d.decodePacket()
		}
		// Pre-ISync valid packets
		if pkt.Type == pktTimestamp || (d.Config.CycleAcc() && (pkt.Type == pktCycleCount || pkt.Type == pktPHdr)) {
			return d.decodePacket()
		}
		return nil

	case etmv3DecodePkts:
		return d.decodePacket()
	}

	return nil
}

func (d *etmv3Decoder) canDecodeElements() bool {
	return d.MemAccess != nil && d.InstrDecode != nil && d.codeFollower != nil
}

func (d *etmv3Decoder) decodePacket() error {
	pkt := d.CurrPacketIn
	d.committedPendThisPacket = false

	if pkt.Err != nil {
		if errors.Is(pkt.Err, errBadPacketSeq) || errors.Is(pkt.Err, errInvalidPcktHdr) {
			d.unsyncInfo = UnsyncBadPacket
			d.currState = etmv3DecodeWaitSync
			d.needIsync = true
			d.OutputTraceElement(Element{ElemType: GenElemNoSync})
			return nil
		}
	}

	// Commit pending elements for all packets except branches (which handles exception cancels)
	if pkt.Type != pktBranchAddress {
		d.committedPendThisPacket = d.hasPendElem || d.hasPendEret
		d.flushPendElem()
	}

	switch pkt.Type {
	case pktIncompleteEOT, pktASync, pktIgnore, pktNotSync:
		// ignore
	case pktBadSequence, pktBadTraceMode, pktReserved:
		d.unsyncInfo = UnsyncBadPacket
		d.currState = etmv3DecodeWaitSync
		d.needIsync = true
		d.OutputTraceElement(Element{ElemType: GenElemNoSync})
	case pktCycleCount:
		elem := Element{ElemType: GenElemCycleCount}
		elem.setCycleCount(pkt.CycleCount)
		d.OutputTraceElement(elem)
	case pktTrigger:
		elem := Element{ElemType: GenElemEvent}
		elem.Payload.TraceEvent.EvType = EventTrigger
		d.OutputTraceElement(elem)
	case pktBranchAddress:
		return d.processBranchAddr()
	case pktISyncCycle, pktISync:
		return d.processISync()
	case pktPHdr:
		return d.processPHdr()
	case pktContextID:
		elem := Element{ElemType: GenElemPeContext}
		d.peContext.ContextID = pkt.Context.CtxtID
		d.peContext.ContextIDValid = true
		elem.Context = d.peContext
		d.OutputTraceElement(elem)
	case pktVMID:
		elem := Element{ElemType: GenElemPeContext}
		d.peContext.VMID = uint32(pkt.Context.VMID)
		d.peContext.VMIDValid = true
		elem.Context = d.peContext
		d.OutputTraceElement(elem)
	case pktExceptionEntry:
		elem := Element{ElemType: GenElemException}
		elem.ExceptionDataMarker = true
		d.OutputTraceElement(elem)
	case pktExceptionExit:
		d.OutputTraceElement(Element{ElemType: GenElemExceptionRet})
	case pktTimestamp:
		elem := Element{ElemType: GenElemTimestamp}
		elem.Timestamp = pkt.Timestamp
		d.OutputTraceElement(elem)
	}

	return nil
}

func (d *etmv3Decoder) processISync() error {
	pkt := d.CurrPacketIn
	ctxtUpdate := pkt.Context.UpdatedC || pkt.Context.UpdatedV || pkt.Context.Updated

	if d.needIsync || pkt.ISyncInfo.Reason != iSyncPeriodic {
		elem := Element{ElemType: GenElemTraceOn}
		elem.setTraceOnReason(TraceOnNormal)
		switch pkt.ISyncInfo.Reason {
		case iSyncTraceRestartAfterOverflow:
			elem.setTraceOnReason(TraceOnOverflow)
		case iSyncDebugExit:
			elem.setTraceOnReason(TraceOnExDebug)
		}
		d.OutputTraceElement(elem)
	}

	if ctxtUpdate || d.needIsync {
		if pkt.Context.UpdatedC {
			d.peContext.ContextID = pkt.Context.CtxtID
			d.peContext.ContextIDValid = true
		}
		if pkt.Context.UpdatedV {
			d.peContext.VMID = uint32(pkt.Context.VMID)
			d.peContext.VMIDValid = true
		}
		if pkt.Context.Updated {
			el := ELUnknown
			if pkt.Context.CurrHyp {
				el = EL2
			}
			sec := SecSecure
			if pkt.Context.CurrNS {
				sec = SecNonsecure
			}
			d.peContext.ExceptionLevel = el
			d.peContext.ELValid = true
			d.peContext.SecurityLevel = sec
		}

		elem := Element{ElemType: GenElemPeContext}
		elem.Context = d.peContext
		elem.ISA = pkt.CurrISA
		d.codeFollower.Isa = pkt.CurrISA
		d.codeFollower.InstrInfo.ISA = pkt.CurrISA

		if pkt.ISyncInfo.HasCycleCount {
			elem.setCycleCount(pkt.CycleCount)
		}
		d.OutputTraceElement(elem)
	}

	if !pkt.ISyncInfo.NoAddress {
		if pkt.ISyncInfo.HasLSipAddr {
			d.iAddr = pkt.Data.Addr
		} else {
			d.iAddr = pkt.Addr
		}
		d.needAddr = false
		d.sentUnknown = false
	}

	d.needIsync = false
	return nil
}

func (d *etmv3Decoder) processBranchAddr() error {
	pkt := d.CurrPacketIn
	updatePEContext := false

	if pkt.ExceptionCancel {
		d.cancelPendElem()
	} else {
		d.flushPendElem()
	}

	d.iAddr = pkt.Addr
	d.needAddr = false
	d.sentUnknown = false
	d.codeFollower.Isa = pkt.CurrISA
	d.codeFollower.InstrInfo.ISA = pkt.CurrISA

	if pkt.Context.UpdatedC || pkt.Context.UpdatedV || pkt.Context.Updated {
		if pkt.Context.UpdatedC && (!d.peContext.ContextIDValid || d.peContext.ContextID != pkt.Context.CtxtID) {
			d.peContext.ContextID = pkt.Context.CtxtID
			d.peContext.ContextIDValid = true
			updatePEContext = true
		}
		if pkt.Context.UpdatedV && (!d.peContext.VMIDValid || d.peContext.VMID != uint32(pkt.Context.VMID)) {
			d.peContext.VMID = uint32(pkt.Context.VMID)
			d.peContext.VMIDValid = true
			updatePEContext = true
		}
		if pkt.Context.Updated {
			sec := SecSecure
			if pkt.Context.CurrNS {
				sec = SecNonsecure
			}
			if sec != d.peContext.SecurityLevel {
				d.peContext.SecurityLevel = sec
				updatePEContext = true
			}

			el := ELUnknown
			if pkt.Context.CurrHyp {
				el = EL2
			}
			if !d.peContext.ELValid || el != d.peContext.ExceptionLevel {
				d.peContext.ExceptionLevel = el
				d.peContext.ELValid = true
				updatePEContext = true
			}
		}
	}

	if updatePEContext {
		elem := Element{ElemType: GenElemPeContext}
		elem.Context = d.peContext
		d.OutputTraceElement(elem)
	}

	if pkt.Exception.Present && pkt.Exception.Number != 0 {
		elem := Element{ElemType: GenElemException}
		elem.Payload.ExceptionNum = uint32(pkt.Exception.Number)
		d.OutputTraceElement(elem)
	}

	return nil
}

func (d *etmv3Decoder) processPHdr() error {
	pkt := d.CurrPacketIn
	atomsNum := pkt.Atom.Num
	enBits := pkt.Atom.EnBits
	isCCPacket := d.Config.CycleAcc()
	instrRanges := 0
	outputElem := func(elem Element) {
		if elem.ElemType == GenElemInstrRange {
			instrRanges++
		}
		d.OutputTraceElement(elem)
	}

	memSpace := MemSpaceN
	if d.peContext.SecurityLevel == SecSecure {
		memSpace = MemSpaceS
	}

	d.codeFollower.MemSpace = memSpace

	for {
		if d.needAddr {
			if !d.sentUnknown || isCCPacket {
				elem := Element{ElemType: GenElemAddrUnknown}
				if d.sentUnknown || atomsNum == 0 {
					elem.ElemType = GenElemCycleCount
				}
				if isCCPacket {
					elem.setCycleCount(d.remainCC(pkt, atomsNum))
				}
				outputElem(elem)
				d.sentUnknown = true
			}
			atomsNum = 0 // Skip remaining atoms
		} else {
			elem := Element{ElemType: GenElemInstrRange}

			if isCCPacket {
				if atomsNum == 0 {
					elem.ElemType = GenElemCycleCount
				}
				elem.setCycleCount(d.atomCC(pkt, atomsNum))
			}

			if atomsNum > 0 {
				val := atomN
				if (enBits & 1) == 1 {
					val = atomE
				}

				d.codeFollower.Isa = pkt.CurrISA
				d.codeFollower.InstrInfo.ISA = pkt.CurrISA

				res, err := d.codeFollower.followSingleAtom(VAddr(d.iAddr), val)
				if err != nil && !errors.Is(err, errMemNacc) {
					return err
				}

				if res.NumInstr > 0 {
					elem.StartAddr = res.RangeSt
					elem.EndAddr = res.RangeEn
					elem.ISA = pkt.CurrISA
					elem.Payload.NumInstrRange = res.NumInstr
					elem.setLastInstrInfo(val == atomE, res.InstrInfo.Type, res.InstrInfo.Subtype, res.InstrInfo.InstrSize)
					elem.LastInstrCond = res.InstrInfo.IsConditional

					d.iAddr = uint64(res.NextAddr)
					pkt.CurrISA = res.InstrInfo.NextISA

					if !res.HasNext {
						d.needAddr = true
						d.sentUnknown = false
					}
				}

				if errors.Is(err, errMemNacc) {
					if res.NumInstr > 0 {
						outputElem(elem)

						naccElem := Element{
							ElemType:  GenElemAddrNacc,
							StartAddr: VAddr(res.NaccAddr),
						}
						naccElem.Payload.ExceptionNum = uint32(memSpace)
						outputElem(naccElem)
					} else {
						elem.ElemType = GenElemAddrNacc
						elem.StartAddr = VAddr(res.NaccAddr)
						elem.Payload.ExceptionNum = uint32(memSpace)
						outputElem(elem)
					}

					d.needAddr = true
					d.sentUnknown = false
				} else {
					outputElem(elem)
				}
			} else {
				outputElem(elem)
			}
		}

		if atomsNum > 0 {
			enBits >>= 1
			atomsNum--
		}

		if atomsNum == 0 {
			break
		}
	}
	if instrRanges > 1 || (instrRanges == 1 && d.committedPendThisPacket) {
		d.flushPendElem()
	}
	return nil
}

func (d *etmv3Decoder) atomCC(pkt *etmv3Packet, atomsNum uint8) uint32 {
	if !d.Config.CycleAcc() {
		return 0
	}
	switch pkt.PHdrFmt {
	case 3:
		return pkt.CycleCount
	case 2:
		if atomsNum > 1 {
			return 1
		}
		return 0
	case 1:
		return 1
	default:
		return 0
	}
}

func (d *etmv3Decoder) remainCC(pkt *etmv3Packet, atomsNum uint8) uint32 {
	if !d.Config.CycleAcc() {
		return 0
	}
	switch pkt.PHdrFmt {
	case 3:
		return pkt.CycleCount
	case 2:
		if atomsNum > 1 {
			return 1
		}
		return 0
	case 1:
		return uint32(atomsNum)
	default:
		return 0
	}
}
