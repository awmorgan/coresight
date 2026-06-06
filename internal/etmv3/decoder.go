package etmv3

import (
	"errors"
	"fmt"

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

// Decoder processes raw trace bytes into ETMv3 packets, then decodes them into Elements.
type Decoder struct {
	Config      *Config
	MemAccess   trace.MemoryReader
	InstrDecode trace.InstructionDecoder
	protocol.Emitter

	ctx parseContext

	// State for element generation
	IndexCurrPkt trace.Index
	CurrPacketIn *Packet
	currState    decodeState
	unsyncInfo   trace.UnsyncInfo

	codeFollower *CodeFollower

	peContext   trace.PEContext
	iAddr       uint64
	needAddr    bool
	sentUnknown bool
	needIsync   bool

	hasPendElem bool
	pendElem    trace.Element

	hasPendEret bool
	pendEret    trace.Element

	committedPendThisPacket bool

	isClosed bool
}

// NewDecoder creates a new ETMv3 decoder instance.
func NewDecoder(cfg *Config, mem trace.MemoryReader, instr trace.InstructionDecoder) (*Decoder, error) {
	if cfg == nil {
		return nil, fmt.Errorf("%w: ETMv3 config cannot be nil", trace.ErrInvalidParamVal)
	}

	d := &Decoder{
		Config:      cfg,
		MemAccess:   mem,
		InstrDecode: instr,
		codeFollower: &CodeFollower{
			MemAccess: mem,
			IdDecode:  instr,
			TraceID:   cfg.TraceID(),
			Arch: trace.ArchProfile{
				Arch:    cfg.ArchVer,
				Profile: cfg.CoreProf,
			},
		},
	}

	d.codeFollower.InstrInfo.PeType = d.codeFollower.Arch
	d.ctx.ByteStream = protocol.NewByteStream()

	d.resetProcessorState()
	d.configureDecoder()

	return d, nil
}

func (d *Decoder) flushPendElem() {
	if d.hasPendElem {
		d.EmitElement(d.pendElem.Index, d.Config.TraceID(), d.pendElem)
		d.hasPendElem = false
	}
	if d.hasPendEret {
		d.EmitElement(d.pendEret.Index, d.Config.TraceID(), d.pendEret)
		d.hasPendEret = false
	}
}

func (d *Decoder) cancelPendElem() {
	// Drop all pending elements due to Exception Cancel
	d.hasPendElem = false
	d.hasPendEret = false
}

func (d *Decoder) OutputTraceElement(elem trace.Element) {
	elem.Index = d.IndexCurrPkt
	elem.TraceID = d.Config.TraceID()

	switch elem.ElemType {
	case trace.GenElemInstrRange:
		d.flushPendElem()
		d.pendElem = elem
		d.hasPendElem = true
	case trace.GenElemExceptionRet:
		// If not Cortex-M, pend the ERET alongside the InstrRange
		if d.Config.CoreProf != trace.ProfileCortexM {
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

func (d *Decoder) OutputTraceElementIdx(idx trace.Index, elem trace.Element) {
	elem.Index = idx
	elem.TraceID = d.Config.TraceID()
	d.flushPendElem()
	d.EmitElement(elem.Index, elem.TraceID, elem)
}

// Write consumes trace data from the demuxer.
func (d *Decoder) Write(index trace.Index, dataBlock []byte) (uint32, error) {
	if len(dataBlock) == 0 {
		return 0, fmt.Errorf("%w: packet processor: zero length data block", trace.ErrInvalidParamVal)
	}
	processed, err := d.processData(index, dataBlock)
	if err != nil {
		return processed, err
	}
	return processed, nil
}

func (d *Decoder) Close() error {
	if d.isClosed {
		return nil
	}
	d.isClosed = true

	// Flush any incomplete bytes
	if len(d.ctx.Reader.Scratch()) > 0 {
		d.ctx.currPacket.Type = PktIncompleteEOT
		_ = d.outputPacket()
	}

	d.flushPendElem()

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
	return nil
}

func (d *Decoder) configureDecoder() {
	d.unsyncInfo = trace.UnsyncInitDecoder
	d.resetDecoder()
}

func (d *Decoder) resetDecoder() {
	d.currState = decodeNoSync
	d.needIsync = true
	d.needAddr = true
	d.sentUnknown = false

	d.peContext = trace.PEContext{
		SecurityLevel:  trace.SecSecure,
		ExceptionLevel: trace.ELUnknown,
	}
	d.iAddr = 0
}

func (d *Decoder) resetProcessorState() {
	d.ctx.processState = stateWaitSync
	d.ctx.waitASyncSOPacket = false
	d.ctx.bAsyncRawOp = false
	d.ctx.unsyncedRaw = nil
	d.resetPacketState()
}

// processPacket is the entrypoint for the Step 5 decoder logic.
func (d *Decoder) processPacket(pkt *Packet) error {
	if pkt == nil {
		return trace.ErrInvalidParamVal
	}
	if !d.canDecodeElements() {
		return nil
	}
	d.CurrPacketIn = pkt
	d.IndexCurrPkt = pkt.Index

	switch d.currState {
	case decodeNoSync:
		elem := trace.Element{ElemType: trace.GenElemNoSync}
		elem.SetUnsyncEndReason(d.unsyncInfo)
		d.OutputTraceElement(elem)

		if pkt.Type == PktASync {
			d.currState = decodeWaitISync
		} else {
			d.currState = decodeWaitSync
		}
		return nil

	case decodeWaitSync:
		if pkt.Type == PktASync {
			d.currState = decodeWaitISync
		}
		return nil

	case decodeWaitISync:
		if pkt.Type == PktISync || pkt.Type == PktISyncCycle {
			d.currState = decodePkts
			return d.decodePacket()
		}
		// Pre-ISync valid packets
		if pkt.Type == PktTimestamp || (d.Config.CycleAcc() && (pkt.Type == PktCycleCount || pkt.Type == PktPHdr)) {
			return d.decodePacket()
		}
		return nil

	case decodePkts:
		return d.decodePacket()
	}

	return nil
}

func (d *Decoder) canDecodeElements() bool {
	return d.MemAccess != nil && d.InstrDecode != nil && d.codeFollower != nil
}

func (d *Decoder) decodePacket() error {
	pkt := d.CurrPacketIn
	d.committedPendThisPacket = false

	if pkt.Err != nil {
		if errors.Is(pkt.Err, trace.ErrBadPacketSeq) || errors.Is(pkt.Err, trace.ErrInvalidPcktHdr) {
			d.unsyncInfo = trace.UnsyncBadPacket
			d.currState = decodeWaitSync
			d.needIsync = true
			d.OutputTraceElement(trace.Element{ElemType: trace.GenElemNoSync})
			return nil
		}
	}

	// Commit pending elements for all packets except branches (which handles exception cancels)
	if pkt.Type != PktBranchAddress {
		d.committedPendThisPacket = d.hasPendElem || d.hasPendEret
		d.flushPendElem()
	}

	switch pkt.Type {
	case PktIncompleteEOT, PktASync, PktIgnore, PktNotSync:
		// ignore
	case PktBadSequence, PktBadTraceMode, PktReserved:
		d.unsyncInfo = trace.UnsyncBadPacket
		d.currState = decodeWaitSync
		d.needIsync = true
		d.OutputTraceElement(trace.Element{ElemType: trace.GenElemNoSync})
	case PktCycleCount:
		elem := trace.Element{ElemType: trace.GenElemCycleCount}
		elem.SetCycleCount(pkt.CycleCount)
		d.OutputTraceElement(elem)
	case PktTrigger:
		elem := trace.Element{ElemType: trace.GenElemEvent}
		elem.Payload.TraceEvent.EvType = trace.EventTrigger
		d.OutputTraceElement(elem)
	case PktBranchAddress:
		return d.processBranchAddr()
	case PktISyncCycle, PktISync:
		return d.processISync()
	case PktPHdr:
		return d.processPHdr()
	case PktContextID:
		elem := trace.Element{ElemType: trace.GenElemPeContext}
		d.peContext.ContextID = pkt.Context.CtxtID
		d.peContext.ContextIDValid = true
		elem.Context = d.peContext
		d.OutputTraceElement(elem)
	case PktVMID:
		elem := trace.Element{ElemType: trace.GenElemPeContext}
		d.peContext.VMID = uint32(pkt.Context.VMID)
		d.peContext.VMIDValid = true
		elem.Context = d.peContext
		d.OutputTraceElement(elem)
	case PktExceptionEntry:
		elem := trace.Element{ElemType: trace.GenElemException}
		elem.ExceptionDataMarker = true
		d.OutputTraceElement(elem)
	case PktExceptionExit:
		d.OutputTraceElement(trace.Element{ElemType: trace.GenElemExceptionRet})
	case PktTimestamp:
		elem := trace.Element{ElemType: trace.GenElemTimestamp}
		elem.Timestamp = pkt.Timestamp
		d.OutputTraceElement(elem)
	}

	return nil
}

func (d *Decoder) processISync() error {
	pkt := d.CurrPacketIn
	ctxtUpdate := pkt.Context.UpdatedC || pkt.Context.UpdatedV || pkt.Context.Updated

	if d.needIsync || pkt.ISyncInfo.Reason != trace.ISyncPeriodic {
		elem := trace.Element{ElemType: trace.GenElemTraceOn}
		elem.SetTraceOnReason(trace.TraceOnNormal)
		switch pkt.ISyncInfo.Reason {
		case trace.ISyncTraceRestartAfterOverflow:
			elem.SetTraceOnReason(trace.TraceOnOverflow)
		case trace.ISyncDebugExit:
			elem.SetTraceOnReason(trace.TraceOnExDebug)
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
			el := trace.ELUnknown
			if pkt.Context.CurrHyp {
				el = trace.EL2
			}
			sec := trace.SecSecure
			if pkt.Context.CurrNS {
				sec = trace.SecNonsecure
			}
			d.peContext.ExceptionLevel = el
			d.peContext.ELValid = true
			d.peContext.SecurityLevel = sec
		}

		elem := trace.Element{ElemType: trace.GenElemPeContext}
		elem.Context = d.peContext
		elem.ISA = pkt.CurrISA
		d.codeFollower.Isa = pkt.CurrISA
		d.codeFollower.InstrInfo.ISA = pkt.CurrISA

		if pkt.ISyncInfo.HasCycleCount {
			elem.SetCycleCount(pkt.CycleCount)
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

func (d *Decoder) processBranchAddr() error {
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
			sec := trace.SecSecure
			if pkt.Context.CurrNS {
				sec = trace.SecNonsecure
			}
			if sec != d.peContext.SecurityLevel {
				d.peContext.SecurityLevel = sec
				updatePEContext = true
			}

			el := trace.ELUnknown
			if pkt.Context.CurrHyp {
				el = trace.EL2
			}
			if !d.peContext.ELValid || el != d.peContext.ExceptionLevel {
				d.peContext.ExceptionLevel = el
				d.peContext.ELValid = true
				updatePEContext = true
			}
		}
	}

	if updatePEContext {
		elem := trace.Element{ElemType: trace.GenElemPeContext}
		elem.Context = d.peContext
		d.OutputTraceElement(elem)
	}

	if pkt.Exception.Present && pkt.Exception.Number != 0 {
		elem := trace.Element{ElemType: trace.GenElemException}
		elem.Payload.ExceptionNum = uint32(pkt.Exception.Number)
		d.OutputTraceElement(elem)
	}

	return nil
}

func (d *Decoder) processPHdr() error {
	pkt := d.CurrPacketIn
	atomsNum := pkt.Atom.Num
	enBits := pkt.Atom.EnBits
	isCCPacket := d.Config.CycleAcc()
	instrRanges := 0
	outputElem := func(elem trace.Element) {
		if elem.ElemType == trace.GenElemInstrRange {
			instrRanges++
		}
		d.OutputTraceElement(elem)
	}

	memSpace := trace.MemSpaceN
	if d.peContext.SecurityLevel == trace.SecSecure {
		memSpace = trace.MemSpaceS
	}

	d.codeFollower.MemSpace = memSpace

	for {
		if d.needAddr {
			if !d.sentUnknown || isCCPacket {
				elem := trace.Element{ElemType: trace.GenElemAddrUnknown}
				if d.sentUnknown || atomsNum == 0 {
					elem.ElemType = trace.GenElemCycleCount
				}
				if isCCPacket {
					elem.SetCycleCount(d.remainCC(pkt, atomsNum))
				}
				outputElem(elem)
				d.sentUnknown = true
			}
			atomsNum = 0 // Skip remaining atoms
		} else {
			elem := trace.Element{ElemType: trace.GenElemInstrRange}

			if isCCPacket {
				if atomsNum == 0 {
					elem.ElemType = trace.GenElemCycleCount
				}
				elem.SetCycleCount(d.atomCC(pkt, atomsNum))
			}

			if atomsNum > 0 {
				val := trace.AtomN
				if (enBits & 1) == 1 {
					val = trace.AtomE
				}

				d.codeFollower.Isa = pkt.CurrISA
				d.codeFollower.InstrInfo.ISA = pkt.CurrISA

				res, err := d.codeFollower.FollowSingleAtom(trace.VAddr(d.iAddr), val)
				if err != nil && !errors.Is(err, trace.ErrMemNacc) {
					return err
				}

				if res.NumInstr > 0 {
					elem.StartAddr = res.RangeSt
					elem.EndAddr = res.RangeEn
					elem.ISA = pkt.CurrISA
					elem.Payload.NumInstrRange = res.NumInstr
					elem.SetLastInstrInfo(val == trace.AtomE, res.InstrInfo.Type, res.InstrInfo.Subtype, res.InstrInfo.InstrSize)
					elem.LastInstrCond = res.InstrInfo.IsConditional

					d.iAddr = uint64(res.NextAddr)
					pkt.CurrISA = res.InstrInfo.NextISA

					if !res.HasNext {
						d.needAddr = true
						d.sentUnknown = false
					}
				}

				if errors.Is(err, trace.ErrMemNacc) {
					if res.NumInstr > 0 {
						outputElem(elem)

						naccElem := trace.Element{
							ElemType:  trace.GenElemAddrNacc,
							StartAddr: trace.VAddr(res.NaccAddr),
						}
						naccElem.Payload.ExceptionNum = uint32(memSpace)
						outputElem(naccElem)
					} else {
						elem.ElemType = trace.GenElemAddrNacc
						elem.StartAddr = trace.VAddr(res.NaccAddr)
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

func (d *Decoder) atomCC(pkt *Packet, atomsNum uint8) uint32 {
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

func (d *Decoder) remainCC(pkt *Packet, atomsNum uint8) uint32 {
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
