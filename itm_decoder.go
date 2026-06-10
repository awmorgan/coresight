package coresight

import (
	"fmt"
)

type itmDecodeState int

const (
	itmDecodeNoSync itmDecodeState = iota
	itmDecodeWaitSync
	itmDecodePkts
)

// itmDecoder processes raw trace bytes into ITM packets, then decodes them into Elements.
type itmDecoder struct {
	Config *itmConfig
	internalEmitter

	ctx itmParseContext

	IndexCurrPkt Index
	CurrPacketIn *itmPacket

	currState     itmDecodeState
	itmInfo       SWTItmInfo
	localTSCount  uint64
	globalTS      uint64
	stimPage      uint8
	needGTS2      bool
	prevOverflow  bool
	gtsFreqChange bool
	unsyncInfo    UnsyncInfo

	isClosed bool
}

// itmNewDecoder creates a new ITM decoder instance.
func itmNewDecoder(cfg *itmConfig) (*itmDecoder, error) {
	if cfg == nil {
		return nil, fmt.Errorf("%w: ITM config cannot be nil", errInvalidParamVal)
	}

	d := &itmDecoder{
		Config: cfg,
	}
	d.ctx.internalByteStream = newInternalByteStream()
	d.resetProcessorState()
	d.configureDecoder()

	return d, nil
}

// OutputTraceElement sends an element using IndexCurrPkt.
func (d *itmDecoder) OutputTraceElement(elem Element) {
	d.EmitElement(d.IndexCurrPkt, d.Config.TraceID(), elem)
}

// Write consumes trace data from the demuxer.
func (d *itmDecoder) Write(index Index, dataBlock []byte) (uint32, error) {
	return d.processData(index, dataBlock)
}

func (d *itmDecoder) Close() error {
	if d.isClosed {
		return nil
	}
	d.isClosed = true

	// Flush any incomplete bytes
	if len(d.ctx.Reader.Scratch()) > 0 {
		d.ctx.currPacket.Type = itmPktIncompleteEOT
		_ = d.outputPacket()
	}

	elem := Element{ElemType: GenElemEOTrace}
	elem.SetUnsyncEndReason(UnsyncEOT)
	d.OutputTraceElement(elem)
	d.EmitTraceEnd()
	return nil
}

func (d *itmDecoder) Reset(index Index) error {
	d.isClosed = false
	d.resetProcessorState()
	d.unsyncInfo = UnsyncResetDecoder
	d.resetDecoder()
	return nil
}

func (d *itmDecoder) Flush() error {
	return nil
}

func (d *itmDecoder) configureDecoder() {
	d.unsyncInfo = UnsyncInitDecoder
	d.resetDecoder()
}

func (d *itmDecoder) resetDecoder() {
	d.currState = itmDecodeNoSync
	d.localTSCount = 0
	d.globalTS = 0
	d.stimPage = 0
	d.needGTS2 = true
	d.prevOverflow = false
	d.gtsFreqChange = false
}

func (d *itmDecoder) resetProcessorState() {
	d.ctx.processState = itmStateWaitSync
	d.ctx.bStreamSync = false
	d.ctx.sentNotSyncPacket = false
	d.ctx.syncStart = false
	d.ctx.dumpUnsyncedBytes = 0
	d.resetPacketState()
}

var (
	globalTSLowMasks = [...]uint64{
		0x00000007F, // [ 6:0]
		0x000003FFF, // [13:0]
		0x0001FFFFF, // [20:0]
		0x003FFFFFF, // [25:0]
	}
	globalTSHiMask = ^globalTSLowMasks[3]
	localTSTCTypes = [...]SWTItmType{
		TSSync,
		TSDelay,
		TSPKTDelay,
		TSPKTTSDelay,
	}
)

func (d *itmDecoder) processPacket(pktIn *itmPacket) error {
	if pktIn == nil {
		return errInvalidParamVal
	}
	d.CurrPacketIn = pktIn
	d.IndexCurrPkt = pktIn.Index
	d.itmInfo = SWTItmInfo{}

	bPktDone := false
	var err error

	for !bPktDone && err == nil {
		switch d.currState {
		case itmDecodeNoSync:
			elem := Element{ElemType: GenElemNoSync}
			elem.SetUnsyncEndReason(d.unsyncInfo)
			d.OutputTraceElement(elem)
			d.currState = itmDecodeWaitSync

		case itmDecodeWaitSync:
			if pktIn.Type == itmPktAsync {
				d.currState = itmDecodePkts
			}
			bPktDone = true

		case itmDecodePkts:
			err = d.decodePacket()
			bPktDone = true
		}
	}
	return err
}

func (d *itmDecoder) decodePacket() error {
	pktIn := d.CurrPacketIn
	sendPacket := false
	srcID := pktIn.SrcID

	switch pktIn.Type {
	case itmPktBadSequence, itmPktReserved:
		d.unsyncInfo = UnsyncBadPacket
		d.resetDecoder()
		return errBadPacketSeq

	case itmPktNotSync:
		d.resetDecoder()
		return nil

	case itmPktAsync, itmPktIncompleteEOT:
		return nil

	case PktDWT:
		d.itmInfo.PktType = DWTPayload
		d.itmInfo.PayloadSize = pktIn.ValSz
		d.itmInfo.Value = pktIn.Value
		d.itmInfo.PayloadSrcID = srcID
		sendPacket = true

	case PktSWIT:
		d.itmInfo.PktType = SWITPayload
		d.itmInfo.PayloadSize = pktIn.ValSz
		d.itmInfo.Value = pktIn.Value
		srcID = (srcID & 0x1F) | (d.stimPage << 5)
		d.itmInfo.PayloadSrcID = srcID
		sendPacket = true

	case itmPktExtension:
		if (srcID&0x80) == 0 && (srcID&0x1F) == 2 {
			d.stimPage = uint8(pktIn.Value)
		}

	case itmPktOverflow:
		d.localTSCount = 0
		d.prevOverflow = true

	case PktTSGlobal1:
		if !d.needGTS2 {
			d.needGTS2 = (srcID & 0x2) != 0
		}
		if !d.gtsFreqChange {
			d.gtsFreqChange = (srcID & 0x1) != 0
		}

		szIdx := min(pktIn.ValSz-1, 3)

		d.globalTS &= ^globalTSLowMasks[szIdx]
		d.globalTS |= uint64(pktIn.Value)

		if !d.needGTS2 {
			d.itmInfo.PktType = TSGlobal
			sendPacket = true
		}

	case PktTSGlobal2:
		d.itmInfo.PktType = TSGlobal
		d.globalTS &= ^globalTSHiMask
		d.globalTS |= (pktIn.ExtValue() << 26)
		d.needGTS2 = false
		sendPacket = true

	case PktTSLocal:
		d.itmInfo.PktType = localTSTCTypes[srcID&0x3]
		d.itmInfo.PayloadSize = pktIn.ValSz
		d.itmInfo.Value = pktIn.Value

		prescale := uint64(1)
		if d.Config != nil {
			prescale = uint64(d.Config.TSPrescaleValue())
		}
		d.localTSCount += uint64(d.itmInfo.Value) * prescale
		sendPacket = true
	}

	if sendPacket {
		elem := Element{ElemType: GenElemITMTrace}

		// Transfer TS values if set
		switch pktIn.Type {
		case PktTSLocal:
			elem.SetTimestamp(d.localTSCount, false)
		case PktTSGlobal1, PktTSGlobal2:
			elem.SetTimestamp(d.globalTS, d.gtsFreqChange)
			d.gtsFreqChange = false
		}

		if d.prevOverflow {
			d.itmInfo.Overflow = 1
			d.prevOverflow = false
		}
		elem.SetITMInfo(d.itmInfo)
		d.OutputTraceElement(elem)
	}

	return nil
}
