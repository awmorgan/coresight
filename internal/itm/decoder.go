package itm

import (
	"fmt"

	"github.com/awmorgan/coresight/internal/protocol"
	"github.com/awmorgan/coresight/trace"
)

type decodeState int

const (
	decodeNoSync decodeState = iota
	decodeWaitSync
	decodePkts
)

// Decoder processes raw trace bytes into ITM packets, then decodes them into Elements.
type Decoder struct {
	Config *Config
	protocol.Emitter

	ctx parseContext

	IndexCurrPkt trace.Index
	CurrPacketIn *Packet

	currState     decodeState
	itmInfo       trace.SWTItmInfo
	localTSCount  uint64
	globalTS      uint64
	stimPage      uint8
	needGTS2      bool
	prevOverflow  bool
	gtsFreqChange bool
	unsyncInfo    trace.UnsyncInfo

	isClosed bool
}

// NewDecoder creates a new ITM decoder instance.
func NewDecoder(cfg *Config) (*Decoder, error) {
	if cfg == nil {
		return nil, fmt.Errorf("%w: ITM config cannot be nil", protocol.ErrInvalidParamVal)
	}

	d := &Decoder{
		Config: cfg,
	}
	d.ctx.ByteStream = protocol.NewByteStream()
	d.resetProcessorState()
	d.configureDecoder()

	return d, nil
}

// OutputTraceElement sends an element using IndexCurrPkt.
func (d *Decoder) OutputTraceElement(elem trace.Element) {
	d.EmitElement(d.IndexCurrPkt, d.Config.TraceID(), elem)
}

// Write consumes trace data from the demuxer.
func (d *Decoder) Write(index trace.Index, dataBlock []byte) (uint32, error) {
	return d.processData(index, dataBlock)
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
	d.localTSCount = 0
	d.globalTS = 0
	d.stimPage = 0
	d.needGTS2 = true
	d.prevOverflow = false
	d.gtsFreqChange = false
}

func (d *Decoder) resetProcessorState() {
	d.ctx.processState = stateWaitSync
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
	localTSTCTypes = [...]trace.SWTItmType{
		trace.TSSync,
		trace.TSDelay,
		trace.TSPKTDelay,
		trace.TSPKTTSDelay,
	}
)

func (d *Decoder) processPacket(pktIn *Packet) error {
	if pktIn == nil {
		return protocol.ErrInvalidParamVal
	}
	d.CurrPacketIn = pktIn
	d.IndexCurrPkt = pktIn.Index
	d.itmInfo = trace.SWTItmInfo{}

	bPktDone := false
	var err error

	for !bPktDone && err == nil {
		switch d.currState {
		case decodeNoSync:
			elem := trace.Element{ElemType: trace.GenElemNoSync}
			elem.SetUnsyncEndReason(d.unsyncInfo)
			d.OutputTraceElement(elem)
			d.currState = decodeWaitSync

		case decodeWaitSync:
			if pktIn.Type == PktAsync {
				d.currState = decodePkts
			}
			bPktDone = true

		case decodePkts:
			err = d.decodePacket()
			bPktDone = true
		}
	}
	return err
}

func (d *Decoder) decodePacket() error {
	pktIn := d.CurrPacketIn
	sendPacket := false
	srcID := pktIn.SrcID

	switch pktIn.Type {
	case PktBadSequence, PktReserved:
		d.unsyncInfo = trace.UnsyncBadPacket
		d.resetDecoder()
		return protocol.ErrBadPacketSeq

	case PktNotSync:
		d.resetDecoder()
		return nil

	case PktAsync, PktIncompleteEOT:
		return nil

	case PktDWT:
		d.itmInfo.PktType = trace.DWTPayload
		d.itmInfo.PayloadSize = pktIn.ValSz
		d.itmInfo.Value = pktIn.Value
		d.itmInfo.PayloadSrcID = srcID
		sendPacket = true

	case PktSWIT:
		d.itmInfo.PktType = trace.SWITPayload
		d.itmInfo.PayloadSize = pktIn.ValSz
		d.itmInfo.Value = pktIn.Value
		srcID = (srcID & 0x1F) | (d.stimPage << 5)
		d.itmInfo.PayloadSrcID = srcID
		sendPacket = true

	case PktExtension:
		if (srcID&0x80) == 0 && (srcID&0x1F) == 2 {
			d.stimPage = uint8(pktIn.Value)
		}

	case PktOverflow:
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
			d.itmInfo.PktType = trace.TSGlobal
			sendPacket = true
		}

	case PktTSGlobal2:
		d.itmInfo.PktType = trace.TSGlobal
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
		elem := trace.Element{ElemType: trace.GenElemITMTrace}

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
