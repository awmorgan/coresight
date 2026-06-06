package stm

import (
	"encoding/binary"
	"fmt"

	"coresight/internal/protocol"
	"coresight/trace"
)

type decodeState int

const (
	decodeNoSync decodeState = iota
	decodeWaitSync
	decodePkts
)

// Decoder processes raw trace bytes into STM packets, then decodes them into Elements.
type Decoder struct {
	Config *Config
	protocol.Emitter

	ctx parseContext

	IndexCurrPkt trace.Index
	CurrPacketIn *Packet

	currState  decodeState
	swtInfo    trace.SWTInfo
	unsyncInfo trace.UnsyncInfo
	isClosed   bool
}

func NewDecoder(cfg *Config) (*Decoder, error) {
	if cfg == nil {
		return nil, fmt.Errorf("%w: STM config cannot be nil", trace.ErrInvalidParamVal)
	}

	d := &Decoder{Config: cfg}
	d.resetProcessorState()
	d.configureDecoder()
	return d, nil
}

func (d *Decoder) OutputTraceElement(elem trace.Element) {
	d.EmitElement(d.IndexCurrPkt, d.Config.TraceID(), elem)
}

func (d *Decoder) Write(index trace.Index, dataBlock []byte) (uint32, error) {
	return d.processData(index, dataBlock)
}

func (d *Decoder) Close() error {
	if d.isClosed {
		return nil
	}
	d.isClosed = true
	if d.ctx.numNibbles > 0 {
		if d.ctx.currPacket.HasMarker {
			return fmt.Errorf("%w: incomplete marked STM packet at end of trace", trace.ErrDataDecodeFatal)
		}
		d.ctx.currPacket.UpdateErrType(PktIncompleteEOT)
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

func (d *Decoder) Flush() error { return nil }

func (d *Decoder) configureDecoder() {
	d.unsyncInfo = trace.UnsyncInitDecoder
	d.resetDecoder()
}

func (d *Decoder) resetDecoder() {
	d.currState = decodeNoSync
	d.swtInfo = trace.SWTInfo{}
}

func (d *Decoder) resetProcessorState() {
	d.ctx.processState = stateWaitSync
	d.ctx.currPacket.InitStartState()
	d.ctx.nibbleSecondValid = false
	if d.ctx.packetData == nil {
		d.ctx.packetData = make([]byte, 0, 32)
	}
	d.initNextPacket()
}

func (d *Decoder) processPacket(pktIn *Packet) error {
	if pktIn == nil {
		return trace.ErrInvalidParamVal
	}
	d.CurrPacketIn = pktIn
	d.IndexCurrPkt = pktIn.Index

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
	pkt := d.CurrPacketIn
	sendPacket := false
	elem := trace.Element{ElemType: trace.GenElemSWTrace}
	d.clearSWTPerPacketInfo()

	switch pkt.Type {
	case PktBadSequence, PktReserved:
		d.unsyncInfo = trace.UnsyncBadPacket
		d.resetDecoder()
		return nil
	case PktNotSync:
		d.resetDecoder()
		return nil
	case PktVersion:
		d.swtInfo.MasterID = uint16(pkt.Master)
		d.swtInfo.ChannelID = pkt.Channel
		d.swtInfo.IDValid = true
	case PktAsync, PktIncompleteEOT:
		return nil
	case PktNull:
		sendPacket = pkt.HasTS
	case PktFreq:
		d.swtInfo.Frequency = true
		d.updatePayload(&elem, pkt, &sendPacket)
	case PktTrig:
		d.swtInfo.TriggerEvent = true
		d.updatePayload(&elem, pkt, &sendPacket)
	case PktGerr:
		d.swtInfo.MasterID = uint16(pkt.Master)
		d.swtInfo.ChannelID = pkt.Channel
		d.swtInfo.GlobalErr = true
		d.swtInfo.IDValid = false
		d.updatePayload(&elem, pkt, &sendPacket)
	case PktMerr:
		d.swtInfo.ChannelID = pkt.Channel
		d.swtInfo.MasterErr = true
		d.updatePayload(&elem, pkt, &sendPacket)
	case PktM8:
		d.swtInfo.MasterID = uint16(pkt.Master)
		d.swtInfo.ChannelID = pkt.Channel
		d.swtInfo.IDValid = true
	case PktC8, PktC16:
		d.swtInfo.ChannelID = pkt.Channel
	case PktFlag:
		d.swtInfo.MarkerPacket = true
		sendPacket = true
	case PktD4, PktD8, PktD16, PktD32, PktD64:
		d.updatePayload(&elem, pkt, &sendPacket)
	}

	if sendPacket {
		if pkt.HasTS {
			elem.SetTimestamp(pkt.Timestamp, false)
			d.swtInfo.HasTimestamp = true
		}
		elem.SetSWTInfo(d.swtInfo)
		d.OutputTraceElement(elem)
	}
	return nil
}

func (d *Decoder) clearSWTPerPacketInfo() {
	idValid := d.swtInfo.IDValid
	d.swtInfo = trace.SWTInfo{
		MasterID:  d.swtInfo.MasterID,
		ChannelID: d.swtInfo.ChannelID,
		IDValid:   idValid,
	}
}

func (d *Decoder) updatePayload(elem *trace.Element, pkt *Packet, sendPacket *bool) {
	*sendPacket = true
	d.swtInfo.PayloadNumPackets = 1
	bitSize := uint8(0)
	switch pkt.Type {
	case PktD4:
		bitSize = 4
	case PktD8, PktTrig, PktGerr, PktMerr:
		bitSize = 8
	case PktD16:
		bitSize = 16
	case PktD32, PktFreq:
		bitSize = 32
	case PktD64:
		bitSize = 64
	}
	d.swtInfo.PayloadPktBitsize = bitSize

	data := make([]byte, 8)
	binary.LittleEndian.PutUint64(data, pkt.Payload)
	elem.SetExtendedDataPtr(data[:max(1, int(bitSize)/8)])
	if pkt.HasMarker {
		d.swtInfo.MarkerPacket = true
	}
}
