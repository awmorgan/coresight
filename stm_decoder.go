package coresight

import (
	"encoding/binary"
	"fmt"
)

type stmDecodeState int

const (
	stmDecodeNoSync stmDecodeState = iota
	stmDecodeWaitSync
	stmDecodePkts
)

// stmDecoder processes raw trace bytes into STM packets, then decodes them into Elements.
type stmDecoder struct {
	Config *stmConfig
	internalEmitter

	ctx stmParseContext

	IndexCurrPkt Index
	CurrPacketIn *stmPacket

	currState  stmDecodeState
	swtInfo    SWTInfo
	unsyncInfo UnsyncInfo
	isClosed   bool
}

func stmNewDecoder(cfg *stmConfig) (*stmDecoder, error) {
	if cfg == nil {
		return nil, fmt.Errorf("%w: STM config cannot be nil", errInvalidParamVal)
	}

	d := &stmDecoder{Config: cfg}
	d.resetProcessorState()
	d.configureDecoder()
	return d, nil
}

func (d *stmDecoder) OutputTraceElement(elem Element) {
	d.EmitElement(d.IndexCurrPkt, d.Config.TraceID(), elem)
}

func (d *stmDecoder) Write(index Index, dataBlock []byte) (uint32, error) {
	return d.processData(index, dataBlock)
}

func (d *stmDecoder) Close() error {
	if d.isClosed {
		return nil
	}
	d.isClosed = true
	if d.ctx.numNibbles > 0 {
		if d.ctx.currPacket.HasMarker {
			return fmt.Errorf("%w: incomplete marked STM packet at end of trace", ErrDataDecodeFatal)
		}
		d.ctx.currPacket.UpdateErrType(stmPktIncompleteEOT)
		_ = d.outputPacket()
	}
	elem := Element{ElemType: GenElemEOTrace}
	elem.SetUnsyncEndReason(UnsyncEOT)
	d.OutputTraceElement(elem)
	d.EmitTraceEnd()
	return nil
}

func (d *stmDecoder) Reset(index Index) error {
	d.isClosed = false
	d.resetProcessorState()
	d.unsyncInfo = UnsyncResetDecoder
	d.resetDecoder()
	return nil
}

func (d *stmDecoder) Flush() error { return nil }

func (d *stmDecoder) configureDecoder() {
	d.unsyncInfo = UnsyncInitDecoder
	d.resetDecoder()
}

func (d *stmDecoder) resetDecoder() {
	d.currState = stmDecodeNoSync
	d.swtInfo = SWTInfo{}
}

func (d *stmDecoder) resetProcessorState() {
	d.ctx.processState = stmStateWaitSync
	d.ctx.currPacket.InitStartState()
	d.ctx.nibbleSecondValid = false
	if d.ctx.packetData == nil {
		d.ctx.packetData = make([]byte, 0, 32)
	}
	d.initNextPacket()
}

func (d *stmDecoder) processPacket(pktIn *stmPacket) error {
	if pktIn == nil {
		return errInvalidParamVal
	}
	d.CurrPacketIn = pktIn
	d.IndexCurrPkt = pktIn.Index

	bPktDone := false
	var err error
	for !bPktDone && err == nil {
		switch d.currState {
		case stmDecodeNoSync:
			elem := Element{ElemType: GenElemNoSync}
			elem.SetUnsyncEndReason(d.unsyncInfo)
			d.OutputTraceElement(elem)
			d.currState = stmDecodeWaitSync
		case stmDecodeWaitSync:
			if pktIn.Type == stmPktAsync {
				d.currState = stmDecodePkts
			}
			bPktDone = true
		case stmDecodePkts:
			err = d.decodePacket()
			bPktDone = true
		}
	}
	return err
}

func (d *stmDecoder) decodePacket() error {
	pkt := d.CurrPacketIn
	sendPacket := false
	elem := Element{ElemType: GenElemSWTrace}
	d.clearSWTPerPacketInfo()

	switch pkt.Type {
	case stmPktBadSequence, stmPktReserved:
		d.unsyncInfo = UnsyncBadPacket
		d.resetDecoder()
		return nil
	case stmPktNotSync:
		d.resetDecoder()
		return nil
	case PktVersion:
		d.swtInfo.MasterID = uint16(pkt.Master)
		d.swtInfo.ChannelID = pkt.Channel
		d.swtInfo.IDValid = true
	case stmPktAsync, stmPktIncompleteEOT:
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

func (d *stmDecoder) clearSWTPerPacketInfo() {
	idValid := d.swtInfo.IDValid
	d.swtInfo = SWTInfo{
		MasterID:  d.swtInfo.MasterID,
		ChannelID: d.swtInfo.ChannelID,
		IDValid:   idValid,
	}
}

func (d *stmDecoder) updatePayload(elem *Element, pkt *stmPacket, sendPacket *bool) {
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
