package itm

import (
	"errors"
	"fmt"

	"github.com/awmorgan/coresight/internal/protocol"
	"github.com/awmorgan/coresight/trace"
)

type processState int

const (
	stateWaitSync processState = iota
	stateProcHdr
	stateProcData
	stateSendPkt
	stateProcErr
)

type parseContext struct {
	protocol.ByteStream

	processState    processState
	procErrReason   error
	currPacket      Packet
	currPacketIndex trace.Index

	bStreamSync       bool
	sentNotSyncPacket bool
	syncStart         bool
	dumpUnsyncedBytes int

	bytesExpected int
	headerByte    uint8
}

func (d *Decoder) readNextByte() (uint8, bool) {
	b, err := d.ctx.ReadByte()
	return b, err == nil
}

func (d *Decoder) resetPacketState() {
	d.ctx.currPacket.Clear()
	d.ctx.EnsureReader()
	d.ctx.Reader.Reset()
	d.ctx.bytesExpected = 0
}

func (d *Decoder) throwMalformedPacketErr(msg string) error {
	d.ctx.processState = stateProcErr
	d.ctx.currPacket.UpdateErrType(PktBadSequence)
	d.ctx.procErrReason = fmt.Errorf("%w: %s", trace.ErrBadPacketSeq, msg)
	return d.ctx.procErrReason
}

func (d *Decoder) canProcessWithoutMoreBytes() bool {
	switch d.ctx.currPacket.Type {
	case PktTSLocal, PktExtension:
		return (d.ctx.headerByte & 0x80) == 0
	case PktSWIT, PktDWT:
		return len(d.ctx.Reader.Scratch())-1 >= d.ctx.bytesExpected
	}
	return false
}

func (d *Decoder) processData(index trace.Index, dataBlock []uint8) (uint32, error) {
	d.ctx.Feed(index, dataBlock)

	var err error

	for d.ctx.Reader.Len() > 0 || d.ctx.processState == stateSendPkt || (d.ctx.processState == stateProcData && d.canProcessWithoutMoreBytes()) {
		switch d.ctx.processState {
		case stateWaitSync:
			err = d.waitASync()

		case stateProcHdr:
			d.ctx.currPacketIndex = d.ctx.CurrentIndex()
			if currByte, ok := d.readNextByte(); ok {
				d.ctx.headerByte = currByte
				d.decodeHeaderByte(currByte)
			} else {
				err = fmt.Errorf("%w: Data Buffer Overrun", trace.ErrPktInterpFail)
			}

		case stateProcData:
			err = d.decodePayload()

		case stateSendPkt:
			err = d.outputPacket()
			d.resetPacketState()
			if d.ctx.bStreamSync {
				d.ctx.processState = stateProcHdr
			} else {
				d.ctx.processState = stateWaitSync
			}

		case stateProcErr:
			err = d.ctx.procErrReason
			if err == nil {
				err = trace.ErrPktInterpFail
			}
		}

		if err != nil {
			if errors.Is(err, trace.ErrBadPacketSeq) || errors.Is(err, trace.ErrInvalidPcktHdr) {
				d.ctx.processState = stateSendPkt
				d.ctx.bStreamSync = false
				err = nil
			} else {
				break
			}
		}
	}

	return uint32(d.ctx.BytesConsumed()), err
}

func (d *Decoder) outputPacket() error {
	d.ctx.currPacket.Index = d.ctx.currPacketIndex
	scratch := d.ctx.Reader.Scratch()

	d.EmitPacket(d.ctx.currPacketIndex, &d.ctx.currPacket, scratch)

	err := d.processPacket(&d.ctx.currPacket)
	d.ctx.Reader.Reset()
	return err
}

func (d *Decoder) flushUnsyncedBytes() {
	if d.ctx.dumpUnsyncedBytes == 0 {
		return
	}

	scratch := d.ctx.Reader.Scratch()
	d.ctx.currPacket.Type = PktNotSync
	d.ctx.currPacket.Index = d.ctx.currPacketIndex

	d.EmitPacket(d.ctx.currPacketIndex, &d.ctx.currPacket, scratch[:d.ctx.dumpUnsyncedBytes])

	if !d.ctx.sentNotSyncPacket {
		_ = d.processPacket(&d.ctx.currPacket)
		d.ctx.sentNotSyncPacket = true
	}

	d.ctx.Reader.DiscardScratchPrefix(d.ctx.dumpUnsyncedBytes)

	d.ctx.dumpUnsyncedBytes = 0
}

func (d *Decoder) readAsyncSeq() (bFoundAsync bool, bError bool) {
	for len(d.ctx.Reader.Scratch()) < 5 && !bError {
		b, ok := d.readNextByte()
		if !ok {
			return false, false
		}
		if b != 0x00 {
			bError = true
		}
	}

	for !bFoundAsync && !bError {
		b, ok := d.readNextByte()
		if !ok {
			return false, false
		}
		if b == 0x80 {
			bFoundAsync = true
		} else if b != 0x00 {
			bError = true
		}
	}
	return bFoundAsync, bError
}

func (d *Decoder) waitASync() error {
	d.ctx.currPacket.Type = PktNotSync
	d.ctx.dumpUnsyncedBytes = 0

	if !d.ctx.syncStart {
		d.ctx.currPacketIndex = d.ctx.CurrentIndex()
	}

	for d.ctx.Reader.Len() > 0 && !d.ctx.bStreamSync {
		if d.ctx.syncStart {
			bStreamSync, bAsyncErr := d.readAsyncSeq()
			d.ctx.bStreamSync = bStreamSync
			if d.ctx.bStreamSync {
				d.ctx.currPacket.Type = PktAsync
				d.ctx.processState = stateSendPkt
				return nil
			} else if bAsyncErr {
				d.ctx.dumpUnsyncedBytes = len(d.ctx.Reader.Scratch())
				d.ctx.syncStart = false
			}
		}

		if !d.ctx.syncStart {
			b, ok := d.readNextByte()
			if !ok {
				break
			}
			if b == 0x00 {
				d.ctx.syncStart = true
				d.flushUnsyncedBytes()
				d.ctx.currPacketIndex = d.ctx.CurrentIndex() - 1
			} else {
				d.ctx.dumpUnsyncedBytes++
				if d.ctx.dumpUnsyncedBytes >= 8 {
					d.flushUnsyncedBytes()
				}
			}
		}
	}

	if !d.ctx.bStreamSync && !d.ctx.syncStart {
		d.flushUnsyncedBytes()
	}
	return nil
}

func (d *Decoder) decodeHeaderByte(b uint8) {
	if (b & 0x03) != 0x00 {
		d.ctx.bytesExpected = int(b & 0x03)
		if d.ctx.bytesExpected == 3 {
			d.ctx.bytesExpected = 4
		}
		if (b & 0x4) != 0 {
			d.ctx.currPacket.Type = PktDWT
		} else {
			d.ctx.currPacket.Type = PktSWIT
		}
		d.ctx.currPacket.SrcID = (b >> 3) & 0x1F
		d.ctx.processState = stateProcData
		return
	}

	if (b & 0x0F) == 0x00 {
		switch b {
		case 0x00:
			d.ctx.currPacket.Type = PktAsync
			d.ctx.processState = stateProcData
		case 0x70:
			d.ctx.currPacket.Type = PktOverflow
			d.ctx.processState = stateSendPkt
		default:
			d.ctx.currPacket.Type = PktTSLocal
			d.ctx.processState = stateProcData
		}
		return
	}

	if (b & 0x0B) == 0x08 {
		d.ctx.currPacket.Type = PktExtension
		d.ctx.processState = stateProcData
		return
	}

	if (b & 0xDF) == 0x94 {
		if (b & 0x20) == 0 {
			d.ctx.currPacket.Type = PktTSGlobal1
		} else {
			d.ctx.currPacket.Type = PktTSGlobal2
		}
		d.ctx.processState = stateProcData
		return
	}

	d.ctx.currPacket.Type = PktReserved
	d.ctx.currPacket.ErrType = PktReserved
	d.ctx.procErrReason = fmt.Errorf("%w: Reserved Header", trace.ErrInvalidPcktHdr)
	d.ctx.processState = stateProcErr
}

func (d *Decoder) decodePayload() error {
	switch d.ctx.currPacket.Type {
	case PktAsync:
		return d.pktAsync()
	case PktSWIT, PktDWT:
		return d.pktData()
	case PktTSLocal:
		return d.pktLocalTS()
	case PktExtension:
		return d.pktExtension()
	case PktTSGlobal1:
		return d.pktGlobalTS1()
	case PktTSGlobal2:
		return d.pktGlobalTS2()
	default:
		return d.throwMalformedPacketErr("Unknown packet type for payload decode")
	}
}

func (d *Decoder) pktAsync() error {
	bFoundAsync, bError := d.readAsyncSeq()
	if bFoundAsync {
		d.ctx.processState = stateSendPkt
	} else if bError {
		return d.throwMalformedPacketErr("Async Packet: unexpected none zero value")
	}
	return nil
}

func (d *Decoder) pktData() error {
	for len(d.ctx.Reader.Scratch())-1 < d.ctx.bytesExpected {
		_, ok := d.readNextByte()
		if !ok {
			return nil
		}
	}

	scratch := d.ctx.Reader.Scratch()
	val := uint32(0)
	for i := 0; i < d.ctx.bytesExpected; i++ {
		val |= uint32(scratch[1+i]) << (i * 8)
	}

	d.ctx.currPacket.SetValue(val, uint8(d.ctx.bytesExpected))
	d.ctx.processState = stateSendPkt
	return nil
}

func (d *Decoder) readContBytes(limit int) bool {
	scratch := d.ctx.Reader.Scratch()
	if len(scratch) > 1 && (scratch[len(scratch)-1]&0x80) == 0 {
		return true
	}
	for len(d.ctx.Reader.Scratch()) < limit {
		b, ok := d.readNextByte()
		if !ok {
			return false
		}
		if (b & 0x80) == 0 {
			return true
		}
	}
	return true
}

func (d *Decoder) extractContField32() (uint32, error) {
	scratch := d.ctx.Reader.Scratch()
	if len(scratch) <= 1 {
		return 0, nil
	}
	val := uint32(0)
	shift := 0

	for i := 1; i < len(scratch); i++ {
		b := scratch[i]

		if shift >= 32 {
			return 0, d.throwMalformedPacketErr("Continuation value exceeds 32-bit width")
		}
		part := uint32(b & 0x7F)
		if shift > 25 {
			maxPart := uint32((uint64(1) << uint(32-shift)) - 1)
			if part > maxPart {
				return 0, d.throwMalformedPacketErr("Continuation value overflows 32-bit width")
			}
		}
		val |= part << shift
		shift += 7
	}

	return val, nil
}

func (d *Decoder) extractContField64() (uint64, error) {
	scratch := d.ctx.Reader.Scratch()
	if len(scratch) <= 1 {
		return 0, nil
	}
	val := uint64(0)
	shift := 0

	for i := 1; i < len(scratch); i++ {
		b := scratch[i]
		if shift >= 64 {
			return 0, d.throwMalformedPacketErr("Continuation value exceeds 64-bit width")
		}
		part := uint64(b & 0x7F)
		if shift > 57 {
			maxPart := (uint64(1) << uint(64-shift)) - 1
			if part > maxPart {
				return 0, d.throwMalformedPacketErr("Continuation value overflows 64-bit width")
			}
		}
		val |= part << shift
		shift += 7
	}
	return val, nil
}

func (d *Decoder) pktLocalTS() error {
	const pktSizeLimit = 5

	if (d.ctx.headerByte & 0x80) == 0 {
		d.ctx.currPacket.SrcID = 0
		d.ctx.currPacket.SetValue(uint32((d.ctx.headerByte>>4)&0x7), 1)
		d.ctx.processState = stateSendPkt
		return nil
	}
	d.ctx.currPacket.SrcID = (d.ctx.headerByte >> 4) & 0x3

	if !d.readContBytes(pktSizeLimit) {
		return nil
	}
	scratch := d.ctx.Reader.Scratch()
	if (scratch[len(scratch)-1] & 0x80) != 0 {
		return d.throwMalformedPacketErr("Local TS packet: Payload continuation value too long")
	}

	val, err := d.extractContField32()
	if err != nil {
		return err
	}
	d.ctx.currPacket.SetValue(val, uint8(len(scratch)-1))
	d.ctx.processState = stateSendPkt
	return nil
}

func (d *Decoder) pktGlobalTS1() error {
	const pktSizeLimit = 5
	if !d.readContBytes(pktSizeLimit) {
		return nil
	}
	scratch := d.ctx.Reader.Scratch()
	if (scratch[len(scratch)-1] & 0x80) != 0 {
		return d.throwMalformedPacketErr("GTS1 packet: Payload continuation value too long")
	}

	if len(scratch) == 5 {
		lastByte := scratch[4]
		d.ctx.currPacket.SrcID = (lastByte >> 5) & 0x3
		scratch[4] = lastByte & 0x1F
	}

	val, err := d.extractContField32()
	if err != nil {
		return err
	}
	d.ctx.currPacket.SetValue(val, uint8(len(scratch)-1))
	d.ctx.processState = stateSendPkt
	return nil
}

func (d *Decoder) pktGlobalTS2() error {
	const pktSizeLimit = 7
	if !d.readContBytes(pktSizeLimit) {
		return nil
	}
	scratch := d.ctx.Reader.Scratch()
	if (scratch[len(scratch)-1] & 0x80) != 0 {
		return d.throwMalformedPacketErr("GTS2 packet: Payload continuation value too long")
	}

	if len(scratch) <= 5 {
		val, err := d.extractContField32()
		if err != nil {
			return err
		}
		d.ctx.currPacket.SetValue(val, uint8(len(scratch)-1))
	} else {
		val, err := d.extractContField64()
		if err != nil {
			return err
		}
		d.ctx.currPacket.SetExtValue(val)
	}
	d.ctx.processState = stateSendPkt
	return nil
}

func (d *Decoder) pktExtension() error {
	const pktSizeLimit = 5
	if (d.ctx.headerByte & 0x80) == 0 {
		d.ctx.currPacket.SrcID = 2
		if (d.ctx.headerByte & 0x4) != 0 {
			d.ctx.currPacket.SrcID |= 0x80
		}
		d.ctx.currPacket.SetValue(uint32((d.ctx.headerByte>>4)&0x7), 4)
		d.ctx.processState = stateSendPkt
		return nil
	}

	if !d.readContBytes(pktSizeLimit) {
		return nil
	}
	scratch := d.ctx.Reader.Scratch()
	if (scratch[len(scratch)-1] & 0x80) != 0 {
		return d.throwMalformedPacketErr("Extension packet: Payload continuation value too long")
	}

	val, err := d.extractContField32()
	if err != nil {
		return err
	}

	bitLength := []uint8{2, 9, 16, 23, 31}
	d.ctx.currPacket.SrcID = bitLength[len(scratch)-1]
	if (d.ctx.headerByte & 0x4) != 0 {
		d.ctx.currPacket.SrcID |= 0x80
	}
	finalVal := (val << 3) | uint32((d.ctx.headerByte>>4)&0x7)
	d.ctx.currPacket.SetValue(finalVal, 4)
	d.ctx.processState = stateSendPkt
	return nil
}
