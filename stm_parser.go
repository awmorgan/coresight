package coresight

import (
	"errors"
	"fmt"
)

type stmProcessState int

const (
	stmStateWaitSync stmProcessState = iota
	stmStateProcHdr
	stmStateProcData
	stmStateSendPkt
)

type pktFn func(*stmDecoder) error

type stmParseContext struct {
	processState stmProcessState

	data      []byte
	blockBase Index
	off       int

	currPacket stmPacket
	packetIdx  Index
	packetData []byte

	nibble            uint8
	nibbleSecond      uint8
	nibbleSecondValid bool

	numNibbles     uint8
	numDataNibbles uint8

	isSync     bool
	syncStart  bool
	syncHigh   bool
	syncLow0   bool
	syncIndex  Index
	numFNibs   uint8
	streamSync bool

	currFn pktFn

	needsTS       bool
	isMarker      bool
	reqTSNibbles  uint8
	currTSNibbles uint8
	tsUpdateValue uint64
	tsReqSet      bool
	val8          uint8
	val16         uint16
	val32         uint32
	val64         uint64
	nibbleHigh    bool
}

func (d *stmDecoder) processData(index Index, dataBlock []byte) (uint32, error) {
	d.ctx.data = dataBlock
	d.ctx.blockBase = index
	d.ctx.off = 0

	var err error
	for d.dataToProcess() && err == nil {
		switch d.ctx.processState {
		case stmStateWaitSync:
			d.waitForSync(index)
		case stmStateProcHdr:
			d.ctx.packetIdx = index + Index(d.ctx.off)
			if d.readNibble() {
				d.ctx.processState = stmStateProcData
				d.ctx.currFn = d.op1(d.ctx.nibble)
			} else {
				return uint32(d.ctx.off), nil
			}
			fallthrough
		case stmStateProcData:
			err = d.ctx.currFn(d)
		case stmStateSendPkt:
			err = d.outputPacket()
		}
		if errors.Is(err, errBadPacketSeq) || errors.Is(err, errInvalidPcktHdr) {
			return uint32(d.ctx.off), fmt.Errorf("%w: %v", ErrDataDecodeFatal, err)
		}
	}
	return uint32(d.ctx.off), err
}

func (d *stmDecoder) dataToProcess() bool {
	return d.ctx.off < len(d.ctx.data) || d.ctx.nibbleSecondValid || d.ctx.processState == stmStateSendPkt
}

func (d *stmDecoder) outputPacket() error {
	d.ctx.currPacket.Index = d.ctx.packetIdx
	if d.PacketObserver != nil && len(d.ctx.packetData) > 0 {
		d.EmitPacket(d.ctx.packetIdx, &d.ctx.currPacket, d.ctx.packetData)
	}

	err := d.processPacket(&d.ctx.currPacket)
	d.initNextPacket()
	if d.ctx.nibbleSecondValid {
		d.savePacketByte(d.ctx.nibbleSecond << 4)
	}
	if d.ctx.streamSync {
		d.ctx.processState = stmStateProcHdr
	} else {
		d.ctx.processState = stmStateWaitSync
	}
	return err
}

func (d *stmDecoder) initNextPacket() {
	d.ctx.needsTS = false
	d.ctx.isMarker = false
	d.ctx.numNibbles = 0
	d.ctx.numDataNibbles = 0
	d.ctx.currPacket.InitNextPacket()
	d.ctx.packetData = d.ctx.packetData[:0]
	d.ctx.val8 = 0
	d.ctx.val16 = 0
	d.ctx.val32 = 0
	d.ctx.val64 = 0
}

func (d *stmDecoder) sendPacket() {
	d.ctx.processState = stmStateSendPkt
}

func (d *stmDecoder) readNibble() bool {
	if d.ctx.nibbleSecondValid {
		d.ctx.nibble = d.ctx.nibbleSecond
		d.ctx.nibbleSecondValid = false
		d.ctx.nibbleHigh = true
		d.ctx.numNibbles++
		d.checkSyncNibble()
		return true
	}
	if d.ctx.off >= len(d.ctx.data) {
		return false
	}
	b := d.ctx.data[d.ctx.off]
	d.ctx.off++
	d.savePacketByte(b)
	d.ctx.nibbleSecond = (b >> 4) & 0xF
	d.ctx.nibbleSecondValid = true
	d.ctx.nibble = b & 0xF
	d.ctx.nibbleHigh = false
	d.ctx.numNibbles++
	d.checkSyncNibble()
	return true
}

func (d *stmDecoder) savePacketByte(b byte) {
	d.ctx.packetData = append(d.ctx.packetData, b)
}

func (d *stmDecoder) checkSyncNibble() {
	if d.ctx.nibble == 0xF {
		if !d.ctx.syncStart {
			d.ctx.syncIndex = d.ctx.blockBase + Index(d.ctx.off-1)
			d.ctx.syncHigh = d.ctx.nibbleHigh
			d.ctx.syncLow0 = d.ctx.nibbleHigh && d.ctx.off > 0 && (d.ctx.data[d.ctx.off-1]&0x0F) == 0
		}
		d.ctx.syncStart = true
		d.ctx.numFNibs++
		return
	}
	if d.ctx.syncStart && d.ctx.numFNibs >= 21 && d.ctx.nibble == 0x0 {
		d.ctx.isSync = true
		d.ctx.numFNibs = 21 // cap at 21 — matches C++ "lose any extra as unsynced data"
		return
	}
	d.clearSyncCount()
}

func (d *stmDecoder) clearSyncCount() {
	d.ctx.isSync = false
	d.ctx.syncStart = false
	d.ctx.syncHigh = false
	d.ctx.syncLow0 = false
	d.ctx.numFNibs = 0
}

func (d *stmDecoder) waitForSync(blockStart Index) {
	bSyncOnEntry := d.ctx.isSync
	d.ctx.packetIdx = blockStart + Index(d.ctx.off)
	d.ctx.numNibbles = d.ctx.numFNibs
	if d.ctx.isSync {
		d.ctx.numNibbles++
	}

	for !d.ctx.isSync && d.readNibble() {
	}

	if d.ctx.numNibbles == 0 {
		return
	}

	bPreAmbleAndSync := d.ctx.isSync && d.ctx.numNibbles > 22
	if bPreAmbleAndSync {
		if len(d.ctx.packetData) >= 11 {
			d.ctx.packetData = d.ctx.packetData[:len(d.ctx.packetData)-11]
		}
	}

	if !d.ctx.isSync || bPreAmbleAndSync {
		d.ctx.currPacket.SetType(stmPktNotSync, false)
	} else {
		d.ctx.currPacket.SetType(stmPktAsync, false)
		d.ctx.streamSync = true
		d.clearSyncCount()
		d.ctx.packetIdx = d.ctx.syncIndex
		if bSyncOnEntry {
			for range 10 {
				d.ctx.packetData = append(d.ctx.packetData, 0xFF)
			}
			d.ctx.packetData = append(d.ctx.packetData, 0x0F)
		}
	}
	d.sendPacket()
}

func (d *stmDecoder) throwBadSequenceError(msg string) error {
	d.ctx.currPacket.UpdateErrType(stmPktBadSequence)
	return fmt.Errorf("%w: %s", errBadPacketSeq, msg)
}

func (d *stmDecoder) throwReservedHdrError(msg string) error {
	d.ctx.currPacket.SetType(stmPktReserved, false)
	return fmt.Errorf("%w: %s", errInvalidPcktHdr, msg)
}

func (d *stmDecoder) op1(n uint8) pktFn {
	switch n {
	case 0x0:
		return (*stmDecoder).stmPktNull
	case 0x1:
		return (*stmDecoder).stmPktM8
	case 0x2:
		return (*stmDecoder).stmPktMERR
	case 0x3:
		return (*stmDecoder).stmPktC8
	case 0x4:
		return (*stmDecoder).stmPktD8
	case 0x5:
		return (*stmDecoder).stmPktD16
	case 0x6:
		return (*stmDecoder).stmPktD32
	case 0x7:
		return (*stmDecoder).stmPktD64
	case 0x8:
		return (*stmDecoder).stmPktD8MTS
	case 0x9:
		return (*stmDecoder).stmPktD16MTS
	case 0xA:
		return (*stmDecoder).stmPktD32MTS
	case 0xB:
		return (*stmDecoder).stmPktD64MTS
	case 0xC:
		return (*stmDecoder).stmPktD4
	case 0xD:
		return (*stmDecoder).stmPktD4MTS
	case 0xE:
		return (*stmDecoder).stmPktFlagTS
	case 0xF:
		return (*stmDecoder).stmPktFExt
	default:
		return (*stmDecoder).stmPktReserved
	}
}

func (d *stmDecoder) op2(n uint8) pktFn {
	switch n {
	case 0x0:
		return (*stmDecoder).stmPktF0Ext
	case 0x2:
		return (*stmDecoder).stmPktGERR
	case 0x3:
		return (*stmDecoder).stmPktC16
	case 0x4:
		return (*stmDecoder).stmPktD8TS
	case 0x5:
		return (*stmDecoder).stmPktD16TS
	case 0x6:
		return (*stmDecoder).stmPktD32TS
	case 0x7:
		return (*stmDecoder).stmPktD64TS
	case 0x8:
		return (*stmDecoder).stmPktD8M
	case 0x9:
		return (*stmDecoder).stmPktD16M
	case 0xA:
		return (*stmDecoder).stmPktD32M
	case 0xB:
		return (*stmDecoder).stmPktD64M
	case 0xC:
		return (*stmDecoder).stmPktD4TS
	case 0xD:
		return (*stmDecoder).stmPktD4M
	case 0xE:
		return (*stmDecoder).stmPktFlag
	case 0xF:
		return (*stmDecoder).stmPktASync
	default:
		return (*stmDecoder).stmPktReservedFn
	}
}

func (d *stmDecoder) op3(n uint8) pktFn {
	switch n {
	case 0x0:
		return (*stmDecoder).stmPktVersion
	case 0x1:
		return (*stmDecoder).stmPktNullTS
	case 0x6:
		return (*stmDecoder).stmPktTrigger
	case 0x7:
		return (*stmDecoder).stmPktTriggerTS
	case 0x8:
		return (*stmDecoder).stmPktFreq
	default:
		return (*stmDecoder).stmPktReservedF0n
	}
}

func (d *stmDecoder) pktNeedsTS() {
	d.ctx.needsTS = true
	d.ctx.reqTSNibbles = 0
	d.ctx.currTSNibbles = 0
	d.ctx.tsUpdateValue = 0
	d.ctx.tsReqSet = false
}

func (d *stmDecoder) extractVal8(nibbles uint8) {
	for d.ctx.numNibbles < nibbles && d.readNibble() {
		d.ctx.val8 = (d.ctx.val8 << 4) | d.ctx.nibble
	}
}

func (d *stmDecoder) extractVal16(nibbles uint8) {
	for d.ctx.numNibbles < nibbles && d.readNibble() {
		d.ctx.val16 = (d.ctx.val16 << 4) | uint16(d.ctx.nibble)
	}
}

func (d *stmDecoder) extractVal32(nibbles uint8) {
	for d.ctx.numNibbles < nibbles && d.readNibble() {
		d.ctx.val32 = (d.ctx.val32 << 4) | uint32(d.ctx.nibble)
	}
}

func (d *stmDecoder) extractVal64(nibbles uint8) {
	for d.ctx.numNibbles < nibbles && d.readNibble() {
		d.ctx.val64 = (d.ctx.val64 << 4) | uint64(d.ctx.nibble)
	}
}

func (d *stmDecoder) stmExtractTS() error {
	if !d.ctx.tsReqSet {
		if !d.readNibble() {
			return nil
		}
		d.ctx.reqTSNibbles = d.ctx.nibble
		switch d.ctx.nibble {
		case 0xD:
			d.ctx.reqTSNibbles = 14
		case 0xE:
			d.ctx.reqTSNibbles = 16
		case 0xF:
			return d.throwBadSequenceError("STM: Invalid timestamp size 0xF")
		}
		d.ctx.tsReqSet = true
	}
	for d.ctx.currTSNibbles < d.ctx.reqTSNibbles && d.readNibble() {
		d.ctx.tsUpdateValue = (d.ctx.tsUpdateValue << 4) | uint64(d.ctx.nibble)
		d.ctx.currTSNibbles++
	}
	if d.ctx.currTSNibbles != d.ctx.reqTSNibbles {
		return nil
	}
	newBits := d.ctx.reqTSNibbles * 4
	switch d.ctx.currPacket.TSType {
	case tsGrey:
		gray := binToGray(d.ctx.currPacket.Timestamp)
		if newBits == 64 {
			gray = d.ctx.tsUpdateValue
		} else {
			mask := bitMask(int(newBits))
			gray &= ^mask
			gray |= d.ctx.tsUpdateValue & mask
		}
		d.ctx.currPacket.SetTimestamp(grayToBin(gray), newBits)
	case tsNatBinary:
		d.ctx.currPacket.SetTimestamp(d.ctx.tsUpdateValue, newBits)
	default:
		return d.throwBadSequenceError("STM: unknown timestamp encoding")
	}
	d.ctx.currPacket.TSUpdate = d.ctx.tsUpdateValue
	d.sendPacket()
	return nil
}

func binToGray(bin uint64) uint64 {
	return bin ^ (bin >> 1)
}

func grayToBin(gray uint64) uint64 {
	var bin uint64
	for ; gray != 0; gray >>= 1 {
		bin ^= gray
	}
	return bin
}
