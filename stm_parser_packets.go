package coresight

func (d *stmDecoder) stmPktReserved() error {
	d.ctx.currPacket.Payload = uint64(d.ctx.nibble)
	return d.throwReservedHdrError("STM: Unsupported or Reserved STPv2 Header")
}

func (d *stmDecoder) stmPktNull() error {
	d.ctx.currPacket.SetType(PktNull, false)
	if d.ctx.needsTS {
		d.ctx.currFn = (*stmDecoder).stmExtractTS
		return d.stmExtractTS()
	}
	d.sendPacket()
	return nil
}

func (d *stmDecoder) stmPktNullTS() error {
	d.pktNeedsTS()
	d.ctx.currFn = (*stmDecoder).stmPktNull
	return d.stmPktNull()
}

func (d *stmDecoder) stmPktM8() error {
	if d.ctx.numNibbles == 1 {
		d.ctx.currPacket.SetType(PktM8, false)
	}
	d.extractVal8(3)
	if d.ctx.numNibbles == 3 {
		d.ctx.currPacket.SetMaster(d.ctx.val8)
		d.sendPacket()
	}
	return nil
}

func (d *stmDecoder) stmPktMERR() error {
	if d.ctx.numNibbles == 1 {
		d.ctx.currPacket.SetType(PktMerr, false)
	}
	d.extractVal8(3)
	if d.ctx.numNibbles == 3 {
		d.ctx.currPacket.SetChannel(0, false)
		d.ctx.currPacket.Payload = uint64(d.ctx.val8)
		d.sendPacket()
	}
	return nil
}

func (d *stmDecoder) stmPktC8() error {
	if d.ctx.numNibbles == 1 {
		d.ctx.currPacket.SetType(PktC8, false)
	}
	d.extractVal8(3)
	if d.ctx.numNibbles == 3 {
		d.ctx.currPacket.SetChannel(uint16(d.ctx.val8), true)
		d.sendPacket()
	}
	return nil
}

func (d *stmDecoder) stmPktD4() error {
	if d.ctx.numNibbles == 1 {
		d.ctx.currPacket.SetType(PktD4, d.ctx.isMarker)
		d.ctx.numDataNibbles = 2
	}
	if d.ctx.numNibbles != d.ctx.numDataNibbles && d.readNibble() {
		d.ctx.currPacket.Payload = uint64(d.ctx.nibble & 0xF)
		if d.ctx.needsTS {
			d.ctx.currFn = (*stmDecoder).stmExtractTS
			return d.stmExtractTS()
		}
		d.sendPacket()
	}
	return nil
}

func (d *stmDecoder) stmPktD8() error {
	if d.ctx.numNibbles == 1 {
		d.ctx.currPacket.SetType(PktD8, d.ctx.isMarker)
		d.ctx.numDataNibbles = 3
	}
	d.extractVal8(d.ctx.numDataNibbles)
	if d.ctx.numNibbles == d.ctx.numDataNibbles {
		d.ctx.currPacket.Payload = uint64(d.ctx.val8)
		if d.ctx.needsTS {
			d.ctx.currFn = (*stmDecoder).stmExtractTS
			return d.stmExtractTS()
		}
		d.sendPacket()
	}
	return nil
}

func (d *stmDecoder) stmPktD16() error {
	if d.ctx.numNibbles == 1 {
		d.ctx.currPacket.SetType(PktD16, d.ctx.isMarker)
		d.ctx.numDataNibbles = 5
	}
	d.extractVal16(d.ctx.numDataNibbles)
	if d.ctx.numNibbles == d.ctx.numDataNibbles {
		d.ctx.currPacket.Payload = uint64(d.ctx.val16)
		if d.ctx.needsTS {
			d.ctx.currFn = (*stmDecoder).stmExtractTS
			return d.stmExtractTS()
		}
		d.sendPacket()
	}
	return nil
}

func (d *stmDecoder) stmPktD32() error {
	if d.ctx.numNibbles == 1 {
		d.ctx.currPacket.SetType(PktD32, d.ctx.isMarker)
		d.ctx.numDataNibbles = 9
	}
	d.extractVal32(d.ctx.numDataNibbles)
	if d.ctx.numNibbles == d.ctx.numDataNibbles {
		d.ctx.currPacket.Payload = uint64(d.ctx.val32)
		if d.ctx.needsTS {
			d.ctx.currFn = (*stmDecoder).stmExtractTS
			return d.stmExtractTS()
		}
		d.sendPacket()
	}
	return nil
}

func (d *stmDecoder) stmPktD64() error {
	if d.ctx.numNibbles == 1 {
		d.ctx.currPacket.SetType(PktD64, d.ctx.isMarker)
		d.ctx.numDataNibbles = 17
	}
	d.extractVal64(d.ctx.numDataNibbles)
	if d.ctx.numNibbles == d.ctx.numDataNibbles {
		d.ctx.currPacket.Payload = d.ctx.val64
		if d.ctx.needsTS {
			d.ctx.currFn = (*stmDecoder).stmExtractTS
			return d.stmExtractTS()
		}
		d.sendPacket()
	}
	return nil
}

func (d *stmDecoder) stmPktD4MTS() error {
	d.pktNeedsTS()
	d.ctx.isMarker = true
	d.ctx.currFn = (*stmDecoder).stmPktD4
	return d.stmPktD4()
}
func (d *stmDecoder) stmPktD8MTS() error {
	d.pktNeedsTS()
	d.ctx.isMarker = true
	d.ctx.currFn = (*stmDecoder).stmPktD8
	return d.stmPktD8()
}
func (d *stmDecoder) stmPktD16MTS() error {
	d.pktNeedsTS()
	d.ctx.isMarker = true
	d.ctx.currFn = (*stmDecoder).stmPktD16
	return d.stmPktD16()
}
func (d *stmDecoder) stmPktD32MTS() error {
	d.pktNeedsTS()
	d.ctx.isMarker = true
	d.ctx.currFn = (*stmDecoder).stmPktD32
	return d.stmPktD32()
}
func (d *stmDecoder) stmPktD64MTS() error {
	d.pktNeedsTS()
	d.ctx.isMarker = true
	d.ctx.currFn = (*stmDecoder).stmPktD64
	return d.stmPktD64()
}

func (d *stmDecoder) stmPktFlagTS() error {
	d.pktNeedsTS()
	d.ctx.currPacket.SetType(PktFlag, false)
	d.ctx.currFn = (*stmDecoder).stmExtractTS
	return d.stmExtractTS()
}

func (d *stmDecoder) stmPktFExt() error {
	if d.readNibble() {
		d.ctx.currFn = d.op2(d.ctx.nibble)
		return d.ctx.currFn(d)
	}
	return nil
}

func (d *stmDecoder) stmPktReservedFn() error {
	d.ctx.currPacket.Payload = uint64(0x00F | (uint16(d.ctx.nibble) << 4))
	return d.throwReservedHdrError("STM: Unsupported or Reserved STPv2 Header")
}

func (d *stmDecoder) stmPktF0Ext() error {
	if d.readNibble() {
		d.ctx.currFn = d.op3(d.ctx.nibble)
		return d.ctx.currFn(d)
	}
	return nil
}

func (d *stmDecoder) stmPktGERR() error {
	if d.ctx.numNibbles == 2 {
		d.ctx.currPacket.SetType(PktGerr, false)
	}
	d.extractVal8(4)
	if d.ctx.numNibbles == 4 {
		d.ctx.currPacket.Payload = uint64(d.ctx.val8)
		d.ctx.currPacket.SetMaster(0)
		d.sendPacket()
	}
	return nil
}

func (d *stmDecoder) stmPktC16() error {
	if d.ctx.numNibbles == 2 {
		d.ctx.currPacket.SetType(PktC16, false)
	}
	d.extractVal16(6)
	if d.ctx.numNibbles == 6 {
		d.ctx.currPacket.SetChannel(d.ctx.val16, false)
		d.sendPacket()
	}
	return nil
}

func (d *stmDecoder) stmPktD4TS() error {
	d.pktNeedsTS()
	d.ctx.currPacket.SetType(PktD4, false)
	d.ctx.numDataNibbles = 3
	d.ctx.currFn = (*stmDecoder).stmPktD4
	return d.stmPktD4()
}
func (d *stmDecoder) stmPktD8TS() error {
	d.pktNeedsTS()
	d.ctx.currPacket.SetType(PktD8, false)
	d.ctx.numDataNibbles = 4
	d.ctx.currFn = (*stmDecoder).stmPktD8
	return d.stmPktD8()
}
func (d *stmDecoder) stmPktD16TS() error {
	d.pktNeedsTS()
	d.ctx.currPacket.SetType(PktD16, false)
	d.ctx.numDataNibbles = 6
	d.ctx.currFn = (*stmDecoder).stmPktD16
	return d.stmPktD16()
}
func (d *stmDecoder) stmPktD32TS() error {
	d.pktNeedsTS()
	d.ctx.currPacket.SetType(PktD32, false)
	d.ctx.numDataNibbles = 10
	d.ctx.currFn = (*stmDecoder).stmPktD32
	return d.stmPktD32()
}
func (d *stmDecoder) stmPktD64TS() error {
	d.pktNeedsTS()
	d.ctx.currPacket.SetType(PktD64, false)
	d.ctx.numDataNibbles = 18
	d.ctx.currFn = (*stmDecoder).stmPktD64
	return d.stmPktD64()
}

func (d *stmDecoder) stmPktD4M() error {
	d.ctx.currPacket.SetType(PktD4, true)
	d.ctx.numDataNibbles = 3
	d.ctx.currFn = (*stmDecoder).stmPktD4
	return d.stmPktD4()
}
func (d *stmDecoder) stmPktD8M() error {
	d.ctx.currPacket.SetType(PktD8, true)
	d.ctx.numDataNibbles = 4
	d.ctx.currFn = (*stmDecoder).stmPktD8
	return d.stmPktD8()
}
func (d *stmDecoder) stmPktD16M() error {
	d.ctx.currPacket.SetType(PktD16, true)
	d.ctx.numDataNibbles = 6
	d.ctx.currFn = (*stmDecoder).stmPktD16
	return d.stmPktD16()
}
func (d *stmDecoder) stmPktD32M() error {
	d.ctx.currPacket.SetType(PktD32, true)
	d.ctx.numDataNibbles = 10
	d.ctx.currFn = (*stmDecoder).stmPktD32
	return d.stmPktD32()
}
func (d *stmDecoder) stmPktD64M() error {
	d.ctx.currPacket.SetType(PktD64, true)
	d.ctx.numDataNibbles = 18
	d.ctx.currFn = (*stmDecoder).stmPktD64
	return d.stmPktD64()
}

func (d *stmDecoder) stmPktFlag() error {
	d.ctx.currPacket.SetType(PktFlag, false)
	d.sendPacket()
	return nil
}

func (d *stmDecoder) stmPktReservedF0n() error {
	d.ctx.currPacket.Payload = uint64(0x00F | (uint16(d.ctx.nibble) << 8))
	return d.throwReservedHdrError("STM: Unsupported or Reserved STPv2 Header")
}

func (d *stmDecoder) stmPktVersion() error {
	if d.ctx.numNibbles == 3 {
		d.ctx.currPacket.SetType(PktVersion, false)
	}
	if d.readNibble() {
		d.ctx.currPacket.Payload = uint64(d.ctx.nibble)
		switch d.ctx.nibble {
		case 3:
			d.ctx.currPacket.OnVersionPkt(tsNatBinary)
		case 4:
			d.ctx.currPacket.OnVersionPkt(tsGrey)
		default:
			return d.throwBadSequenceError("STM VERSION packet : unrecognised version number.")
		}
		d.sendPacket()
	}
	return nil
}

func (d *stmDecoder) stmPktTrigger() error {
	if d.ctx.numNibbles == 3 {
		d.ctx.currPacket.SetType(PktTrig, false)
	}
	d.extractVal8(5)
	if d.ctx.numNibbles == 5 {
		d.ctx.currPacket.Payload = uint64(d.ctx.val8)
		if d.ctx.needsTS {
			d.ctx.currFn = (*stmDecoder).stmExtractTS
			return d.stmExtractTS()
		}
		d.sendPacket()
	}
	return nil
}

func (d *stmDecoder) stmPktTriggerTS() error {
	d.pktNeedsTS()
	d.ctx.currFn = (*stmDecoder).stmPktTrigger
	return d.stmPktTrigger()
}

func (d *stmDecoder) stmPktFreq() error {
	if d.ctx.numNibbles == 3 {
		d.ctx.currPacket.SetType(PktFreq, false)
		d.ctx.val32 = 0
	}
	d.extractVal32(11)
	if d.ctx.numNibbles == 11 {
		d.ctx.currPacket.Payload = uint64(d.ctx.val32)
		d.sendPacket()
	}
	return nil
}

func (d *stmDecoder) stmPktASync() error {
	for d.readNibble() {
		if d.ctx.isSync {
			d.ctx.streamSync = true
			d.ctx.currPacket.SetType(stmPktAsync, false)
			d.clearSyncCount()
			d.sendPacket()
			return nil
		}
		if !d.ctx.syncStart {
			return d.throwBadSequenceError("STM: Invalid ASYNC sequence")
		}
	}
	return nil
}
