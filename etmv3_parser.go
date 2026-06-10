package coresight

import (
	"errors"
	"fmt"

)

type etmv3ProcessState int

const (
	etmv3StateWaitSync etmv3ProcessState = iota
	etmv3StateProcHdr
	etmv3StateProcData
	etmv3StateSendPkt
	etmv3StateProcErr
)

type etmv3PacketHandler func(*etmv3Decoder) error

var etmv3Handlers = [32]etmv3PacketHandler{
	PktBranchAddress:  (*etmv3Decoder).pktBranchAddress,
	PktASync:          (*etmv3Decoder).pktASync,
	PktCycleCount:     (*etmv3Decoder).pktCycleCount,
	PktISync:          (*etmv3Decoder).pktISync,
	PktISyncCycle:     (*etmv3Decoder).pktISync,
	PktTrigger:        (*etmv3Decoder).pktTrigger,
	PktPHdr:           (*etmv3Decoder).pktPHdr,
	PktContextID:      (*etmv3Decoder).pktContextID,
	PktVMID:           (*etmv3Decoder).pktVMID,
	PktTimestamp:      (*etmv3Decoder).pktTimestamp,
	PktExceptionEntry: (*etmv3Decoder).pktExceptionEntry,
	PktExceptionExit:  (*etmv3Decoder).pktExceptionExit,
	PktIgnore:         (*etmv3Decoder).pktIgnore,
	PktReserved:       (*etmv3Decoder).pktReserved,
}

type etmv3ParseContext struct {
	internalByteStream

	processState    etmv3ProcessState
	procErrReason   error
	currPacket      etmv3Packet
	currPacketIndex Index

	waitASyncSOPacket bool
	bAsyncRawOp       bool
	unsyncedRaw       []byte

	bytesExpected int
	branchNeedsEx bool
	isyncGotCC    bool
	isyncGetLSiP  bool
	isyncInfoIdx  int
}

func (d *etmv3Decoder) readNextByte() (uint8, bool) {
	b, err := d.ctx.ReadByte()
	return b, err == nil
}

func (d *etmv3Decoder) resetPacketState() {
	d.ctx.currPacket.Clear()
	d.ctx.EnsureReader()
	d.ctx.Reader.Reset()
	d.ctx.bytesExpected = 0
	d.ctx.branchNeedsEx = false
	d.ctx.isyncGotCC = false
	d.ctx.isyncGetLSiP = false
	d.ctx.isyncInfoIdx = 0
}

func (d *etmv3Decoder) throwMalformedPacketErr(msg string) error {
	d.ctx.processState = etmv3StateProcErr
	d.ctx.currPacket.Err = errBadPacketSeq
	d.ctx.procErrReason = fmt.Errorf("%w: %s", errBadPacketSeq, msg)
	return d.ctx.procErrReason
}

func (d *etmv3Decoder) processData(index Index, dataBlock []uint8) (uint32, error) {
	d.ctx.Feed(index, dataBlock)

	var err error

	for d.ctx.Reader.Len() > 0 || d.ctx.processState == etmv3StateSendPkt {
		switch d.ctx.processState {
		case etmv3StateWaitSync:
			if !d.ctx.waitASyncSOPacket {
				d.ctx.currPacketIndex = d.ctx.CurrentIndex()
				d.ctx.currPacket.Type = PktNotSync
				d.ctx.bAsyncRawOp = d.PacketObserver != nil
			}
			err = d.waitASync()

		case etmv3StateProcHdr:
			d.ctx.currPacketIndex = d.ctx.CurrentIndex()
			if currByte, ok := d.readNextByte(); ok {
				d.decodeHeaderByte(currByte)
			} else {
				err = fmt.Errorf("%w: Data Buffer Overrun", errPktInterpFail)
			}

		case etmv3StateProcData:
			if int(d.ctx.currPacket.Type) < len(etmv3Handlers) && etmv3Handlers[d.ctx.currPacket.Type] != nil {
				err = etmv3Handlers[d.ctx.currPacket.Type](d)
			} else {
				err = d.pktReserved()
			}

		case etmv3StateSendPkt:
			err = d.outputPacket()
			d.resetPacketState()
			d.ctx.processState = etmv3StateProcHdr

		case etmv3StateProcErr:
			err = d.ctx.procErrReason
			if err == nil {
				err = errPktInterpFail
			}
		}

		if err != nil {
			if errors.Is(err, errBadPacketSeq) || errors.Is(err, errInvalidPcktHdr) || errors.Is(err, errHWCfgUnsupp) {
				d.ctx.processState = etmv3StateSendPkt
				err = nil
			} else {
				break
			}
		}
	}

	return uint32(d.ctx.BytesConsumed()), err
}

func (d *etmv3Decoder) outputPacket() error {
	d.ctx.currPacket.Index = d.ctx.currPacketIndex
	scratch := d.ctx.Reader.Scratch()

	d.EmitPacket(d.ctx.currPacketIndex, &d.ctx.currPacket, scratch)

	err := d.processPacket(&d.ctx.currPacket)
	d.ctx.Reader.Reset()
	return err
}

func (d *etmv3Decoder) waitASync() error {
	bSendBlock := false

	for d.ctx.Reader.Len() > 0 && !bSendBlock {
		if len(d.ctx.unsyncedRaw) == 0 {
			d.ctx.currPacketIndex = d.ctx.CurrentIndex()
		}
		currByte, _ := d.ctx.Reader.ReadByte()

		if d.ctx.waitASyncSOPacket {
			d.ctx.unsyncedRaw = append(d.ctx.unsyncedRaw, currByte)
			if currByte == 0x80 && len(d.ctx.unsyncedRaw) >= 6 {
				bSendBlock = true
				if len(d.ctx.unsyncedRaw) > 6 {
					d.ctx.unsyncedRaw = d.ctx.unsyncedRaw[:len(d.ctx.unsyncedRaw)-1]
					d.ctx.Reader.UnreadByte()

					sendLen := len(d.ctx.unsyncedRaw) - 5
					d.ctx.currPacket.Type = PktNotSync
					d.ctx.currPacket.Index = d.ctx.currPacketIndex

					if d.ctx.bAsyncRawOp {
						d.EmitPacket(d.ctx.currPacketIndex, &d.ctx.currPacket, d.ctx.unsyncedRaw[:sendLen])
					}
					_ = d.processPacket(&d.ctx.currPacket)

					d.ctx.currPacketIndex += Index(sendLen)
					d.ctx.Reader.Reset()

					rem := make([]byte, 5)
					copy(rem, d.ctx.unsyncedRaw[sendLen:])
					d.ctx.unsyncedRaw = rem
					bSendBlock = false
				} else {
					d.ctx.currPacket.Type = PktASync
				}
			} else if currByte != 0x00 {
				d.ctx.waitASyncSOPacket = false
			} else if len(d.ctx.unsyncedRaw) >= 13 {
				d.ctx.currPacket.Type = PktNotSync
				d.ctx.currPacket.Index = d.ctx.currPacketIndex

				if d.ctx.bAsyncRawOp {
					d.EmitPacket(d.ctx.currPacketIndex, &d.ctx.currPacket, d.ctx.unsyncedRaw[:8])
				}
				_ = d.processPacket(&d.ctx.currPacket)

				d.ctx.currPacketIndex += 8
				d.ctx.Reader.Reset()

				rem := make([]byte, len(d.ctx.unsyncedRaw)-8)
				copy(rem, d.ctx.unsyncedRaw[8:])
				d.ctx.unsyncedRaw = rem
				bSendBlock = false
			}
		} else {
			if currByte == 0x00 {
				if len(d.ctx.unsyncedRaw) == 0 {
					d.ctx.unsyncedRaw = append(d.ctx.unsyncedRaw, currByte)
					d.ctx.waitASyncSOPacket = true
				} else {
					d.ctx.Reader.UnreadByte()
					bSendBlock = true
					d.ctx.currPacket.Type = PktNotSync
				}
			} else {
				d.ctx.unsyncedRaw = append(d.ctx.unsyncedRaw, currByte)
				if d.ctx.Reader.Len() == 0 || len(d.ctx.unsyncedRaw) == 16 {
					bSendBlock = true
					d.ctx.currPacket.Type = PktNotSync
				}
			}
		}
	}

	if bSendBlock {
		d.ctx.currPacket.Index = d.ctx.currPacketIndex
		if d.ctx.bAsyncRawOp {
			d.EmitPacket(d.ctx.currPacketIndex, &d.ctx.currPacket, d.ctx.unsyncedRaw)
		}
		_ = d.processPacket(&d.ctx.currPacket)

		if d.ctx.currPacket.Type == PktASync {
			d.ctx.processState = etmv3StateProcHdr
		} else {
			d.ctx.processState = etmv3StateWaitSync
		}

		d.ctx.unsyncedRaw = nil
		d.ctx.Reader.Reset()
	}
	return nil
}

func (d *etmv3Decoder) decodeHeaderByte(by uint8) {
	d.ctx.processState = etmv3StateProcData

	if (by & 0x01) == 0x01 {
		d.ctx.currPacket.Type = PktBranchAddress
		d.ctx.branchNeedsEx = false
		if (by & 0x80) != 0x80 {
			d.onBranchAddress()
			if d.ctx.processState != etmv3StateProcErr {
				d.ctx.processState = etmv3StateSendPkt
			}
		}
	} else if (by & 0x81) == 0x80 {
		d.ctx.currPacket.Type = PktPHdr
		if d.ctx.currPacket.UpdateAtomFromPHdr(by, d.Config.CycleAcc()) {
			d.ctx.processState = etmv3StateSendPkt
		} else {
			d.throwMalformedPacketErr("Invalid P-Header.")
		}
	} else if (by & 0xF3) == 0x00 {
		switch by {
		case 0x00:
			d.ctx.currPacket.Type = PktASync
		case 0x04:
			d.ctx.currPacket.Type = PktCycleCount
		case 0x08:
			d.ctx.currPacket.Type = PktISync
		case 0x0C:
			d.ctx.currPacket.Type = PktTrigger
			d.ctx.processState = etmv3StateSendPkt
		}
	} else if (by & 0x03) == 0x00 {
		if (by & 0x93) == 0x00 {
			d.ctx.currPacket.Type = PktOOOData
			d.ctx.currPacket.Err = errHWCfgUnsupp
			d.ctx.processState = etmv3StateSendPkt
		} else if by == 0x70 {
			d.ctx.currPacket.Type = PktISyncCycle
		} else if by == 0x50 {
			d.ctx.currPacket.Type = PktStoreFail
			d.ctx.currPacket.Err = errHWCfgUnsupp
			d.ctx.processState = etmv3StateSendPkt
		} else if (by & 0xD3) == 0x50 {
			d.ctx.currPacket.Type = PktOOOAddrPlc
			d.ctx.currPacket.Err = errHWCfgUnsupp
			d.ctx.processState = etmv3StateSendPkt
		} else if by == 0x3C {
			d.ctx.currPacket.Type = PktVMID
		} else {
			d.ctx.currPacket.Err = errInvalidPcktHdr
			d.ctx.processState = etmv3StateSendPkt
		}
	} else if (by & 0xD3) == 0x02 {
		d.ctx.currPacket.Type = PktNormData
		d.ctx.currPacket.Err = errHWCfgUnsupp
		d.ctx.processState = etmv3StateSendPkt
	} else if by == 0x62 {
		d.ctx.currPacket.Type = PktDataSuppressed
		d.ctx.currPacket.Err = errHWCfgUnsupp
		d.ctx.processState = etmv3StateSendPkt
	} else if (by & 0xEF) == 0x6A {
		d.ctx.currPacket.Type = PktValNotTraced
		d.ctx.currPacket.Err = errHWCfgUnsupp
		d.ctx.processState = etmv3StateSendPkt
	} else if by == 0x66 {
		d.ctx.currPacket.Type = PktIgnore
		d.ctx.processState = etmv3StateSendPkt
	} else if by == 0x6E {
		d.ctx.currPacket.Type = PktContextID
		d.ctx.bytesExpected = 1 + d.Config.CtxtIDBytes()
	} else if by == 0x76 {
		d.ctx.currPacket.Type = PktExceptionExit
		d.ctx.processState = etmv3StateSendPkt
	} else if by == 0x7E {
		d.ctx.currPacket.Type = PktExceptionEntry
		d.ctx.processState = etmv3StateSendPkt
	} else if (by & 0xFB) == 0x42 {
		d.ctx.currPacket.Type = PktTimestamp
	} else {
		d.ctx.currPacket.Err = errInvalidPcktHdr
		d.ctx.processState = etmv3StateSendPkt
	}
}

func (d *etmv3Decoder) pktBranchAddress() error {
	for {
		currByte, ok := d.readNextByte()
		if !ok {
			return nil
		}

		bTopBitSet := (currByte & 0x80) != 0
		packetDone := false
		scratchLen := len(d.ctx.Reader.Scratch())

		if d.Config.AltBranch() {
			if !bTopBitSet {
				if !d.ctx.branchNeedsEx {
					if (currByte & 0xC0) == 0x40 {
						d.ctx.branchNeedsEx = true
					} else {
						packetDone = true
					}
				} else {
					packetDone = true
				}
			}
		} else {
			// Branch exception presence flag must be evaluated on the 5th byte read.
			// scratchLen includes the 1 header byte + 4 payload bytes, making it exactly 5.
			if scratchLen == 5 {
				if (currByte & 0xC0) == 0x40 {
					d.ctx.branchNeedsEx = true
				} else {
					packetDone = true
				}
			} else if d.ctx.branchNeedsEx {
				if !bTopBitSet {
					packetDone = true
				}
			} else {
				if !bTopBitSet {
					packetDone = true
				}
			}
		}

		if packetDone {
			d.onBranchAddress()
			if d.ctx.processState != etmv3StateProcErr {
				d.ctx.processState = etmv3StateSendPkt
			}
			return d.ctx.procErrReason
		}
	}
}

func (d *etmv3Decoder) pktISync() error {
	scratch := d.ctx.Reader.Scratch()

	if d.ctx.currPacket.Type == PktISyncCycle && !d.ctx.isyncGotCC {
		for {
			currByte, ok := d.readNextByte()
			if !ok {
				return nil
			}
			if (currByte&0x80) == 0 || len(d.ctx.Reader.Scratch()) >= 6 {
				d.ctx.isyncGotCC = true
				scratch = d.ctx.Reader.Scratch()
				break
			}
		}
	}

	if d.ctx.bytesExpected == 0 {
		cycCountBytes := len(scratch) - 1
		if d.ctx.currPacket.Type == PktISync {
			cycCountBytes = 0
		}
		ctxtIDBytes := d.Config.CtxtIDBytes()

		if d.Config.InstrTrace() {
			d.ctx.bytesExpected = 1 + cycCountBytes + 5 + ctxtIDBytes // hdr + CC + info + addr[4] + ctxt
		} else {
			d.ctx.bytesExpected = 1 + cycCountBytes + 1 + ctxtIDBytes // hdr + CC + info + ctxt
		}
		d.ctx.isyncInfoIdx = 1 + cycCountBytes + ctxtIDBytes
	}

	for len(d.ctx.Reader.Scratch()) < d.ctx.bytesExpected {
		_, ok := d.readNextByte()
		if !ok {
			return nil
		}
	}
	scratch = d.ctx.Reader.Scratch()

	d.ctx.isyncGetLSiP = (scratch[d.ctx.isyncInfoIdx] & 0x80) != 0
	if d.ctx.isyncGetLSiP {
		for {
			currByte, ok := d.readNextByte()
			if !ok {
				return nil
			}
			if (currByte & 0x80) == 0 {
				break
			}
		}
	}

	d.onISyncPacket()
	if d.ctx.processState != etmv3StateProcErr {
		d.ctx.processState = etmv3StateSendPkt
	}
	return d.ctx.procErrReason
}

func (d *etmv3Decoder) pktTimestamp() error {
	for {
		currByte, ok := d.readNextByte()
		if !ok {
			return nil
		}
		if (currByte & 0x80) == 0 {
			break
		}
	}

	tsVal, tsBits := d.extractTimestamp(1)
	if d.ctx.processState != etmv3StateProcErr {
		d.ctx.currPacket.UpdateTimestamp(tsVal, tsBits)
		d.ctx.processState = etmv3StateSendPkt
	}
	return d.ctx.procErrReason
}

func (d *etmv3Decoder) pktCycleCount() error {
	for {
		currByte, ok := d.readNextByte()
		if !ok {
			return nil
		}
		if (currByte&0x80) == 0 || len(d.ctx.Reader.Scratch()) >= 6 {
			break
		}
	}

	cc, _ := d.extractCycleCount(1)
	d.ctx.currPacket.CycleCount = cc
	if d.ctx.processState != etmv3StateProcErr {
		d.ctx.processState = etmv3StateSendPkt
	}
	return d.ctx.procErrReason
}

func (d *etmv3Decoder) pktContextID() error {
	for len(d.ctx.Reader.Scratch()) < d.ctx.bytesExpected {
		_, ok := d.readNextByte()
		if !ok {
			return nil
		}
	}

	d.ctx.currPacket.Context.CtxtID = d.extractCtxtID(1)
	if d.ctx.processState != etmv3StateProcErr {
		d.ctx.currPacket.Context.UpdatedC = true
		d.ctx.processState = etmv3StateSendPkt
	}
	return d.ctx.procErrReason
}

func (d *etmv3Decoder) pktVMID() error {
	by, ok := d.readNextByte()
	if !ok {
		return nil
	}
	d.ctx.currPacket.Context.VMID = by
	d.ctx.currPacket.Context.UpdatedV = true
	d.ctx.processState = etmv3StateSendPkt
	return nil
}

func (d *etmv3Decoder) pktASync() error {
	for d.ctx.Reader.Len() > 0 {
		b, _ := d.readNextByte()

		if b == 0x80 {
			d.ctx.processState = etmv3StateSendPkt
			return nil
		}

		if b != 0x00 {
			return d.throwMalformedPacketErr("Malformed A-Sync packet payload")
		}
	}
	return nil
}

func (d *etmv3Decoder) pktTrigger() error        { d.ctx.processState = etmv3StateSendPkt; return nil }
func (d *etmv3Decoder) pktPHdr() error           { d.ctx.processState = etmv3StateSendPkt; return nil }
func (d *etmv3Decoder) pktExceptionEntry() error { d.ctx.processState = etmv3StateSendPkt; return nil }
func (d *etmv3Decoder) pktExceptionExit() error  { d.ctx.processState = etmv3StateSendPkt; return nil }
func (d *etmv3Decoder) pktIgnore() error         { d.ctx.processState = etmv3StateSendPkt; return nil }
func (d *etmv3Decoder) pktReserved() error       { return d.throwMalformedPacketErr("Reserved packet header") }

func (d *etmv3Decoder) onBranchAddress() {
	partAddr, validBits, _ := d.extractBrAddrPkt(0)
	d.ctx.currPacket.UpdateAddress(partAddr, validBits)
}

func (d *etmv3Decoder) extractBrAddrPkt(offset int) (value uint64, nBitsOut int, consumed int) {
	addrshift := []int{2, 1, 1, 0}
	addrMask := []uint8{0x7, 0xF, 0xF, 0x1F}
	addrBits := []int{3, 4, 4, 5}

	CBit := true
	bytecount := 0
	bitcount := 0
	shift := 0
	isa_idx := 0
	var addrbyte uint8
	byte5AddrUpdate := false

	scratch := d.ctx.Reader.Scratch()
	currIdx := offset

	for CBit && bytecount < 4 {
		if currIdx >= len(scratch) {
			_ = d.throwMalformedPacketErr("Malformed Packet - oversized packet.")
			return 0, 0, 0
		}
		addrbyte = scratch[currIdx]
		currIdx++

		CBit = (addrbyte & 0x80) != 0
		shift = bitcount
		if bytecount == 0 {
			addrbyte &= ^uint8(0x81)
			bitcount += 6
			addrbyte >>= 1
		} else {
			if d.Config.AltBranch() && !CBit {
				if (addrbyte & 0x40) == 0x40 {
					currIdx = d.extractExceptionData(currIdx)
				}
				addrbyte &= 0x3F
				bitcount += 6
			} else {
				addrbyte &= 0x7F
				bitcount += 7
			}
		}
		value |= uint64(addrbyte) << shift
		bytecount++
	}

	if CBit {
		if currIdx >= len(scratch) {
			_ = d.throwMalformedPacketErr("Malformed Packet - oversized packet.")
			return 0, 0, 0
		}
		addrbyte = scratch[currIdx]
		currIdx++

		if (addrbyte & 0x80) != 0 {
			excep_num := (addrbyte >> 3) & 0x7
			d.ctx.currPacket.UpdateISA(ISAArm)
			d.ctx.currPacket.SetException(exceptionTypeARMdeprecated[excep_num], uint16(excep_num))
		} else {
			if (addrbyte & 0x40) == 0x40 {
				currIdx = d.extractExceptionData(currIdx)
			}
			if (addrbyte & 0xB8) == 0x08 {
				d.ctx.currPacket.UpdateISA(ISAArm)
			} else if (addrbyte & 0xB0) == 0x10 {
				if d.ctx.currPacket.Context.CurrAltIsa {
					d.ctx.currPacket.UpdateISA(ISATee)
				} else {
					d.ctx.currPacket.UpdateISA(ISAThumb2)
				}
			} else if (addrbyte & 0xA0) == 0x20 {
				d.ctx.currPacket.UpdateISA(ISAJazelle)
			}
		}
		byte5AddrUpdate = true
	}

	switch d.ctx.currPacket.CurrISA {
	case ISAThumb2:
		isa_idx = 1
	case ISATee:
		isa_idx = 2
	case ISAJazelle:
		isa_idx = 3
	default:
		isa_idx = 0
	}

	if byte5AddrUpdate {
		value |= uint64(addrbyte&addrMask[isa_idx]) << bitcount
		bitcount += addrBits[isa_idx]
	}

	shift = addrshift[isa_idx]
	value <<= shift
	bitcount += shift

	return value, bitcount, currIdx - offset
}

func (d *etmv3Decoder) extractExceptionData(offset int) int {
	if !d.ctx.branchNeedsEx {
		return offset
	}
	scratch := d.ctx.Reader.Scratch()
	if offset >= len(scratch) {
		return offset
	}

	dataByte := scratch[offset]
	offset++

	d.ctx.currPacket.Context.CurrNS = (dataByte & 0x1) != 0
	exceptionNum := uint16((dataByte >> 1) & 0xF)
	cancelPrevInstr := (dataByte & 0x20) != 0
	d.ctx.currPacket.Context.CurrAltIsa = (dataByte & 0x40) != 0
	d.ctx.currPacket.Context.Updated = true

	if (dataByte & 0x80) != 0 {
		if offset >= len(scratch) {
			return offset
		}
		dataByte = scratch[offset]
		offset++

		if (dataByte & 0x40) != 0 {
		} else {
			if d.Config.V7MArch() {
				exceptionNum |= uint16(dataByte&0x1F) << 4
			}
			d.ctx.currPacket.Context.CurrHyp = (dataByte & 0x20) != 0
			d.ctx.currPacket.Context.Updated = true

			if (dataByte & 0x80) != 0 {
				if offset >= len(scratch) {
					return offset
				}
				offset++
			}
		}
	}

	excepType := excpReserved
	if d.Config.V7MArch() {
		exceptionNum &= 0x1FF
		if int(exceptionNum) < len(exceptionTypesCM) {
			excepType = exceptionTypesCM[exceptionNum]
		} else {
			excepType = excpCMIRQn
		}
	} else {
		exceptionNum &= 0xF
		excepType = exceptionTypesStd[exceptionNum]
	}

	d.ctx.currPacket.SetExceptionWithCancel(excepType, exceptionNum, cancelPrevInstr)
	return offset
}

func (d *etmv3Decoder) onISyncPacket() {
	scratch := d.ctx.Reader.Scratch()
	currIdx := 1

	if d.ctx.isyncGotCC {
		cc, consumed := d.extractCycleCount(currIdx)
		d.ctx.currPacket.CycleCount = cc
		if d.ctx.processState == etmv3StateProcErr {
			return
		}
		d.ctx.currPacket.ISyncInfo.HasCycleCount = true
		currIdx += consumed
	}

	if d.Config.CtxtIDBytes() > 0 {
		d.ctx.currPacket.Context.CtxtID = d.extractCtxtID(currIdx)
		if d.ctx.processState == etmv3StateProcErr {
			return
		}
		d.ctx.currPacket.Context.UpdatedC = true
		currIdx += d.Config.CtxtIDBytes()
	}

	if currIdx >= len(scratch) {
		return
	}
	infoByte := scratch[currIdx]
	currIdx++

	d.ctx.currPacket.ISyncInfo.Reason = iSyncReason((infoByte >> 5) & 0x3)
	j := (infoByte >> 4) & 0x1
	var altISA uint8
	if d.Config.MinorRev() >= 3 {
		altISA = (infoByte >> 2) & 0x1
	}
	d.ctx.currPacket.Context.CurrNS = (infoByte & 0x08) != 0
	if d.Config.HasVirtExt() {
		d.ctx.currPacket.Context.CurrHyp = ((infoByte >> 1) & 0x1) != 0
	}
	d.ctx.currPacket.Context.Updated = true

	if d.Config.InstrTrace() {
		var instrAddr uint32
		for i := range 4 {
			if currIdx >= len(scratch) {
				return
			}
			instrAddr |= uint32(scratch[currIdx]) << (i * 8)
			currIdx++
		}

		t := uint8(instrAddr & 0x1)
		instrAddr &= 0xFFFFFFFE
		d.ctx.currPacket.UpdateAddress(uint64(instrAddr), 32)

		currISA := ISAArm
		if j != 0 {
			currISA = ISAJazelle
		} else if t != 0 {
			if altISA != 0 {
				currISA = ISATee
			} else {
				currISA = ISAThumb2
			}
		}
		d.ctx.currPacket.UpdateISA(currISA)

		if d.ctx.isyncGetLSiP {
			partAddr, bits, _ := d.extractBrAddrPkt(currIdx)
			if d.ctx.processState == etmv3StateProcErr {
				return
			}
			d.ctx.currPacket.Data.Addr = uint64(instrAddr)
			d.ctx.currPacket.Data.UpdateAddr = true
			if bits > 0 {
				mask := uint64((uint64(1) << uint(bits)) - 1)
				d.ctx.currPacket.Data.Addr = (d.ctx.currPacket.Data.Addr & ^mask) | (partAddr & mask)
			}
			d.ctx.currPacket.ISyncInfo.HasLSipAddr = true
		}
	} else {
		d.ctx.currPacket.ISyncInfo.NoAddress = true
	}
}

func (d *etmv3Decoder) extractCycleCount(offset int) (uint32, int) {
	cycleCount := uint32(0)
	byteIdx := 0
	mask := uint8(0x7F)
	scratch := d.ctx.Reader.Scratch()

	currIdx := offset
	for ; currIdx < len(scratch); currIdx++ {
		currByte := scratch[currIdx]

		if byteIdx == 4 {
			if (currByte & 0x80) != 0 {
				_ = d.throwMalformedPacketErr("Malformed cycle count: overlong continuation")
				return 0, 0
			}
			if (currByte & 0x70) != 0 {
				_ = d.throwMalformedPacketErr("Malformed cycle count: overflow in terminal byte")
				return 0, 0
			}
		}

		cycleCount |= uint32(currByte&mask) << (7 * byteIdx)
		byteIdx++

		if byteIdx == 4 {
			mask = 0x0F
		}
		if (currByte & 0x80) == 0 {
			currIdx++
			break
		}
	}
	return cycleCount, currIdx - offset
}

func (d *etmv3Decoder) extractCtxtID(offset int) uint32 {
	val := uint32(0)
	ctxtBytes := d.Config.CtxtIDBytes()
	scratch := d.ctx.Reader.Scratch()

	if offset+ctxtBytes > len(scratch) {
		_ = d.throwMalformedPacketErr("Too few bytes to extract context ID.")
		return 0
	}

	for i := 0; i < int(ctxtBytes); i++ {
		val |= uint32(scratch[offset+i]) << (i * 8)
	}
	return val
}

func (d *etmv3Decoder) extractTimestamp(offset int) (val uint64, tsBits uint8) {
	tsMaxBytes := 7
	if d.Config.TSPkt64() {
		tsMaxBytes = 9
	}

	mask := uint8(0x7F)
	lastMask := uint8(0x3F)
	if d.Config.TSPkt64() {
		lastMask = 0xFF
	}

	tsIterBits := uint8(7)
	tsLastIterBits := uint8(6)
	if d.Config.TSPkt64() {
		tsLastIterBits = 8
	}

	scratch := d.ctx.Reader.Scratch()
	tsCurrBytes := 0

	for currIdx := offset; currIdx < len(scratch) && tsCurrBytes < tsMaxBytes; currIdx++ {
		currByte := scratch[currIdx]

		val |= uint64(currByte&mask) << (7 * tsCurrBytes)
		tsCurrBytes++
		tsBits += tsIterBits

		if tsCurrBytes == tsMaxBytes-1 {
			mask = lastMask
			tsIterBits = tsLastIterBits
		}
		if (currByte & 0x80) == 0 {
			break
		}
	}
	return val, tsBits
}

var exceptionTypeARMdeprecated = []armV7Exception{
	excpReset, excpIRQ, excpReserved, excpReserved,
	excpJazelle, excpFIQ, excpAsyncDAbort, excpDebugHalt,
}

var exceptionTypesStd = []armV7Exception{
	excpNoException, excpDebugHalt, excpSMC, excpHyp,
	excpAsyncDAbort, excpJazelle, excpReserved, excpReserved,
	excpReset, excpUndef, excpSVC, excpPrefAbort,
	excpSyncDataAbort, excpGeneric, excpIRQ, excpFIQ,
}

var exceptionTypesCM = []armV7Exception{
	excpNoException, excpCMIRQn, excpCMIRQn, excpCMIRQn,
	excpCMIRQn, excpCMIRQn, excpCMIRQn, excpCMIRQn,
	excpCMIRQn, excpCMUsageFault, excpCMNMI, excpSVC,
	excpCMDebugMonitor, excpCMMemManage, excpCMPendSV, excpCMSysTick,
	excpReserved, excpReset, excpReserved, excpCMHardFault,
	excpReserved, excpCMBusFault, excpReserved, excpReserved,
}
