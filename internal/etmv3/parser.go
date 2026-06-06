package etmv3

import (
	"errors"
	"fmt"

	"coresight/internal/protocol"
	"coresight/trace"
)

type processState int

const (
	stateWaitSync processState = iota
	stateProcHdr
	stateProcData
	stateSendPkt
	stateProcErr
)

type packetHandler func(*Decoder) error

var handlers = [32]packetHandler{
	PktBranchAddress:  (*Decoder).pktBranchAddress,
	PktASync:          (*Decoder).pktASync,
	PktCycleCount:     (*Decoder).pktCycleCount,
	PktISync:          (*Decoder).pktISync,
	PktISyncCycle:     (*Decoder).pktISync,
	PktTrigger:        (*Decoder).pktTrigger,
	PktPHdr:           (*Decoder).pktPHdr,
	PktContextID:      (*Decoder).pktContextID,
	PktVMID:           (*Decoder).pktVMID,
	PktTimestamp:      (*Decoder).pktTimestamp,
	PktExceptionEntry: (*Decoder).pktExceptionEntry,
	PktExceptionExit:  (*Decoder).pktExceptionExit,
	PktIgnore:         (*Decoder).pktIgnore,
	PktReserved:       (*Decoder).pktReserved,
}

type parseContext struct {
	protocol.ByteStream

	processState    processState
	procErrReason   error
	currPacket      Packet
	currPacketIndex trace.Index

	waitASyncSOPacket bool
	bAsyncRawOp       bool
	unsyncedRaw       []byte

	bytesExpected int
	branchNeedsEx bool
	isyncGotCC    bool
	isyncGetLSiP  bool
	isyncInfoIdx  int
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
	d.ctx.branchNeedsEx = false
	d.ctx.isyncGotCC = false
	d.ctx.isyncGetLSiP = false
	d.ctx.isyncInfoIdx = 0
}

func (d *Decoder) throwMalformedPacketErr(msg string) error {
	d.ctx.processState = stateProcErr
	d.ctx.currPacket.Err = trace.ErrBadPacketSeq
	d.ctx.procErrReason = fmt.Errorf("%w: %s", trace.ErrBadPacketSeq, msg)
	return d.ctx.procErrReason
}

func (d *Decoder) processData(index trace.Index, dataBlock []uint8) (uint32, error) {
	d.ctx.Feed(index, dataBlock)

	var err error

	for d.ctx.Reader.Len() > 0 || d.ctx.processState == stateSendPkt {
		switch d.ctx.processState {
		case stateWaitSync:
			if !d.ctx.waitASyncSOPacket {
				d.ctx.currPacketIndex = d.ctx.CurrentIndex()
				d.ctx.currPacket.Type = PktNotSync
				d.ctx.bAsyncRawOp = d.PacketObserver != nil
			}
			err = d.waitASync()

		case stateProcHdr:
			d.ctx.currPacketIndex = d.ctx.CurrentIndex()
			if currByte, ok := d.readNextByte(); ok {
				d.decodeHeaderByte(currByte)
			} else {
				err = fmt.Errorf("%w: Data Buffer Overrun", trace.ErrPktInterpFail)
			}

		case stateProcData:
			if int(d.ctx.currPacket.Type) < len(handlers) && handlers[d.ctx.currPacket.Type] != nil {
				err = handlers[d.ctx.currPacket.Type](d)
			} else {
				err = d.pktReserved()
			}

		case stateSendPkt:
			err = d.outputPacket()
			d.resetPacketState()
			d.ctx.processState = stateProcHdr

		case stateProcErr:
			err = d.ctx.procErrReason
			if err == nil {
				err = trace.ErrPktInterpFail
			}
		}

		if err != nil {
			if errors.Is(err, trace.ErrBadPacketSeq) || errors.Is(err, trace.ErrInvalidPcktHdr) || errors.Is(err, trace.ErrHWCfgUnsupp) {
				d.ctx.processState = stateSendPkt
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

func (d *Decoder) waitASync() error {
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

					d.ctx.currPacketIndex += trace.Index(sendLen)
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
			d.ctx.processState = stateProcHdr
		} else {
			d.ctx.processState = stateWaitSync
		}

		d.ctx.unsyncedRaw = nil
		d.ctx.Reader.Reset()
	}
	return nil
}

func (d *Decoder) decodeHeaderByte(by uint8) {
	d.ctx.processState = stateProcData

	if (by & 0x01) == 0x01 {
		d.ctx.currPacket.Type = PktBranchAddress
		d.ctx.branchNeedsEx = false
		if (by & 0x80) != 0x80 {
			d.onBranchAddress()
			if d.ctx.processState != stateProcErr {
				d.ctx.processState = stateSendPkt
			}
		}
	} else if (by & 0x81) == 0x80 {
		d.ctx.currPacket.Type = PktPHdr
		if d.ctx.currPacket.UpdateAtomFromPHdr(by, d.Config.CycleAcc()) {
			d.ctx.processState = stateSendPkt
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
			d.ctx.processState = stateSendPkt
		}
	} else if (by & 0x03) == 0x00 {
		if (by & 0x93) == 0x00 {
			d.ctx.currPacket.Type = PktOOOData
			d.ctx.currPacket.Err = trace.ErrHWCfgUnsupp
			d.ctx.processState = stateSendPkt
		} else if by == 0x70 {
			d.ctx.currPacket.Type = PktISyncCycle
		} else if by == 0x50 {
			d.ctx.currPacket.Type = PktStoreFail
			d.ctx.currPacket.Err = trace.ErrHWCfgUnsupp
			d.ctx.processState = stateSendPkt
		} else if (by & 0xD3) == 0x50 {
			d.ctx.currPacket.Type = PktOOOAddrPlc
			d.ctx.currPacket.Err = trace.ErrHWCfgUnsupp
			d.ctx.processState = stateSendPkt
		} else if by == 0x3C {
			d.ctx.currPacket.Type = PktVMID
		} else {
			d.ctx.currPacket.Err = trace.ErrInvalidPcktHdr
			d.ctx.processState = stateSendPkt
		}
	} else if (by & 0xD3) == 0x02 {
		d.ctx.currPacket.Type = PktNormData
		d.ctx.currPacket.Err = trace.ErrHWCfgUnsupp
		d.ctx.processState = stateSendPkt
	} else if by == 0x62 {
		d.ctx.currPacket.Type = PktDataSuppressed
		d.ctx.currPacket.Err = trace.ErrHWCfgUnsupp
		d.ctx.processState = stateSendPkt
	} else if (by & 0xEF) == 0x6A {
		d.ctx.currPacket.Type = PktValNotTraced
		d.ctx.currPacket.Err = trace.ErrHWCfgUnsupp
		d.ctx.processState = stateSendPkt
	} else if by == 0x66 {
		d.ctx.currPacket.Type = PktIgnore
		d.ctx.processState = stateSendPkt
	} else if by == 0x6E {
		d.ctx.currPacket.Type = PktContextID
		d.ctx.bytesExpected = 1 + d.Config.CtxtIDBytes()
	} else if by == 0x76 {
		d.ctx.currPacket.Type = PktExceptionExit
		d.ctx.processState = stateSendPkt
	} else if by == 0x7E {
		d.ctx.currPacket.Type = PktExceptionEntry
		d.ctx.processState = stateSendPkt
	} else if (by & 0xFB) == 0x42 {
		d.ctx.currPacket.Type = PktTimestamp
	} else {
		d.ctx.currPacket.Err = trace.ErrInvalidPcktHdr
		d.ctx.processState = stateSendPkt
	}
}

func (d *Decoder) pktBranchAddress() error {
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
			if d.ctx.processState != stateProcErr {
				d.ctx.processState = stateSendPkt
			}
			return d.ctx.procErrReason
		}
	}
}

func (d *Decoder) pktISync() error {
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
	if d.ctx.processState != stateProcErr {
		d.ctx.processState = stateSendPkt
	}
	return d.ctx.procErrReason
}

func (d *Decoder) pktTimestamp() error {
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
	if d.ctx.processState != stateProcErr {
		d.ctx.currPacket.UpdateTimestamp(tsVal, tsBits)
		d.ctx.processState = stateSendPkt
	}
	return d.ctx.procErrReason
}

func (d *Decoder) pktCycleCount() error {
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
	if d.ctx.processState != stateProcErr {
		d.ctx.processState = stateSendPkt
	}
	return d.ctx.procErrReason
}

func (d *Decoder) pktContextID() error {
	for len(d.ctx.Reader.Scratch()) < d.ctx.bytesExpected {
		_, ok := d.readNextByte()
		if !ok {
			return nil
		}
	}

	d.ctx.currPacket.Context.CtxtID = d.extractCtxtID(1)
	if d.ctx.processState != stateProcErr {
		d.ctx.currPacket.Context.UpdatedC = true
		d.ctx.processState = stateSendPkt
	}
	return d.ctx.procErrReason
}

func (d *Decoder) pktVMID() error {
	by, ok := d.readNextByte()
	if !ok {
		return nil
	}
	d.ctx.currPacket.Context.VMID = by
	d.ctx.currPacket.Context.UpdatedV = true
	d.ctx.processState = stateSendPkt
	return nil
}

func (d *Decoder) pktASync() error {
	for d.ctx.Reader.Len() > 0 {
		b, _ := d.readNextByte()

		if b == 0x80 {
			d.ctx.processState = stateSendPkt
			return nil
		}

		if b != 0x00 {
			return d.throwMalformedPacketErr("Malformed A-Sync packet payload")
		}
	}
	return nil
}

func (d *Decoder) pktTrigger() error        { d.ctx.processState = stateSendPkt; return nil }
func (d *Decoder) pktPHdr() error           { d.ctx.processState = stateSendPkt; return nil }
func (d *Decoder) pktExceptionEntry() error { d.ctx.processState = stateSendPkt; return nil }
func (d *Decoder) pktExceptionExit() error  { d.ctx.processState = stateSendPkt; return nil }
func (d *Decoder) pktIgnore() error         { d.ctx.processState = stateSendPkt; return nil }
func (d *Decoder) pktReserved() error       { return d.throwMalformedPacketErr("Reserved packet header") }

func (d *Decoder) onBranchAddress() {
	partAddr, validBits, _ := d.extractBrAddrPkt(0)
	d.ctx.currPacket.UpdateAddress(partAddr, validBits)
}

func (d *Decoder) extractBrAddrPkt(offset int) (value uint64, nBitsOut int, consumed int) {
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
			d.ctx.currPacket.UpdateISA(trace.ISAArm)
			d.ctx.currPacket.SetException(exceptionTypeARMdeprecated[excep_num], uint16(excep_num))
		} else {
			if (addrbyte & 0x40) == 0x40 {
				currIdx = d.extractExceptionData(currIdx)
			}
			if (addrbyte & 0xB8) == 0x08 {
				d.ctx.currPacket.UpdateISA(trace.ISAArm)
			} else if (addrbyte & 0xB0) == 0x10 {
				if d.ctx.currPacket.Context.CurrAltIsa {
					d.ctx.currPacket.UpdateISA(trace.ISATee)
				} else {
					d.ctx.currPacket.UpdateISA(trace.ISAThumb2)
				}
			} else if (addrbyte & 0xA0) == 0x20 {
				d.ctx.currPacket.UpdateISA(trace.ISAJazelle)
			}
		}
		byte5AddrUpdate = true
	}

	switch d.ctx.currPacket.CurrISA {
	case trace.ISAThumb2:
		isa_idx = 1
	case trace.ISATee:
		isa_idx = 2
	case trace.ISAJazelle:
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

func (d *Decoder) extractExceptionData(offset int) int {
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

	excepType := trace.ExcpReserved
	if d.Config.V7MArch() {
		exceptionNum &= 0x1FF
		if int(exceptionNum) < len(exceptionTypesCM) {
			excepType = exceptionTypesCM[exceptionNum]
		} else {
			excepType = trace.ExcpCMIRQn
		}
	} else {
		exceptionNum &= 0xF
		excepType = exceptionTypesStd[exceptionNum]
	}

	d.ctx.currPacket.SetExceptionWithCancel(excepType, exceptionNum, cancelPrevInstr)
	return offset
}

func (d *Decoder) onISyncPacket() {
	scratch := d.ctx.Reader.Scratch()
	currIdx := 1

	if d.ctx.isyncGotCC {
		cc, consumed := d.extractCycleCount(currIdx)
		d.ctx.currPacket.CycleCount = cc
		if d.ctx.processState == stateProcErr {
			return
		}
		d.ctx.currPacket.ISyncInfo.HasCycleCount = true
		currIdx += consumed
	}

	if d.Config.CtxtIDBytes() > 0 {
		d.ctx.currPacket.Context.CtxtID = d.extractCtxtID(currIdx)
		if d.ctx.processState == stateProcErr {
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

	d.ctx.currPacket.ISyncInfo.Reason = trace.ISyncReason((infoByte >> 5) & 0x3)
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

		currISA := trace.ISAArm
		if j != 0 {
			currISA = trace.ISAJazelle
		} else if t != 0 {
			if altISA != 0 {
				currISA = trace.ISATee
			} else {
				currISA = trace.ISAThumb2
			}
		}
		d.ctx.currPacket.UpdateISA(currISA)

		if d.ctx.isyncGetLSiP {
			partAddr, bits, _ := d.extractBrAddrPkt(currIdx)
			if d.ctx.processState == stateProcErr {
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

func (d *Decoder) extractCycleCount(offset int) (uint32, int) {
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

func (d *Decoder) extractCtxtID(offset int) uint32 {
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

func (d *Decoder) extractTimestamp(offset int) (val uint64, tsBits uint8) {
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

var exceptionTypeARMdeprecated = []trace.ArmV7Exception{
	trace.ExcpReset, trace.ExcpIRQ, trace.ExcpReserved, trace.ExcpReserved,
	trace.ExcpJazelle, trace.ExcpFIQ, trace.ExcpAsyncDAbort, trace.ExcpDebugHalt,
}

var exceptionTypesStd = []trace.ArmV7Exception{
	trace.ExcpNoException, trace.ExcpDebugHalt, trace.ExcpSMC, trace.ExcpHyp,
	trace.ExcpAsyncDAbort, trace.ExcpJazelle, trace.ExcpReserved, trace.ExcpReserved,
	trace.ExcpReset, trace.ExcpUndef, trace.ExcpSVC, trace.ExcpPrefAbort,
	trace.ExcpSyncDataAbort, trace.ExcpGeneric, trace.ExcpIRQ, trace.ExcpFIQ,
}

var exceptionTypesCM = []trace.ArmV7Exception{
	trace.ExcpNoException, trace.ExcpCMIRQn, trace.ExcpCMIRQn, trace.ExcpCMIRQn,
	trace.ExcpCMIRQn, trace.ExcpCMIRQn, trace.ExcpCMIRQn, trace.ExcpCMIRQn,
	trace.ExcpCMIRQn, trace.ExcpCMUsageFault, trace.ExcpCMNMI, trace.ExcpSVC,
	trace.ExcpCMDebugMonitor, trace.ExcpCMMemManage, trace.ExcpCMPendSV, trace.ExcpCMSysTick,
	trace.ExcpReserved, trace.ExcpReset, trace.ExcpReserved, trace.ExcpCMHardFault,
	trace.ExcpReserved, trace.ExcpCMBusFault, trace.ExcpReserved, trace.ExcpReserved,
}
