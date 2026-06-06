package ptm

import (
	"errors"
	"fmt"

	"github.com/awmorgan/coresight/internal/protocol"
	"github.com/awmorgan/coresight/trace"
)

type asyncResult int

const (
	asyncResultAsync asyncResult = iota
	asyncResultNotAsync
	asyncResultAsyncExtra0
	asyncResultThrow0
	asyncResultAsyncIncomplete
)

const (
	asyncPad0Limit = 11
	asyncReq0      = 5
)

type processState int

type packetHandler func(*Decoder) error

var handlers = [32]packetHandler{
	PacketBranchAddress: (*Decoder).pktBranchAddr,
	PacketAtom:          (*Decoder).PacketAtom,
	PacketASync:         (*Decoder).PacketASync,
	PacketISync:         (*Decoder).PacketISync,
	PacketWPointUpdate:  (*Decoder).PacketWPointUpdate,
	PacketTrigger:       (*Decoder).PacketTrigger,
	PacketContextID:     (*Decoder).pktCtxtID,
	PacketVMID:          (*Decoder).PacketVMID,
	PacketTimestamp:     (*Decoder).PacketTimestamp,
	PacketExceptionRet:  (*Decoder).PacketExceptionRet,
	PacketIgnore:        (*Decoder).PacketIgnore,
	PacketReserved:      (*Decoder).PacketReserved,
}

const (
	stateWaitSync processState = iota
	stateProcHdr
	stateProcData
	stateSendPkt
)

type parseContext struct {
	protocol.ByteStream

	processState      processState
	currPacket        Packet
	currPacketIndex   trace.Index
	waitASyncSOPacket bool
	bAsyncRawOp       bool
	bOPNotSyncPacket  bool
	async0            int
	numPacketBytesReq int
	needCycleCount    bool
	gotCycleCount     bool
	gotCCBytes        int
	numCtxtIDBytes    int
	gotCtxtIDBytes    int
	gotTSBytes        bool
	tsByteMax         int
	gotAddrBytes      bool
	numAddrBytes      int
	gotExcepBytes     bool
	numExcepBytes     int
	addrPacketIsa     trace.ISA
	excepAltISA       int
}

func (p *Decoder) Write(index trace.Index, dataBlock []byte) (uint32, error) {
	if len(dataBlock) == 0 {
		return 0, fmt.Errorf("%w: packet processor: zero length data block", protocol.ErrInvalidParamVal)
	}
	processed, err := p.processData(index, dataBlock)
	if err != nil {
		return processed, err
	}
	return processed, nil
}

func (p *Decoder) resetProcessorState() {
	p.ctx.currPacket.Type = PacketNotSync

	p.ctx.processState = stateWaitSync
	p.ctx.async0 = 0
	p.ctx.waitASyncSOPacket = false
	p.ctx.bAsyncRawOp = false
	p.ctx.bOPNotSyncPacket = false
	p.ctx.excepAltISA = 0

	p.ctx.currPacket.ResetState()
	p.resetPacketState()
}

func (p *Decoder) resetPacketState() {
	p.ctx.currPacket.Clear()
	p.ctx.Reader.Reset()
	p.ctx.numPacketBytesReq = 0
	p.ctx.needCycleCount = false
	p.ctx.gotCycleCount = false
	p.ctx.gotCCBytes = 0
	p.ctx.numCtxtIDBytes = 0
	p.ctx.gotCtxtIDBytes = 0
	p.ctx.gotTSBytes = false
	p.ctx.tsByteMax = 0
	p.ctx.gotAddrBytes = false
	p.ctx.numAddrBytes = 0
	p.ctx.gotExcepBytes = false
	p.ctx.numExcepBytes = 0
	p.ctx.addrPacketIsa = trace.ISAUnknown
	p.ctx.excepAltISA = 0
}

func (p *Decoder) readNextByte() (uint8, bool) {
	b, err := p.ctx.ReadByte()
	return b, err == nil
}

func (p *Decoder) malformedPacketErr(msg string) error {
	p.ctx.currPacket.SetErrType(PacketBadSequence)
	return fmt.Errorf("%w: %s", protocol.ErrBadPacketSeq, msg)
}

func (p *Decoder) processData(index trace.Index, dataBlock []uint8) (uint32, error) {
	if p.Config == nil {
		return 0, protocol.ErrNotInit
	}

	p.ctx.Feed(index, dataBlock)

	var err error

	for p.ctx.Reader.Len() > 0 || p.ctx.processState == stateSendPkt {
		switch p.ctx.processState {
		case stateWaitSync:
			if !p.ctx.waitASyncSOPacket {
				p.ctx.currPacketIndex = p.ctx.CurrentIndex()
				p.ctx.currPacket.Type = PacketNotSync
				p.ctx.bAsyncRawOp = p.PacketObserver != nil
			}
			err = p.waitASync()

		case stateProcHdr:
			p.ctx.currPacketIndex = p.ctx.CurrentIndex()
			if currByte, ok := p.readNextByte(); ok {
				p.ctx.currPacket.Type = headerToPacketType(currByte)
				p.ctx.processState = stateProcData
			} else {
				err = fmt.Errorf("%w: Data Buffer Overrun", protocol.ErrPktInterpFail)
			}
			if p.ctx.processState != stateProcData {
				break
			}
			fallthrough

		case stateProcData:
			handler := handlers[p.ctx.currPacket.Type]
			if handler != nil {
				err = handler(p)
			} else {
				err = p.PacketReserved()
			}

		case stateSendPkt:
			err = p.outputPacket()
			p.resetPacketState()
			p.ctx.processState = stateProcHdr
		}

		if err != nil {
			if errors.Is(err, protocol.ErrBadPacketSeq) || errors.Is(err, protocol.ErrInvalidPcktHdr) {
				p.ctx.processState = stateSendPkt
			} else {
				break
			}
		}
	}

	return uint32(p.ctx.BytesConsumed()), err
}

func (d *Decoder) outputDecodedPacket(indexSOP trace.Index, pkt *Packet) error {
	pkt.Index = indexSOP
	return d.processPacket(pkt)
}

func (d *Decoder) outputRawPacketToMonitor(indexSOP trace.Index, pkt *Packet, pData []byte) {
	d.EmitPacket(indexSOP, pkt, pData)
}

func (d *Decoder) outputPacket() error {
	d.ctx.currPacket.Index = d.ctx.currPacketIndex

	scratch := d.ctx.Reader.Scratch()
	d.EmitPacket(d.ctx.currPacketIndex, &d.ctx.currPacket, scratch)

	err := d.processPacket(&d.ctx.currPacket)

	d.ctx.Reader.Reset()
	return err
}

func (p *Decoder) waitASync() error {
	var err error
	doScan := true
	bSendUnsyncedData := false
	bHaveASync := false
	unsyncedBytes := 0
	unsyncScanBlockStart := p.ctx.BytesConsumed()
	pktBytesOnEntry := len(p.ctx.Reader.Scratch())
	spareZeros := make([]uint8, 16)

	const unsyncPktMax = 16

	for doScan && err == nil {
		if p.ctx.waitASyncSOPacket {
			switch p.findAsync() {
			case asyncResultAsync, asyncResultAsyncExtra0:
				p.ctx.processState = stateSendPkt
				p.ctx.waitASyncSOPacket = false
				bSendUnsyncedData = true
				bHaveASync = true
				doScan = false
			case asyncResultThrow0:
				unsyncedBytes += asyncPad0Limit
				p.ctx.waitASyncSOPacket = false
				p.ctx.Reader.DiscardScratchPrefix(asyncPad0Limit)
			case asyncResultNotAsync:
				unsyncedBytes += len(p.ctx.Reader.Scratch())
				p.ctx.waitASyncSOPacket = false
				p.ctx.Reader.Reset()
			case asyncResultAsyncIncomplete:
				bSendUnsyncedData = true
				doScan = false
			}
		} else {
			if p.ctx.Reader.Len() > 0 {
				b, _ := p.ctx.Reader.Peek()
				if b == 0x00 {
					_, _ = p.ctx.Reader.ReadByte()
					p.ctx.waitASyncSOPacket = true
					p.ctx.async0 = 1
				} else {
					_, _ = p.ctx.Reader.ReadByte()
					p.ctx.Reader.Reset()
					unsyncedBytes++
				}
			}
		}

		if unsyncedBytes >= unsyncPktMax {
			bSendUnsyncedData = true
		}

		if p.ctx.Reader.Len() == 0 {
			bSendUnsyncedData = true
			doScan = false
		}

		if bSendUnsyncedData && unsyncedBytes > 0 {
			if p.ctx.bAsyncRawOp {
				if pktBytesOnEntry > 0 {
					p.outputRawPacketToMonitor(p.ctx.currPacketIndex, &p.ctx.currPacket, spareZeros[:pktBytesOnEntry])
					p.ctx.currPacketIndex += trace.Index(pktBytesOnEntry)
					pktBytesOnEntry = 0
				}
				rawEnd := unsyncScanBlockStart + unsyncedBytes
				if rawEnd <= p.ctx.BlockLen {
					p.outputRawPacketToMonitor(p.ctx.currPacketIndex, &p.ctx.currPacket, p.ctx.DataBlock[unsyncScanBlockStart:rawEnd])
				} else if unsyncScanBlockStart < p.ctx.BlockLen {
					base := p.ctx.DataBlock[unsyncScanBlockStart:]
					missing := rawEnd - p.ctx.BlockLen
					if missing > 0 {
						fill := byte(p.ctx.BlockLen)
						tmp := make([]byte, len(base)+missing)
						copy(tmp, base)
						for i := len(base); i < len(tmp); i++ {
							tmp[i] = fill
						}
						p.outputRawPacketToMonitor(p.ctx.currPacketIndex, &p.ctx.currPacket, tmp)
					} else {
						p.outputRawPacketToMonitor(p.ctx.currPacketIndex, &p.ctx.currPacket, base)
					}
				}
			}
			if !p.ctx.bOPNotSyncPacket {
				err = p.outputDecodedPacket(p.ctx.currPacketIndex, &p.ctx.currPacket)
				p.ctx.bOPNotSyncPacket = true
			}
			unsyncScanBlockStart += unsyncedBytes
			p.ctx.currPacketIndex += trace.Index(unsyncedBytes)
			unsyncedBytes = 0
			bSendUnsyncedData = false
		}

		if bHaveASync {
			p.ctx.currPacket.Type = PacketASync
		}
	}
	return err
}

func (p *Decoder) findAsync() asyncResult {
	for {
		currByte, ok := p.readNextByte()
		if !ok {
			return asyncResultAsyncIncomplete
		}
		if currByte == 0x00 {
			p.ctx.async0++
			if p.ctx.async0 >= asyncPad0Limit+asyncReq0 {
				return asyncResultThrow0
			}
			continue
		}
		if currByte == PktASyncByte {
			switch {
			case p.ctx.async0 == 5:
				return asyncResultAsync
			case p.ctx.async0 > 5:
				return asyncResultAsyncExtra0
			}
		}
		return asyncResultNotAsync
	}
}

func (p *Decoder) PacketASync() error {
	if len(p.ctx.Reader.Scratch()) == 1 {
		p.ctx.async0 = 1
	}
	switch p.findAsync() {
	case asyncResultAsync, asyncResultAsyncExtra0:
		p.ctx.processState = stateSendPkt
	case asyncResultThrow0, asyncResultNotAsync:
		return p.malformedPacketErr("Bad Async packet")
	case asyncResultAsyncIncomplete:
	}
	return nil
}

func (p *Decoder) extractCycleCount(offset int) (uint32, error) {
	data := p.ctx.Reader.Scratch()
	if offset >= len(data) {
		return 0, p.malformedPacketErr("Insufficient packet bytes for Cycle Count value.")
	}

	b := data[offset]
	cycleCount := uint32((b >> 2) & 0xF)
	p.ctx.gotCCBytes = 1
	if (b & PktCCContMask) == 0 {
		return cycleCount, nil
	}

	shift := 4
	for i := 1; i < 5; i++ {
		if offset+i >= len(data) {
			return 0, p.malformedPacketErr("Insufficient packet bytes for Cycle Count value.")
		}
		currByte := data[offset+i]
		p.ctx.gotCCBytes++

		cycleCount |= uint32(currByte&0x7F) << shift
		shift += 7
		if (currByte&PktContMask) == 0 || i == 4 {
			return cycleCount, nil
		}
	}
	return cycleCount, nil
}

func (p *Decoder) extractCtxtID(idx int) (uint32, error) {
	ctxtID := uint32(0)
	shift := 0
	data := p.ctx.Reader.Scratch()
	for i := 0; i < p.ctx.numCtxtIDBytes; i++ {
		if idx+i >= len(data) {
			return 0, p.malformedPacketErr("Insufficient packet bytes for Context ID value.")
		}
		ctxtID |= uint32(data[idx+i]) << shift
		shift += 8
	}
	return ctxtID, nil
}

func (p *Decoder) extractTS() (uint64, uint8, int, error) {
	data := p.ctx.Reader.Scratch()
	b64 := p.Config.TSPacket64
	var tsVal uint64
	var tsUpdateBits uint8
	shift := 0

	for tsIdx := 1; ; tsIdx++ {
		if tsIdx >= len(data) {
			return 0, 0, 0, p.malformedPacketErr("Insufficient packet bytes for Timestamp value.")
		}
		if shift >= 64 {
			return 0, 0, 0, p.malformedPacketErr("Timestamp shift exceeds 64-bit accumulator width.")
		}
		byteVal := data[tsIdx]
		limit := 7
		if b64 {
			limit = 9
		}
		if tsIdx < limit {
			tsVal |= uint64(byteVal&0x7F) << shift
			shift += 7
			tsUpdateBits += 7
			if (byteVal & PktContMask) == 0 {
				return tsVal, tsUpdateBits, tsIdx + 1, nil
			}
		} else {
			if !b64 {
				byteVal &= 0x3F
				tsUpdateBits += 6
			} else {
				tsUpdateBits += 8
			}
			tsVal |= uint64(byteVal) << shift
			return tsVal, tsUpdateBits, tsIdx + 1, nil
		}
	}
}

func (p *Decoder) extractAddress(offset int) (uint32, uint8, error) {
	if p.ctx.numAddrBytes <= 0 || p.ctx.numAddrBytes > 5 {
		return 0, 0, p.malformedPacketErr("Address value has invalid encoded length.")
	}
	data := p.ctx.Reader.Scratch()
	if offset < 0 || offset+p.ctx.numAddrBytes > len(data) {
		return 0, 0, p.malformedPacketErr("Insufficient packet bytes for address value.")
	}

	addrVal := uint32(0)
	totalBits := uint8(0)
	shift := 0

	for i := 0; i < p.ctx.numAddrBytes; i++ {
		b := data[offset+i]
		var mask uint8
		var numBits uint8

		switch {
		case i == 0:
			mask = 0x7E
			numBits = 7
		case i < 4:
			mask = 0x7F
			numBits = 7
			if i == p.ctx.numAddrBytes-1 {
				mask = 0x3F
				numBits = 6
			}
		default: // i == 4
			mask = 0x0F
			numBits = 4
			switch p.ctx.addrPacketIsa {
			case trace.ISAJazelle:
				mask = 0x1F
				numBits = 5
			case trace.ISAArm:
				mask = 0x07
				numBits = 3
			}
		}

		part := uint32(b & mask)
		if i == 0 && p.ctx.addrPacketIsa == trace.ISAJazelle {
			part >>= 1
			numBits--
		}

		if shift >= 32 {
			return 0, 0, p.malformedPacketErr("Address shift exceeds 32-bit accumulator width.")
		}
		if shift > 25 {
			maxPart := uint32((uint64(1) << uint(32-shift)) - 1)
			if part > maxPart {
				return 0, 0, p.malformedPacketErr("Address value overflows 32-bit accumulator.")
			}
		}

		addrVal |= part << shift
		totalBits += numBits

		if i == 0 {
			shift = int(numBits)
		} else {
			shift += 7
		}
	}

	if p.ctx.addrPacketIsa == trace.ISAArm {
		addrVal <<= 1
		totalBits++
	}
	return addrVal, totalBits, nil
}

func (p *Decoder) PacketISync() error {
	if len(p.ctx.Reader.Scratch())-1 == 0 {
		p.ctx.numCtxtIDBytes = p.Config.CtxtIDBytes
		p.ctx.gotCtxtIDBytes = 0
		p.ctx.numPacketBytesReq = 6 + p.ctx.numCtxtIDBytes
	}

	for {
		currByte, ok := p.readNextByte()
		if !ok {
			return nil // wait for more data
		}
		scratch := p.ctx.Reader.Scratch()
		pktIndex := len(scratch) - 1
		if pktIndex == 5 {
			altISA := (currByte >> 2) & 0x1
			reason := (currByte >> 5) & 0x3
			p.ctx.currPacket.ISyncReason = protocol.ISyncReason(reason)

			p.ctx.currPacket.Context.CurrNS = (currByte & PktISyncNSMask) != 0
			p.ctx.currPacket.Context.CurrAltISA = (currByte & PktISyncAltISAMask) != 0
			p.ctx.currPacket.Context.CurrHyp = (currByte & PktISyncHypMask) != 0
			p.ctx.currPacket.Context.Updated = true

			isa := trace.ISAArm
			if (scratch[1] & 0x1) != 0 {
				if altISA != 0 {
					isa = trace.ISATee
				} else {
					isa = trace.ISAThumb2
				}
			}
			p.ctx.currPacket.UpdateISA(isa)

			p.ctx.needCycleCount = reason != 0 && p.Config.EnaCycleAcc
			p.ctx.gotCycleCount = false
			p.ctx.gotCCBytes = 0
			if p.ctx.needCycleCount {
				p.ctx.numPacketBytesReq++
			}
		} else if pktIndex > 5 {
			if p.ctx.needCycleCount && !p.ctx.gotCycleCount {
				if pktIndex == 6 {
					p.ctx.gotCycleCount = (currByte & PktCCContMask) == 0
				} else {
					p.ctx.gotCycleCount = (currByte&PktContMask) == 0 || pktIndex == 10
				}
				p.ctx.gotCCBytes++
				if !p.ctx.gotCycleCount {
					p.ctx.numPacketBytesReq++
				}
			} else if p.ctx.numCtxtIDBytes > p.ctx.gotCtxtIDBytes {
				p.ctx.gotCtxtIDBytes++
			}
		}
		if p.ctx.numPacketBytesReq == len(p.ctx.Reader.Scratch()) {
			break
		}
	}

	optIdx := 6
	scratch := p.ctx.Reader.Scratch()
	address := uint32(scratch[1]) & 0xFE
	address |= uint32(scratch[2]) << 8
	address |= uint32(scratch[3]) << 16
	address |= uint32(scratch[4]) << 24
	p.ctx.currPacket.UpdateAddress(trace.VAddr(address), 32)

	if p.ctx.needCycleCount {
		cycleCount, err := p.extractCycleCount(optIdx)
		if err != nil {
			return err
		}
		p.ctx.currPacket.CycleCount = cycleCount
		p.ctx.currPacket.CCValid = true
		optIdx += p.ctx.gotCCBytes
	}

	if p.ctx.numCtxtIDBytes > 0 {
		ctxtID, err := p.extractCtxtID(optIdx)
		if err != nil {
			return err
		}
		p.ctx.currPacket.UpdateContextID(ctxtID)
	}
	p.ctx.processState = stateSendPkt
	return nil
}

func (p *Decoder) PacketTrigger() error {
	p.ctx.processState = stateSendPkt
	return nil
}

func (p *Decoder) PacketWPointUpdate() error {
	if len(p.ctx.Reader.Scratch()) == 1 {
		p.ctx.gotAddrBytes = false
		p.ctx.numAddrBytes = 0
		p.ctx.gotExcepBytes = false
		p.ctx.numExcepBytes = 0
		p.ctx.addrPacketIsa = trace.ISAUnknown
	}

	bDone := false
	for !bDone {
		currByte, ok := p.readNextByte()
		if !ok {
			return nil // wait for more data
		}
		byteIdx := len(p.ctx.Reader.Scratch()) - 1

		if !p.ctx.gotAddrBytes {
			if byteIdx <= 4 {
				if (currByte & PktContMask) == 0 {
					p.ctx.gotAddrBytes = true
					bDone = true
					p.ctx.gotExcepBytes = true
				}
			} else {
				if (currByte & PktCCContMask) == 0 {
					p.ctx.gotExcepBytes = true
				}
				p.ctx.gotAddrBytes = true
				bDone = p.ctx.gotExcepBytes

				p.ctx.addrPacketIsa = trace.ISAArm
				switch currByte & PktBranchISAMask {
				case PktBranchISAJazelle:
					p.ctx.addrPacketIsa = trace.ISAJazelle
				case PktBranchISAThumb2:
					p.ctx.addrPacketIsa = trace.ISAThumb2
				}
			}
			p.ctx.numAddrBytes++
		} else if !p.ctx.gotExcepBytes {
			p.ctx.excepAltISA = 0
			if (currByte & PktCCContMask) == PktCCContMask {
				p.ctx.excepAltISA = 1
			}
			p.ctx.gotExcepBytes = true
			p.ctx.numExcepBytes++
			bDone = true
		}
	}

	if p.ctx.addrPacketIsa == trace.ISAUnknown {
		p.ctx.addrPacketIsa = p.ctx.currPacket.CurrISA
	}

	if p.ctx.gotExcepBytes {
		if p.ctx.addrPacketIsa == trace.ISATee && p.ctx.excepAltISA == 0 {
			p.ctx.addrPacketIsa = trace.ISAThumb2
		} else if p.ctx.addrPacketIsa == trace.ISAThumb2 && p.ctx.excepAltISA == 1 {
			p.ctx.addrPacketIsa = trace.ISATee
		}
	}
	p.ctx.currPacket.UpdateISA(p.ctx.addrPacketIsa)

	addrVal, totalBits, err := p.extractAddress(1)
	if err != nil {
		return err
	}
	p.ctx.currPacket.UpdateAddress(trace.VAddr(addrVal), int(totalBits))
	p.ctx.processState = stateSendPkt
	return nil
}

func (p *Decoder) PacketIgnore() error {
	p.ctx.processState = stateSendPkt
	return nil
}

func (p *Decoder) pktCtxtID() error {
	pktIndex := len(p.ctx.Reader.Scratch()) - 1
	if pktIndex == 0 {
		p.ctx.numCtxtIDBytes = p.Config.CtxtIDBytes
		p.ctx.gotCtxtIDBytes = 0
	}

	for p.ctx.numCtxtIDBytes > p.ctx.gotCtxtIDBytes {
		if _, ok := p.readNextByte(); !ok {
			return nil // Wait for more data
		}
		p.ctx.gotCtxtIDBytes++
	}

	if p.ctx.numCtxtIDBytes > 0 {
		ctxtID, err := p.extractCtxtID(1)
		if err != nil {
			return err
		}
		p.ctx.currPacket.UpdateContextID(ctxtID)
	}
	p.ctx.processState = stateSendPkt
	return nil
}

func (p *Decoder) PacketVMID() error {
	if currByte, ok := p.readNextByte(); ok {
		p.ctx.currPacket.UpdateVMID(currByte)
		p.ctx.processState = stateSendPkt
	}
	return nil
}

func (p *Decoder) PacketAtom() error {
	pHdr := p.ctx.Reader.Scratch()[0]
	if !p.Config.EnaCycleAcc {
		p.ctx.currPacket.SetAtomFromPHdr(pHdr)
		p.ctx.processState = stateSendPkt
	} else {
		if (pHdr & PktCCContMask) != 0 {
			for {
				currByte, ok := p.readNextByte()
				if !ok {
					return nil // wait for more data
				}
				if (currByte&PktContMask) == 0 || len(p.ctx.Reader.Scratch()) == 5 {
					break
				}
			}
		}

		if len(p.ctx.Reader.Scratch()) > 0 {
			cycleCount, err := p.extractCycleCount(0)
			if err != nil {
				return err
			}
			p.ctx.currPacket.CycleCount = cycleCount
			p.ctx.currPacket.CCValid = true
			p.ctx.currPacket.SetCycleAccAtomFromPHdr(pHdr)
			p.ctx.processState = stateSendPkt
		}
	}
	return nil
}

func (p *Decoder) PacketTimestamp() error {
	if len(p.ctx.Reader.Scratch())-1 == 0 {
		p.ctx.gotTSBytes = false
		p.ctx.needCycleCount = p.Config.EnaCycleAcc
		p.ctx.gotCCBytes = 0
		p.ctx.tsByteMax = 8
		if p.Config.TSPacket64 {
			p.ctx.tsByteMax = 10
		}
	}

	for {
		currByte, ok := p.readNextByte()
		if !ok {
			return nil // wait for more data
		}
		if !p.ctx.gotTSBytes {
			if (currByte&PktContMask) == 0 || len(p.ctx.Reader.Scratch()) == p.ctx.tsByteMax {
				p.ctx.gotTSBytes = true
				if !p.ctx.needCycleCount {
					break
				}
			}
		} else {
			ccContMask := uint8(PktContMask)
			if p.ctx.gotCCBytes == 0 {
				ccContMask = PktCCContMask
			}
			p.ctx.gotCCBytes++
			if (currByte&ccContMask) == 0 || p.ctx.gotCCBytes == 5 {
				break
			}
		}
	}

	tsVal, tsUpdateBits, tsEndIdx, err := p.extractTS()
	if err != nil {
		return err
	}
	if p.ctx.needCycleCount {
		cycleCount, err := p.extractCycleCount(tsEndIdx)
		if err != nil {
			return err
		}
		p.ctx.currPacket.CycleCount = cycleCount
		p.ctx.currPacket.CCValid = true
	}
	p.ctx.currPacket.UpdateTimestamp(tsVal, tsUpdateBits)
	p.ctx.processState = stateSendPkt
	return nil
}

func (p *Decoder) PacketExceptionRet() error {
	p.ctx.processState = stateSendPkt
	return nil
}

func (p *Decoder) pktBranchAddr() error {
	scratch := p.ctx.Reader.Scratch()
	currByte := scratch[0]
	skipLoop := false

	if len(scratch) == 1 {
		p.ctx.gotAddrBytes = false
		p.ctx.numAddrBytes = 1
		p.ctx.needCycleCount = p.Config.EnaCycleAcc
		p.ctx.gotCCBytes = 0
		p.ctx.gotExcepBytes = false
		p.ctx.numExcepBytes = 0
		p.ctx.addrPacketIsa = trace.ISAUnknown

		if (currByte & PktContMask) == 0 {
			p.ctx.gotAddrBytes = true
			p.ctx.gotExcepBytes = true
			if !p.ctx.needCycleCount {
				skipLoop = true
			}
		}
	}

	if !skipLoop {
		for {
			var ok bool
			currByte, ok = p.readNextByte()
			if !ok {
				return nil // wait for more data
			}
			byteIdx := len(p.ctx.Reader.Scratch()) - 1
			if !p.ctx.gotAddrBytes {
				if byteIdx < 4 {
					if (currByte & PktContMask) == 0 {
						if (currByte & PktCCContMask) == 0 {
							p.ctx.gotExcepBytes = true
						}
						p.ctx.gotAddrBytes = true
						p.ctx.numAddrBytes++
						if p.ctx.gotExcepBytes && !p.ctx.needCycleCount {
							break
						}
					} else {
						p.ctx.numAddrBytes++
					}
				} else {
					if (currByte & PktCCContMask) == 0 {
						p.ctx.gotExcepBytes = true
					}
					p.ctx.gotAddrBytes = true
					p.ctx.addrPacketIsa = trace.ISAArm
					switch currByte & PktBranchISAMask {
					case PktBranchISAJazelle:
						p.ctx.addrPacketIsa = trace.ISAJazelle
					case PktBranchISAThumb2:
						p.ctx.addrPacketIsa = trace.ISAThumb2
					}
					p.ctx.numAddrBytes++
					if p.ctx.gotExcepBytes && !p.ctx.needCycleCount {
						break
					}
				}
			} else if !p.ctx.gotExcepBytes {
				if p.ctx.numExcepBytes == 0 {
					if (currByte & PktContMask) == 0 {
						p.ctx.gotExcepBytes = true
					}
					p.ctx.excepAltISA = 0
					if (currByte & PktCCContMask) == PktCCContMask {
						p.ctx.excepAltISA = 1
					}
				} else {
					p.ctx.gotExcepBytes = true
				}
				p.ctx.numExcepBytes++
				if p.ctx.gotExcepBytes && !p.ctx.needCycleCount {
					break
				}
			} else if p.ctx.needCycleCount {
				if p.ctx.gotCCBytes == 0 {
					if (currByte & PktCCContMask) == 0 {
						break
					}
				} else {
					if (currByte&PktContMask) == 0 || p.ctx.gotCCBytes == 4 {
						break
					}
				}
				p.ctx.gotCCBytes++
			} else {
				return p.malformedPacketErr("sequencing error analysing branch packet")
			}
		}
	}

	if p.ctx.addrPacketIsa == trace.ISAUnknown {
		p.ctx.addrPacketIsa = p.ctx.currPacket.CurrISA
	}

	if p.ctx.gotExcepBytes {
		if p.ctx.addrPacketIsa == trace.ISATee && p.ctx.excepAltISA == 0 {
			p.ctx.addrPacketIsa = trace.ISAThumb2
		} else if p.ctx.addrPacketIsa == trace.ISAThumb2 && p.ctx.excepAltISA == 1 {
			p.ctx.addrPacketIsa = trace.ISATee
		}
	}
	p.ctx.currPacket.UpdateISA(p.ctx.addrPacketIsa)

	addrVal, totalBits, err := p.extractAddress(0)
	if err != nil {
		return err
	}
	p.ctx.currPacket.UpdateAddress(trace.VAddr(addrVal), int(totalBits))

	if p.ctx.numExcepBytes > 0 {
		scratch := p.ctx.Reader.Scratch()
		E1 := scratch[p.ctx.numAddrBytes]
		ENum := uint16(E1>>1) & 0xF
		excep := protocol.ExcpReserved

		p.ctx.currPacket.Context.CurrNS = (E1 & 0x1) != 0
		p.ctx.currPacket.Context.Updated = true

		if p.ctx.numExcepBytes > 1 {
			E2 := scratch[p.ctx.numAddrBytes+1]
			p.ctx.currPacket.Context.CurrHyp = ((E2 >> 5) & 0x1) != 0
			ENum |= uint16(E2&0x1F) << 4
		}
		if ENum <= 0xF {
			v7ARExceptions := []protocol.ArmV7Exception{
				protocol.ExcpNoException, protocol.ExcpDebugHalt, protocol.ExcpSMC, protocol.ExcpHyp,
				protocol.ExcpAsyncDAbort, protocol.ExcpJazelle, protocol.ExcpReserved, protocol.ExcpReserved,
				protocol.ExcpReset, protocol.ExcpUndef, protocol.ExcpSVC, protocol.ExcpPrefAbort,
				protocol.ExcpSyncDataAbort, protocol.ExcpGeneric, protocol.ExcpIRQ, protocol.ExcpFIQ,
			}
			excep = v7ARExceptions[ENum]
		}
		p.ctx.currPacket.SetException(excep, ENum)
	}

	if p.ctx.needCycleCount {
		countIdx := p.ctx.numAddrBytes + p.ctx.numExcepBytes
		cycleCount, err := p.extractCycleCount(countIdx)
		if err != nil {
			return err
		}
		p.ctx.currPacket.CycleCount = cycleCount
		p.ctx.currPacket.CCValid = true
	}
	p.ctx.processState = stateSendPkt
	return nil
}

func (p *Decoder) PacketReserved() error {
	p.ctx.processState = stateSendPkt
	return nil
}

func headerToPacketType(hdr byte) PacketType {
	if (hdr & PktHeaderBranchAddrMask) == PktHeaderBranchAddrMask {
		return PacketBranchAddress
	}
	if (hdr & PktHeaderAtomMask) == PktHeaderAtomVal {
		return PacketAtom
	}

	switch hdr {
	case PktHeaderASync:
		return PacketASync
	case PktHeaderISync:
		return PacketISync
	case PktHeaderWPoint:
		return PacketWPointUpdate
	case PktHeaderTrigger:
		return PacketTrigger
	case PktHeaderContextID:
		return PacketContextID
	case PktHeaderVMID:
		return PacketVMID
	case PktHeaderTimestamp1, PktHeaderTimestamp2:
		return PacketTimestamp
	case PktHeaderExcepRet:
		return PacketExceptionRet
	case PktHeaderIgnore:
		return PacketIgnore
	default:
		return PacketReserved
	}
}
