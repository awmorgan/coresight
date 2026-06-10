package coresight


type etmv4ProcessState int

const (
	etmv4StateProcHdr etmv4ProcessState = iota
	etmv4StateProcData
	etmv4StateSendPkt
	stateSendUnsynced
)

type etmv4PacketHandler func(*etmv4Decoder, byte) error

type packetTableEntry struct {
	pktType etmv4PacketType
	handler etmv4PacketHandler
}

type etmv4ParseContext struct {
	internalByteStream
	processState etmv4ProcessState
	currHandler  etmv4PacketHandler
	currPacket   etmv4Packet
	packetIndex  Index

	isSync                  bool
	firstTraceInfo          bool
	sentNotSync             bool
	raw                     []byte
	dumpUnsyncedBytes       int
	updateUnsyncPacketIndex Index

	table [256]packetTableEntry

	tinfoSectFlags uint8
	tinfoCtrlBytes uint8

	addrBytes    int
	addrIS       uint8
	addr64       bool
	vmidBytes    int
	ctxtIDBytes  int
	ctxtInfoDone bool
	ccountDone   bool
	tsDone       bool
	tsBytes      int
	excepSize    int
	hasCount     bool
	countDone    bool
	commitDone   bool
	ccf2MaxSpec  bool
	hasAddr      bool
	addrShort    bool
	addrMatch    bool
	qType        uint8
}

const (
	tinfoInfoSect = 0x01
	tinfoKeySect  = 0x02
	tinfoSpecSect = 0x04
	tinfoCyctSect = 0x08
	tinfoWndwSect = 0x10
	tinfoCtrl     = 0x20
	tinfoAllSect  = 0x1F
	tinfoAll      = 0x3F
)

func (d *etmv4Decoder) processData(index Index, data []byte) (uint32, error) {
	d.ctx.Feed(index, data)
	for d.ctx.Reader.Len() > 0 || d.ctx.processState == etmv4StateSendPkt {
		switch d.ctx.processState {
		case etmv4StateProcHdr:
			d.ctx.packetIndex = d.ctx.CurrentIndex()
			if d.ctx.isSync {
				b, err := d.ctx.Reader.Peek()
				if err != nil {
					return uint32(d.ctx.BytesConsumed()), nil
				}
				entry := d.ctx.table[b]
				d.ctx.currPacket.Type = entry.pktType
				d.ctx.currHandler = entry.handler
			} else {
				d.ctx.currPacket.Type = etmv4PktNotSync
				d.ctx.currHandler = (*etmv4Decoder).iNotSync
			}
			d.ctx.processState = etmv4StateProcData

		case etmv4StateProcData:
			if d.ctx.currHandler == nil {
				d.ctx.processState = etmv4StateProcHdr
				break
			}
			for d.ctx.Reader.Len() > 0 && d.ctx.processState == etmv4StateProcData {
				b, _ := d.ctx.Reader.ReadByteRaw()
				d.ctx.raw = append(d.ctx.raw, b)
				if err := d.ctx.currHandler(d, b); err != nil {
					return uint32(d.ctx.BytesConsumed()), err
				}
			}

		case etmv4StateSendPkt:
			if err := d.outputPacket(); err != nil {
				return uint32(d.ctx.BytesConsumed()), err
			}
			d.initPacketState()
			d.ctx.processState = etmv4StateProcHdr

		case stateSendUnsynced:
			d.outputUnsyncedRawPacket()
			if d.ctx.updateUnsyncPacketIndex != 0 {
				d.ctx.packetIndex = d.ctx.updateUnsyncPacketIndex
				d.ctx.updateUnsyncPacketIndex = 0
			}
			d.ctx.processState = etmv4StateProcData
		}
	}
	return uint32(d.ctx.BytesConsumed()), nil
}

func (d *etmv4Decoder) outputPacket() error {
	d.ctx.currPacket.Index = d.ctx.packetIndex
	d.ctx.currPacket.IsETE = d.Config.IsETE()
	if d.pendingRawPrefix != "" {
		d.ctx.currPacket.RawPrefix = d.pendingRawPrefix
		d.pendingRawPrefix = ""
	}
	d.EmitPacket(d.ctx.packetIndex, &d.ctx.currPacket, d.ctx.raw)
	return d.processPacket(&d.ctx.currPacket)
}

func (d *etmv4Decoder) outputUnsyncedRawPacket() {
	n := min(d.ctx.dumpUnsyncedBytes, len(d.ctx.raw))
	if n <= 0 {
		return
	}
	d.ctx.currPacket.Index = d.ctx.packetIndex
	d.EmitPacket(d.ctx.packetIndex, &d.ctx.currPacket, d.ctx.raw[:n])
	if !d.ctx.sentNotSync {
		_ = d.processPacket(&d.ctx.currPacket)
		d.ctx.sentNotSync = true
	}
	copy(d.ctx.raw, d.ctx.raw[n:])
	d.ctx.raw = d.ctx.raw[:len(d.ctx.raw)-n]
}

func (d *etmv4Decoder) initPacketState() {
	d.ctx.raw = d.ctx.raw[:0]
	d.ctx.currPacket.InitNextPacket()
	d.ctx.updateUnsyncPacketIndex = 0
}

func (d *etmv4Decoder) initProcessorState() {
	d.initPacketState()
	d.ctx.processState = etmv4StateProcHdr
	d.ctx.currHandler = (*etmv4Decoder).iNotSync
	d.ctx.packetIndex = 0
	d.ctx.isSync = false
	d.ctx.firstTraceInfo = false
	d.ctx.sentNotSync = false
	d.ctx.currPacket.InitStartState()
	d.buildPacketTable()
}

func (d *etmv4Decoder) iNotSync(lastByte byte) error {
	if lastByte == 0 {
		if len(d.ctx.raw) > 1 {
			d.ctx.dumpUnsyncedBytes = len(d.ctx.raw) - 1
			d.ctx.processState = stateSendUnsynced
			d.ctx.updateUnsyncPacketIndex = d.ctx.BlockBaseIdx + Index(d.ctx.BytesConsumed()) - 1
		} else {
			d.ctx.packetIndex = d.ctx.BlockBaseIdx + Index(d.ctx.BytesConsumed()) - 1
		}
		d.ctx.currHandler = d.ctx.table[lastByte].handler
	} else if len(d.ctx.raw) >= 8 {
		d.ctx.dumpUnsyncedBytes = len(d.ctx.raw)
		d.ctx.processState = stateSendUnsynced
		d.ctx.updateUnsyncPacketIndex = d.ctx.BlockBaseIdx + Index(d.ctx.BytesConsumed())
	}
	return nil
}

func (d *etmv4Decoder) iPktNoPayload(lastByte byte) error {
	switch d.ctx.currPacket.Type {
	case PktAddrMatch, PktSrcAddrMatch:
		d.ctx.currPacket.setAddressExactMatch(lastByte & 0x3)
	case PktEvent:
		d.ctx.currPacket.EventVal = lastByte & 0xF
	case PktNumDSMarker, PktUnnumDSMarker:
		d.ctx.currPacket.DSMVal = lastByte & 0x7
	}
	d.ctx.processState = etmv4StateSendPkt
	return nil
}

func (d *etmv4Decoder) iPktReserved(lastByte byte) error {
	d.ctx.currPacket.updateErr(etmv4PktReserved, errInvalidPcktHdr)
	d.ctx.processState = etmv4StateSendPkt
	return nil
}

func (d *etmv4Decoder) iPktInvalidCfg(lastByte byte) error {
	d.ctx.currPacket.updateErr(PktReservedCfg, errInvalidPcktHdr)
	d.ctx.processState = etmv4StateSendPkt
	return nil
}

func (d *etmv4Decoder) iPktExtension(lastByte byte) error {
	if len(d.ctx.raw) != 2 {
		return nil
	}
	if !d.ctx.isSync && lastByte != 0 {
		d.ctx.currPacket.Type = etmv4PktNotSync
		d.ctx.currHandler = (*etmv4Decoder).iNotSync
		return nil
	}
	switch lastByte {
	case 0x00:
		d.ctx.currPacket.Type = etmv4PktASync
		d.ctx.currHandler = (*etmv4Decoder).iPktASync
	case 0x03:
		d.ctx.currPacket.Type = PktDiscard
		d.ctx.processState = etmv4StateSendPkt
	case 0x05:
		d.ctx.currPacket.Type = PktOverflow
		d.ctx.processState = etmv4StateSendPkt
	default:
		d.ctx.currPacket.updateErr(etmv4PktBadSequence, errBadPacketSeq)
		d.ctx.processState = etmv4StateSendPkt
	}
	return nil
}

func (d *etmv4Decoder) iPktASync(lastByte byte) error {
	if lastByte != 0 {
		if !d.ctx.isSync && len(d.ctx.raw) != 12 {
			d.ctx.currPacket.Type = etmv4PktNotSync
			d.ctx.currHandler = (*etmv4Decoder).iNotSync
			return nil
		}
		d.ctx.processState = etmv4StateSendPkt
		if len(d.ctx.raw) != 12 || lastByte != 0x80 {
			d.ctx.currPacket.updateErr(etmv4PktBadSequence, errBadPacketSeq)
		} else {
			d.ctx.isSync = true
		}
	} else if len(d.ctx.raw) == 12 {
		if !d.ctx.isSync {
			d.ctx.dumpUnsyncedBytes = 1
			d.ctx.processState = stateSendUnsynced
		} else {
			d.ctx.currPacket.updateErr(etmv4PktBadSequence, errBadPacketSeq)
			d.ctx.processState = etmv4StateSendPkt
		}
	}
	return nil
}

func (d *etmv4Decoder) iPktTraceInfo(lastByte byte) error {
	switch len(d.ctx.raw) {
	case 1:
		d.ctx.tinfoSectFlags = 0
		d.ctx.tinfoCtrlBytes = 1
	case 2:
		d.ctx.tinfoSectFlags = (^lastByte) & tinfoAllSect
		if lastByte&0x80 == 0 {
			d.ctx.tinfoSectFlags |= tinfoCtrl
		}
	default:
		if d.ctx.tinfoSectFlags&tinfoCtrl == 0 {
			if lastByte&0x80 == 0 {
				d.ctx.tinfoSectFlags |= tinfoCtrl
			}
			d.ctx.tinfoCtrlBytes++
		} else if d.ctx.tinfoSectFlags&tinfoInfoSect == 0 {
			if lastByte&0x80 == 0 {
				d.ctx.tinfoSectFlags |= tinfoInfoSect
			}
		} else if d.ctx.tinfoSectFlags&tinfoKeySect == 0 {
			if lastByte&0x80 == 0 {
				d.ctx.tinfoSectFlags |= tinfoKeySect
			}
		} else if d.ctx.tinfoSectFlags&tinfoSpecSect == 0 {
			if lastByte&0x80 == 0 {
				d.ctx.tinfoSectFlags |= tinfoSpecSect
			}
		} else if d.ctx.tinfoSectFlags&tinfoCyctSect == 0 {
			if lastByte&0x80 == 0 {
				d.ctx.tinfoSectFlags |= tinfoCyctSect
			}
		} else if d.ctx.tinfoSectFlags&tinfoWndwSect == 0 && lastByte&0x80 == 0 {
			d.ctx.tinfoSectFlags |= tinfoWndwSect
		}
	}
	if d.ctx.tinfoSectFlags == tinfoAll {
		idx := int(d.ctx.tinfoCtrlBytes) + 1
		pres := d.ctx.raw[1] & tinfoAllSect
		d.ctx.currPacket.TraceInfo = etmv4TraceInfo{}
		if pres&tinfoInfoSect != 0 && idx < len(d.ctx.raw) {
			v, n := extractContField(d.ctx.raw, idx, 5)
			idx += n
			d.ctx.currPacket.TraceInfo.Value = v
			d.ctx.currPacket.TraceInfo.CCEnabled = v&1 != 0
			d.ctx.currPacket.TraceInfo.InTransState = v&0x40 != 0
		}
		if pres&tinfoKeySect != 0 && idx < len(d.ctx.raw) {
			v, n := extractContField(d.ctx.raw, idx, 5)
			idx += n
			d.ctx.currPacket.P0Key = v
		}
		if pres&tinfoSpecSect != 0 && idx < len(d.ctx.raw) {
			v, n := extractContField(d.ctx.raw, idx, 5)
			idx += n
			d.ctx.currPacket.CurrSpecDepth = v
			d.ctx.currPacket.TraceInfo.SpecFieldPresent = true
		}
		if pres&tinfoCyctSect != 0 && idx < len(d.ctx.raw) {
			v, n := extractContField(d.ctx.raw, idx, 5)
			idx += n
			d.ctx.currPacket.CCThreshold = v
		}
		if !d.ctx.firstTraceInfo {
			d.ctx.currPacket.TraceInfo.Initial = true
			d.ctx.firstTraceInfo = true
		}
		d.ctx.processState = etmv4StateSendPkt
	}
	return nil
}

func (d *etmv4Decoder) iPktTimestamp(lastByte byte) error {
	if len(d.ctx.raw) == 1 {
		d.ctx.ccountDone = lastByte&1 == 0
		d.ctx.tsDone = false
		d.ctx.tsBytes = 0
		return nil
	}
	if !d.ctx.tsDone {
		d.ctx.tsBytes++
		d.ctx.tsDone = d.ctx.tsBytes == 9 || lastByte&0x80 == 0
	} else if !d.ctx.ccountDone {
		d.ctx.ccountDone = lastByte&0x80 == 0
	}
	if d.ctx.tsDone && d.ctx.ccountDone {
		ts, n := extractTSField64(d.ctx.raw, 1)
		bits := uint8(n * 7)
		if n >= 9 {
			bits = 64
		}
		if d.ctx.currPacket.TSBitsChanged == 0 && d.ctx.firstTraceInfo {
			bits = 64
		}
		d.ctx.currPacket.setTimestamp(ts, bits)
		if d.ctx.raw[0]&1 != 0 {
			cc, _ := extractContField(d.ctx.raw, 1+n, 3)
			d.ctx.currPacket.CycleCount = cc & uint32(bitMask(int(d.Config.CCSize())))
			d.ctx.currPacket.CCValid = true
		}
		d.ctx.processState = etmv4StateSendPkt
	}
	return nil
}

func (d *etmv4Decoder) iPktException(lastByte byte) error {
	switch len(d.ctx.raw) {
	case 1:
		d.ctx.excepSize = 3
	case 2:
		if lastByte&0x80 == 0 {
			d.ctx.excepSize = 2
		}
		if d.Config.IsETE() {
			excepType := (d.ctx.raw[1] >> 1) & 0x1F
			if excepType == 0 || excepType == 0x18 {
				d.ctx.excepSize = 3
			}
		}
	}
	if len(d.ctx.raw) == d.ctx.excepSize {
		excepType := uint16((d.ctx.raw[1] >> 1) & 0x1F)
		addrInterp := uint8((d.ctx.raw[1]&0x40)>>5 | (d.ctx.raw[1] & 0x1))
		mFaultPending := false
		if d.ctx.raw[1]&0x80 != 0 {
			excepType |= uint16(d.ctx.raw[2]&0x1F) << 5
			mFaultPending = ((d.ctx.raw[2] >> 5) & 0x1) != 0
		}
		d.ctx.currPacket.Exception.Type = excepType
		d.ctx.currPacket.Exception.AddrInterp = addrInterp
		d.ctx.currPacket.Exception.MFaultPending = mFaultPending
		d.ctx.currPacket.Exception.MType = d.Config.CoreProf == ProfileCortexM
		d.ctx.processState = etmv4StateSendPkt

		if d.Config.IsETE() {
			if excepType == 0x0 || excepType == 0x18 {
				d.ctx.currPacket.Addr = etmv4Address{Size: 64, ValidBits: 64}
				if excepType == 0x18 {
					d.ctx.currPacket.Type = PktTransFail
				} else {
					d.ctx.currPacket.Type = PktPEReset
				}
			}
		}
	}
	return nil
}

func (d *etmv4Decoder) iPktITE(lastByte byte) error {
	if len(d.ctx.raw) < 10 {
		return nil
	}
	d.ctx.currPacket.ITE.EL = d.ctx.raw[1]
	var value uint64
	for i := range 8 {
		value |= uint64(d.ctx.raw[2+i]) << (i * 8)
	}
	d.ctx.currPacket.ITE.Value = value
	d.ctx.processState = etmv4StateSendPkt
	return nil
}

func (d *etmv4Decoder) iPktCycleCntF123(lastByte byte) error {
	if len(d.ctx.raw) == 1 {
		h := d.ctx.raw[0]
		d.ctx.countDone = false
		d.ctx.commitDone = false
		d.ctx.ccf2MaxSpec = false
		d.ctx.hasCount = true

		switch d.ctx.currPacket.Type {
		case PktCycleCountF3:
			if !d.Config.CommitOpt1() {
				d.ctx.currPacket.Commit = uint32((h>>2)&0x3) + 1
				d.ctx.currPacket.CommitValid = true
			}
			d.ctx.currPacket.CycleCount = d.ctx.currPacket.CCThreshold + uint32(h&0x3)
			d.ctx.currPacket.CCValid = true
			d.ctx.processState = etmv4StateSendPkt
		case PktCycleCountF1:
			if h&0x1 != 0 {
				d.ctx.hasCount = false
				d.ctx.countDone = true
			}
			if d.Config.CommitOpt1() {
				d.ctx.commitDone = true
			}
			if d.ctx.commitDone && d.ctx.countDone {
				d.ctx.currPacket.CycleCount = 0
				d.ctx.currPacket.CCValid = true
				d.ctx.processState = etmv4StateSendPkt
			}
		case PktCycleCountF2:
			d.ctx.ccf2MaxSpec = h&0x1 != 0
		}
		return nil
	}
	if d.ctx.currPacket.Type == PktCycleCountF2 && len(d.ctx.raw) == 2 {
		d.ctx.currPacket.CycleCount = d.ctx.currPacket.CCThreshold + uint32(lastByte&0xF)
		d.ctx.currPacket.CCValid = true
		if !d.Config.CommitOpt1() {
			commitOffset := 1
			if d.ctx.ccf2MaxSpec {
				commitOffset = int(d.Config.MaxSpecDepth()) - 15
			}
			d.ctx.currPacket.Commit = uint32(int((lastByte>>4)&0xF) + commitOffset)
			d.ctx.currPacket.CommitValid = true
		}
		d.ctx.processState = etmv4StateSendPkt
		return nil
	}
	if !d.ctx.countDone {
		d.ctx.countDone = lastByte&0x80 == 0
	} else if !d.ctx.commitDone {
		d.ctx.commitDone = lastByte&0x80 == 0
	}
	if d.ctx.countDone && d.ctx.commitDone {
		idx := 1
		if !d.Config.CommitOpt1() {
			v, n := extractContField(d.ctx.raw, idx, 5)
			idx += n
			d.ctx.currPacket.Commit = v
			d.ctx.currPacket.CommitValid = true
		}
		if d.ctx.hasCount {
			v, _ := extractContField(d.ctx.raw, idx, 3)
			d.ctx.currPacket.CycleCount = d.ctx.currPacket.CCThreshold + v
		} else {
			d.ctx.currPacket.CycleCount = 0
		}
		d.ctx.currPacket.CCValid = true
		d.ctx.processState = etmv4StateSendPkt
	}
	return nil
}

func (d *etmv4Decoder) iPktSpeclRes(lastByte byte) error {
	h := d.ctx.raw[0]
	if len(d.ctx.raw) == 1 {
		switch d.ctx.currPacket.Type {
		case PktMispredict:
			switch h & 0x3 {
			case 0x1:
				d.ctx.currPacket.Atom = etmv4Atom{EnBits: 0x1, Num: 1}
			case 0x2:
				d.ctx.currPacket.Atom = etmv4Atom{EnBits: 0x3, Num: 2}
			case 0x3:
				d.ctx.currPacket.Atom = etmv4Atom{EnBits: 0x0, Num: 1}
			}
			d.ctx.currPacket.Cancel = 0
			d.ctx.currPacket.CancelValid = true
			d.ctx.processState = etmv4StateSendPkt
		case PktCancelF2:
			switch h & 0x3 {
			case 0x1:
				d.ctx.currPacket.Atom = etmv4Atom{EnBits: 0x1, Num: 1}
			case 0x2:
				d.ctx.currPacket.Atom = etmv4Atom{EnBits: 0x3, Num: 2}
			case 0x3:
				d.ctx.currPacket.Atom = etmv4Atom{EnBits: 0x0, Num: 1}
			}
			d.ctx.currPacket.Cancel = 1
			d.ctx.currPacket.CancelValid = true
			d.ctx.processState = etmv4StateSendPkt
		case PktCancelF3:
			d.ctx.currPacket.Cancel = uint32((h>>1)&0x3) + 2
			d.ctx.currPacket.CancelValid = true
			if h&0x1 != 0 {
				d.ctx.currPacket.Atom = etmv4Atom{EnBits: 1, Num: 1}
			}
			d.ctx.processState = etmv4StateSendPkt
		}
		return nil
	}

	if lastByte&0x80 == 0 {
		field, _ := extractContField(d.ctx.raw, 1, 5)
		switch d.ctx.currPacket.Type {
		case PktCommit:
			d.ctx.currPacket.Commit = field
			d.ctx.currPacket.CommitValid = true
		case PktCancelF1, PktCancelF1Mispred:
			d.ctx.currPacket.Cancel = field
			d.ctx.currPacket.CancelValid = true
		}
		d.ctx.processState = etmv4StateSendPkt
	}
	return nil
}

func (d *etmv4Decoder) iPktContext(lastByte byte) error {
	switch len(d.ctx.raw) {
	case 1:
		d.ctx.vmidBytes = 0
		d.ctx.ctxtIDBytes = 0
		if lastByte&0x1 == 0 {
			d.ctx.processState = etmv4StateSendPkt
		}
		return nil
	case 2:
		d.ctx.vmidBytes, d.ctx.ctxtIDBytes = contextPayloadBytes(lastByte, d.Config)
	}
	if len(d.ctx.raw) >= 2+d.ctx.vmidBytes+d.ctx.ctxtIDBytes {
		extractAndSetContextInfo(&d.ctx.currPacket, d.ctx.raw, 1, d.Config)
		d.ctx.processState = etmv4StateSendPkt
	}
	return nil
}

func (d *etmv4Decoder) iPktAddrCtxt(lastByte byte) error {
	if len(d.ctx.raw) == 1 {
		h := d.ctx.raw[0]
		d.ctx.addrIS = packetAddrIS(d.ctx.currPacket.Type)
		d.ctx.addr64 = h >= 0x85
		d.ctx.addrBytes = 4
		if d.ctx.addr64 {
			d.ctx.addrBytes = 8
		}
		d.ctx.vmidBytes = 0
		d.ctx.ctxtIDBytes = 0
		d.ctx.ctxtInfoDone = false
		return nil
	}
	infoIdx := 1 + d.ctx.addrBytes
	if !d.ctx.ctxtInfoDone && len(d.ctx.raw) > infoIdx {
		d.ctx.vmidBytes, d.ctx.ctxtIDBytes = contextPayloadBytes(d.ctx.raw[infoIdx], d.Config)
		d.ctx.ctxtInfoDone = true
	}
	if d.ctx.ctxtInfoDone && len(d.ctx.raw) >= infoIdx+1+d.ctx.vmidBytes+d.ctx.ctxtIDBytes {
		idx := 1
		d.setLongAddr(idx, d.ctx.addrIS, d.ctx.addr64)
		idx += d.ctx.addrBytes
		extractAndSetContextInfo(&d.ctx.currPacket, d.ctx.raw, idx, d.Config)
		d.ctx.processState = etmv4StateSendPkt
	}
	return nil
}

func (d *etmv4Decoder) iPktShortAddr(lastByte byte) error {
	if len(d.ctx.raw) == 1 {
		d.ctx.addrIS = packetAddrIS(d.ctx.currPacket.Type)
		return nil
	}
	if len(d.ctx.raw) == 3 || lastByte&0x80 == 0 {
		value, bits, _ := extractShortAddr(d.ctx.raw, 1, d.ctx.addrIS)
		addr := d.ctx.currPacket.Addr
		mask := bitMask(bits)
		addr.Val = VAddr((uint64(addr.Val) & ^mask) | (uint64(value) & mask))
		addr.IS = d.ctx.addrIS
		addr.PktBits = bits
		if addr.ValidBits < bits {
			addr.ValidBits = bits
		}
		if addr.Size == 0 {
			addr.Size = 64
		}
		d.ctx.currPacket.pushAddr(addr)
		d.ctx.processState = etmv4StateSendPkt
	}
	return nil
}

func (d *etmv4Decoder) iPktLongAddr(lastByte byte) error {
	if len(d.ctx.raw) == 1 {
		h := d.ctx.raw[0]
		d.ctx.addrIS = packetAddrIS(d.ctx.currPacket.Type)
		d.ctx.addr64 = h >= 0x9D && h < 0xB0 || h >= 0xB8
		d.ctx.addrBytes = 4
		if d.ctx.addr64 {
			d.ctx.addrBytes = 8
		}
	}
	if len(d.ctx.raw) >= 1+d.ctx.addrBytes {
		d.setLongAddr(1, d.ctx.addrIS, d.ctx.addr64)
		d.ctx.processState = etmv4StateSendPkt
	}
	return nil
}

func (d *etmv4Decoder) iPktQ(lastByte byte) error {
	if len(d.ctx.raw) == 1 {
		h := d.ctx.raw[0]
		d.ctx.qType = h & 0xF

		d.ctx.addrBytes = 0
		d.ctx.countDone = false
		d.ctx.hasAddr = false
		d.ctx.addrShort = true
		d.ctx.addrMatch = false
		d.ctx.addrIS = 1

		switch d.ctx.qType {
		// count only - implied address
		case 0x0, 0x1, 0x2:
			d.ctx.addrMatch = true
			d.ctx.hasAddr = true
		case 0xC:
			break

		// count + short address
		case 0x5:
			d.ctx.addrIS = 0
			fallthrough
		case 0x6:
			d.ctx.hasAddr = true
			d.ctx.addrBytes = 2

		// count + long address
		case 0xA:
			d.ctx.addrIS = 0
			fallthrough
		case 0xB:
			d.ctx.hasAddr = true
			d.ctx.addrShort = false
			d.ctx.addrBytes = 4

		// no count, no address
		case 0xF:
			d.ctx.countDone = true

		default:
			d.ctx.currPacket.updateErr(etmv4PktBadSequence, errBadPacketSeq)
			d.ctx.processState = etmv4StateSendPkt
			return nil
		}
		return nil
	}

	if d.ctx.addrBytes > 0 {
		if d.ctx.addrShort && d.ctx.addrBytes == 2 {
			if lastByte&0x80 == 0 {
				d.ctx.addrBytes--
			}
		}
		d.ctx.addrBytes--
	} else if !d.ctx.countDone {
		d.ctx.countDone = lastByte&0x80 == 0
	}

	if d.ctx.addrBytes == 0 && d.ctx.countDone {
		idx := 1
		var qCount uint32

		if d.ctx.hasAddr {
			if d.ctx.addrMatch {
				d.ctx.currPacket.setAddressExactMatch(d.ctx.qType & 0x3)
			} else if d.ctx.addrShort {
				v, bits, consumed := extractShortAddr(d.ctx.raw, idx, d.ctx.addrIS)
				addr := d.ctx.currPacket.Addr
				mask := bitMask(bits)
				addr.Val = VAddr((uint64(addr.Val) & ^mask) | (uint64(v) & mask))
				addr.IS = d.ctx.addrIS
				addr.PktBits = bits
				if addr.ValidBits < bits {
					addr.ValidBits = bits
				}
				if addr.Size == 0 {
					addr.Size = 64
				}
				d.ctx.currPacket.pushAddr(addr)
				idx += consumed
			} else {
				d.setLongAddr(idx, d.ctx.addrIS, false)
				idx += 4
			}
		}

		if d.ctx.qType != 0xF {
			v, n := extractContField(d.ctx.raw, idx, 5)
			qCount = v
			idx += n
		}

		q := etmv4QInfo{
			Type:         d.ctx.qType,
			CountPresent: d.ctx.qType != 0xF,
			Count:        qCount,
			AddrPresent:  d.ctx.hasAddr,
			AddrMatch:    d.ctx.addrMatch,
		}
		d.ctx.currPacket.Q = q
		d.ctx.processState = etmv4StateSendPkt
	}
	return nil
}

func (d *etmv4Decoder) iAtom(lastByte byte) error {
	h := d.ctx.raw[0]
	var pattern uint32
	var count uint8
	switch d.ctx.currPacket.Type {
	case PktAtomF1:
		count = 1
		pattern = uint32(h & 0x1)
	case PktAtomF2:
		count = 2
		pattern = uint32(h & 0x3)
	case PktAtomF3:
		count = 3
		pattern = uint32(h & 0x7)
	case PktAtomF4:
		count = 4
		pattern = [...]uint32{0xE, 0x0, 0xA, 0x5}[h&0x3]
	case PktAtomF5:
		count = 5
		switch ((h & 0x20) >> 3) | (h & 0x3) {
		case 5:
			pattern = 0x1E
		case 1:
			pattern = 0
		case 2:
			pattern = 0x0A
		case 3:
			pattern = 0x15
		}
	case PktAtomF6:
		eCount := (h & 0x1F) + 3
		count = eCount + 1
		pattern = uint32(bitMask(int(eCount)))
		if h&0x20 == 0 {
			pattern |= 1 << eCount
		}
	}
	d.ctx.currPacket.Atom = etmv4Atom{EnBits: pattern, Num: count}
	d.ctx.processState = etmv4StateSendPkt
	return nil
}

func (d *etmv4Decoder) iPktUnsupported(lastByte byte) error {
	d.ctx.currPacket.updateErr(etmv4PktBadTraceMode, errHWCfgUnsupp)
	d.ctx.processState = etmv4StateSendPkt
	return nil
}

func (d *etmv4Decoder) setLongAddr(idx int, is uint8, is64 bool) {
	var value uint64
	if is == 0 {
		value |= uint64(d.ctx.raw[idx]&0x7F) << 2
		value |= uint64(d.ctx.raw[idx+1]&0x7F) << 9
	} else {
		value |= uint64(d.ctx.raw[idx]&0x7F) << 1
		value |= uint64(d.ctx.raw[idx+1]) << 8
	}
	value |= uint64(d.ctx.raw[idx+2]) << 16
	value |= uint64(d.ctx.raw[idx+3]) << 24
	size := 64
	valid := 64
	pktBits := 64
	if is64 {
		value |= uint64(d.ctx.raw[idx+4]) << 32
		value |= uint64(d.ctx.raw[idx+5]) << 40
		value |= uint64(d.ctx.raw[idx+6]) << 48
		value |= uint64(d.ctx.raw[idx+7]) << 56
	} else {
		pktBits = 32
		if d.ctx.currPacket.Context.SF {
			value = (uint64(d.ctx.currPacket.Addr.Val) & ^bitMask(32)) | (value & bitMask(32))
		}
	}
	d.ctx.currPacket.pushAddr(etmv4Address{Val: VAddr(value), IS: is, Size: size, ValidBits: valid, PktBits: pktBits})
}

func contextPayloadBytes(info byte, cfg *etmv4Config) (vmidBytes, ctxtIDBytes int) {
	if info&0x40 != 0 {
		vmidBytes = int(cfg.VMIDSize() / 8)
	}
	if info&0x80 != 0 {
		ctxtIDBytes = int(cfg.CIDSize() / 8)
	}
	return vmidBytes, ctxtIDBytes
}

func extractAndSetContextInfo(pkt *etmv4Packet, b []byte, idx int, cfg *etmv4Config) {
	if idx >= len(b) {
		return
	}
	info := b[idx]
	idx++
	pkt.Context.Updated = true
	pkt.Context.EL = info & 0x3
	pkt.Context.NS = info&0x20 != 0
	pkt.Context.SF = info&0x10 != 0
	pkt.Context.NSE = info&0x08 != 0
	if info&0x40 != 0 {
		bytes := int(cfg.VMIDSize() / 8)
		for i := 0; i < bytes && idx+i < len(b); i++ {
			pkt.Context.VMID |= uint32(b[idx+i]) << (i * 8)
		}
		idx += bytes
		pkt.Context.UpdatedV = bytes > 0
	}
	if info&0x80 != 0 {
		bytes := int(cfg.CIDSize() / 8)
		for i := 0; i < bytes && idx+i < len(b); i++ {
			pkt.Context.CtxtID |= uint32(b[idx+i]) << (i * 8)
		}
		pkt.Context.UpdatedC = bytes > 0
	}
}

func packetAddrIS(t etmv4PacketType) uint8 {
	switch t {
	case PktAddrCtxtL32IS1, PktAddrCtxtL64IS1, PktAddrSIS1, PktAddrL32IS1, PktAddrL64IS1,
		PktSrcAddrSIS1, PktSrcAddrL32IS1, PktSrcAddrL64IS1:
		return 1
	default:
		return 0
	}
}

func extractShortAddr(b []byte, idx int, is uint8) (uint32, int, int) {
	shift := 2
	if is != 0 {
		shift = 1
	}
	if idx >= len(b) {
		return 0, 0, 0
	}
	value := uint32(b[idx]&0x7F) << shift
	bits := 7 + shift
	consumed := 1
	if b[idx]&0x80 != 0 && idx+1 < len(b) {
		value |= uint32(b[idx+1]) << (7 + shift)
		bits += 8
		consumed++
	}
	return value, bits, consumed
}

func extractContField(b []byte, idx, limit int) (uint32, int) {
	var value uint32
	for i := 0; i < limit && idx+i < len(b); i++ {
		by := b[idx+i]
		value |= uint32(by&0x7F) << (i * 7)
		if by&0x80 == 0 {
			return value, i + 1
		}
	}
	return value, min(limit, len(b)-idx)
}

func extractTSField64(b []byte, idx int) (uint64, int) {
	var value uint64
	for i := 0; idx+i < len(b); i++ {
		by := b[idx+i]
		mask := byte(0x7F)
		last := by&0x80 == 0
		if i == 8 {
			mask = 0xFF
			last = true
		}
		value |= uint64(by&mask) << (i * 7)
		if last {
			return value, i + 1
		}
	}
	return value, len(b) - idx
}

func (d *etmv4Decoder) buildPacketTable() {
	for i := range d.ctx.table {
		d.ctx.table[i] = packetTableEntry{etmv4PktReserved, (*etmv4Decoder).iPktReserved}
	}
	set := func(h byte, t etmv4PacketType, fn etmv4PacketHandler) { d.ctx.table[h] = packetTableEntry{t, fn} }
	set(0x00, PktExtension, (*etmv4Decoder).iPktExtension)
	set(0x01, PktTraceInfo, (*etmv4Decoder).iPktTraceInfo)
	set(0x02, etmv4PktTimestamp, (*etmv4Decoder).iPktTimestamp)
	set(0x03, etmv4PktTimestamp, (*etmv4Decoder).iPktTimestamp)
	set(0x04, PktTraceOn, (*etmv4Decoder).iPktNoPayload)
	set(0x05, PktFuncRet, (*etmv4Decoder).iPktNoPayload)
	set(0x06, PktException, (*etmv4Decoder).iPktException)
	exceptRtnFn := (*etmv4Decoder).iPktNoPayload
	if d.Config.IsETE() {
		exceptRtnFn = (*etmv4Decoder).iPktInvalidCfg
	}
	set(0x07, PktExceptionReturn, exceptRtnFn)
	if d.Config.IsETE() {
		set(0x09, PktITE, (*etmv4Decoder).iPktITE)
		set(0x0A, PktTransStart, (*etmv4Decoder).iPktNoPayload)
		set(0x0B, PktTransCommit, (*etmv4Decoder).iPktNoPayload)
	}
	for i := range 4 {
		t := PktCycleCountF2
		if i >= 2 {
			t = PktCycleCountF1
		}
		set(byte(0x0C+i), t, (*etmv4Decoder).iPktCycleCntF123)
	}
	for i := range 16 {
		set(byte(0x10+i), PktCycleCountF3, (*etmv4Decoder).iPktCycleCntF123)
	}
	for i := range 8 {
		fn := (*etmv4Decoder).iPktInvalidCfg
		if d.Config.EnabledDataTrace() {
			fn = (*etmv4Decoder).iPktNoPayload
		}
		set(byte(0x20+i), PktNumDSMarker, fn)
	}
	for i := range 5 {
		fn := (*etmv4Decoder).iPktInvalidCfg
		if d.Config.EnabledDataTrace() {
			fn = (*etmv4Decoder).iPktNoPayload
		}
		set(byte(0x28+i), PktUnnumDSMarker, fn)
	}
	set(0x2D, PktCommit, (*etmv4Decoder).iPktSpeclRes)
	set(0x2E, PktCancelF1, (*etmv4Decoder).iPktSpeclRes)
	set(0x2F, PktCancelF1Mispred, (*etmv4Decoder).iPktSpeclRes)
	for i := range 4 {
		set(byte(0x30+i), PktMispredict, (*etmv4Decoder).iPktSpeclRes)
		set(byte(0x34+i), PktCancelF2, (*etmv4Decoder).iPktSpeclRes)
	}
	for i := range 8 {
		set(byte(0x38+i), PktCancelF3, (*etmv4Decoder).iPktSpeclRes)
	}
	condFn := (*etmv4Decoder).iPktUnsupported
	if d.Config.HasCondTrace() && d.Config.EnabledCondITrace() != condTraceDisabled {
		condFn = (*etmv4Decoder).iPktNoPayload
	}
	for _, h := range []byte{0x40, 0x41, 0x42} {
		set(h, PktCondInstrF2, condFn)
	}
	set(0x43, PktCondFlush, condFn)
	for _, h := range []byte{0x44, 0x45, 0x46} {
		set(h, PktCondResultF4, condFn)
	}
	for _, h := range []byte{0x48, 0x49, 0x4A, 0x4C, 0x4D, 0x4E} {
		set(h, PktCondResultF2, condFn)
	}
	for i := range 16 {
		set(byte(0x50+i), PktCondResultF3, condFn)
	}
	for _, h := range []byte{0x68, 0x69, 0x6A, 0x6B, 0x6E, 0x6F} {
		set(h, PktCondResultF1, condFn)
	}
	set(0x6C, PktCondInstrF1, condFn)
	set(0x6D, PktCondInstrF3, condFn)
	if d.Config.FullVersion() >= 0x43 {
		set(0x70, etmv4PktIgnore, (*etmv4Decoder).iPktNoPayload)
	}
	for i := range 15 {
		set(byte(0x71+i), PktEvent, (*etmv4Decoder).iPktNoPayload)
	}
	set(0x80, PktContext, (*etmv4Decoder).iPktContext)
	set(0x81, PktContext, (*etmv4Decoder).iPktContext)
	set(0x82, PktAddrCtxtL32IS0, (*etmv4Decoder).iPktAddrCtxt)
	set(0x83, PktAddrCtxtL32IS1, (*etmv4Decoder).iPktAddrCtxt)
	set(0x85, PktAddrCtxtL64IS0, (*etmv4Decoder).iPktAddrCtxt)
	set(0x86, PktAddrCtxtL64IS1, (*etmv4Decoder).iPktAddrCtxt)
	if d.Config.FullVersion() >= 0x46 {
		set(0x88, PktTSMarker, (*etmv4Decoder).iPktNoPayload)
	}
	for i := range 3 {
		set(byte(0x90+i), PktAddrMatch, (*etmv4Decoder).iPktNoPayload)
	}
	set(0x95, PktAddrSIS0, (*etmv4Decoder).iPktShortAddr)
	set(0x96, PktAddrSIS1, (*etmv4Decoder).iPktShortAddr)
	set(0x9A, PktAddrL32IS0, (*etmv4Decoder).iPktLongAddr)
	set(0x9B, PktAddrL32IS1, (*etmv4Decoder).iPktLongAddr)
	set(0x9D, PktAddrL64IS0, (*etmv4Decoder).iPktLongAddr)
	set(0x9E, PktAddrL64IS1, (*etmv4Decoder).iPktLongAddr)
	for i := range 16 {
		switch i {
		case 3, 4, 7, 8, 9, 13, 14:
		default:
			if d.Config.HasQElem() {
				set(byte(0xA0+i), PktQ, (*etmv4Decoder).iPktQ)
			}
		}
	}
	if d.Config.IsETE() {
		for i := range 3 {
			set(byte(0xB0+i), PktSrcAddrMatch, (*etmv4Decoder).iPktNoPayload)
		}
		set(0xB4, PktSrcAddrSIS0, (*etmv4Decoder).iPktShortAddr)
		set(0xB5, PktSrcAddrSIS1, (*etmv4Decoder).iPktShortAddr)
		set(0xB6, PktSrcAddrL32IS0, (*etmv4Decoder).iPktLongAddr)
		set(0xB7, PktSrcAddrL32IS1, (*etmv4Decoder).iPktLongAddr)
		set(0xB8, PktSrcAddrL64IS0, (*etmv4Decoder).iPktLongAddr)
		set(0xB9, PktSrcAddrL64IS1, (*etmv4Decoder).iPktLongAddr)
	}
	for i := 0xC0; i <= 0xD4; i++ {
		set(byte(i), PktAtomF6, (*etmv4Decoder).iAtom)
	}
	for i := 0xD5; i <= 0xD7; i++ {
		set(byte(i), PktAtomF5, (*etmv4Decoder).iAtom)
	}
	for i := 0xD8; i <= 0xDB; i++ {
		set(byte(i), PktAtomF2, (*etmv4Decoder).iAtom)
	}
	for i := 0xDC; i <= 0xDF; i++ {
		set(byte(i), PktAtomF4, (*etmv4Decoder).iAtom)
	}
	for i := 0xE0; i <= 0xF4; i++ {
		set(byte(i), PktAtomF6, (*etmv4Decoder).iAtom)
	}
	set(0xF5, PktAtomF5, (*etmv4Decoder).iAtom)
	set(0xF6, PktAtomF1, (*etmv4Decoder).iAtom)
	set(0xF7, PktAtomF1, (*etmv4Decoder).iAtom)
	for i := 0xF8; i <= 0xFF; i++ {
		set(byte(i), PktAtomF3, (*etmv4Decoder).iAtom)
	}
}
