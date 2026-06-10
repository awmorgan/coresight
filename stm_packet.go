package coresight

import (
	"strconv"
)

type stmPktType int

const (
	stmPktNotSync stmPktType = iota
	stmPktIncompleteEOT
	stmPktNoErrType
	stmPktAsync
	pktVersion
	pktFreq
	pktNull
	pktTrig
	pktGerr
	pktMerr
	pktM8
	pktC8
	pktC16
	pktFlag
	pktD4
	pktD8
	pktD16
	pktD32
	pktD64
	stmPktBadSequence
	stmPktReserved
)

type tsType int

const (
	tsUnknown tsType = iota
	tsNatBinary
	tsGrey
)

type stmPacket struct {
	Index     Index
	Type      stmPktType
	Master    uint8
	Channel   uint16
	Timestamp uint64
	PktTSBits uint8
	HasTS     bool
	TSType    tsType
	HasMarker bool
	Payload   uint64
	errType   stmPktType
	TSUpdate  uint64
}

func (p *stmPacket) InitStartState() {
	p.Master = 0
	p.Channel = 0
	p.Timestamp = 0
	p.TSType = tsUnknown
	p.Type = stmPktNotSync
	p.InitNextPacket()
}

func (p *stmPacket) InitNextPacket() {
	p.errType = stmPktNoErrType
	p.PktTSBits = 0
	p.HasTS = false
	p.HasMarker = false
	p.Payload = 0
	p.TSUpdate = 0
}

func (p *stmPacket) SetType(t stmPktType, marker bool) {
	p.Type = t
	if marker {
		p.HasMarker = true
	}
}

func (p *stmPacket) UpdateErrType(t stmPktType) {
	p.errType = p.Type
	p.Type = t
}

func (p *stmPacket) SetMaster(master uint8) {
	p.Master = master
	p.Channel = 0
}

func (p *stmPacket) SetChannel(channel uint16, low8 bool) {
	if low8 {
		p.Channel = (p.Channel & 0xFF00) | (channel & 0x00FF)
	} else {
		p.Channel = channel
	}
}

func (p *stmPacket) OnVersionPkt(t tsType) {
	p.TSType = t
	p.Master = 0
	p.Channel = 0
}

func (p *stmPacket) setTimestamp(ts uint64, updatedBits uint8) {
	if updatedBits == 64 {
		p.Timestamp = ts
	} else {
		mask := bitMask(int(updatedBits))
		p.Timestamp &= ^mask
		p.Timestamp |= ts & mask
	}
	p.PktTSBits = updatedBits
	p.HasTS = true
}

func (p *stmPacket) IsBadPacket() bool {
	return p.Type >= stmPktBadSequence
}

func (p *stmPacket) String() string {
	return string(p.AppendStringTo(nil))
}

func (p *stmPacket) AppendStringTo(dst []byte) []byte {
	dst = p.appendTypeName(dst, p.Type)
	dst = append(dst, ':')
	dst = p.appendTypeDesc(dst, p.Type)

	switch p.Type {
	case stmPktIncompleteEOT, stmPktBadSequence:
		dst = append(dst, '[')
		dst = p.appendTypeName(dst, p.errType)
		dst = append(dst, ']')
	case pktVersion:
		dst = append(dst, "; Ver="...)
		dst = strconv.AppendUint(dst, p.Payload&0xFF, 10)
	case pktFreq:
		dst = append(dst, "; Freq="...)
		dst = strconv.AppendUint(dst, uint64(uint32(p.Payload)), 10)
		dst = append(dst, "Hz"...)
	case pktTrig:
		dst = append(dst, "; TrigData=0x"...)
		dst = stmAppendLowerHex(dst, p.Payload&0xFF, 2)
	case pktM8:
		dst = append(dst, "; Master=0x"...)
		dst = stmAppendLowerHex(dst, uint64(p.Master), 2)
	case pktC8, pktC16:
		dst = append(dst, "; Chan=0x"...)
		dst = stmAppendLowerHex(dst, uint64(p.Channel), 4)
	case pktD4:
		dst = append(dst, "; Data=0x"...)
		dst = strconv.AppendUint(dst, p.Payload&0xF, 16)
	case pktD8:
		dst = append(dst, "; Data=0x"...)
		dst = stmAppendLowerHex(dst, p.Payload&0xFF, 2)
	case pktD16:
		dst = append(dst, "; Data=0x"...)
		dst = stmAppendLowerHex(dst, p.Payload&0xFFFF, 4)
	case pktD32:
		dst = append(dst, "; Data=0x"...)
		dst = stmAppendLowerHex(dst, uint64(uint32(p.Payload)), 8)
	case pktD64:
		dst = append(dst, "; Data=0x"...)
		dst = stmAppendLowerHex(dst, p.Payload, 16)
	}

	if p.HasTS {
		dst = append(dst, "; TS=0x"...)
		dst = stmAppendUpperHex(dst, p.Timestamp, 16)
		dst = append(dst, " ~[0x"...)
		dst = stmAppendUpperHex(dst, p.TSUpdate&bitMask(int(p.PktTSBits)), 0)
		dst = append(dst, ']')
	}
	return dst
}

func (p *stmPacket) appendTypeName(dst []byte, t stmPktType) []byte {
	switch t {
	case stmPktReserved:
		return append(dst, "RESERVED"...)
	case stmPktNotSync:
		return append(dst, "NOTSYNC"...)
	case stmPktIncompleteEOT:
		return append(dst, "INCOMPLETE_EOT"...)
	case stmPktNoErrType:
		return append(dst, "NO_ERR_TYPE"...)
	case stmPktBadSequence:
		return append(dst, "BAD_SEQUENCE"...)
	case stmPktAsync:
		return append(dst, "ASYNC"...)
	case pktVersion:
		return append(dst, "VERSION"...)
	case pktFreq:
		return append(dst, "FREQ"...)
	case pktNull:
		return append(dst, "NULL"...)
	case pktTrig:
		dst = append(dst, "TRIG"...)
	case pktGerr:
		return append(dst, "GERR"...)
	case pktMerr:
		return append(dst, "MERR"...)
	case pktM8:
		return append(dst, "M8"...)
	case pktC8:
		return append(dst, "C8"...)
	case pktC16:
		return append(dst, "C16"...)
	case pktFlag:
		dst = append(dst, "FLAG"...)
	case pktD4:
		dst = append(dst, "D4"...)
	case pktD8:
		dst = append(dst, "D8"...)
	case pktD16:
		dst = append(dst, "D16"...)
	case pktD32:
		dst = append(dst, "D32"...)
	case pktD64:
		dst = append(dst, "D64"...)
	default:
		return append(dst, "UNKNOWN"...)
	}
	if p.HasMarker {
		dst = append(dst, 'M')
	}
	if p.HasTS {
		dst = append(dst, "TS"...)
	}
	return dst
}

func (p *stmPacket) appendTypeDesc(dst []byte, t stmPktType) []byte {
	switch t {
	case stmPktReserved:
		return append(dst, "Reserved Packet Header"...)
	case stmPktNotSync:
		return append(dst, "STM not synchronised"...)
	case stmPktIncompleteEOT:
		return append(dst, "Incomplete packet flushed at end of trace"...)
	case stmPktNoErrType:
		return append(dst, "Error type not set"...)
	case stmPktBadSequence:
		return append(dst, "Invalid sequence in packet"...)
	case stmPktAsync:
		return append(dst, "Alignment synchronisation packet"...)
	case pktVersion:
		return append(dst, "Version packet"...)
	case pktFreq:
		return append(dst, "Frequency packet"...)
	case pktNull:
		return append(dst, "Null packet"...)
	case pktTrig:
		dst = append(dst, "Trigger packet"...)
	case pktGerr:
		return append(dst, "Global Error"...)
	case pktMerr:
		return append(dst, "Master Error"...)
	case pktM8:
		return append(dst, "Set current master"...)
	case pktC8, pktC16:
		return append(dst, "Set current channel"...)
	case pktFlag:
		dst = append(dst, "Flag packet"...)
	case pktD4:
		dst = append(dst, "4 bit data"...)
	case pktD8:
		dst = append(dst, "8 bit data"...)
	case pktD16:
		dst = append(dst, "16 bit data"...)
	case pktD32:
		dst = append(dst, "32 bit data"...)
	case pktD64:
		dst = append(dst, "64 bit data"...)
	default:
		return append(dst, "ERROR: unknown packet type"...)
	}
	if p.HasMarker {
		dst = append(dst, " + marker"...)
	}
	if p.HasTS {
		dst = append(dst, " + timestamp"...)
	}
	return dst
}

func stmAppendLowerHex(dst []byte, value uint64, minWidth int) []byte {
	var buf [16]byte
	b := strconv.AppendUint(buf[:0], value, 16)
	for i := len(b); i < minWidth; i++ {
		dst = append(dst, '0')
	}
	return append(dst, b...)
}

func stmAppendUpperHex(dst []byte, value uint64, minWidth int) []byte {
	var buf [16]byte
	b := strconv.AppendUint(buf[:0], value, 16)
	for i := len(b); i < minWidth; i++ {
		dst = append(dst, '0')
	}
	for _, c := range b {
		if c >= 'a' && c <= 'f' {
			c -= 'a' - 'A'
		}
		dst = append(dst, c)
	}
	return dst
}
