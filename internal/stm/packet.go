package stm

import (
	"strconv"

	"coresight/trace"
)

type PktType int

const (
	PktNotSync PktType = iota
	PktIncompleteEOT
	PktNoErrType
	PktAsync
	PktVersion
	PktFreq
	PktNull
	PktTrig
	PktGerr
	PktMerr
	PktM8
	PktC8
	PktC16
	PktFlag
	PktD4
	PktD8
	PktD16
	PktD32
	PktD64
	PktBadSequence
	PktReserved
)

type tsType int

const (
	tsUnknown tsType = iota
	tsNatBinary
	tsGrey
)

type Packet struct {
	Index     trace.Index
	Type      PktType
	Master    uint8
	Channel   uint16
	Timestamp uint64
	PktTSBits uint8
	HasTS     bool
	TSType    tsType
	HasMarker bool
	Payload   uint64
	ErrType   PktType
	TSUpdate  uint64
}

func (p *Packet) InitStartState() {
	p.Master = 0
	p.Channel = 0
	p.Timestamp = 0
	p.TSType = tsUnknown
	p.Type = PktNotSync
	p.InitNextPacket()
}

func (p *Packet) InitNextPacket() {
	p.ErrType = PktNoErrType
	p.PktTSBits = 0
	p.HasTS = false
	p.HasMarker = false
	p.Payload = 0
	p.TSUpdate = 0
}

func (p *Packet) SetType(t PktType, marker bool) {
	p.Type = t
	if marker {
		p.HasMarker = true
	}
}

func (p *Packet) UpdateErrType(t PktType) {
	p.ErrType = p.Type
	p.Type = t
}

func (p *Packet) SetMaster(master uint8) {
	p.Master = master
	p.Channel = 0
}

func (p *Packet) SetChannel(channel uint16, low8 bool) {
	if low8 {
		p.Channel = (p.Channel & 0xFF00) | (channel & 0x00FF)
	} else {
		p.Channel = channel
	}
}

func (p *Packet) OnVersionPkt(t tsType) {
	p.TSType = t
	p.Master = 0
	p.Channel = 0
}

func (p *Packet) SetTimestamp(ts uint64, updatedBits uint8) {
	if updatedBits == 64 {
		p.Timestamp = ts
	} else {
		mask := trace.BitMask(int(updatedBits))
		p.Timestamp &= ^mask
		p.Timestamp |= ts & mask
	}
	p.PktTSBits = updatedBits
	p.HasTS = true
}

func (p *Packet) IsBadPacket() bool {
	return p.Type >= PktBadSequence
}

func (p *Packet) String() string {
	return string(p.AppendStringTo(nil))
}

func (p *Packet) AppendStringTo(dst []byte) []byte {
	dst = p.appendTypeName(dst, p.Type)
	dst = append(dst, ':')
	dst = p.appendTypeDesc(dst, p.Type)

	switch p.Type {
	case PktIncompleteEOT, PktBadSequence:
		dst = append(dst, '[')
		dst = p.appendTypeName(dst, p.ErrType)
		dst = append(dst, ']')
	case PktVersion:
		dst = append(dst, "; Ver="...)
		dst = strconv.AppendUint(dst, p.Payload&0xFF, 10)
	case PktFreq:
		dst = append(dst, "; Freq="...)
		dst = strconv.AppendUint(dst, uint64(uint32(p.Payload)), 10)
		dst = append(dst, "Hz"...)
	case PktTrig:
		dst = append(dst, "; TrigData=0x"...)
		dst = appendLowerHex(dst, p.Payload&0xFF, 2)
	case PktM8:
		dst = append(dst, "; Master=0x"...)
		dst = appendLowerHex(dst, uint64(p.Master), 2)
	case PktC8, PktC16:
		dst = append(dst, "; Chan=0x"...)
		dst = appendLowerHex(dst, uint64(p.Channel), 4)
	case PktD4:
		dst = append(dst, "; Data=0x"...)
		dst = strconv.AppendUint(dst, p.Payload&0xF, 16)
	case PktD8:
		dst = append(dst, "; Data=0x"...)
		dst = appendLowerHex(dst, p.Payload&0xFF, 2)
	case PktD16:
		dst = append(dst, "; Data=0x"...)
		dst = appendLowerHex(dst, p.Payload&0xFFFF, 4)
	case PktD32:
		dst = append(dst, "; Data=0x"...)
		dst = appendLowerHex(dst, uint64(uint32(p.Payload)), 8)
	case PktD64:
		dst = append(dst, "; Data=0x"...)
		dst = appendLowerHex(dst, p.Payload, 16)
	}

	if p.HasTS {
		dst = append(dst, "; TS=0x"...)
		dst = appendUpperHex(dst, p.Timestamp, 16)
		dst = append(dst, " ~[0x"...)
		dst = appendUpperHex(dst, p.TSUpdate&trace.BitMask(int(p.PktTSBits)), 0)
		dst = append(dst, ']')
	}
	return dst
}

func (p *Packet) appendTypeName(dst []byte, t PktType) []byte {
	switch t {
	case PktReserved:
		return append(dst, "RESERVED"...)
	case PktNotSync:
		return append(dst, "NOTSYNC"...)
	case PktIncompleteEOT:
		return append(dst, "INCOMPLETE_EOT"...)
	case PktNoErrType:
		return append(dst, "NO_ERR_TYPE"...)
	case PktBadSequence:
		return append(dst, "BAD_SEQUENCE"...)
	case PktAsync:
		return append(dst, "ASYNC"...)
	case PktVersion:
		return append(dst, "VERSION"...)
	case PktFreq:
		return append(dst, "FREQ"...)
	case PktNull:
		return append(dst, "NULL"...)
	case PktTrig:
		dst = append(dst, "TRIG"...)
	case PktGerr:
		return append(dst, "GERR"...)
	case PktMerr:
		return append(dst, "MERR"...)
	case PktM8:
		return append(dst, "M8"...)
	case PktC8:
		return append(dst, "C8"...)
	case PktC16:
		return append(dst, "C16"...)
	case PktFlag:
		dst = append(dst, "FLAG"...)
	case PktD4:
		dst = append(dst, "D4"...)
	case PktD8:
		dst = append(dst, "D8"...)
	case PktD16:
		dst = append(dst, "D16"...)
	case PktD32:
		dst = append(dst, "D32"...)
	case PktD64:
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

func (p *Packet) appendTypeDesc(dst []byte, t PktType) []byte {
	switch t {
	case PktReserved:
		return append(dst, "Reserved Packet Header"...)
	case PktNotSync:
		return append(dst, "STM not synchronised"...)
	case PktIncompleteEOT:
		return append(dst, "Incomplete packet flushed at end of trace"...)
	case PktNoErrType:
		return append(dst, "Error type not set"...)
	case PktBadSequence:
		return append(dst, "Invalid sequence in packet"...)
	case PktAsync:
		return append(dst, "Alignment synchronisation packet"...)
	case PktVersion:
		return append(dst, "Version packet"...)
	case PktFreq:
		return append(dst, "Frequency packet"...)
	case PktNull:
		return append(dst, "Null packet"...)
	case PktTrig:
		dst = append(dst, "Trigger packet"...)
	case PktGerr:
		return append(dst, "Global Error"...)
	case PktMerr:
		return append(dst, "Master Error"...)
	case PktM8:
		return append(dst, "Set current master"...)
	case PktC8, PktC16:
		return append(dst, "Set current channel"...)
	case PktFlag:
		dst = append(dst, "Flag packet"...)
	case PktD4:
		dst = append(dst, "4 bit data"...)
	case PktD8:
		dst = append(dst, "8 bit data"...)
	case PktD16:
		dst = append(dst, "16 bit data"...)
	case PktD32:
		dst = append(dst, "32 bit data"...)
	case PktD64:
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

func appendLowerHex(dst []byte, value uint64, minWidth int) []byte {
	var buf [16]byte
	b := strconv.AppendUint(buf[:0], value, 16)
	for i := len(b); i < minWidth; i++ {
		dst = append(dst, '0')
	}
	return append(dst, b...)
}

func appendUpperHex(dst []byte, value uint64, minWidth int) []byte {
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
