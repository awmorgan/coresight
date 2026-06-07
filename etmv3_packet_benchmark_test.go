package coresight

import (
	"testing"

)

func BenchmarkEtmv3PacketString_PHdr(b *testing.B) {
	pkt := etmv3Packet{
		Type:       PktPHdr,
		Atom:       etmv3AtomPkt{EnBits: 0x1f, Num: 6},
		PHdrFmt:    1,
		CycleCount: 6,
	}
	for b.Loop() {
		_ = pkt.String()
	}
}

func BenchmarkEtmv3PacketAppendStringTo_PHdr(b *testing.B) {
	pkt := etmv3Packet{
		Type:       PktPHdr,
		Atom:       etmv3AtomPkt{EnBits: 0x1f, Num: 6},
		PHdrFmt:    1,
		CycleCount: 6,
	}
	buf := make([]byte, 0, 128)
	for b.Loop() {
		buf = pkt.AppendStringTo(buf[:0])
	}
}

func BenchmarkEtmv3PacketString_BranchAddress(b *testing.B) {
	pkt := etmv3Packet{
		Type:        PktBranchAddress,
		Addr:        0xc0012345,
		AddrPktBits: 32,
		CurrISA:     ISAThumb2,
		PrevISA:     ISAArm,
	}
	for b.Loop() {
		_ = pkt.String()
	}
}

func BenchmarkEtmv3PacketAppendStringTo_BranchAddress(b *testing.B) {
	pkt := etmv3Packet{
		Type:        PktBranchAddress,
		Addr:        0xc0012345,
		AddrPktBits: 32,
		CurrISA:     ISAThumb2,
		PrevISA:     ISAArm,
	}
	buf := make([]byte, 0, 128)
	for b.Loop() {
		buf = pkt.AppendStringTo(buf[:0])
	}
}

func BenchmarkEtmv3PacketString_ISync(b *testing.B) {
	pkt := etmv3Packet{
		Type:    PktISyncCycle,
		Addr:    0xc0012345,
		CurrISA: ISAThumb2,
		Context: etmv3Context{
			CurrNS:   true,
			UpdatedC: true,
			CtxtID:   0x12345678,
		},
		ISyncInfo:  etmv3ISyncInfo{Reason: iSyncPeriodic},
		CycleCount: 12,
	}
	for b.Loop() {
		_ = pkt.String()
	}
}

func BenchmarkEtmv3PacketAppendStringTo_ISync(b *testing.B) {
	pkt := etmv3Packet{
		Type:    PktISyncCycle,
		Addr:    0xc0012345,
		CurrISA: ISAThumb2,
		Context: etmv3Context{
			CurrNS:   true,
			UpdatedC: true,
			CtxtID:   0x12345678,
		},
		ISyncInfo:  etmv3ISyncInfo{Reason: iSyncPeriodic},
		CycleCount: 12,
	}
	buf := make([]byte, 0, 160)
	for b.Loop() {
		buf = pkt.AppendStringTo(buf[:0])
	}
}
