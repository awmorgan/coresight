package etmv3

import (
	"testing"

	"github.com/awmorgan/coresight/trace"
)

func BenchmarkPacketString_PHdr(b *testing.B) {
	pkt := Packet{
		Type:       PktPHdr,
		Atom:       AtomPkt{EnBits: 0x1f, Num: 6},
		PHdrFmt:    1,
		CycleCount: 6,
	}
	for b.Loop() {
		_ = pkt.String()
	}
}

func BenchmarkPacketAppendStringTo_PHdr(b *testing.B) {
	pkt := Packet{
		Type:       PktPHdr,
		Atom:       AtomPkt{EnBits: 0x1f, Num: 6},
		PHdrFmt:    1,
		CycleCount: 6,
	}
	buf := make([]byte, 0, 128)
	for b.Loop() {
		buf = pkt.AppendStringTo(buf[:0])
	}
}

func BenchmarkPacketString_BranchAddress(b *testing.B) {
	pkt := Packet{
		Type:        PktBranchAddress,
		Addr:        0xc0012345,
		AddrPktBits: 32,
		CurrISA:     trace.ISAThumb2,
		PrevISA:     trace.ISAArm,
	}
	for b.Loop() {
		_ = pkt.String()
	}
}

func BenchmarkPacketAppendStringTo_BranchAddress(b *testing.B) {
	pkt := Packet{
		Type:        PktBranchAddress,
		Addr:        0xc0012345,
		AddrPktBits: 32,
		CurrISA:     trace.ISAThumb2,
		PrevISA:     trace.ISAArm,
	}
	buf := make([]byte, 0, 128)
	for b.Loop() {
		buf = pkt.AppendStringTo(buf[:0])
	}
}

func BenchmarkPacketString_ISync(b *testing.B) {
	pkt := Packet{
		Type:    PktISyncCycle,
		Addr:    0xc0012345,
		CurrISA: trace.ISAThumb2,
		Context: Context{
			CurrNS:   true,
			UpdatedC: true,
			CtxtID:   0x12345678,
		},
		ISyncInfo:  ISyncInfo{Reason: trace.ISyncPeriodic},
		CycleCount: 12,
	}
	for b.Loop() {
		_ = pkt.String()
	}
}

func BenchmarkPacketAppendStringTo_ISync(b *testing.B) {
	pkt := Packet{
		Type:    PktISyncCycle,
		Addr:    0xc0012345,
		CurrISA: trace.ISAThumb2,
		Context: Context{
			CurrNS:   true,
			UpdatedC: true,
			CtxtID:   0x12345678,
		},
		ISyncInfo:  ISyncInfo{Reason: trace.ISyncPeriodic},
		CycleCount: 12,
	}
	buf := make([]byte, 0, 160)
	for b.Loop() {
		buf = pkt.AppendStringTo(buf[:0])
	}
}
