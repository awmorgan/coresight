package ptm

import (
	"testing"

	"github.com/awmorgan/coresight/internal/protocol"
	"github.com/awmorgan/coresight/trace"
)

func BenchmarkPacketString_Atom(b *testing.B) {
	pkt := Packet{
		Type: PacketAtom,
		Atom: AtomPkt{EnBits: 0x1f, Num: 6},
	}
	for b.Loop() {
		_ = pkt.String()
	}
}

func BenchmarkPacketString_BranchAddress(b *testing.B) {
	pkt := Packet{
		Type:          PacketBranchAddress,
		AddrVal:       trace.VAddr(0xc0012345),
		AddrBits:      32,
		AddrValidBits: 32,
		CurrISA:       trace.ISAThumb2,
		PrevISA:       trace.ISAArm,
		Context:       Context{Updated: true, CurrNS: true},
	}
	for b.Loop() {
		_ = pkt.String()
	}
}

func BenchmarkPacketString_ISync(b *testing.B) {
	pkt := Packet{
		Type:        PacketISync,
		AddrVal:     trace.VAddr(0xc0012345),
		CurrISA:     trace.ISAThumb2,
		Context:     Context{CurrNS: true, UpdatedC: true, CtxtID: 0x12345678},
		ISyncReason: protocol.ISyncPeriodic,
		CycleCount:  12,
		CCValid:     true,
	}
	for b.Loop() {
		_ = pkt.String()
	}
}
