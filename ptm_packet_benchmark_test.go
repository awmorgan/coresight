package coresight

import (
	"testing"

)

func BenchmarkPtmPacketString_Atom(b *testing.B) {
	pkt := ptmPacket{
		Type: PacketAtom,
		Atom: ptmAtomPkt{EnBits: 0x1f, Num: 6},
	}
	for b.Loop() {
		_ = pkt.String()
	}
}

func BenchmarkPtmPacketString_BranchAddress(b *testing.B) {
	pkt := ptmPacket{
		Type:          PacketBranchAddress,
		AddrVal:       VAddr(0xc0012345),
		AddrBits:      32,
		AddrValidBits: 32,
		CurrISA:       ISAThumb2,
		PrevISA:       ISAArm,
		Context:          ptmContext{Updated: true, CurrNS: true},
	}
	for b.Loop() {
		_ = pkt.String()
	}
}

func BenchmarkPtmPacketString_ISync(b *testing.B) {
	pkt := ptmPacket{
		Type:        PacketISync,
		AddrVal:     VAddr(0xc0012345),
		CurrISA:     ISAThumb2,
		Context:     ptmContext{CurrNS: true, UpdatedC: true, CtxtID: 0x12345678},
		ISyncReason: iSyncPeriodic,
		CycleCount:  12,
		CCValid:     true,
	}
	for b.Loop() {
		_ = pkt.String()
	}
}
