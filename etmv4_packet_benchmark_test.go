package coresight

import (
	"testing"
)

func BenchmarkEtmv4PacketString_Atom(b *testing.B) {
	pkt := etmv4Packet{
		Type: pktAtomF6,
		Atom: etmv4Atom{EnBits: 0x1f, Num: 6},
	}
	for b.Loop() {
		_ = pkt.String()
	}
}

func BenchmarkEtmv4PacketAppendStringTo_Atom(b *testing.B) {
	pkt := etmv4Packet{
		Type: pktAtomF6,
		Atom: etmv4Atom{EnBits: 0x1f, Num: 6},
	}
	buf := make([]byte, 0, 128)
	for b.Loop() {
		buf = pkt.AppendStringTo(buf[:0])
	}
}

func BenchmarkEtmv4PacketString_AddressContext(b *testing.B) {
	pkt := etmv4Packet{
		Type: pktAddrCtxtL64IS1,
		Addr: etmv4Address{
			Val:       VAddr(0xffffffc000123456),
			IS:        1,
			Size:      64,
			PktBits:   64,
			ValidBits: 64,
		},
		Context: etmv4Context{
			Updated:  true,
			UpdatedC: true,
			UpdatedV: true,
			SF:       true,
			NS:       true,
			EL:       1,
			CtxtID:   0x12345678,
			VMID:     0x42,
		},
	}
	for b.Loop() {
		_ = pkt.String()
	}
}

func BenchmarkEtmv4PacketAppendStringTo_AddressContext(b *testing.B) {
	pkt := etmv4Packet{
		Type: pktAddrCtxtL64IS1,
		Addr: etmv4Address{
			Val:       VAddr(0xffffffc000123456),
			IS:        1,
			Size:      64,
			PktBits:   64,
			ValidBits: 64,
		},
		Context: etmv4Context{
			Updated:  true,
			UpdatedC: true,
			UpdatedV: true,
			SF:       true,
			NS:       true,
			EL:       1,
			CtxtID:   0x12345678,
			VMID:     0x42,
		},
	}
	buf := make([]byte, 0, 160)
	for b.Loop() {
		buf = pkt.AppendStringTo(buf[:0])
	}
}
