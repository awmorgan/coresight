package etmv4

import (
	"testing"

	"github.com/awmorgan/coresight/trace"
)

func BenchmarkPacketString_Atom(b *testing.B) {
	pkt := Packet{
		Type: PktAtomF6,
		Atom: Atom{EnBits: 0x1f, Num: 6},
	}
	for b.Loop() {
		_ = pkt.String()
	}
}

func BenchmarkPacketAppendStringTo_Atom(b *testing.B) {
	pkt := Packet{
		Type: PktAtomF6,
		Atom: Atom{EnBits: 0x1f, Num: 6},
	}
	buf := make([]byte, 0, 128)
	for b.Loop() {
		buf = pkt.AppendStringTo(buf[:0])
	}
}

func BenchmarkPacketString_AddressContext(b *testing.B) {
	pkt := Packet{
		Type: PktAddrCtxtL64IS1,
		Addr: Address{
			Val:       trace.VAddr(0xffffffc000123456),
			IS:        1,
			Size:      64,
			PktBits:   64,
			ValidBits: 64,
		},
		Context: Context{
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

func BenchmarkPacketAppendStringTo_AddressContext(b *testing.B) {
	pkt := Packet{
		Type: PktAddrCtxtL64IS1,
		Addr: Address{
			Val:       trace.VAddr(0xffffffc000123456),
			IS:        1,
			Size:      64,
			PktBits:   64,
			ValidBits: 64,
		},
		Context: Context{
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
