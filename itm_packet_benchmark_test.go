package coresight

import "testing"

func BenchmarkPacketString_SWIT(b *testing.B) {
	pkt := itmPacket{Type: pktSWIT, SrcID: 0x12, Value: 0x12345678, ValSz: 4}
	for b.Loop() {
		_ = pkt.String()
	}
}

func BenchmarkPacketString_DWT(b *testing.B) {
	pkt := itmPacket{Type: pktDWT, SrcID: 0x10, Value: 0x12345678, ValSz: 4}
	for b.Loop() {
		_ = pkt.String()
	}
}

func BenchmarkPacketString_TSLocal(b *testing.B) {
	pkt := itmPacket{Type: pktTSLocal, SrcID: 0x3, Value: 0x12345678, ValSz: 4}
	for b.Loop() {
		_ = pkt.String()
	}
}
