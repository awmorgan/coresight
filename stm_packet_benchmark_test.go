package coresight

import "testing"

func BenchmarkPacketString_Data32Timestamp(b *testing.B) {
	pkt := stmPacket{
		Type:      pktD32,
		Payload:   0x12345678,
		Timestamp: 0x123456789abcdef0,
		TSUpdate:  0xdef0,
		PktTSBits: 16,
		HasTS:     true,
		HasMarker: true,
	}
	for b.Loop() {
		_ = pkt.String()
	}
}

func BenchmarkPacketAppendStringTo_Data32Timestamp(b *testing.B) {
	pkt := stmPacket{
		Type:      pktD32,
		Payload:   0x12345678,
		Timestamp: 0x123456789abcdef0,
		TSUpdate:  0xdef0,
		PktTSBits: 16,
		HasTS:     true,
		HasMarker: true,
	}
	buf := make([]byte, 0, 160)
	for b.Loop() {
		buf = pkt.AppendStringTo(buf[:0])
	}
}

func BenchmarkPacketString_Channel(b *testing.B) {
	pkt := stmPacket{Type: pktC16, Channel: 0x1234}
	for b.Loop() {
		_ = pkt.String()
	}
}

func BenchmarkPacketAppendStringTo_Channel(b *testing.B) {
	pkt := stmPacket{Type: pktC16, Channel: 0x1234}
	buf := make([]byte, 0, 80)
	for b.Loop() {
		buf = pkt.AppendStringTo(buf[:0])
	}
}
