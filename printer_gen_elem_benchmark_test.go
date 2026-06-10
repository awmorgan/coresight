package coresight

import (
	"bytes"
	"io"
	"testing"
)

func BenchmarkElementFormatter_InstrRange(b *testing.B) {
	elem := instrRangeElement()
	var formatter ElementFormatter
	var buf bytes.Buffer

	for b.Loop() {
		buf.Reset()
		formatter.FormatElementTo(&buf, elem)
	}
}

func BenchmarkGenericElementPrinter_InstrRange(b *testing.B) {
	elem := instrRangeElement()
	printer := NewGenericElementPrinter(io.Discard)

	for b.Loop() {
		printer.PrintElement(elem)
	}
}

func instrRangeElement() Element {
	elem := Element{
		Index:             1234,
		TraceID:           0x10,
		ElemType:          GenElemInstrRange,
		StartAddr:         0xffffffc000123000,
		EndAddr:           0xffffffc000123040,
		ISA:               ISAAArch64,
		LastInstrCond:     true,
		LastInstrType:     InstrBr,
		LastInstrSize:     4,
		LastInstrExecuted: true,
	}
	elem.Payload.NumInstrRange = 16
	return elem
}
