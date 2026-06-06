package printers

import (
	"coresight/trace"
	"fmt"
	"io"
	"strings"
)

const rawFrameBytesPerLine = 16

type RawFramePrinter struct {
	writer io.Writer
	muted  bool
}

func NewRawFramePrinter(writer io.Writer) *RawFramePrinter {
	return &RawFramePrinter{writer: writer}
}

func (p *RawFramePrinter) SetMute(mute bool) { p.muted = mute }
func (p *RawFramePrinter) IsMuted() bool     { return p.muted }

func (p *RawFramePrinter) WriteRawFrame(index trace.Index, frameElem trace.RawframeElem, data []byte, traceID uint8) error {
	if p.muted || p.writer == nil {
		return nil
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "Frame Data; Index%7d; %s", index, rawFrameElemLabel(frameElem, traceID))
	writeRawFrameBytes(&sb, data)
	sb.WriteByte('\n')

	_, err := io.WriteString(p.writer, sb.String())
	return err
}

func rawFrameElemLabel(frameElem trace.RawframeElem, traceID uint8) string {
	switch frameElem {
	case trace.FrmPacked:
		return fmt.Sprintf("%15s", "RAW_PACKED; ")
	case trace.FrmHsync:
		return fmt.Sprintf("%15s", "HSYNC; ")
	case trace.FrmFsync:
		return fmt.Sprintf("%15s", "FSYNC; ")
	case trace.FrmIDData:
		return rawFrameIDLabel(traceID)
	default:
		return fmt.Sprintf("%15s", "UNKNOWN; ")
	}
}

func rawFrameIDLabel(traceID uint8) string {
	id := "????"
	if traceID != trace.BadCSSrcID {
		id = fmt.Sprintf("0x%02x", traceID)
	}
	return fmt.Sprintf("%10s%s]; ", "ID_DATA[", id)
}

func writeRawFrameBytes(sb *strings.Builder, data []byte) {
	for i, b := range data {
		if i > 0 && i%rawFrameBytesPerLine == 0 {
			sb.WriteByte('\n')
		}
		fmt.Fprintf(sb, "%02x ", b)
	}
}
