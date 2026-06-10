package coresight

import (
	"fmt"
	"io"
	"strings"
)

const rawFrameBytesPerLine = 16

// RawFramePrinter formats and prints raw trace frames to a writer.
type RawFramePrinter struct {
	writer io.Writer
	muted  bool
}

// NewRawFramePrinter returns a new RawFramePrinter.
func NewRawFramePrinter(writer io.Writer) *RawFramePrinter {
	return &RawFramePrinter{writer: writer}
}

// SetMute configures whether printing is muted.
func (p *RawFramePrinter) SetMute(mute bool) { p.muted = mute }

// IsMuted returns true if the printer is muted.
func (p *RawFramePrinter) IsMuted() bool { return p.muted }

// WriteRawFrame writes a raw trace frame to the output writer.
func (p *RawFramePrinter) WriteRawFrame(index Index, frameElem RawframeElem, data []byte, traceID uint8) error {
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

func rawFrameElemLabel(frameElem RawframeElem, traceID uint8) string {
	switch frameElem {
	case FrmPacked:
		return fmt.Sprintf("%15s", "RAW_PACKED; ")
	case FrmHsync:
		return fmt.Sprintf("%15s", "HSYNC; ")
	case FrmFsync:
		return fmt.Sprintf("%15s", "FSYNC; ")
	case FrmIDData:
		return rawFrameIDLabel(traceID)
	default:
		return fmt.Sprintf("%15s", "UNKNOWN; ")
	}
}

func rawFrameIDLabel(traceID uint8) string {
	id := "????"
	if traceID != badCSSrcID {
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
