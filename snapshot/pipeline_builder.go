package snapshot

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/awmorgan/coresight"
)

var snapshotNewPipeline = coresight.NewPipeline

// PipelineBuilder builds a coresight.Pipeline from snapshot metadata.
type PipelineBuilder struct {
	reader         *SnapshotReader
	pipe           *coresight.Pipeline
	packetProcOnly bool
	bufferFileName string
	mapper         *coresight.GlobalMapper
	diagnostics    []string

	errOnAA64BadOpcode bool
	instrRangeLimit    uint32
	srcAddrNAtoms      bool
}

// NewPipelineBuilder creates a new builder for a coresight.Pipeline from a SnapshotReader.
func NewPipelineBuilder(r *SnapshotReader) *PipelineBuilder {
	return &PipelineBuilder{reader: r}
}

// Pipeline returns the built coresight.Pipeline, or nil if Build has not succeeded.
func (b *PipelineBuilder) Pipeline() *coresight.Pipeline {
	return b.pipe
}

// BufferFileName returns the full path of the trace binary buffer file to load.
func (b *PipelineBuilder) BufferFileName() string {
	return b.bufferFileName
}

// MemoryMapper returns the builder-managed memory mapper used in full decode mode.
// It returns nil when packet-only mode is selected.
func (b *PipelineBuilder) MemoryMapper() *coresight.GlobalMapper {
	return b.mapper
}

// Diagnostics returns non-fatal snapshot-to-pipeline conversion diagnostics.
func (b *PipelineBuilder) Diagnostics() []string {
	return append([]string(nil), b.diagnostics...)
}

// SetErrOnAA64BadOpcode controls whether the decoder returns an error on bad AArch64 opcodes.
func (b *PipelineBuilder) SetErrOnAA64BadOpcode(enabled bool) {
	b.errOnAA64BadOpcode = enabled
}

// SetInstrRangeLimit sets an optional limit on consecutive instructions decoded per range element.
func (b *PipelineBuilder) SetInstrRangeLimit(limit uint32) {
	b.instrRangeLimit = limit
}

// SetSrcAddrNAtoms controls whether source addresses are emitted on N-atom packets.
func (b *PipelineBuilder) SetSrcAddrNAtoms(enabled bool) {
	b.srcAddrNAtoms = enabled
}

// Build builds the pipeline for a specific named source buffer (e.g., "ETB_0").
func (b *PipelineBuilder) Build(sourceName string, packetProcOnly bool) (*coresight.Pipeline, error) {
	if !b.reader.ReadOK {
		return nil, fmt.Errorf("supplied snapshot reader has not correctly read the snapshot")
	}

	if b.reader.Trace == nil {
		return nil, fmt.Errorf("trace metadata not loaded")
	}

	b.packetProcOnly = packetProcOnly
	b.diagnostics = nil
	tree, ok := SourceTree(sourceName, b.reader.Trace)
	if !ok {
		return nil, fmt.Errorf("source tree for buffer %q not found", sourceName)
	}

	b.bufferFileName = filepath.Join(b.reader.SnapshotPath, tree.BufferInfo.DataFileName)

	dataFormat := strings.ToLower(tree.BufferInfo.DataFormat)
	framedInput := dataFormat != "source_data"
	var demuxOpts coresight.DemuxOptions
	if dataFormat == "dstream_coresight" {
		demuxOpts.HasFsyncs = true
	} else {
		demuxOpts.FrameMemAlign = true
	}

	newPipe, err := snapshotNewPipeline(framedInput, demuxOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to create pipeline object: %w", err)
	}
	b.pipe = newPipe

	b.mapper = nil
	var mem coresight.MemoryReader
	if !packetProcOnly {
		b.mapper = coresight.NewGlobalMapper()
		mem = b.mapper
	}

	sourceSpecs, snapshotSkipped := b.sourceRouteSpecs(tree)
	created, routeSkipped := b.attachSourceRoutes(sourceSpecs, mem)
	snapshotSkipped = append(snapshotSkipped, routeSkipped...)

	if created == 0 {
		b.pipe = nil
		err := errors.Join(snapshotSkipped...)
		if err == nil {
			err = errNoProtocol
		}
		return nil, fmt.Errorf("no supported protocols found: %w", err)
	}

	return b.pipe, nil
}

var errNoProtocol = errors.New("trace protocol unsupported")

func setReg32(dev *Device, name string, dst *uint32) error {
	val, ok := dev.RegValue(name)
	if !ok {
		return nil
	}

	parsed, err := parseUint(val)
	if err != nil {
		return fmt.Errorf("parse register %s=%q: %w", name, val, err)
	}

	*dst = uint32(parsed)
	return nil
}

type etmPTMRegs struct {
	ctrl  uint32
	trcID uint32
	idr   uint32
	ccer  uint32
}

func etmPTMDeviceRegs(dev *Device, defaultIDR uint32) (etmPTMRegs, error) {
	regs := etmPTMRegs{idr: defaultIDR}
	for _, reg := range []struct {
		name string
		dst  *uint32
	}{
		{Etmv3PTMRegCR, &regs.ctrl},
		{Etmv3PTMRegTraceIDR, &regs.trcID},
		{Etmv3PTMRegIDR, &regs.idr},
		{Etmv3PTMRegCCER, &regs.ccer},
	} {
		if err := setReg32(dev, reg.name, reg.dst); err != nil {
			return etmPTMRegs{}, err
		}
	}
	return regs, nil
}

func (b *PipelineBuilder) decodeInterfaces() coresight.MemoryReader {
	if b.packetProcOnly {
		return nil
	}
	return b.mapper
}
