package snapshot

import (
	"coresight/internal/demux"
	"coresight/internal/idec"
	"coresight/internal/memacc"
	"coresight/internal/pipeline"
	"coresight/trace"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// archProfileMap is a package-level cache of the core architecture map (shared, read-only after init).
var archProfileMap = NewCoreArchProfileMap()

var newPipeline = pipeline.NewPipeline

// PipelineBuilder builds a pipeline from snapshot metadata.
type PipelineBuilder struct {
	reader         *Reader
	pipe           *pipeline.Pipeline
	packetProcOnly bool
	bufferFileName string
	mapper         *memacc.GlobalMapper
	memIf          trace.MemoryReader
	instrDecode    trace.InstructionDecoder
	diagnostics    []string

	errOnAA64BadOpcode bool
	instrRangeLimit    uint32
	srcAddrNAtoms      bool
}

type etmPTMRegs struct {
	ctrl  uint32
	trcID uint32
	idr   uint32
	ccer  uint32
}

// NewPipelineBuilder creates a new builder for Pipeline from a snapshot.
func NewPipelineBuilder(r *Reader) *PipelineBuilder {
	return &PipelineBuilder{
		reader: r,
	}
}

// Pipeline returns the built pipeline.
func (b *PipelineBuilder) Pipeline() *pipeline.Pipeline {
	return b.pipe
}

// BufferFileName returns the full path of the trace binary buffer file to load.
func (b *PipelineBuilder) BufferFileName() string {
	return b.bufferFileName
}

// MemoryMapper returns the builder-managed memory mapper used in full decode mode.
// It returns nil when packet-only mode is selected.
func (b *PipelineBuilder) MemoryMapper() *memacc.GlobalMapper {
	return b.mapper
}

// Diagnostics returns non-fatal snapshot-to-pipeline conversion diagnostics.
func (b *PipelineBuilder) Diagnostics() []string {
	return append([]string(nil), b.diagnostics...)
}

func (b *PipelineBuilder) SetErrOnAA64BadOpcode(enabled bool) {
	b.errOnAA64BadOpcode = enabled
}

func (b *PipelineBuilder) SetInstrRangeLimit(limit uint32) {
	b.instrRangeLimit = limit
}

func (b *PipelineBuilder) SetSrcAddrNAtoms(enabled bool) {
	b.srcAddrNAtoms = enabled
}

// Build builds the pipeline for a specific named source buffer (e.g., "ETB_0").
func (b *PipelineBuilder) Build(sourceName string, packetProcOnly bool) (*pipeline.Pipeline, error) {
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

	var demuxOpts demux.DemuxOptions
	b.bufferFileName = filepath.Join(b.reader.SnapshotPath, tree.BufferInfo.DataFileName)

	dataFormat := strings.ToLower(tree.BufferInfo.DataFormat)
	framedInput := dataFormat != "source_data"
	if dataFormat == "dstream_coresight" {
		demuxOpts.HasFsyncs = true
	} else {
		demuxOpts.FrameMemAlign = true
	}

	newPipe, err := newPipeline(framedInput, demuxOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to create pipeline object: %w", err)
	}
	b.pipe = newPipe

	// Create a memory accessor mapper in full-decoder mode only.
	b.mapper = nil
	b.memIf = nil
	b.instrDecode = nil
	if !packetProcOnly {
		b.mapper = memacc.NewGlobalMapper()
		b.memIf = b.mapper
		b.instrDecode = idec.DecodeInstruction
	}

	sourceSpecs, skipped := b.sourceRouteSpecs(tree)
	created, routeSkipped := b.attachSourceRoutes(sourceSpecs)
	skipped = append(skipped, routeSkipped...)

	if created == 0 {
		b.pipe = nil
		err := errors.Join(skipped...)
		if err == nil {
			err = trace.ErrNoProtocol
		}
		return nil, fmt.Errorf("no supported protocols found: %w", err)
	}

	return b.pipe, nil
}

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

func etmPTMDeviceRegs(dev *Device, defaultIDR uint32) (etmPTMRegs, error) {
	regs := etmPTMRegs{idr: defaultIDR}
	for _, reg := range []struct {
		name string
		dst  *uint32
	}{
		{ETMv3PTMRegCR, &regs.ctrl},
		{ETMv3PTMRegTraceIDR, &regs.trcID},
		{ETMv3PTMRegIDR, &regs.idr},
		{ETMv3PTMRegCCER, &regs.ccer},
	} {
		if err := setReg32(dev, reg.name, reg.dst); err != nil {
			return etmPTMRegs{}, err
		}
	}
	return regs, nil
}

func (b *PipelineBuilder) decodeInterfaces() (trace.MemoryReader, trace.InstructionDecoder) {
	if b.packetProcOnly {
		return nil, nil
	}
	return b.memIf, b.instrDecode
}

func protocolBase(name string) string {
	base, _, _ := strings.Cut(name, ".")
	return base
}

// getCoreProfile maps a core device type name (e.g. "Cortex-A57") to its architecture version
// and core profile
func getCoreProfile(coreName string) (trace.ArchVersion, trace.CoreProfile) {
	if ap, ok := archProfileMap.ArchProfile(coreName); ok {
		return ap.Arch, ap.Profile
	}
	return trace.ArchUnknown, trace.ProfileUnknown
}
