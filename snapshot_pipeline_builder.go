package coresight

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// archProfileMap is a package-level cache of the core architecture map (shared, read-only after init).
var archProfileMap = newCoreArchProfileMap()

var snapshotNewPipeline = newPipeline

// PipelineBuilder builds a pipeline from snapshot metadata.
type PipelineBuilder struct {
	reader         *SnapshotReader
	pipe           *Pipeline
	packetProcOnly bool
	bufferFileName string
	mapper         *GlobalMapper
	memIf          internalMemoryReader
	instrDecode    internalInstructionDecoder
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

// NewPipelineBuilder creates a new builder for Pipeline from a 
func NewPipelineBuilder(r *SnapshotReader) *PipelineBuilder {
	return &PipelineBuilder{
		reader: r,
	}
}

// Pipeline returns the built 
func (b *PipelineBuilder) Pipeline() *Pipeline {
	return b.pipe
}

// BufferFileName returns the full path of the trace binary buffer file to load.
func (b *PipelineBuilder) BufferFileName() string {
	return b.bufferFileName
}

// MemoryMapper returns the builder-managed memory mapper used in full decode mode.
// It returns nil when packet-only mode is selected.
func (b *PipelineBuilder) MemoryMapper() *GlobalMapper {
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
func (b *PipelineBuilder) Build(sourceName string, packetProcOnly bool) (*Pipeline, error) {
	if !b.reader.ReadOK {
		return nil, fmt.Errorf("supplied snapshot reader has not correctly read the snapshot")
	}

	if b.reader.Trace == nil {
		return nil, fmt.Errorf("trace metadata not loaded")
	}

	b.packetProcOnly = packetProcOnly
	b.diagnostics = nil
	tree, ok := sourceTree(sourceName, b.reader.Trace)
	if !ok {
		return nil, fmt.Errorf("source tree for buffer %q not found", sourceName)
	}

	var demuxOpts DemuxOptions
	b.bufferFileName = filepath.Join(b.reader.SnapshotPath, tree.BufferInfo.DataFileName)

	dataFormat := strings.ToLower(tree.BufferInfo.DataFormat)
	framedInput := dataFormat != "source_data"
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

	// Create a memory accessor mapper in full-decoder mode only.
	b.mapper = nil
	b.memIf = nil
	b.instrDecode = nil
	if !packetProcOnly {
		b.mapper = NewGlobalMapper()
		b.memIf = b.mapper
		b.instrDecode = decodeInstruction
	}

	sourceSpecs, snapshotSkipped := b.sourceRouteSpecs(tree)
	created, routeSkipped := b.attachSourceRoutes(sourceSpecs)
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
		{etmv3PTMRegCR, &regs.ctrl},
		{etmv3PTMRegTraceIDR, &regs.trcID},
		{etmv3PTMRegIDR, &regs.idr},
		{etmv3PTMRegCCER, &regs.ccer},
	} {
		if err := setReg32(dev, reg.name, reg.dst); err != nil {
			return etmPTMRegs{}, err
		}
	}
	return regs, nil
}

func (b *PipelineBuilder) decodeInterfaces() (internalMemoryReader, internalInstructionDecoder) {
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
func getCoreProfile(coreName string) (ArchVersion, CoreProfile) {
	if ap, ok := archProfileMap.ArchProfile(coreName); ok {
		return ap.Arch, ap.Profile
	}
	return ArchUnknown, ProfileUnknown
}
