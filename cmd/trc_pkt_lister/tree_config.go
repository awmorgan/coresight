package main

import (
	"errors"
	"fmt"
	"github.com/awmorgan/coresight"
	"github.com/awmorgan/coresight/snapshot"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func configureFrameDemux(pipe *coresight.Pipeline, out io.Writer, opts options) error {
	demuxer := pipe.Demuxer
	if demuxer == nil {
		return nil
	}

	demuxOpts := demuxer.Config()
	if opts.tpiuFormat {
		demuxOpts.HasFsyncs = true
	}
	if opts.hasHSync {
		demuxOpts.HasHsyncs = true
	}
	if opts.tpiuFormat {
		demuxOpts.FrameMemAlign = false
	}
	if !demuxOpts.HasFsyncs && !demuxOpts.HasHsyncs && !demuxOpts.FrameMemAlign {
		demuxOpts.FrameMemAlign = true
	}

	if opts.outRawPacked {
		demuxOpts.PackedRawOut = true
	}
	if opts.outRawUnpacked {
		demuxOpts.UnpackedRawOut = true
	}

	if err := demuxer.Configure(demuxOpts); err != nil {
		return fmt.Errorf("configure frame demuxer: %w", err)
	}
	if opts.outRawPacked || opts.outRawUnpacked {
		rp := coresight.NewRawFramePrinter(out)
		pipe.Demuxer.SetRawFrameHandler(rp.WriteRawFrame)
	}
	return nil
}

func prepareDecodeMode(builder *snapshot.PipelineBuilder, reader *snapshot.SnapshotReader, opts options) ([]string, error) {
	if !opts.decode {
		return nil, nil
	}

	mapper := builder.MemoryMapper()
	if mapper == nil {
		return nil, errors.New("trace packet lister: decode mode requires a memory mapper")
	}

	diagnostics, err := mapMemoryRangesWithDiagnostics(mapper, opts.ssDir, reader)
	if err != nil {
		return nil, fmt.Errorf("trace packet lister: map memory ranges failed: %w", err)
	}

	return diagnostics, nil
}

func configureDecodeMode(out io.Writer, builder *snapshot.PipelineBuilder, opts options) error {
	if !opts.decode {
		return nil
	}

	mapper := builder.MemoryMapper()
	if mapper == nil {
		return errors.New("trace packet lister: decode mode requires a memory mapper")
	}

	fmt.Fprintln(out, "Trace Packet Lister : Set trace element decode printer")

	fmt.Fprint(out, mapper.DumpMappings())

	return nil
}

func mapMemoryRanges(mapper *coresight.GlobalMapper, ssDir string, reader *snapshot.SnapshotReader) error {
	_, err := mapMemoryRangesWithDiagnostics(mapper, ssDir, reader)
	return err
}

func mapMemoryRangesWithDiagnostics(mapper *coresight.GlobalMapper, ssDir string, reader *snapshot.SnapshotReader) ([]string, error) {
	seenAccessors := make(map[string]struct{})
	loadErrs := make([]string, 0)
	diagnostics := make([]string, 0)

	recordLoadErr := func(filePath string, memParams snapshot.MemoryDump, format string, args ...any) {
		msg := fmt.Sprintf(format, args...)
		loadErrs = append(loadErrs, fmt.Sprintf(
			"path=%s address=0x%x offset=%d length=%d space=%q: %s",
			filepath.ToSlash(filePath),
			memParams.Address,
			memParams.Offset,
			memParams.Length,
			memParams.Space,
			msg,
		))
	}

	for _, dev := range reader.ParsedDeviceList {
		if dev == nil || !strings.EqualFold(dev.Class, "core") {
			continue
		}
		for _, memParams := range dev.Memory {
			if strings.TrimSpace(memParams.Path) == "" {
				continue
			}

			safePath, err := snapshot.SafeRelativePath(memParams.Path)
			if err != nil {
				recordLoadErr("", memParams, "invalid memory dump path: %v", err)
				continue
			}

			filePath := filepath.Join(ssDir, safePath)
			normPath := filepath.ToSlash(filePath)
			space := parseMemSpace(memParams.Space)

			f, err := os.Open(filePath)
			if err != nil {
				// Missing/unreadable external dump images are non-fatal, but the reference decoder logs them.
				diagnostics = append(diagnostics, fmt.Sprintf(
					"ss2_dcdtree : 0x0003 (OCSD_ERR_NOT_INIT) [Component not initialised.]; Failed to create memory accessor for file %s.",
					memoryDiagnosticPath(ssDir, memParams.Path, normPath),
				))
				continue
			}

			closeFile := func(reason string) {
				if err := f.Close(); err != nil {
					recordLoadErr(filePath, memParams, "%s close failed: %v", reason, err)
				}
			}

			stat, err := f.Stat()
			if err != nil {
				closeFile("after stat failure")
				recordLoadErr(filePath, memParams, "stat failed: %v", err)
				continue
			}
			fileSize := stat.Size()

			if memParams.Offset >= uint64(fileSize) {
				closeFile("after invalid offset")
				recordLoadErr(filePath, memParams, "offset beyond EOF: file_size=%d requested_offset=%d", fileSize, memParams.Offset)
				continue
			}

			var windowLen uint64
			if memParams.Length == 0 {
				windowLen = uint64(fileSize) - memParams.Offset
			} else {
				remaining := uint64(fileSize) - memParams.Offset
				windowLen = min(memParams.Length, remaining)
			}

			if windowLen == 0 {
				closeFile("after zero mapping length")
				recordLoadErr(filePath, memParams, "effective mapping length is zero")
				continue
			}

			accKey := fmt.Sprintf(
				"%s|%s|0x%x|%d|%d",
				coresight.MemSpaceString(space),
				normPath,
				memParams.Address,
				windowLen,
				memParams.Offset,
			)
			if _, seen := seenAccessors[accKey]; seen {
				closeFile("after duplicate mapping")
				continue
			}

			b := make([]byte, windowLen)
			if _, err := f.ReadAt(b, int64(memParams.Offset)); err != nil && err != io.EOF {
				closeFile("after read failure")
				recordLoadErr(filePath, memParams, "read failed: %v", err)
				continue
			}

			if err := f.Close(); err != nil {
				recordLoadErr(filePath, memParams, "close failed: %v", err)
				continue
			}

			acc := coresight.NewBufferAccessor(coresight.VAddr(memParams.Address), b, space, normPath)
			if err := mapper.AddAccessor(acc); err != nil {
				if !errors.Is(err, coresight.ErrMemAccOverlap) {
					return diagnostics, fmt.Errorf("add memory accessor for %s @0x%x: %w", filePath, memParams.Address, err)
				}
			}
			seenAccessors[accKey] = struct{}{}
		}
	}

	if len(loadErrs) > 0 {
		return diagnostics, fmt.Errorf("trace packet lister: snapshot memory mapping load failures:\n%s", strings.Join(loadErrs, "\n"))
	}

	return diagnostics, nil
}

func memoryDiagnosticPath(ssDir, memPath, normPath string) string {
	ssDirSlash := filepath.ToSlash(ssDir)
	if strings.Contains(ssDirSlash, "/testdata/") {
		snapshotRoot := "snapshots"
		if strings.Contains(ssDirSlash, "/internal/ete/testdata/") {
			snapshotRoot = "snapshots-ete"
		}
		return "./" + snapshotRoot + "/" + filepath.Base(ssDirSlash) + "/" + filepath.ToSlash(memPath)
	}
	return normPath
}
