package main

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"

	"github.com/awmorgan/coresight"
	"github.com/awmorgan/coresight/snapshot"
)

func listTracePackets(out io.Writer, reader *snapshot.SnapshotReader, opts options, sourceNames []string) error {
	builder, pipe, err := buildSnapshotDecodeTree(reader, opts)
	if err != nil {
		return err
	}

	if err := configureFrameDemux(pipe, out, opts); err != nil {
		return err
	}

	for _, diag := range builder.Diagnostics() {
		fmt.Fprintln(out, diag)
	}

	if opts.decode {
		diagnostics, err := prepareDecodeMode(builder, reader, opts)
		if err != nil {
			return err
		}
		for _, diag := range diagnostics {
			fmt.Fprint(out, diag)
		}
	}

	genPrinter := coresight.NewGenericElementPrinter(out)
	genPrinter.SetIDFilter(opts.idList)
	if opts.profile {
		genPrinter.SetMute(true)
		genPrinter.SetCollectStats()
	}

	printersAttached := 0
	if !opts.decodeOnly {
		printersAttached = attachPacketPrinters(out, pipe, opts)
	}

	if err := configureDecodeMode(out, builder, opts); err != nil {
		return err
	}

	pipe.SetElementSink(genPrinter.PrintElement)

	if !opts.decode && printersAttached == 0 {
		fmt.Fprintln(out, "Trace Packet Lister : No supported protocols found.")
		return nil
	}

	if !opts.multiSession {
		return runSingleSession(out, pipe, builder.BufferFileName(), genPrinter, opts)
	}

	return runMultiSession(out, reader, pipe, sourceNames, genPrinter, opts)
}

func buildSnapshotDecodeTree(
	reader *snapshot.SnapshotReader,
	opts options,
) (*snapshot.PipelineBuilder, *coresight.Pipeline, error) {
	builder := snapshot.NewPipelineBuilder(reader)
	builder.SetErrOnAA64BadOpcode(opts.aa64OpcodeChk)
	builder.SetInstrRangeLimit(opts.instrRangeLimit)
	builder.SetSrcAddrNAtoms(opts.srcAddrNAtoms)
	packetProcOnly := !opts.decode

	pipe, err := builder.Build(opts.srcName, packetProcOnly)
	if err != nil {
		return nil, nil, fmt.Errorf(
			"trace packet lister: failed to create decode tree for source %s: %w",
			opts.srcName, err,
		)
	}
	if pipe == nil {
		return nil, nil, errors.New("trace packet lister: no supported protocols found")
	}

	return builder, pipe, nil
}

func runSingleSession(
	out io.Writer,
	pipe *coresight.Pipeline,
	fileName string,
	genPrinter *coresight.GenericElementPrinter,
	opts options,
) error {
	return processTraceFile(out, pipe, fileName, genPrinter, opts)
}

func runMultiSession(
	out io.Writer,
	reader *snapshot.SnapshotReader,
	pipe *coresight.Pipeline,
	sourceNames []string,
	genPrinter *coresight.GenericElementPrinter,
	opts options,
) error {
	total := len(sourceNames)
	for i, sourceName := range sourceNames {
		fmt.Fprintf(out, "####### Multi Session decode: Buffer %d of %d; Source name = %s.\n\n", i+1, total, sourceName)
		srcTree, ok := reader.SourceTrees[sourceName]
		if !ok || srcTree == nil || srcTree.BufferInfo == nil {
			fmt.Fprintf(out, "Trace Packet Lister : ERROR : Multi-session decode for buffer %s - buffer not found. Aborting.\n\n", sourceName)
			break
		}
		safeDataFile, err := snapshot.SafeRelativePath(srcTree.BufferInfo.DataFileName)
		if err != nil {
			fmt.Fprintf(out, "Trace Packet Lister : ERROR : Multi-session decode for buffer %s - invalid file path: %v. Aborting.\n\n", sourceName, err)
			return err
		}
		binFile := filepath.Join(reader.SnapshotPath, safeDataFile)

		if err := processTraceFile(out, pipe, binFile, genPrinter, opts); err != nil {
			fmt.Fprintf(out, "Trace Packet Lister : ERROR : Multi-session decode for buffer %s failed. Aborting.\n\n", sourceName)
			return err
		}
		fmt.Fprintf(out, "####### Buffer %d : %s Complete\n\n", i+1, sourceName)
	}
	return nil
}
