package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/awmorgan/coresight"
	"github.com/awmorgan/coresight/snapshot"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func run(args []string) (err error) {
	opts, err := parseOptions(args)
	if err != nil {
		return err
	}
	if opts.help {
		printHelp(os.Stdout)
		return nil
	}
	if opts.ssDir == "" {
		return errors.New("trace packet lister: error: missing directory string on -ss_dir option")
	}

	out, closeFn, err := configureOutput(opts)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := closeFn(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	logHeader(out)
	logCmdLine(out, append([]string{os.Args[0]}, args...))

	fmt.Fprintf(out, "Trace Packet Lister : reading snapshot from path %s\n", opts.ssDir)

	reader := snapshot.NewSnapshotReader()
	reader.SnapshotPath = opts.ssDir
	if err := reader.Read(); err != nil {
		return fmt.Errorf("trace packet lister: failed to read snapshot: %w", err)
	}

	sourceNames := getSourceNames(reader)
	if len(sourceNames) == 0 {
		return errors.New("trace packet lister: no trace source buffer names found")
	}

	if opts.srcName == "" {
		opts.srcName = sourceNames[0]
	} else {
		valid := slices.Contains(sourceNames, opts.srcName)
		if !valid {
			fmt.Fprintf(out, "Trace Packet Lister : Trace source name %s not found\n", opts.srcName)
			fmt.Fprintln(out, "Valid source names are:-")
			for _, src := range sourceNames {
				fmt.Fprintln(out, src)
			}
			return fmt.Errorf("trace packet lister: trace source name %q not found", opts.srcName)
		}
	}

	if opts.multiSession && opts.srcName != "" {
		sourceNames = rotateSourceNames(sourceNames, opts.srcName)
	}

	for _, warning := range reader.Warnings {
		fmt.Fprintf(out, "Trace Packet Lister : Warning: %v\n", warning)
	}

	if len(reader.Warnings) > 0 {
		var relevant []error
		activeSources := []string{opts.srcName}
		if opts.multiSession {
			activeSources = sourceNames
		}
		for _, warn := range reader.Warnings {
			warnStr := warn.Error()
			if strings.Contains(warnStr, "trace.ini") || strings.Contains(warnStr, "trace metadata") {
				relevant = append(relevant, warn)
				continue
			}
			if reader.Trace != nil {
				for _, srcName := range activeSources {
					tree, ok := snapshot.SourceTree(srcName, reader.Trace)
					if !ok {
						continue
					}
					for srcDev, coreDev := range tree.SourceCoreAssoc {
						if strings.Contains(warnStr, srcDev) {
							relevant = append(relevant, warn)
							break
						}
						if coreDev != "" && coreDev != "<none>" && strings.Contains(warnStr, coreDev) {
							relevant = append(relevant, warn)
							break
						}
					}
					if tree.BufferInfo != nil && tree.BufferInfo.DataFileName != "" {
						if strings.Contains(warnStr, tree.BufferInfo.DataFileName) {
							relevant = append(relevant, warn)
						}
					}
				}
			} else {
				relevant = append(relevant, warn)
			}
		}
		if len(relevant) > 0 {
			return fmt.Errorf("trace packet lister: failed to read snapshot data needed for the selected decode path: %w", errors.Join(relevant...))
		}
	}

	fmt.Fprintf(out, "Using %s as trace source\n", opts.srcName)
	return listTracePackets(out, reader, opts, sourceNames)
}

func rotateSourceNames(sourceNames []string, first string) []string {
	idx := slices.Index(sourceNames, first)
	if idx <= 0 {
		return sourceNames
	}
	rotated := make([]string, 0, len(sourceNames))
	rotated = append(rotated, sourceNames[idx:]...)
	rotated = append(rotated, sourceNames[:idx]...)
	return rotated
}

func configureOutput(opts options) (io.Writer, func() error, error) {
	outputs := make([]io.Writer, 0, 3)
	flushers := make([]*bufio.Writer, 0, 3)
	closers := make([]io.Closer, 0, 1)

	if opts.logStdout {
		outputs = append(outputs, os.Stdout)
	}
	if opts.logStderr {
		outputs = append(outputs, os.Stderr)
	}
	if opts.logFile {
		f, err := os.Create(opts.logFileName)
		if err != nil {
			return nil, nil, fmt.Errorf("trace packet lister: error: cannot open logfile %s: %w", opts.logFileName, err)
		}
		outputs = append(outputs, f)
		closers = append(closers, f)
	}

	if len(outputs) == 0 {
		outputs = append(outputs, os.Stdout)
	}

	bufferedOutputs := make([]io.Writer, 0, len(outputs))
	for _, out := range outputs {
		bw := bufio.NewWriterSize(out, 256<<10)
		flushers = append(flushers, bw)
		bufferedOutputs = append(bufferedOutputs, bw)
	}

	closeFn := func() error {
		var outErr error
		for _, f := range flushers {
			if err := f.Flush(); err != nil && outErr == nil {
				outErr = fmt.Errorf("trace packet lister: error flushing output: %w", err)
			}
		}
		for _, c := range closers {
			if err := c.Close(); err != nil && outErr == nil {
				outErr = fmt.Errorf("trace packet lister: error closing output: %w", err)
			}
		}
		return outErr
	}

	if len(bufferedOutputs) == 1 {
		return bufferedOutputs[0], closeFn, nil
	}
	return io.MultiWriter(bufferedOutputs...), closeFn, nil
}

func logHeader(out io.Writer) {
	fmt.Fprintln(out, "Trace Packet Lister: CS Decode library testing")
	fmt.Fprintln(out, "-----------------------------------------------")
	fmt.Fprintln(out)
}

func logCmdLine(out io.Writer, args []string) {
	fmt.Fprintln(out, "Test Command Line:-")
	for i, a := range args {
		if i == 0 {
			fmt.Fprintf(out, "%s   ", a)
			continue
		}
		fmt.Fprintf(out, "%s  ", a)
	}
	fmt.Fprintln(out)
	fmt.Fprintln(out)
}

func getSourceNames(reader *snapshot.SnapshotReader) []string {
	if reader.Trace == nil {
		return nil
	}
	result := make([]string, 0, len(reader.Trace.Buffers))
	for _, b := range reader.Trace.Buffers {
		result = append(result, b.BufferName)
	}
	return result
}

func parseMemSpace(space string) coresight.MemSpaceAcc {
	s := strings.TrimSpace(strings.ToLower(space))
	switch s {
	case "s", "secure":
		return coresight.MemSpaceS
	case "n", "nonsecure", "ns":
		return coresight.MemSpaceN
	case "r", "realm":
		return coresight.MemSpaceR
	case "el1s":
		return coresight.MemSpaceEL1S
	case "el1n":
		return coresight.MemSpaceEL1N
	case "el2":
		return coresight.MemSpaceEL2
	case "el3":
		return coresight.MemSpaceEL3
	case "root":
		return coresight.MemSpaceRoot
	default:
		return coresight.MemSpaceAny
	}
}
