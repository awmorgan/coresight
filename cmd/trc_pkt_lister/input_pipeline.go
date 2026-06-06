package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/awmorgan/coresight/internal/pipeline"
	"github.com/awmorgan/coresight/internal/printers"
	"github.com/awmorgan/coresight/trace"
)

func processTraceFile(out io.Writer, pipe *pipeline.Pipeline, fileName string, genPrinter *printers.GenericElementPrinter, opts options) error {
	file, err := os.Open(fileName)
	if err != nil {
		return fmt.Errorf("trace packet lister: error: unable to open trace buffer %s: %w", fileName, err)
	}
	defer file.Close()

	start := time.Now()
	buf := make([]byte, 4096)
	var footer [8]byte
	var traceIndex uint32
	dataPathFatal := false
	haveDStreamFooter := false

	for !dataPathFatal {
		n, err := readTraceChunk(file, buf, opts)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			n = max(n, 0)
		} else if err != nil {
			return err
		}

		if n > 0 {
			_, wErr := pipe.Write(trace.Index(traceIndex), buf[:n])
			traceIndex += uint32(n)

			if wErr != nil {
				fmt.Fprintln(out, "Trace Packet Lister : Data Path fatal error")
				dataPathFatal = true
				break
			}
		}

		if opts.dstreamFormat {
			if fErr := readDStreamFooter(out, file, footer[:], opts, haveDStreamFooter); fErr != nil {
				if fErr == io.EOF || fErr == io.ErrUnexpectedEOF {
					break
				}
				return fErr
			}
			haveDStreamFooter = true
		}

		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
	}

	if !dataPathFatal {
		if err := pipe.Close(); err != nil {
			if errors.Is(err, trace.ErrDataDecodeFatal) {
				fmt.Fprintln(out, "Trace Packet Lister : Data Path fatal error")
				reportProcessedInput(out, traceIndex, start, genPrinter, opts)
				return nil
			}
			return fmt.Errorf("trace packet lister: OpEOT error: %w", err)
		}
	}

	reportProcessedInput(out, traceIndex, start, genPrinter, opts)

	if opts.multiSession {
		if err := pipe.Reset(0); err != nil {
			return fmt.Errorf("trace packet lister: OpReset error: %w", err)
		}
		reportResetOperation(out, pipe, opts)
	}

	return nil
}

func readTraceChunk(in io.Reader, buf []byte, opts options) (int, error) {
	if opts.dstreamFormat {
		n, err := io.ReadFull(in, buf[:512-8])
		if err == io.ErrUnexpectedEOF || err == io.EOF {
			return max(n, 0), err
		}
		return n, err
	}
	return in.Read(buf)
}

func readDStreamFooter(out io.Writer, in io.Reader, footer []byte, opts options, haveFooter bool) error {
	n, ferr := io.ReadFull(in, footer)
	if opts.outRawPacked && (ferr == nil || (ferr == io.EOF && n == 0 && haveFooter)) {
		fmt.Fprint(out, "DSTREAM footer [")
		for _, b := range footer {
			fmt.Fprintf(out, "0x%x ", b)
		}
		fmt.Fprintln(out, "]")
	}
	return ferr
}

func reportProcessedInput(out io.Writer, traceIndex uint32, start time.Time, genPrinter *printers.GenericElementPrinter, opts options) {
	fmt.Fprintf(out, "Trace Packet Lister : Trace buffer done, processed %d bytes", traceIndex)
	if opts.noTimePrint {
		fmt.Fprintln(out, ".")
	} else {
		fmt.Fprintf(out, " in %.8f seconds.\n", time.Since(start).Seconds())
	}

	if opts.stats {
		fmt.Fprint(out, "\nReading packet decoder statistics....\n\n")
		fmt.Fprintln(out, "Decode stats unavailable in Go port for this snapshot.")
	}

	if opts.profile {
		genPrinter.PrintStats()
	}
}
