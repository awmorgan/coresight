package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/awmorgan/coresight"
)

const defaultLogFile = "trc_pkt_lister.ppl"

type options struct {
	ssDir           string
	srcName         string
	multiSession    bool
	decode          bool
	decodeOnly      bool
	pktMon          bool
	stats           bool
	profile         bool
	noTimePrint     bool
	outRawPacked    bool
	outRawUnpacked  bool
	dstreamFormat   bool
	tpiuFormat      bool
	hasHSync        bool
	aa64OpcodeChk   bool
	srcAddrNAtoms   bool
	instrRangeLimit uint32

	allSourceIDs bool
	idList       []uint8
	logStdout    bool
	logStderr    bool
	logFile      bool
	logFileName  string
	help         bool
}

// idListValue implements flag.Value to allow multiple -id flags.
type idListValue []uint8

func (i *idListValue) String() string {
	return fmt.Sprintf("%v", *i)
}

func (i *idListValue) Set(value string) error {
	v, err := strconv.ParseUint(value, 0, 8)
	if err != nil {
		return fmt.Errorf("invalid ID number %s", value)
	}
	id := uint8(v)
	if !coresight.IsValidCSSrcID(id) {
		return fmt.Errorf("invalid ID number 0x%x", id)
	}
	*i = append(*i, id)
	return nil
}

func parseOptions(args []string) (options, error) {
	opts := options{
		allSourceIDs: true,
		logStdout:    true,
		logFile:      true,
		logFileName:  defaultLogFile,
	}

	fs := flag.NewFlagSet("Trace Packet Lister", flag.ContinueOnError)
	fs.Usage = func() {}

	fs.StringVar(&opts.ssDir, "ss_dir", "", "Set the directory path to a trace snapshot")
	fs.StringVar(&opts.srcName, "src_name", "", "List packets from a given snapshot source name")
	fs.BoolVar(&opts.multiSession, "multi_session", false, "Decode all source buffers with same config")
	fs.BoolVar(&opts.decode, "decode", false, "Full decode of packets from snapshot")
	fs.BoolVar(&opts.pktMon, "pkt_mon", false, "Enable packet monitor")
	fs.BoolVar(&opts.stats, "stats", false, "Output packet processing statistics")
	fs.BoolVar(&opts.profile, "profile", false, "Profile output")
	fs.BoolVar(&opts.noTimePrint, "no_time_print", false, "Do not output elapsed time")
	fs.BoolVar(&opts.outRawPacked, "o_raw_packed", false, "Output raw packed trace frames")
	fs.BoolVar(&opts.outRawUnpacked, "o_raw_unpacked", false, "Output raw unpacked trace data per ID")
	fs.BoolVar(&opts.dstreamFormat, "dstream_format", false, "Input is DSTREAM framed")
	fs.BoolVar(&opts.aa64OpcodeChk, "aa64_opcode_chk", false, "Treat AA64 opcodes with zero top 16 bits as invalid")
	fs.BoolVar(&opts.srcAddrNAtoms, "src_addr_n", false, "Split ETE source address ranges on N atoms")
	var instrRangeLimit uint
	fs.UintVar(&instrRangeLimit, "instr_range_limit", 0, "Limit consecutive instructions decoded in one range")

	fs.Var((*idListValue)(&opts.idList), "id", "Set an ID to list (may be used multiple times)")

	var flagDecodeOnly, flagTPIU, flagTPIUHSync bool
	fs.BoolVar(&flagDecodeOnly, "decode_only", false, "Decode only, no packet printer output")
	fs.BoolVar(&flagTPIU, "tpiu", false, "Input from TPIU - sync by FSYNC")
	fs.BoolVar(&flagTPIUHSync, "tpiu_hsync", false, "Input from TPIU - sync by FSYNC and HSYNC")

	var flagLogStdout, flagLogStderr, flagLogFile bool
	var flagLogFileName string
	fs.BoolVar(&flagLogStdout, "logstdout", false, "Output to stdout")
	fs.BoolVar(&flagLogStderr, "logstderr", false, "Output to stderr")
	fs.BoolVar(&flagLogFile, "logfile", false, "Output to default file")
	fs.StringVar(&flagLogFileName, "logfilename", "", "Output to specific file name")

	fs.BoolVar(&opts.help, "help", false, "Show help")

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			opts.help = true
			return opts, nil
		}
		return opts, fmt.Errorf("trace packet lister: error parsing flags: %w", err)
	}

	if opts.help {
		return opts, nil
	}

	if flagDecodeOnly {
		opts.decodeOnly = true
		opts.decode = true
	}

	if flagTPIU {
		opts.tpiuFormat = true
	}
	if flagTPIUHSync {
		opts.tpiuFormat = true
		opts.hasHSync = true
	}
	if os.Getenv("OPENCSD_ERR_ON_AA64_BAD_OPCODE") != "" {
		opts.aa64OpcodeChk = true
	}
	if instrRangeLimit > 0 {
		opts.instrRangeLimit = uint32(instrRangeLimit)
	}
	if envLimit := os.Getenv("OPENCSD_INSTR_RANGE_LIMIT"); envLimit != "" {
		limit, err := strconv.ParseUint(envLimit, 0, 32)
		if err != nil {
			return opts, fmt.Errorf("trace packet lister: invalid OPENCSD_INSTR_RANGE_LIMIT %q: %w", envLimit, err)
		}
		opts.instrRangeLimit = uint32(limit)
	}

	if len(opts.idList) > 0 {
		opts.allSourceIDs = false
	}

	switch {
	case flagLogStdout:
		opts.logStdout = true
		opts.logStderr = false
		opts.logFile = false
	case flagLogStderr:
		opts.logStdout = false
		opts.logStderr = true
		opts.logFile = false
	case flagLogFileName != "":
		opts.logFileName = flagLogFileName
		opts.logStdout = false
		opts.logStderr = false
		opts.logFile = true
	case flagLogFile:
		opts.logStdout = false
		opts.logStderr = false
		opts.logFile = true
	}

	return opts, nil
}

func printHelp(out io.Writer) {
	fmt.Fprintln(out, "Trace Packet Lister - commands")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Snapshot:")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "-ss_dir <dir>       Set the directory path to a trace snapshot")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Decode:")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "-id <n>             Set an ID to list (may be used multiple times)")
	fmt.Fprintln(out, "-src_name <name>    List packets from a given snapshot source name")
	fmt.Fprintln(out, "-multi_session      Decode all source buffers with same config")
	fmt.Fprintln(out, "-dstream_format     Input is DSTREAM framed")
	fmt.Fprintln(out, "-tpiu               Input from TPIU - sync by FSYNC")
	fmt.Fprintln(out, "-tpiu_hsync         Input from TPIU - sync by FSYNC and HSYNC")
	fmt.Fprintln(out, "-decode             Full decode of packets from snapshot")
	fmt.Fprintln(out, "-decode_only        Decode only, no packet printer output")
	fmt.Fprintln(out, "-aa64_opcode_chk    Treat AA64 opcodes with zero top 16 bits as invalid")
	fmt.Fprintln(out, "-src_addr_n         Split ETE source address ranges on N atoms")
	fmt.Fprintln(out, "-instr_range_limit <n> Limit consecutive instructions decoded in one range")
	fmt.Fprintln(out, "-o_raw_packed       Output raw packed trace frames")
	fmt.Fprintln(out, "-o_raw_unpacked     Output raw unpacked trace data per ID")
	fmt.Fprintln(out, "-stats              Output packet processing statistics")
	fmt.Fprintln(out, "-no_time_print      Do not output elapsed time")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Output:")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "-logstdout          Output to stdout")
	fmt.Fprintln(out, "-logstderr          Output to stderr")
	fmt.Fprintln(out, "-logfile            Output to default file")
	fmt.Fprintln(out, "-logfilename <name> Output to file <name>")
}
