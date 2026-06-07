package main

import (
	"fmt"
	"github.com/awmorgan/coresight"
	"io"
	"slices"
	"strconv"
)

type genericRawPrinter struct {
	writer       io.Writer
	id           uint8
	showRawBytes bool
	pktBuf       []byte
	prefixBuf    []byte
	rawBuf       []byte
}

type traceErrorPrefixer interface {
	TraceErrorPrefix(coresight.Index, uint8) string
}

type packetAppender interface {
	AppendStringTo([]byte) []byte
}

func (p *genericRawPrinter) SetMute(bool) {}

func (p *genericRawPrinter) ObservePacket(indexSOP uint64, pkt fmt.Stringer, rawData []byte) {
	if len(rawData) == 0 {
		return
	}

	p.pktBuf = p.pktBuf[:0]
	if appender, ok := pkt.(packetAppender); ok {
		p.pktBuf = appender.AppendStringTo(p.pktBuf)
	} else {
		p.pktBuf = append(p.pktBuf, pkt.String()...)
	}
	if len(p.pktBuf) == 0 {
		return
	}

	prefix := ""
	if pfx, ok := pkt.(traceErrorPrefixer); ok {
		prefix = pfx.TraceErrorPrefix(coresight.Index(indexSOP), p.id)
	}

	if p.showRawBytes {
		p.writePrefix(prefix, coresight.Index(indexSOP))
		io.WriteString(p.writer, " [")
		p.writeRawBytes(rawData)
		io.WriteString(p.writer, "];\t")
		p.writer.Write(p.pktBuf)
		io.WriteString(p.writer, "\n")
	} else {
		p.writePrefix(prefix, coresight.Index(indexSOP))
		io.WriteString(p.writer, "\t")
		p.writer.Write(p.pktBuf)
		io.WriteString(p.writer, "\n")
	}
}

func (p *genericRawPrinter) writePrefix(prefix string, index coresight.Index) {
	p.prefixBuf = p.prefixBuf[:0]
	if prefix != "" {
		p.prefixBuf = append(p.prefixBuf, prefix...)
	}
	p.prefixBuf = append(p.prefixBuf, "Idx:"...)
	p.prefixBuf = strconv.AppendUint(p.prefixBuf, uint64(index), 10)
	p.prefixBuf = append(p.prefixBuf, "; ID:"...)
	p.prefixBuf = strconv.AppendUint(p.prefixBuf, uint64(p.id), 16)
	p.prefixBuf = append(p.prefixBuf, ';')
	p.writer.Write(p.prefixBuf)
}

func (p *genericRawPrinter) writeRawBytes(rawData []byte) {
	const hex = "0123456789abcdef"
	if len(rawData)*5 <= 4096 {
		p.rawBuf = p.rawBuf[:0]
		for _, b := range rawData {
			p.rawBuf = append(p.rawBuf, '0', 'x', hex[b>>4], hex[b&0x0f], ' ')
		}
		p.writer.Write(p.rawBuf)
		return
	}
	var buf [5]byte
	for _, b := range rawData {
		buf = [5]byte{'0', 'x', hex[b>>4], hex[b&0x0f], ' '}
		p.writer.Write(buf[:])
	}
}

func (p *genericRawPrinter) ObserveTraceEnd() {
	fmt.Fprintf(p.writer, "ID:%x\tEND OF TRACE DATA\n", p.id)
}

func (p *genericRawPrinter) PrintTraceReset() {
	fmt.Fprintf(p.writer, "ID:%x\tRESET operation on trace decode path\n", p.id)
}

func attachPacketPrinters(out io.Writer, pipe *coresight.Pipeline, opts options) int {
	attached := 0

	forEachPacketPrinterRoute(pipe, opts, func(route coresight.Route) {
		csID := route.TraceID
		protocolName := coresight.ProtocolName(route.Protocol)
		mon := &genericRawPrinter{
			writer:       out,
			id:           csID,
			showRawBytes: opts.decode || opts.pktMon,
		}

		if setter, ok := route.ByteSink.(interface{ SetPacketObserver(coresight.PacketObserver) }); ok {
			setter.SetPacketObserver(mon.ObservePacket)
			if endSetter, ok := route.ByteSink.(interface{ SetTraceEndObserver(func()) }); ok {
				endSetter.SetTraceEndObserver(mon.ObserveTraceEnd)
			}
			fmt.Fprintf(out, "Trace Packet Lister : Protocol printer %s on Trace ID 0x%x\n", protocolName, csID)
			attached++
		} else {
			fmt.Fprintf(out, "Trace Packet Lister : Failed to attach Protocol printer %s on Trace ID 0x%x\n", protocolName, csID)
		}
	})

	return attached
}

func reportResetOperation(out io.Writer, pipe *coresight.Pipeline, opts options) {
	if opts.decodeOnly {
		return
	}

	forEachPacketPrinterRoute(pipe, opts, func(route coresight.Route) {
		mon := &genericRawPrinter{
			writer: out,
			id:     route.TraceID,
		}
		mon.PrintTraceReset()
	})
}

func forEachPacketPrinterRoute(pipe *coresight.Pipeline, opts options, fn func(coresight.Route)) {
	idFilter := make(map[uint8]bool, len(opts.idList))
	for _, id := range opts.idList {
		idFilter[id] = true
	}

	routes := slices.Clone(pipe.Routes)
	slices.SortFunc(routes, func(a, b coresight.Route) int {
		return int(a.TraceID) - int(b.TraceID)
	})

	for _, route := range routes {
		if !opts.allSourceIDs && !idFilter[route.TraceID] {
			continue
		}

		fn(route)
	}
}
