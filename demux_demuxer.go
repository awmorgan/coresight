package coresight

const (
	maxTraceID = MaxTraceID
)

// DemuxOptions defines the configuration for the frame demuxer.
type DemuxOptions struct {
	HasFsyncs      bool
	HasHsyncs      bool
	FrameMemAlign  bool
	PackedRawOut   bool
	UnpackedRawOut bool
	ResetOn4xFsync bool
}

// Demuxer translates the CoreSight formatted trace byte stream into a demuxed packet stream per ID.
type Demuxer struct {
	opts           DemuxOptions
	alignment      uint32
	forceSyncIdx   uint32
	useForceSync   bool
	outPackedRaw   bool
	outUnpackedRaw bool
	rawChanEnable  []bool

	streams         []ByteSink
	rawFrameHandler internalFrameObserver

	trcCurrIdx  Index
	frameSynced bool
	currSrcID   uint8

	exFrmBytes    uint32
	fsyncStartEOB bool
	trcCurrIdxSof Index

	exFrmData [dfrmtrFrameSize]byte

	inBlock []byte

	unpackBuf [16]byte

	pending                    []byte
	lastWriteEndIndex          Index
	lastWriteProcessedEndIndex Index
}

func newDemuxer(streams []ByteSink) *Demuxer {
	d := &Demuxer{
		rawChanEnable: make([]bool, maxTraceID),
		streams:       streams,
	}
	d.resetStateParams()

	for i := range d.rawChanEnable {
		d.rawChanEnable[i] = true
	}

	return d
}

// SetRawFrameHandler sets the handler function for raw trace frames.
func (d *Demuxer) SetRawFrameHandler(handler internalFrameObserver) {
	d.rawFrameHandler = handler
}

// Configure applies the given options to the demuxer.
func (d *Demuxer) Configure(opts DemuxOptions) error {
	if err := validateFormatterOptions(opts); err != nil {
		return err
	}

	d.opts = opts
	d.alignment = alignmentForOptions(opts)
	return nil
}

func validateFormatterOptions(opts DemuxOptions) error {
	if !opts.HasFsyncs && !opts.HasHsyncs && !opts.FrameMemAlign &&
		!opts.PackedRawOut && !opts.UnpackedRawOut && !opts.ResetOn4xFsync {
		return errInvalidParamVal
	}

	if opts.FrameMemAlign && (opts.HasFsyncs || opts.HasHsyncs) {
		return errInvalidParamVal
	}
	return nil
}

func alignmentForOptions(opts DemuxOptions) uint32 {
	switch {
	case opts.HasHsyncs:
		return 2
	case opts.HasFsyncs:
		return 4
	default:
		return dfrmtrFrameSize
	}
}

func validTraceID(id uint8) bool {
	return id < maxTraceID
}

// Config returns the current configuration of the demuxer.
func (d *Demuxer) Config() DemuxOptions {
	return d.opts
}

func (d *Demuxer) rawChanEnabled(id uint8) bool {
	return validTraceID(id) && d.rawChanEnable[id]
}

func (d *Demuxer) outputRawMonBytes(index Index, frameElem RawframeElem, data []byte, traceID uint8) error {
	if d.rawFrameHandler != nil {
		if err := d.rawFrameHandler(index, frameElem, data, traceID); err != nil {
			return err
		}
	}
	return nil
}

func (d *Demuxer) flushAllIDs() error {
	return d.controlAllIDs(func(stream ByteSink) error { return stream.Flush() })
}

func (d *Demuxer) resetAllIDs(index Index) error {
	return d.controlAllIDs(func(stream ByteSink) error { return stream.Reset(index) })
}

func (d *Demuxer) closeAllIDs() error {
	return d.controlAllIDs(func(stream ByteSink) error { return stream.Close() })
}

func (d *Demuxer) controlAllIDs(streamOp func(ByteSink) error) error {
	var outErr error
	for _, stream := range d.streams {
		if stream == nil {
			continue
		}
		if err := streamOp(stream); err != nil && outErr == nil {
			outErr = err
		}
	}
	return outErr
}

// Reset resets the demuxer state and all output streams to the starting index.
func (d *Demuxer) Reset(index Index) error {
	d.resetStateParams()
	return d.resetAllIDs(index)
}

// Flush flushes all output streams.
func (d *Demuxer) Flush() error {
	return d.flushAllIDs()
}

func (d *Demuxer) resetStateParams() {
	d.trcCurrIdx = BadIndex
	d.frameSynced = false
	d.currSrcID = badCSSrcID

	d.exFrmBytes = 0
	d.fsyncStartEOB = false
	d.trcCurrIdxSof = BadIndex

	d.pending = nil
	d.lastWriteEndIndex = 0
	d.lastWriteProcessedEndIndex = 0
}

// Write processes the raw trace byte stream, demuxing frames into individual trace streams.
func (d *Demuxer) Write(index Index, dataBlock []byte) (uint32, error) {
	d.updateRawOutputState()
	if len(dataBlock) == 0 {
		return 0, errInvalidParamVal
	}
	if d.alignment == 0 {
		return 0, errDfrmtrNotConfigured
	}

	if len(d.pending) > 0 {
		if index == d.lastWriteProcessedEndIndex {
			d.pending = nil
		} else if index != d.lastWriteEndIndex {
			d.pending = nil
		}
	}

	origPendingLen := len(d.pending)
	var combinedBlock []byte
	if origPendingLen > 0 {
		combinedBlock = make([]byte, origPendingLen+len(dataBlock))
		copy(combinedBlock, d.pending)
		copy(combinedBlock[origPendingLen:], dataBlock)
	} else {
		combinedBlock = dataBlock
	}

	d.trcCurrIdx = index - Index(origPendingLen)
	d.inBlock = combinedBlock

	if !d.checkForSync() {
		if len(d.inBlock) > 0 {
			newPending := make([]byte, len(d.inBlock))
			copy(newPending, d.inBlock)
			d.pending = newPending
		} else {
			d.pending = nil
		}
		processedFromDataBlock := max(int(d.trcCurrIdx-index), 0)
		d.lastWriteEndIndex = index + Index(len(dataBlock))
		d.lastWriteProcessedEndIndex = index + Index(processedFromDataBlock)
		return uint32(processedFromDataBlock), nil
	}

	var err error
	for len(d.inBlock) > 0 {
		limit := len(d.inBlock)
		if d.exFrmBytes == 0 {
			limit -= d.partialSyncLen()
		}

		if d.opts.FrameMemAlign {
			if limit < int(dfrmtrFrameSize) {
				break
			}
		} else {
			limit = limit - (limit % 2)
			if limit < 2 {
				break
			}
		}

		origInBlock := d.inBlock
		d.inBlock = origInBlock[:limit]

		processing, extractErr := d.extractFrame()

		consumed := limit - len(d.inBlock)
		d.inBlock = origInBlock[consumed:]

		if extractErr != nil {
			err = extractErr
			break
		}
		if processing {
			if unpackErr := d.unpackAndOutputFrame(); unpackErr != nil {
				err = unpackErr
				break
			}
		} else {
			break
		}
	}

	if len(d.inBlock) > 0 {
		newPending := make([]byte, len(d.inBlock))
		copy(newPending, d.inBlock)
		d.pending = newPending
	} else {
		d.pending = nil
	}

	processedFromDataBlock := max(int(d.trcCurrIdx-index), 0)
	d.lastWriteEndIndex = index + Index(len(dataBlock))
	d.lastWriteProcessedEndIndex = index + Index(processedFromDataBlock)
	return uint32(processedFromDataBlock), err
}

// Close forwards an EOT operation through the legacy multiplexer.
func (d *Demuxer) Close() error {
	d.updateRawOutputState()
	if len(d.pending) > 0 {
		return errDfrmtrIncompleteTail
	}
	return d.closeAllIDs()
}

func (d *Demuxer) updateRawOutputState() {
	d.outPackedRaw = d.rawFrameHandler != nil && d.opts.PackedRawOut
	d.outUnpackedRaw = d.rawFrameHandler != nil && d.opts.UnpackedRawOut
}

func (d *Demuxer) emitUnpackBuf(startIndex Index, count int) error {
	if count == 0 {
		return nil
	}
	data := d.unpackBuf[:count]
	if d.shouldOutputRawEntry(d.currSrcID) {
		if err := d.outputRawMonBytes(startIndex, FrmIDData, data, d.currSrcID); err != nil {
			return err
		}
	}
	if stream := d.outputStream(d.currSrcID); stream != nil {
		if _, err := stream.Write(startIndex, data); err != nil {
			return err
		}
	}
	return nil
}

func (d *Demuxer) unpackAndOutputFrame() error {
	frameFlagBit := uint8(0x1)
	count := 0
	startIndex := d.trcCurrIdxSof

	for i := 0; i < 14; i += 2 {
		b := d.exFrmData[i]
		if b&0x1 != 0 {
			newID := (b >> 1) & 0x7F
			if newID != d.currSrcID {
				prevIDandIDChange := frameFlagBit&d.exFrmData[15] != 0
				if prevIDandIDChange {
					d.unpackBuf[count] = d.exFrmData[i+1]
					count++
				}

				if err := d.emitUnpackBuf(startIndex, count); err != nil {
					return err
				}
				count = 0

				d.currSrcID = newID
				startIndex = d.trcCurrIdxSof + Index(i)

				if !prevIDandIDChange {
					d.unpackBuf[count] = d.exFrmData[i+1]
					count++
				}
			} else {
				d.unpackBuf[count] = d.exFrmData[i+1]
				count++
			}
		} else {
			d.unpackBuf[count] = d.dataByteWithFlag(i, frameFlagBit)
			count++
			d.unpackBuf[count] = d.exFrmData[i+1]
			count++
		}
		frameFlagBit <<= 1
	}

	if d.exFrmData[14]&0x1 != 0 {
		newID := (d.exFrmData[14] >> 1) & 0x7F
		if newID != d.currSrcID {
			if err := d.emitUnpackBuf(startIndex, count); err != nil {
				return err
			}
			count = 0
			d.currSrcID = newID
			startIndex = d.trcCurrIdxSof + 14
		}
	} else {
		d.unpackBuf[count] = d.dataByteWithFlag(14, frameFlagBit)
		count++
	}

	if err := d.emitUnpackBuf(startIndex, count); err != nil {
		return err
	}
	count = 0

	d.exFrmBytes = 0
	return nil
}

func (d *Demuxer) shouldOutputRawEntry(id uint8) bool {
	if !d.outUnpackedRaw {
		return false
	}
	if id == badCSSrcID {
		return true
	}
	return d.rawChanEnabled(id)
}

func (d *Demuxer) dataByteWithFlag(i int, frameFlagBit uint8) byte {
	b := d.exFrmData[i]
	if frameFlagBit&d.exFrmData[15] != 0 {
		b |= 0x1
	}
	return b
}

func (d *Demuxer) outputStream(id uint8) ByteSink {
	if !validTraceID(id) {
		return nil
	}
	return d.streams[id]
}

func (d *Demuxer) partialSyncLen() int {
	n := len(d.inBlock)
	if n == 0 {
		return 0
	}
	if d.opts.HasFsyncs {
		if n >= 3 && d.inBlock[n-3] == 0xff && d.inBlock[n-2] == 0xff && d.inBlock[n-1] == 0xff {
			return 3
		}
		if n >= 2 && d.inBlock[n-2] == 0xff && d.inBlock[n-1] == 0xff {
			return 2
		}
		if n >= 1 && d.inBlock[n-1] == 0xff {
			return 1
		}
	}
	if d.opts.HasHsyncs {
		if n >= 1 && d.inBlock[n-1] == 0xff {
			return 1
		}
	}
	return 0
}
