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

	pending                     []byte
	lastWriteEndIndex           Index
	lastWriteProcessedEndIndex  Index
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

func (d *Demuxer) SetRawFrameHandler(handler internalFrameObserver) {
	d.rawFrameHandler = handler
}

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

func (d *Demuxer) Config() DemuxOptions {
	return d.opts
}

func (d *Demuxer) rawChanEnabled(id uint8) bool {
	return validTraceID(id) && d.rawChanEnable[id]
}

func (d *Demuxer) outputRawMonBytes(index Index, frameElem RawframeElem, data []byte, traceID uint8) {
	if d.rawFrameHandler != nil {
		_ = d.rawFrameHandler(index, frameElem, data, traceID)
	}
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

func (d *Demuxer) Reset(index Index) error {
	d.resetStateParams()
	return d.resetAllIDs(index)
}

func (d *Demuxer) Flush() error {
	return d.flushAllIDs()
}

func (d *Demuxer) resetStateParams() {
	d.trcCurrIdx = BadIndex
	d.frameSynced = false
	d.currSrcID = BadCSSrcID

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

	totalLen := uint32(len(combinedBlock))
	processSize := totalLen - (totalLen % d.alignment)
	if processSize == 0 {
		d.pending = append(d.pending, dataBlock...)
		d.lastWriteEndIndex = index + Index(len(dataBlock))
		d.lastWriteProcessedEndIndex = index
		return 0, nil
	}

	processedFromDataBlock := int(processSize) - origPendingLen

	remainingTail := combinedBlock[processSize:]
	if len(remainingTail) > 0 {
		newPending := make([]byte, len(remainingTail))
		copy(newPending, remainingTail)
		d.pending = newPending
	} else {
		d.pending = nil
	}

	d.trcCurrIdx = index - Index(origPendingLen)
	d.inBlock = combinedBlock[:processSize]

	if !d.checkForSync() {
		d.lastWriteEndIndex = index + Index(len(dataBlock))
		d.lastWriteProcessedEndIndex = index + Index(processedFromDataBlock)
		return uint32(processedFromDataBlock), nil
	}

	for len(d.inBlock) > 0 {
		processing, err := d.extractFrame()
		if err != nil {
			d.lastWriteEndIndex = index + Index(len(dataBlock))
			d.lastWriteProcessedEndIndex = index + Index(processedFromDataBlock)
			return uint32(processedFromDataBlock), err
		}
		if processing {
			if err := d.unpackAndOutputFrame(); err != nil {
				d.lastWriteEndIndex = index + Index(len(dataBlock))
				d.lastWriteProcessedEndIndex = index + Index(processedFromDataBlock)
				return uint32(processedFromDataBlock), err
			}
		} else {
			break
		}
	}

	d.lastWriteEndIndex = index + Index(len(dataBlock))
	d.lastWriteProcessedEndIndex = index + Index(processedFromDataBlock)
	return uint32(processedFromDataBlock), nil
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
		d.outputRawMonBytes(startIndex, FrmIDData, data, d.currSrcID)
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
	if id == BadCSSrcID {
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
