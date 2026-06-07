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

	streams         []internalByteSink
	rawFrameHandler internalFrameObserver

	trcCurrIdx  Index
	frameSynced bool
	currSrcID   uint8

	exFrmBytes    uint32
	fsyncStartEOB bool
	trcCurrIdxSof Index

	exFrmData [DfrmtrFrameSize]byte

	inBlock []byte

	unpackBuf [16]byte
}

func NewDemuxer(streams []internalByteSink) *Demuxer {
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
		return ErrInvalidParamVal
	}

	if opts.FrameMemAlign && (opts.HasFsyncs || opts.HasHsyncs) {
		return ErrInvalidParamVal
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
		return DfrmtrFrameSize
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
	return d.controlAllIDs(func(stream internalByteSink) error { return stream.Flush() })
}

func (d *Demuxer) resetAllIDs(index Index) error {
	return d.controlAllIDs(func(stream internalByteSink) error { return stream.Reset(index) })
}

func (d *Demuxer) closeAllIDs() error {
	return d.controlAllIDs(func(stream internalByteSink) error { return stream.Close() })
}

func (d *Demuxer) controlAllIDs(streamOp func(internalByteSink) error) error {
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
}

// Write processes the raw trace byte stream, demuxing frames into individual trace streams.
func (d *Demuxer) Write(index Index, dataBlock []byte) (uint32, error) {
	d.updateRawOutputState()
	if len(dataBlock) == 0 {
		return 0, ErrInvalidParamVal
	}
	if d.alignment == 0 {
		return 0, ErrDfrmtrNotConfigured
	}

	processSize := uint32(len(dataBlock))
	processSize -= processSize % d.alignment
	if processSize == 0 {
		return uint32(len(dataBlock)), nil
	}

	d.trcCurrIdx = index
	d.inBlock = dataBlock[:processSize]

	if !d.checkForSync() {
		return uint32(len(dataBlock)), nil
	}

	for len(d.inBlock) > 0 {
		processing, err := d.extractFrame()
		if err != nil {
			return uint32(len(dataBlock)), err
		}
		if processing {
			if err := d.unpackAndOutputFrame(); err != nil {
				return uint32(len(dataBlock)), err
			}
		} else {
			break
		}
	}

	return uint32(len(dataBlock)), nil
}

// Close forwards an EOT operation through the legacy multiplexer.
func (d *Demuxer) Close() error {
	d.updateRawOutputState()
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

func (d *Demuxer) outputStream(id uint8) internalByteSink {
	if !validTraceID(id) {
		return nil
	}
	return d.streams[id]
}
