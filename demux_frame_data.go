package coresight

import (
	"bytes"
	"encoding/binary"
	"errors"
)

const (
	fSyncPattern uint32 = 0x7FFFFFFF
	hSyncPattern uint16 = 0x7FFF
	fSyncStart   uint16 = 0xFFFF
)

var fSyncPatternBytes = []byte{0xff, 0xff, 0xff, 0x7f}

func (d *Demuxer) checkForSync() bool {
	if d.frameSynced {
		return true
	}

	var unsyncedBytes uint32
	switch {
	case d.useForceSync:
		unsyncedBytes = d.unsyncedPrefixLenForForcedSync()
	case d.opts.HasFsyncs:
		unsyncedBytes = d.findfirstFSync()
	default:
		d.frameSynced = true
		return true
	}

	if unsyncedBytes > 0 {
		d.advanceInput(unsyncedBytes)
	}
	return d.frameSynced
}

func (d *Demuxer) unsyncedPrefixLenForForcedSync() uint32 {
	start := d.trcCurrIdx
	end := start + Index(len(d.inBlock))
	forceSyncIdx := Index(d.forceSyncIdx)
	if forceSyncIdx >= start && forceSyncIdx < end {
		d.frameSynced = true
		return d.forceSyncIdx - uint32(start)
	}
	return uint32(len(d.inBlock))
}

func (d *Demuxer) findfirstFSync() uint32 {
	if len(d.inBlock) < len(fSyncPatternBytes) {
		return uint32(len(d.inBlock))
	}

	idx := bytes.Index(d.inBlock, fSyncPatternBytes)
	if idx >= 0 {
		d.frameSynced = true
		return uint32(idx)
	}
	return uint32(len(d.inBlock) - len(fSyncPatternBytes) + 1)
}

func (d *Demuxer) checkForResetFSyncPatterns() (uint32, error) {
	numFsyncs := d.countLeadingFSyncs()
	if numFsyncs == 0 {
		return 0, nil
	}

	fSyncBytes := uint32(numFsyncs * len(fSyncPatternBytes))
	if numFsyncs%4 != 0 {
		return fSyncBytes, errDfrmtrBadFhsync
	}

	err := d.resetAllIDs(d.trcCurrIdx)
	d.currSrcID = BadCSSrcID
	d.exFrmBytes = 0
	d.trcCurrIdxSof = BadIndex
	return fSyncBytes, err
}

func (d *Demuxer) countLeadingFSyncs() int {
	count := 0
	buf := d.inBlock
	for len(buf) >= len(fSyncPatternBytes) && binary.LittleEndian.Uint32(buf) == fSyncPattern {
		count++
		buf = buf[len(fSyncPatternBytes):]
	}
	return count
}

func (d *Demuxer) extractFrame() (bool, error) {
	if len(d.inBlock) == 0 {
		return false, nil
	}

	startIdx := d.trcCurrIdx
	startInBlock := d.inBlock

	var err error
	if d.opts.FrameMemAlign {
		err = d.extractAlignedFrame()
	} else {
		err = d.extractUnalignedFrame()
	}

	if err != nil {
		return false, err
	}

	totalProcessed := uint32(d.trcCurrIdx - startIdx)
	if (d.exFrmBytes == dfrmtrFrameSize || len(d.inBlock) == 0) && d.outPackedRaw {
		d.outputRawMonBytes(startIdx, FrmPacked, startInBlock[:totalProcessed], 0)
	}

	return d.exFrmBytes == dfrmtrFrameSize, nil
}

func (d *Demuxer) extractAlignedFrame() error {
	if d.opts.ResetOn4xFsync {
		if err := d.consumeResetFSyncs(); err != nil {
			return err
		}
	}

	if len(d.inBlock) == 0 {
		return nil
	}
	if len(d.inBlock) < int(dfrmtrFrameSize) {
		return errDfrmtrUnaligned
	}

	d.trcCurrIdxSof = d.trcCurrIdx
	copy(d.exFrmData[:], d.inBlock[:dfrmtrFrameSize])
	d.exFrmBytes = dfrmtrFrameSize
	d.advanceInput(dfrmtrFrameSize)
	return nil
}

func (d *Demuxer) consumeResetFSyncs() error {
	fSyncBytes, err := d.checkForResetFSyncPatterns()
	if fSyncBytes > 0 {
		if d.outPackedRaw || d.outUnpackedRaw {
			d.outputRawMonBytes(d.trcCurrIdx, FrmFsync, d.inBlock[:fSyncBytes], 0)
		}
		d.advanceInput(fSyncBytes)
	}
	if err == nil {
		return nil
	}
	if errors.Is(err, errDfrmtrBadFhsync) {
		return errDfrmtrBadFsyncReset
	}
	return err
}

func (d *Demuxer) extractUnalignedFrame() error {
	hasFSyncs := d.opts.HasFsyncs
	hasHSyncs := d.opts.HasHsyncs

	if hasFSyncs && d.exFrmBytes == 0 {
		if err := d.consumeLeadingUnalignedFSyncs(); err != nil {
			return err
		}
	}

	for d.exFrmBytes < dfrmtrFrameSize && len(d.inBlock) >= 2 {
		if d.exFrmBytes == 0 {
			d.trcCurrIdxSof = d.trcCurrIdx
		}

		pair := binary.LittleEndian.Uint16(d.inBlock)
		switch pair {
		case hSyncPattern:
			if !hasHSyncs {
				return errDfrmtrBadHSync
			}
			d.advanceInput(2)
		case fSyncStart:
			return errDfrmtrBadFsyncStart
		default:
			d.copyFramePair()
			d.advanceInput(2)
		}
	}

	if len(d.inBlock) == 1 && d.exFrmBytes < dfrmtrFrameSize {
		return errDfrmtrOddByte
	}

	return nil
}

func (d *Demuxer) consumeLeadingUnalignedFSyncs() error {
	if d.fsyncStartEOB {
		if len(d.inBlock) >= 2 {
			if binary.LittleEndian.Uint16(d.inBlock) != hSyncPattern {
				return errDfrmtrBadFsyncStart
			}
			d.advanceInput(2)
		}
		d.fsyncStartEOB = false
	}

	for len(d.inBlock) >= len(fSyncPatternBytes) && binary.LittleEndian.Uint32(d.inBlock) == fSyncPattern {
		d.advanceInput(uint32(len(fSyncPatternBytes)))
	}

	if len(d.inBlock) == 2 && binary.LittleEndian.Uint16(d.inBlock) == fSyncStart {
		d.advanceInput(2)
		d.fsyncStartEOB = true
	}

	return nil
}

func (d *Demuxer) copyFramePair() {
	d.exFrmData[d.exFrmBytes] = d.inBlock[0]
	d.exFrmData[d.exFrmBytes+1] = d.inBlock[1]
	d.exFrmBytes += 2
}

func (d *Demuxer) advanceInput(numBytes uint32) {
	d.inBlock = d.inBlock[numBytes:]
	d.trcCurrIdx += Index(numBytes)
}
