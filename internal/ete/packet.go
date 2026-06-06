package ete

import "github.com/awmorgan/coresight/internal/etmv4"

type PacketType = etmv4.PacketType
type TraceInfo = etmv4.TraceInfo
type Context = etmv4.Context
type Atom = etmv4.Atom
type Address = etmv4.Address
type ExceptionInfo = etmv4.ExceptionInfo
type QInfo = etmv4.QInfo
type ITEInfo = etmv4.ITEInfo
type Packet = etmv4.Packet

const (
	PktExtension       = etmv4.PktExtension
	PktTraceInfo       = etmv4.PktTraceInfo
	PktTimestamp       = etmv4.PktTimestamp
	PktTraceOn         = etmv4.PktTraceOn
	PktFuncRet         = etmv4.PktFuncRet
	PktException       = etmv4.PktException
	PktExceptionReturn = etmv4.PktExceptionReturn
	PktITE             = etmv4.PktITE
	PktCycleCountF2    = etmv4.PktCycleCountF2
	PktCycleCountF1    = etmv4.PktCycleCountF1
	PktCycleCountF3    = etmv4.PktCycleCountF3
	PktNumDSMarker     = etmv4.PktNumDSMarker
	PktUnnumDSMarker   = etmv4.PktUnnumDSMarker
	PktCommit          = etmv4.PktCommit
	PktCancelF1        = etmv4.PktCancelF1
	PktCancelF1Mispred = etmv4.PktCancelF1Mispred
	PktMispredict      = etmv4.PktMispredict
	PktCancelF2        = etmv4.PktCancelF2
	PktCancelF3        = etmv4.PktCancelF3
	PktCondInstrF2     = etmv4.PktCondInstrF2
	PktCondFlush       = etmv4.PktCondFlush
	PktCondResultF4    = etmv4.PktCondResultF4
	PktCondResultF2    = etmv4.PktCondResultF2
	PktCondResultF3    = etmv4.PktCondResultF3
	PktCondResultF1    = etmv4.PktCondResultF1
	PktCondInstrF1     = etmv4.PktCondInstrF1
	PktCondInstrF3     = etmv4.PktCondInstrF3
	PktIgnore          = etmv4.PktIgnore
	PktEvent           = etmv4.PktEvent
	PktContext         = etmv4.PktContext
	PktAddrCtxtL32IS0  = etmv4.PktAddrCtxtL32IS0
	PktAddrCtxtL32IS1  = etmv4.PktAddrCtxtL32IS1
	PktAddrCtxtL64IS0  = etmv4.PktAddrCtxtL64IS0
	PktAddrCtxtL64IS1  = etmv4.PktAddrCtxtL64IS1
	PktAddrMatch       = etmv4.PktAddrMatch
	PktAddrSIS0        = etmv4.PktAddrSIS0
	PktAddrSIS1        = etmv4.PktAddrSIS1
	PktAddrL32IS0      = etmv4.PktAddrL32IS0
	PktAddrL32IS1      = etmv4.PktAddrL32IS1
	PktAddrL64IS0      = etmv4.PktAddrL64IS0
	PktAddrL64IS1      = etmv4.PktAddrL64IS1
	PktQ               = etmv4.PktQ
	PktAtomF6          = etmv4.PktAtomF6
	PktAtomF5          = etmv4.PktAtomF5
	PktAtomF2          = etmv4.PktAtomF2
	PktAtomF4          = etmv4.PktAtomF4
	PktAtomF1          = etmv4.PktAtomF1
	PktAtomF3          = etmv4.PktAtomF3
	PktASync           = etmv4.PktASync
	PktDiscard         = etmv4.PktDiscard
	PktOverflow        = etmv4.PktOverflow
	PktNotSync         = etmv4.PktNotSync
	PktIncompleteEOT   = etmv4.PktIncompleteEOT
	PktNoErrType       = etmv4.PktNoErrType
	PktTSMarker        = etmv4.PktTSMarker
	PktBadSequence     = etmv4.PktBadSequence
	PktBadTraceMode    = etmv4.PktBadTraceMode
	PktReserved        = etmv4.PktReserved
	PktReservedCfg     = etmv4.PktReservedCfg
)
