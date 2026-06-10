package coresight

import (
	"fmt"
)

// instrInfo structure moved from trace package.
type instrInfo struct {
	PeType          archProfile
	ISA             ISA
	InstrAddr       VAddr
	Opcode          uint32
	DsbDmbWaypoints uint8
	WfiWfeBranch    uint8
	TrackItBlock    uint8

	Type              InstrType
	BranchAddr        VAddr
	NextISA           ISA
	InstrSize         uint8
	IsConditional     bool
	IsLink            bool
	ThumbItConditions uint8
	Subtype           InstrSubtype
}

type archProfile struct {
	Arch    ArchVersion
	Profile CoreProfile
}

func isArchMinVer(arch, minArch ArchVersion) bool { return arch >= minArch }

const (
	maxVABitsize = 64
	vaMask       = ^uint64(0)
)

func bitMask(bits int) uint64 {
	switch {
	case bits <= 0:
		return 0
	case bits >= maxVABitsize:
		return vaMask
	default:
		return (uint64(1) << bits) - 1
	}
}

// atmVal represents atom evaluation (Executed or Not Executed).
type atmVal int

const (
	atomN atmVal = 0
	atomE atmVal = 1
)

// iSyncReason represents the reason for an instruction synchronization packet.
type iSyncReason int

const (
	iSyncPeriodic                  iSyncReason = 0
	iSyncTraceEnable               iSyncReason = 1
	iSyncTraceRestartAfterOverflow iSyncReason = 2
	iSyncDebugExit                 iSyncReason = 3
)

// String returns the string representation for r.
func (r iSyncReason) String() string {
	switch r {
	case iSyncPeriodic:
		return "Periodic"
	case iSyncTraceEnable:
		return "Trace Enable"
	case iSyncTraceRestartAfterOverflow:
		return "Restart Overflow"
	case iSyncDebugExit:
		return "Debug Exit"
	default:
		return fmt.Sprintf("Unknown (%d)", int(r))
	}
}

// armV7Exception represents an ARMv7 Exception type
type armV7Exception int

const (
	excpReserved         armV7Exception = 0
	excpNoException      armV7Exception = 1
	excpReset            armV7Exception = 2
	excpIRQ              armV7Exception = 3
	excpFIQ              armV7Exception = 4
	excpAsyncDAbort      armV7Exception = 5
	excpDebugHalt        armV7Exception = 6
	excpJazelle          armV7Exception = 7
	excpSVC              armV7Exception = 8
	excpSMC              armV7Exception = 9
	excpHyp              armV7Exception = 10
	excpUndef            armV7Exception = 11
	excpPrefAbort        armV7Exception = 12
	excpGeneric          armV7Exception = 13
	excpSyncDataAbort    armV7Exception = 14
	excpCMUsageFault     armV7Exception = 15
	excpCMNMI            armV7Exception = 16
	excpCMDebugMonitor   armV7Exception = 17
	excpCMMemManage      armV7Exception = 18
	excpCMPendSV         armV7Exception = 19
	excpCMSysTick        armV7Exception = 20
	excpCMBusFault       armV7Exception = 21
	excpCMHardFault      armV7Exception = 22
	excpCMIRQn           armV7Exception = 23
	excpThumbEECheckFail armV7Exception = 24
)

const (
	// BadIndex represents an invalid index in trace stream.
	BadIndex Index = ^Index(0)
	// MaxTraceID is the upper boundary for trace IDs in the demuxer.
	MaxTraceID = 128
)

// IsValidCSSrcID returns true if the trace ID is valid for CoreSight.
func IsValidCSSrcID(id uint8) bool {
	return id > 0 && id < 0x70
}

const (
	dfrmtrFrameSize = 0x10
)
