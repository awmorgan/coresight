package coresight

import (
	"fmt"

)

// InstrInfo structure moved from trace package.
type InstrInfo struct {
	PeType          ArchProfile
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

type ArchProfile struct {
	Arch    ArchVersion
	Profile CoreProfile
}

func IsV8Arch(arch ArchVersion) bool              { return arch >= ArchV8 && arch <= ArchV8max }
func IsArchMinVer(arch, minArch ArchVersion) bool { return arch >= minArch }

const (
	MaxVABitsize = 64
	VAMask       = ^uint64(0)
)

func BitMask(bits int) uint64 {
	switch {
	case bits <= 0:
		return 0
	case bits >= MaxVABitsize:
		return VAMask
	default:
		return (uint64(1) << bits) - 1
	}
}

// AtmVal represents atom evaluation (Executed or Not Executed).
type AtmVal int

const (
	AtomN AtmVal = 0
	AtomE AtmVal = 1
)

// ISyncReason represents the reason for an instruction synchronization packet.
type ISyncReason int

const (
	ISyncPeriodic                  ISyncReason = 0
	ISyncTraceEnable               ISyncReason = 1
	ISyncTraceRestartAfterOverflow ISyncReason = 2
	ISyncDebugExit                 ISyncReason = 3
)

// String returns the OpenCSD-style name for r.
func (r ISyncReason) String() string {
	switch r {
	case ISyncPeriodic:
		return "Periodic"
	case ISyncTraceEnable:
		return "Trace Enable"
	case ISyncTraceRestartAfterOverflow:
		return "Restart Overflow"
	case ISyncDebugExit:
		return "Debug Exit"
	default:
		return fmt.Sprintf("Unknown (%d)", int(r))
	}
}

// ArmV7Exception represents an ARMv7 Exception type
type ArmV7Exception int

const (
	ExcpReserved         ArmV7Exception = 0
	ExcpNoException      ArmV7Exception = 1
	ExcpReset            ArmV7Exception = 2
	ExcpIRQ              ArmV7Exception = 3
	ExcpFIQ              ArmV7Exception = 4
	ExcpAsyncDAbort      ArmV7Exception = 5
	ExcpDebugHalt        ArmV7Exception = 6
	ExcpJazelle          ArmV7Exception = 7
	ExcpSVC              ArmV7Exception = 8
	ExcpSMC              ArmV7Exception = 9
	ExcpHyp              ArmV7Exception = 10
	ExcpUndef            ArmV7Exception = 11
	ExcpPrefAbort        ArmV7Exception = 12
	ExcpGeneric          ArmV7Exception = 13
	ExcpSyncDataAbort    ArmV7Exception = 14
	ExcpCMUsageFault     ArmV7Exception = 15
	ExcpCMNMI            ArmV7Exception = 16
	ExcpCMDebugMonitor   ArmV7Exception = 17
	ExcpCMMemManage      ArmV7Exception = 18
	ExcpCMPendSV         ArmV7Exception = 19
	ExcpCMSysTick        ArmV7Exception = 20
	ExcpCMBusFault       ArmV7Exception = 21
	ExcpCMHardFault      ArmV7Exception = 22
	ExcpCMIRQn           ArmV7Exception = 23
	ExcpThumbEECheckFail ArmV7Exception = 24
)

const (
	BadIndex   Index = ^Index(0)
	MaxTraceID             = 128
)

func IsValidCSSrcID(id uint8) bool {
	return id > 0 && id < 0x70
}

func IsReservedCSSrcID(id uint8) bool {
	return id == 0 || (id >= 0x70 && id <= 0x7F)
}

const (
	DfrmtrFrameSize = 0x10
)
