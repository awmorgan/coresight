package coresight

import (
	"fmt"
	"strings"
)

// Index is the trace source index type.
// Equivalent to ocsd_trc_index_t 64-bit fallback.
type Index uint64

const (
	// badCSSrcID is an invalid trace source ID value.
	badCSSrcID uint8 = 0xFF
)

// RawframeElem indicates the type of raw frame element demuxed from the stream.
type RawframeElem uint32

const (
	// FrmNone represents no raw frame.
	FrmNone RawframeElem = 0
	// FrmPacked is a packed raw frame.
	FrmPacked RawframeElem = 1
	// FrmHsync represents a half frame synchronization marker.
	FrmHsync RawframeElem = 2
	// FrmFsync represents a full frame synchronization marker.
	FrmFsync RawframeElem = 3
	// FrmIDData represents a frame containing trace ID channel data.
	FrmIDData RawframeElem = 4
)

// ArchVersion represents the ARM trace hardware architecture version.
type ArchVersion uint32

const (
	// ArchUnknown indicates an unknown architecture version.
	ArchUnknown ArchVersion = 0x0000
	// ArchCustom indicates a custom architecture version.
	ArchCustom ArchVersion = 0x0001
	// ArchV7 represents ARMv7 architecture.
	ArchV7 ArchVersion = 0x0700
	// ArchV8 represents ARMv8 architecture.
	ArchV8 ArchVersion = 0x0800
	// ArchV8r3 represents ARMv8.3 architecture.
	ArchV8r3 ArchVersion = 0x0803
	// ArchAA64 represents AArch64 trace version.
	ArchAA64 ArchVersion = 0x0864
	// ArchV8max is the highest supported ARMv8 architecture.
	ArchV8max ArchVersion = ArchAA64
)

// CoreProfile represents the target processing element profile.
type CoreProfile uint32

const (
	// ProfileUnknown represents an unknown PE profile.
	ProfileUnknown CoreProfile = 0
	// ProfileCortexM represents the Cortex-M profile.
	ProfileCortexM CoreProfile = 1
	// ProfileCortexR represents the Cortex-R profile.
	ProfileCortexR CoreProfile = 2
	// ProfileCortexA represents the Cortex-A profile.
	ProfileCortexA CoreProfile = 3
	// ProfileCustom represents a custom profile.
	ProfileCustom CoreProfile = 4
)

// VAddr is a target virtual address.
type VAddr uint64

// ISA represents the instruction set architecture being executed.
type ISA uint32

const (
	// ISAArm represents the ARM A32 instruction set.
	ISAArm ISA = 0
	// ISAThumb2 represents the Thumb/T32 instruction set.
	ISAThumb2 ISA = 1
	// ISAAArch64 represents the AArch64 instruction set.
	ISAAArch64 ISA = 2
	// ISATee represents the ThumbEE instruction set.
	ISATee ISA = 3
	// ISAJazelle represents the Jazelle instruction set.
	ISAJazelle ISA = 4
	// ISACustom represents a custom/non-standard instruction set.
	ISACustom ISA = 5
	// ISAUnknown represents an unknown instruction set.
	ISAUnknown ISA = 6
)

// Valid returns true if the ISA is valid.
func (i ISA) Valid() bool {
	return i >= ISAArm && i <= ISAUnknown
}

// SecLevel represents the security level of the target processor execution.
type SecLevel uint32

const (
	// SecSecure indicates secure state.
	SecSecure SecLevel = 0
	// SecNonsecure indicates non-secure state.
	SecNonsecure SecLevel = 1
	// SecRoot indicates root state.
	SecRoot SecLevel = 2
	// SecRealm indicates realm state.
	SecRealm SecLevel = 3
)

// Valid returns true if the SecLevel is valid.
func (s SecLevel) Valid() bool {
	return s >= SecSecure && s <= SecRealm
}

// ExLevel represents the target Exception Level (EL).
type ExLevel int32

const (
	// ELUnknown indicates an unknown Exception Level.
	ELUnknown ExLevel = -1
	// EL0 represents Exception Level 0 (User mode).
	EL0 ExLevel = 0
	// EL1 represents Exception Level 1 (Kernel/OS mode).
	EL1 ExLevel = 1
	// EL2 represents Exception Level 2 (Hypervisor mode).
	EL2 ExLevel = 2
	// EL3 represents Exception Level 3 (Monitor mode).
	EL3 ExLevel = 3
)

// Valid returns true if the Exception Level is valid.
func (e ExLevel) Valid() bool {
	return e >= ELUnknown && e <= EL3
}

// InstrType represents the decoded instruction branch/barrier type.
type InstrType uint32

const (
	// InstrOther represents standard non-branch instruction.
	InstrOther InstrType = 0
	// InstrBr represents standard branch.
	InstrBr InstrType = 1
	// InstrBrIndirect represents indirect branch.
	InstrBrIndirect InstrType = 2
	// InstrIsb represents instruction synchronization barrier.
	InstrIsb InstrType = 3
	// InstrDsbDmb represents data barrier.
	InstrDsbDmb InstrType = 4
	// InstrWfiWfe represents wait for interrupt/event.
	InstrWfiWfe InstrType = 5
	// InstrTstart represents transaction start.
	InstrTstart InstrType = 6
)

// Valid returns true if the instruction type is valid.
func (t InstrType) Valid() bool {
	return t >= InstrOther && t <= InstrTstart
}

// InstrSubtype represents subtype classifications of instructions.
type InstrSubtype uint32

const (
	// SInstrNone represents no branch subtype.
	SInstrNone InstrSubtype = 0
	// SInstrBrLink represents branch with link (call).
	SInstrBrLink InstrSubtype = 1
	// SInstrV8Ret represents ARMv8 return instruction.
	SInstrV8Ret InstrSubtype = 2
	// SInstrV8Eret represents exception return instruction.
	SInstrV8Eret InstrSubtype = 3
	// SInstrV7ImpliedRet represents implicit return.
	SInstrV7ImpliedRet InstrSubtype = 4
)

// Valid returns true if the instruction subtype is valid.
func (s InstrSubtype) Valid() bool {
	return s >= SInstrNone && s <= SInstrV7ImpliedRet
}

// PEContext represents the Execution Context of the target processor.
type PEContext struct {
	SecurityLevel  SecLevel
	ExceptionLevel ExLevel
	ContextID      uint32
	VMID           uint32
	Bits64         bool
	ContextIDValid bool
	VMIDValid      bool
	ELValid        bool
}

// MemSpaceAcc represents the target memory space access privileges.
type MemSpaceAcc uint32

const (
	// MemSpaceNone represents no memory space access.
	MemSpaceNone MemSpaceAcc = 0x0
	// MemSpaceEL1S represents Secure EL1 memory space access.
	MemSpaceEL1S MemSpaceAcc = 0x1
	// MemSpaceEL1N represents Non-secure EL1 memory space access.
	MemSpaceEL1N MemSpaceAcc = 0x2
	// MemSpaceEL2 represents Non-secure EL2 memory space access.
	MemSpaceEL2 MemSpaceAcc = 0x4
	// MemSpaceEL3 represents Secure EL3 memory space access.
	MemSpaceEL3 MemSpaceAcc = 0x8
	// MemSpaceEL2S represents Secure EL2 memory space access.
	MemSpaceEL2S MemSpaceAcc = 0x10
	// MemSpaceEL1R represents Realm EL1 memory space access.
	MemSpaceEL1R MemSpaceAcc = 0x20
	// MemSpaceEL2R represents Realm EL2 memory space access.
	MemSpaceEL2R MemSpaceAcc = 0x40
	// MemSpaceRoot represents Root memory space access.
	MemSpaceRoot MemSpaceAcc = 0x80
	// MemSpaceS represents all Secure memory spaces.
	MemSpaceS MemSpaceAcc = 0x19
	// MemSpaceN represents all Non-secure memory spaces.
	MemSpaceN MemSpaceAcc = 0x6
	// MemSpaceR represents all Realm memory spaces.
	MemSpaceR MemSpaceAcc = 0x60
	// MemSpaceAny represents any/all memory spaces.
	MemSpaceAny MemSpaceAcc = 0xFF
)

var memSpaceNames = map[MemSpaceAcc]string{
	MemSpaceNone: "None",
	MemSpaceEL1S: "EL1S",
	MemSpaceEL1N: "EL1N",
	MemSpaceEL2:  "EL2N",
	MemSpaceEL3:  "EL3",
	MemSpaceEL2S: "EL2S",
	MemSpaceEL1R: "EL1R",
	MemSpaceEL2R: "EL2R",
	MemSpaceRoot: "Root",
	MemSpaceS:    "Any S",
	MemSpaceN:    "Any NS",
	MemSpaceR:    "Any R",
	MemSpaceAny:  "Any",
}

var memSpacePartNames = []struct {
	space MemSpaceAcc
	name  string
}{
	{MemSpaceEL1S, "EL1S"},
	{MemSpaceEL1N, "EL1N"},
	{MemSpaceEL2, "EL2N"},
	{MemSpaceEL3, "EL3"},
	{MemSpaceEL2S, "EL2S"},
	{MemSpaceEL1R, "EL1R"},
	{MemSpaceEL2R, "EL2R"},
	{MemSpaceRoot, "Root"},
}

// String returns a comma-separated representation of the memory spaces included in the mask.
func (m MemSpaceAcc) String() string {
	if name, ok := memSpaceNames[m]; ok {
		return name
	}

	parts := make([]string, 0, len(memSpacePartNames))
	for _, part := range memSpacePartNames {
		if m&part.space != 0 {
			parts = append(parts, part.name)
		}
	}
	return strings.Join(parts, ",")
}

// TraceProtocol represents the specific CoreSight hardware trace protocol.
type TraceProtocol uint32

const (
	// ProtocolUnknown represents an unknown trace protocol.
	ProtocolUnknown TraceProtocol = iota
	// ProtocolETMV3 represents ETMv3 protocol.
	ProtocolETMV3
	// ProtocolETMV4I represents ETMv4 instruction trace protocol.
	ProtocolETMV4I
	// ProtocolETMV4D represents ETMv4 data trace protocol.
	ProtocolETMV4D
	// ProtocolPTM represents PTM protocol.
	ProtocolPTM
	// ProtocolSTM represents STM protocol.
	ProtocolSTM
	// ProtocolETE represents ETE protocol.
	ProtocolETE
	// ProtocolITM represents ITM protocol.
	ProtocolITM
)

// ProtocolName returns the canonical name for a TraceProtocol.
func ProtocolName(p TraceProtocol) string {
	switch p {
	case ProtocolETMV3:
		return "ETMV3"
	case ProtocolETMV4I:
		return "ETMV4I"
	case ProtocolETMV4D:
		return "ETMV4D"
	case ProtocolPTM:
		return "PTM"
	case ProtocolSTM:
		return "STM"
	case ProtocolETE:
		return "ETE"
	case ProtocolITM:
		return "ITM"
	default:
		return "UNKNOWN"
	}
}

// SWTInfo represents decoded software trace context info.
type SWTInfo struct {
	MasterID          uint16
	ChannelID         uint16
	PayloadPktBitsize uint8
	PayloadNumPackets uint8
	MarkerPacket      bool
	HasTimestamp      bool
	MarkerFirst       bool
	MasterErr         bool
	GlobalErr         bool
	TriggerEvent      bool
	Frequency         bool
	IDValid           bool
}

// String returns the canonical string representation for i.
func (i ISA) String() string {
	switch i {
	case ISAArm:
		return "ARM(32)"
	case ISAThumb2:
		return "Thumb2"
	case ISAAArch64:
		return "AArch64"
	case ISATee:
		return "ThumbEE"
	case ISAJazelle:
		return "Jazelle"
	case ISACustom:
		return "Custom"
	case ISAUnknown:
		return "Unknown"
	default:
		return fmt.Sprintf("Unknown (%d)", int(i))
	}
}
