package trace

import (
	"errors"
	"fmt"
	"strings"
)

// Index is the trace source index type.
// Equivalent to ocsd_trc_index_t 64-bit fallback.
type Index uint64

const (
	// BadIndex is an invalid trace index value.
	BadIndex Index = ^Index(0)

	// BadCSSrcID is an invalid trace source ID value.
	BadCSSrcID uint8 = 0xFF

	// MaxTraceID is the maximum number of CoreSight Trace IDs (0-127).
	MaxTraceID = 128
)

// IsValidCSSrcID reports whether id is an architecturally valid CoreSight trace source ID.
func IsValidCSSrcID(id uint8) bool {
	return id > 0 && id < 0x70
}

// IsReservedCSSrcID reports whether id is in the reserved CoreSight trace source ID range.
func IsReservedCSSrcID(id uint8) bool {
	return id == 0 || (id >= 0x70 && id <= 0x7F)
}

var (
	ErrFail                  = errors.New("general failure")
	ErrMem                   = errors.New("internal memory allocation error")
	ErrNotInit               = errors.New("component not initialised")
	ErrInvalidID             = errors.New("invalid CoreSight Trace Source ID")
	ErrBadHandle             = errors.New("invalid handle passed to component")
	ErrInvalidParamVal       = errors.New("invalid value parameter passed to component")
	ErrInvalidParamType      = errors.New("type mismatch on abstract interface")
	ErrFileError             = errors.New("file access error")
	ErrNoProtocol            = errors.New("trace protocol unsupported")
	ErrAttachTooMany         = errors.New("cannot attach - attach device limit reached")
	ErrAttachInvalidParam    = errors.New("cannot attach - invalid parameter")
	ErrAttachCompNotFound    = errors.New("cannot detach - component not found")
	ErrRdrFileNotFound       = errors.New("source reader - file not found")
	ErrRdrInvalidInit        = errors.New("source reader - invalid initialisation parameter")
	ErrRdrNoDecoder          = errors.New("source reader - no trace decoder set")
	ErrDataDecodeFatal       = errors.New("a decoder in the data path has returned a fatal error")
	ErrDfrmtrNotconttrace    = errors.New("trace input to deformatter non-continuous")
	ErrDfrmtrBadFhsync       = errors.New("bad frame or half frame sync in trace deformatter")
	ErrDfrmtrUnaligned       = errors.New("insufficient bytes for aligned frame")
	ErrDfrmtrBadFsyncReset   = errors.New("incorrect FSYNC frame reset pattern")
	ErrDfrmtrBadHSync        = errors.New("bad HSYNC in frame")
	ErrDfrmtrBadFsyncStart   = errors.New("bad FSYNC start in frame or invalid ID (0x7F)")
	ErrDfrmtrOddByte         = errors.New("odd trailing byte in frame stream")
	ErrDfrmtrNotConfigured   = errors.New("deformatter not configured")
	ErrBadPacketSeq          = errors.New("bad packet sequence")
	ErrInvalidPcktHdr        = errors.New("invalid packet header")
	ErrPktInterpFail         = errors.New("interpreter failed - cannot recover - bad data or sequence")
	ErrUnsupportedISA        = errors.New("ISA not supported in decoder")
	ErrHWCfgUnsupp           = errors.New("programmed trace configuration not supported by decoder")
	ErrUnsuppDecodePkt       = errors.New("packet not supported in decoder")
	ErrBadDecodePkt          = errors.New("reserved or unknown packet in decoder")
	ErrCommitPktOverrun      = errors.New("overrun in commit packet stack - tried to commit more than available")
	ErrMemNacc               = errors.New("unable to access required memory address")
	ErrRetStackOverflow      = errors.New("internal return stack overflow checks failed - popped more than we pushed")
	ErrDcdtNoFormatter       = errors.New("no formatter in use - operation not valid")
	ErrMemAccOverlap         = errors.New("attempted to set an overlapping range in memory access map")
	ErrMemAccFileNotFound    = errors.New("memory access file could not be opened")
	ErrMemAccFileDiffRange   = errors.New("attempt to re-use the same memory access file for a different address range")
	ErrMemAccRangeInvalid    = errors.New("address range in accessor set to invalid values")
	ErrMemAccBadLen          = errors.New("memory accessor returned a bad read length value (larger than requested)")
	ErrTestSnapshotParse     = errors.New("test snapshot file parse error")
	ErrTestSnapshotParseInfo = errors.New("test snapshot file parse information")
	ErrTestSnapshotRead      = errors.New("test snapshot reader error")
	ErrTestSSToDecoder       = errors.New("test snapshot to decode tree conversion error")
	ErrDcdregNameRepeat      = errors.New("attempted to register a decoder with the same name as another one")
	ErrDcdregNameUnknown     = errors.New("attempted to find a decoder with a name that is not known in the library")
	ErrDcdregTypeUnknown     = errors.New("attempted to find a decoder with a type that is not known in the library")
	ErrDcdregToomany         = errors.New("attempted to register too many custom decoders")
	ErrDcdInterfaceUnused    = errors.New("attempt to connect or use and interface not supported by this decoder")
	ErrInvalidOpcode         = errors.New("illegal Opcode found while decoding program memory")
	ErrIRangeLimitOverrun    = errors.New("an optional limit on consecutive instructions in range during decode has been exceeded")
	ErrBadDecodeImage        = errors.New("mismatch between trace packets and decode image")
)

type RawframeElem uint32

const (
	FrmNone   RawframeElem = 0
	FrmPacked RawframeElem = 1
	FrmHsync  RawframeElem = 2
	FrmFsync  RawframeElem = 3
	FrmIDData RawframeElem = 4
)

const (
	DfrmtrFrameSize = 0x10
)

type ArchVersion uint32

const (
	ArchUnknown ArchVersion = 0x0000
	ArchCustom  ArchVersion = 0x0001
	ArchV7      ArchVersion = 0x0700
	ArchV8      ArchVersion = 0x0800
	ArchV8r3    ArchVersion = 0x0803
	ArchAA64    ArchVersion = 0x0864
	ArchV8max   ArchVersion = ArchAA64
)

func IsV8Arch(arch ArchVersion) bool              { return arch >= ArchV8 && arch <= ArchV8max }
func IsArchMinVer(arch, minArch ArchVersion) bool { return arch >= minArch }

type CoreProfile uint32

const (
	ProfileUnknown CoreProfile = 0
	ProfileCortexM CoreProfile = 1
	ProfileCortexR CoreProfile = 2
	ProfileCortexA CoreProfile = 3
	ProfileCustom  CoreProfile = 4
)

type ArchProfile struct {
	Arch    ArchVersion
	Profile CoreProfile
}

// VAddr is a target virtual address.
type VAddr uint64

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

type ISA uint32

const (
	ISAArm     ISA = 0
	ISAThumb2  ISA = 1
	ISAAArch64 ISA = 2
	ISATee     ISA = 3
	ISAJazelle ISA = 4
	ISACustom  ISA = 5
	ISAUnknown ISA = 6
)

func (i ISA) Valid() bool {
	return i >= ISAArm && i <= ISAUnknown
}

type SecLevel uint32

const (
	SecSecure    SecLevel = 0
	SecNonsecure SecLevel = 1
	SecRoot      SecLevel = 2
	SecRealm     SecLevel = 3
)

func (s SecLevel) Valid() bool {
	return s >= SecSecure && s <= SecRealm
}

type ExLevel int32

const (
	ELUnknown ExLevel = -1
	EL0       ExLevel = 0
	EL1       ExLevel = 1
	EL2       ExLevel = 2
	EL3       ExLevel = 3
)

func (e ExLevel) Valid() bool {
	return e >= ELUnknown && e <= EL3
}

type InstrType uint32

const (
	InstrOther      InstrType = 0
	InstrBr         InstrType = 1
	InstrBrIndirect InstrType = 2
	InstrIsb        InstrType = 3
	InstrDsbDmb     InstrType = 4
	InstrWfiWfe     InstrType = 5
	InstrTstart     InstrType = 6
)

func (t InstrType) Valid() bool {
	return t >= InstrOther && t <= InstrTstart
}

type InstrSubtype uint32

const (
	SInstrNone         InstrSubtype = 0
	SInstrBrLink       InstrSubtype = 1
	SInstrV8Ret        InstrSubtype = 2
	SInstrV8Eret       InstrSubtype = 3
	SInstrV7ImpliedRet InstrSubtype = 4
)

func (s InstrSubtype) Valid() bool {
	return s >= SInstrNone && s <= SInstrV7ImpliedRet
}

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

type MemSpaceAcc uint32

const (
	MemSpaceNone MemSpaceAcc = 0x0
	MemSpaceEL1S MemSpaceAcc = 0x1
	MemSpaceEL1N MemSpaceAcc = 0x2
	MemSpaceEL2  MemSpaceAcc = 0x4
	MemSpaceEL3  MemSpaceAcc = 0x8
	MemSpaceEL2S MemSpaceAcc = 0x10
	MemSpaceEL1R MemSpaceAcc = 0x20
	MemSpaceEL2R MemSpaceAcc = 0x40
	MemSpaceRoot MemSpaceAcc = 0x80
	MemSpaceS    MemSpaceAcc = 0x19
	MemSpaceN    MemSpaceAcc = 0x6
	MemSpaceR    MemSpaceAcc = 0x60
	MemSpaceAny  MemSpaceAcc = 0xFF
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

type FileMemRegion struct {
	FileOffset   uint64
	StartAddress VAddr
	RegionSize   uint64
}

type TraceProtocol uint32

const (
	ProtocolUnknown TraceProtocol = iota
	ProtocolETMV3
	ProtocolETMV4I
	ProtocolETMV4D
	ProtocolPTM
	ProtocolSTM
	ProtocolETE
	ProtocolITM
)

// ProtocolName returns the canonical name for a protocol.
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

const SwtIDValidMask = 0x1 << 23

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

// String returns the OpenCSD-style name for i.
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
