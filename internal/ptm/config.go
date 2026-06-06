package ptm

import "coresight/trace"

const (
	ctrlBranchBcast = 1 << 8
	ctrlCycleAcc    = 1 << 12
	ctrlTsEna       = 1 << 28
	ctrlRetStackEna = 1 << 29
	ctrlVmidEna     = 1 << 30

	ccerTsImpl      = 1 << 22
	ccerRestackImpl = 1 << 23
	ccerDmsbWpt     = 1 << 24
	ccerTsDmsb      = 1 << 25
	ccerVirtExt     = 1 << 26
	ccerTsEncNat    = 1 << 28
	ccerTs64Bit     = 1 << 29
)

// Config represents the trace capture time configuration of a PTM hardware component.
type Config struct {
	TraceID        uint8
	ArchVer        trace.ArchVersion
	CoreProf       trace.CoreProfile
	EnaBranchBCast bool
	EnaCycleAcc    bool
	EnaRetStack    bool
	HasRetStack    bool
	HasTS          bool
	EnaTS          bool
	TSPacket64     bool
	TSBinEnc       bool
	CtxtIDBytes    int
	HasVirtExt     bool
	EnaVMID        bool
	DmsbGenTS      bool
	DmsbWayPt      bool
}

var ctxtIDByteSizes = [...]int{0, 1, 2, 4}

// ParseConfig creates a Config from raw hardware register values.
func ParseConfig(traceID, idr, ctrl, ccer uint32, arch trace.ArchVersion, prof trace.CoreProfile) *Config {
	minorRev := int(idr&0xF0) >> 4
	postMinor0 := minorRev != 0

	return &Config{
		TraceID:        uint8(traceID & 0x7F),
		ArchVer:        arch,
		CoreProf:       prof,
		EnaBranchBCast: (ctrl & ctrlBranchBcast) != 0,
		EnaCycleAcc:    (ctrl & ctrlCycleAcc) != 0,
		EnaRetStack:    (ctrl & ctrlRetStackEna) != 0,
		HasRetStack:    (ccer & ccerRestackImpl) != 0,
		HasTS:          (ccer & ccerTsImpl) != 0,
		EnaTS:          (ctrl & ctrlTsEna) != 0,
		TSPacket64:     postMinor0 && (ccer&ccerTs64Bit) != 0,
		TSBinEnc:       postMinor0 && (ccer&ccerTsEncNat) != 0,
		CtxtIDBytes:    ctxtIDByteSizes[(ctrl>>14)&0x3],
		HasVirtExt:     (ccer & ccerVirtExt) != 0,
		EnaVMID:        (ctrl & ctrlVmidEna) != 0,
		DmsbGenTS:      (ccer & ccerTsDmsb) != 0,
		DmsbWayPt:      (ccer & ccerDmsbWpt) != 0,
	}
}

// NewDefaultConfig replicates the C++ default constructor, setting ETMv1.1 and V7A defaults.
func NewDefaultConfig() *Config {
	return ParseConfig(
		0,
		0x4100F310,
		0,
		0,
		trace.ArchV7,
		trace.ProfileCortexA,
	)
}
