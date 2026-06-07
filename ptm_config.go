package coresight


const (
	ctrlBranchBcast = 1 << 8
	ptmCtrlCycleAcc    = 1 << 12
	ptmCtrlTsEna       = 1 << 28
	ctrlRetStackEna = 1 << 29
	ptmCtrlVmidEna     = 1 << 30

	ccerTsImpl      = 1 << 22
	ccerRestackImpl = 1 << 23
	ccerDmsbWpt     = 1 << 24
	ccerTsDmsb      = 1 << 25
	ptmCcerVirtExt     = 1 << 26
	ccerTsEncNat    = 1 << 28
	ptmCcerTs64Bit     = 1 << 29
)

// ptmConfig represents the trace capture time configuration of a PTM hardware component.
type ptmConfig struct {
	TraceID        uint8
	ArchVer        ArchVersion
	CoreProf       CoreProfile
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

// ptmParseConfig creates a ptmConfig from raw hardware register values.
func ptmParseConfig(traceID, idr, ctrl, ccer uint32, arch ArchVersion, prof CoreProfile) *ptmConfig {
	minorRev := int(idr&0xF0) >> 4
	postMinor0 := minorRev != 0

	return &ptmConfig{
		TraceID:        uint8(traceID & 0x7F),
		ArchVer:        arch,
		CoreProf:       prof,
		EnaBranchBCast: (ctrl & ctrlBranchBcast) != 0,
		EnaCycleAcc:    (ctrl & ptmCtrlCycleAcc) != 0,
		EnaRetStack:    (ctrl & ctrlRetStackEna) != 0,
		HasRetStack:    (ccer & ccerRestackImpl) != 0,
		HasTS:          (ccer & ccerTsImpl) != 0,
		EnaTS:          (ctrl & ptmCtrlTsEna) != 0,
		TSPacket64:     postMinor0 && (ccer&ptmCcerTs64Bit) != 0,
		TSBinEnc:       postMinor0 && (ccer&ccerTsEncNat) != 0,
		CtxtIDBytes:    ctxtIDByteSizes[(ctrl>>14)&0x3],
		HasVirtExt:     (ccer & ptmCcerVirtExt) != 0,
		EnaVMID:        (ctrl & ptmCtrlVmidEna) != 0,
		DmsbGenTS:      (ccer & ccerTsDmsb) != 0,
		DmsbWayPt:      (ccer & ccerDmsbWpt) != 0,
	}
}

// ptmNewDefaultConfig replicates the C++ default constructor, setting ETMv1.1 and V7A defaults.
func ptmNewDefaultConfig() *ptmConfig {
	return ptmParseConfig(
		0,
		0x4100F310,
		0,
		0,
		ArchV7,
		ProfileCortexA,
	)
}
