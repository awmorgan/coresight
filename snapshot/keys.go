package snapshot

const (
	SnapshotSectionName = "snapshot"
	VersionKey          = "version"
	DescriptionKey      = "description"

	DeviceListSectionName = "device_list"

	TraceSectionName = "trace"
	MetadataKey      = "metadata"

	DeviceSectionName = "device"
	DeviceNameKey     = "name"
	DeviceClassKey    = "class"
	DeviceTypeKey     = "type"

	SymbolicRegsSectionName = "regs"

	DumpFileSectionPrefix = "dump"
	DumpAddressKey        = "address"
	DumpLengthKey         = "length"
	DumpOffsetKey         = "offset"
	DumpFileKey           = "file"
	DumpSpaceKey          = "space"

	BuffersSectionName = "trace_buffers"
	BufferListKey      = "buffers"

	BufferSectionPrefix = "buffer"
	BufferNameKey       = "name"
	BufferFileKey       = "file"
	BufferFormatKey     = "format"

	SourceBuffersSectionName = "source_buffers"
	CoreSourcesSectionName   = "core_trace_sources"

	GlobalSectionName       = "global"
	CoreKey                 = "core"
	ExtendedRegsSectionName = "extendregs"
	ClustersSectionName     = "clusters"

	CpuProfileA = "Cortex-A"
	CpuProfileR = "Cortex-R"
	CpuProfileM = "Cortex-M"

	BuffFmtCS = "github.com/awmorgan/coresight"
	ProtocolTypeETMv3 = "ETM3"
	ProtocolTypeETMv4 = "ETM4"
	ProtocolTypePTM   = "PTM1"
	ProtocolTypePFT   = "PFT1"
	ProtocolTypeETE   = "ETE"
	ProtocolTypeSTM   = "STM"
	ProtocolTypeITM   = "ITM"

	Etmv4RegCfg   = "TRCCONFIGR"
	Etmv4RegIDR   = "TRCTRACEIDR"
	Etmv4RegAuth  = "TRCAUTHSTATUS"
	Etmv4RegIDR0  = "TRCIDR0"
	Etmv4RegIDR1  = "TRCIDR1"
	Etmv4RegIDR2  = "TRCIDR2"
	Etmv4RegIDR8  = "TRCIDR8"
	Etmv4RegIDR9  = "TRCIDR9"
	Etmv4RegIDR10 = "TRCIDR10"
	Etmv4RegIDR11 = "TRCIDR11"
	Etmv4RegIDR12 = "TRCIDR12"
	Etmv4RegIDR13 = "TRCIDR13"

	EteRegDevArch = "TRCDEVARCH"

	Etmv3PTMRegIDR      = "ETMIDR"
	Etmv3PTMRegCR       = "ETMCR"
	Etmv3PTMRegCCER     = "ETMCCER"
	Etmv3PTMRegTraceIDR = "ETMTRACEIDR"

	StmRegTCSR = "STMTCSR"

	ItmRegTCR = "ITMTCR"
)
