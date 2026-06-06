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

	CPUprofileA = "Cortex-A"
	CPUprofileR = "Cortex-R"
	CPUprofileM = "Cortex-M"

	BuffFmtCS = "coresight"

	ProtocolTypeETMv3 = "ETM3"
	ProtocolTypeETMv4 = "ETM4"
	ProtocolTypePTM   = "PTM1"
	ProtocolTypePFT   = "PFT1"
	ProtocolTypeETE   = "ETE"
	ProtocolTypeSTM   = "STM"
	ProtocolTypeITM   = "ITM"

	ETMv4RegCfg   = "TRCCONFIGR"
	ETMv4RegIDR   = "TRCTRACEIDR"
	ETMv4RegAuth  = "TRCAUTHSTATUS"
	ETMv4RegIDR0  = "TRCIDR0"
	ETMv4RegIDR1  = "TRCIDR1"
	ETMv4RegIDR2  = "TRCIDR2"
	ETMv4RegIDR8  = "TRCIDR8"
	ETMv4RegIDR9  = "TRCIDR9"
	ETMv4RegIDR10 = "TRCIDR10"
	ETMv4RegIDR11 = "TRCIDR11"
	ETMv4RegIDR12 = "TRCIDR12"
	ETMv4RegIDR13 = "TRCIDR13"

	ETERegDevArch = "TRCDEVARCH"

	ETMv3PTMRegIDR      = "ETMIDR"
	ETMv3PTMRegCR       = "ETMCR"
	ETMv3PTMRegCCER     = "ETMCCER"
	ETMv3PTMRegTraceIDR = "ETMTRACEIDR"

	STMRegTCSR = "STMTCSR"

	ITMRegTCR = "ITMTCR"
)
