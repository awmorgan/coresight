package snapshot

const (
	snapshotSectionName = "snapshot"
	versionKey          = "version"
	descriptionKey      = "description"

	deviceListSectionName = "device_list"

	traceSectionName = "trace"
	metadataKey      = "metadata"

	deviceSectionName = "device"
	deviceNameKey     = "name"
	deviceClassKey    = "class"
	deviceTypeKey     = "type"

	symbolicRegsSectionName = "regs"

	dumpFileSectionPrefix = "dump"
	dumpAddressKey        = "address"
	dumpLengthKey         = "length"
	dumpOffsetKey         = "offset"
	dumpFileKey           = "file"
	dumpSpaceKey          = "space"

	buffersSectionName = "trace_buffers"
	bufferListKey      = "buffers"

	bufferSectionPrefix = "buffer"
	bufferNameKey       = "name"
	bufferFileKey       = "file"
	bufferFormatKey     = "format"

	sourceBuffersSectionName = "source_buffers"
	coreSourcesSectionName   = "core_trace_sources"

	globalSectionName       = "global"
	coreKey                 = "core"
	extendedRegsSectionName = "extendregs"
	clustersSectionName     = "clusters"

	buffFmtCS         = "github.com/awmorgan/coresight"
	protocolTypeETMv3 = "ETM3"
	protocolTypeETMv4 = "ETM4"
	protocolTypePTM   = "PTM1"
	protocolTypePFT   = "PFT1"
	protocolTypeETE   = "ETE"
	protocolTypeSTM   = "STM"
	protocolTypeITM   = "ITM"

	etmv4RegCfg   = "TRCCONFIGR"
	etmv4RegIDR   = "TRCTRACEIDR"
	etmv4RegAuth  = "TRCAUTHSTATUS"
	etmv4RegIDR0  = "TRCIDR0"
	etmv4RegIDR1  = "TRCIDR1"
	etmv4RegIDR2  = "TRCIDR2"
	etmv4RegIDR8  = "TRCIDR8"
	etmv4RegIDR9  = "TRCIDR9"
	etmv4RegIDR10 = "TRCIDR10"
	etmv4RegIDR11 = "TRCIDR11"
	etmv4RegIDR12 = "TRCIDR12"
	etmv4RegIDR13 = "TRCIDR13"

	eteRegDevArch = "TRCDEVARCH"

	etmv3PTMRegIDR      = "ETMIDR"
	etmv3PTMRegCR       = "ETMCR"
	etmv3PTMRegCCER     = "ETMCCER"
	etmv3PTMRegTraceIDR = "ETMTRACEIDR"

	stmRegTCSR = "STMTCSR"

	itmRegTCR = "ITMTCR"
)
