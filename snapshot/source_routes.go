package snapshot

import (
	"fmt"
	"sort"
	"strings"

	"github.com/awmorgan/coresight"
)

type sourceRouteSpec struct {
	sourceName   string
	coreName     string
	sourceDevice *Device
	coreDevice   *Device
}

func (b *PipelineBuilder) sourceRouteSpecs(tree *TraceBufferSourceTree) ([]sourceRouteSpec, []error) {
	if tree == nil {
		return nil, []error{fmt.Errorf("source tree is nil")}
	}

	specs := make([]sourceRouteSpec, 0, len(tree.SourceCoreAssoc))
	var snapshotSkipped []error

	sourceNames := make([]string, 0, len(tree.SourceCoreAssoc))
	for sourceName := range tree.SourceCoreAssoc {
		sourceNames = append(sourceNames, sourceName)
	}
	sort.Strings(sourceNames)

	for _, sourceName := range sourceNames {
		coreName := tree.SourceCoreAssoc[sourceName]
		devSrc := b.reader.ParsedDeviceList[sourceName]
		if devSrc == nil {
			msg := fmt.Sprintf("ss2_dcdtree : 0x0026 (OCSD_ERR_TEST_SS_TO_DECODER) [test snapshot to decode tree conversion error]; Failed to find device data for source %s.", sourceName)
			b.diagnostics = append(b.diagnostics, msg)
			snapshotSkipped = append(snapshotSkipped, fmt.Errorf("%s", msg))
			continue
		}

		devType := protocolBase(devSrc.Type)
		var coreDev *Device
		if coreName == "" || coreName == "<none>" {
			if protocolRequiresCore(devType) {
				snapshotSkipped = append(snapshotSkipped, fmt.Errorf("source %q has no associated PE core", sourceName))
				continue
			}
		} else {
			coreDev = b.reader.ParsedDeviceList[coreName]
			if coreDev == nil {
				snapshotSkipped = append(snapshotSkipped, fmt.Errorf("core device %q not found", coreName))
				continue
			}
		}

		specs = append(specs, sourceRouteSpec{
			sourceName:   sourceName,
			coreName:     coreName,
			sourceDevice: devSrc,
			coreDevice:   coreDev,
		})
	}

	return specs, snapshotSkipped
}

func (b *PipelineBuilder) attachSourceRoutes(specs []sourceRouteSpec, mem coresight.MemoryReader) (int, []error) {
	created := 0
	var snapshotSkipped []error

	for _, spec := range specs {
		devType := protocolBase(spec.sourceDevice.Type)

		var route coresight.Route
		var err error
		isSupported := false

		switch devType {
		case ProtocolTypePTM, ProtocolTypePFT:
			route, err = b.buildPTMRoute(spec)
			isSupported = true
		case ProtocolTypeETMv3:
			route, err = b.buildETMv3Route(spec)
			isSupported = true
		case ProtocolTypeETMv4:
			route, err = b.buildETMv4Route(spec)
			isSupported = true
		case ProtocolTypeETE:
			route, err = b.buildETERoute(spec)
			isSupported = true
		case ProtocolTypeITM:
			route, err = b.buildITMRoute(spec)
			isSupported = true
		case ProtocolTypeSTM:
			route, err = b.buildSTMRoute(spec)
			isSupported = true
		}

		if !isSupported {
			if isKnownUnsupportedPEProtocol(devType) {
				snapshotSkipped = append(snapshotSkipped, fmt.Errorf("unsupported PE decoder protocol %q for source %q", devType, spec.sourceName))
			} else {
				snapshotSkipped = append(snapshotSkipped, fmt.Errorf("create PE route for %q: unknown PE device type %q", spec.sourceName, devType))
			}
			continue
		}

		if err != nil {
			snapshotSkipped = append(snapshotSkipped, fmt.Errorf("create PE route for %q: %w", spec.sourceName, err))
			continue
		}

		if err := b.pipe.AddRoute(route); err != nil {
			snapshotSkipped = append(snapshotSkipped, fmt.Errorf("create PE route for %q: %w", spec.sourceName, err))
			continue
		}
		created++
	}

	return created, snapshotSkipped
}

func protocolBase(name string) string {
	base, _, _ := strings.Cut(name, ".")
	return base
}

func protocolRequiresCore(devType string) bool {
	switch devType {
	case ProtocolTypeITM, ProtocolTypeSTM:
		return false
	default:
		return true
	}
}

func isKnownUnsupportedPEProtocol(devType string) bool {
	return strings.HasPrefix(devType, "ETMv4")
}
