package snapshot

import (
	"github.com/awmorgan/coresight/internal/protocol"
	"github.com/awmorgan/coresight/trace"
	"maps"
	"strconv"
	"strings"
)

var defaultCoreMap = map[string]protocol.ArchProfile{
	// Cortex-A Series
	"Cortex-A77": {Arch: trace.ArchV8r3, Profile: trace.ProfileCortexA},
	"Cortex-A76": {Arch: trace.ArchV8r3, Profile: trace.ProfileCortexA},
	"Cortex-A75": {Arch: trace.ArchV8r3, Profile: trace.ProfileCortexA},
	"Cortex-A73": {Arch: trace.ArchV8, Profile: trace.ProfileCortexA},
	"Cortex-A72": {Arch: trace.ArchV8, Profile: trace.ProfileCortexA},
	"Cortex-A65": {Arch: trace.ArchV8r3, Profile: trace.ProfileCortexA},
	"Cortex-A57": {Arch: trace.ArchV8, Profile: trace.ProfileCortexA},
	"Cortex-A55": {Arch: trace.ArchV8r3, Profile: trace.ProfileCortexA},
	"Cortex-A53": {Arch: trace.ArchV8, Profile: trace.ProfileCortexA},
	"Cortex-A35": {Arch: trace.ArchV8, Profile: trace.ProfileCortexA},
	"Cortex-A32": {Arch: trace.ArchV8, Profile: trace.ProfileCortexA},
	"Cortex-A17": {Arch: trace.ArchV7, Profile: trace.ProfileCortexA},
	"Cortex-A15": {Arch: trace.ArchV7, Profile: trace.ProfileCortexA},
	"Cortex-A12": {Arch: trace.ArchV7, Profile: trace.ProfileCortexA},
	"Cortex-A9":  {Arch: trace.ArchV7, Profile: trace.ProfileCortexA},
	"Cortex-A8":  {Arch: trace.ArchV7, Profile: trace.ProfileCortexA},
	"Cortex-A7":  {Arch: trace.ArchV7, Profile: trace.ProfileCortexA},
	"Cortex-A5":  {Arch: trace.ArchV7, Profile: trace.ProfileCortexA},

	// Cortex-R Series
	"Cortex-R52": {Arch: trace.ArchV8, Profile: trace.ProfileCortexR},
	"Cortex-R8":  {Arch: trace.ArchV7, Profile: trace.ProfileCortexR},
	"Cortex-R7":  {Arch: trace.ArchV7, Profile: trace.ProfileCortexR},
	"Cortex-R5":  {Arch: trace.ArchV7, Profile: trace.ProfileCortexR},
	"Cortex-R4":  {Arch: trace.ArchV7, Profile: trace.ProfileCortexR},

	// Cortex-M Series
	"Cortex-M55": {Arch: trace.ArchV8, Profile: trace.ProfileCortexM},
	"Cortex-M33": {Arch: trace.ArchV8, Profile: trace.ProfileCortexM},
	"Cortex-M23": {Arch: trace.ArchV8, Profile: trace.ProfileCortexM},
	"Cortex-M4":  {Arch: trace.ArchV7, Profile: trace.ProfileCortexM},
	"Cortex-M3":  {Arch: trace.ArchV7, Profile: trace.ProfileCortexM},
	"Cortex-M0+": {Arch: trace.ArchV7, Profile: trace.ProfileCortexM},
	"Cortex-M0":  {Arch: trace.ArchV7, Profile: trace.ProfileCortexM},
}

var unknownArchProfile = protocol.ArchProfile{Arch: trace.ArchUnknown, Profile: trace.ProfileUnknown}

// CoreArchProfileMap maps core names to architecture profiles.
type CoreArchProfileMap struct {
	coreMap map[string]protocol.ArchProfile
}

// NewCoreArchProfileMap creates a new map.
func NewCoreArchProfileMap() *CoreArchProfileMap {
	m := make(map[string]protocol.ArchProfile, len(defaultCoreMap))
	maps.Copy(m, defaultCoreMap)

	return &CoreArchProfileMap{coreMap: m}
}

// ArchProfile returns the architecture profile for a given core name.
func (m *CoreArchProfileMap) ArchProfile(coreName string) (protocol.ArchProfile, bool) {
	if val, ok := m.coreMap[coreName]; ok {
		return val, true
	}

	return getPatternMatchCoreName(coreName)
}

func getPatternMatchCoreName(coreName string) (protocol.ArchProfile, bool) {
	if rest, ok := strings.CutPrefix(coreName, "ARMv"); ok {
		return parseARMvCoreName(rest)
	}
	if rest, ok := strings.CutPrefix(coreName, "ARM-"); ok {
		return parseARMDashCoreName(rest)
	}
	return unknownArchProfile, false
}

func parseARMvCoreName(rest string) (protocol.ArchProfile, bool) {
	version, profile, ok := strings.Cut(rest, "-")
	if !ok || profile == "" {
		return unknownArchProfile, false
	}

	major, minor, ok := parseARMVersion(version)
	if !ok {
		return unknownArchProfile, false
	}

	ap := protocol.ArchProfile{}
	if !setProfileFromByte(&ap, profile[0]) {
		return unknownArchProfile, false
	}
	if !setArchFromARMVersion(&ap, major, minor) {
		return unknownArchProfile, false
	}
	return ap, true
}

func parseARMDashCoreName(rest string) (protocol.ArchProfile, bool) {
	archName, profile, hasProfile := strings.Cut(rest, "-")
	if !strings.EqualFold(archName, "aa64") {
		return unknownArchProfile, false
	}

	ap := protocol.ArchProfile{Arch: trace.ArchAA64, Profile: trace.ProfileCortexA}
	if !hasProfile || profile == "" {
		return ap, true
	}

	switch profile[0] {
	case 'R':
		ap.Profile = trace.ProfileCortexR
	case 'M':
		ap.Profile = trace.ProfileCortexM
	}
	return ap, true
}

func parseARMVersion(version string) (major, minor int, ok bool) {
	majorPart, minorPart, hasMinor := strings.Cut(version, ".")

	major, err := strconv.Atoi(majorPart)
	if err != nil || major < 0 {
		return 0, 0, false
	}

	if !hasMinor {
		return major, 0, true
	}

	minor, err = strconv.Atoi(minorPart)
	if err != nil || minor < 0 {
		return 0, 0, false
	}
	return major, minor, true
}

func setArchFromARMVersion(ap *protocol.ArchProfile, major, minor int) bool {
	switch {
	case major == 7:
		ap.Arch = trace.ArchV7
	case major == 8 && minor < 3:
		ap.Arch = trace.ArchV8
	case major == 8 && minor == 3:
		ap.Arch = trace.ArchV8r3
	case major >= 8:
		ap.Arch = trace.ArchAA64
	default:
		return false
	}
	return true
}

func setProfileFromByte(ap *protocol.ArchProfile, profile byte) bool {
	switch profile {
	case 'A':
		ap.Profile = trace.ProfileCortexA
	case 'R':
		ap.Profile = trace.ProfileCortexR
	case 'M':
		ap.Profile = trace.ProfileCortexM
	default:
		return false
	}
	return true
}
