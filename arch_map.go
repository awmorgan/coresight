package coresight

import (
	"maps"
	"strconv"
	"strings"
)

var defaultCoreMap = map[string]archProfile{
	// Cortex-A Series
	"Cortex-A77": {Arch: ArchV8r3, Profile: ProfileCortexA},
	"Cortex-A76": {Arch: ArchV8r3, Profile: ProfileCortexA},
	"Cortex-A75": {Arch: ArchV8r3, Profile: ProfileCortexA},
	"Cortex-A73": {Arch: ArchV8, Profile: ProfileCortexA},
	"Cortex-A72": {Arch: ArchV8, Profile: ProfileCortexA},
	"Cortex-A65": {Arch: ArchV8r3, Profile: ProfileCortexA},
	"Cortex-A57": {Arch: ArchV8, Profile: ProfileCortexA},
	"Cortex-A55": {Arch: ArchV8r3, Profile: ProfileCortexA},
	"Cortex-A53": {Arch: ArchV8, Profile: ProfileCortexA},
	"Cortex-A35": {Arch: ArchV8, Profile: ProfileCortexA},
	"Cortex-A32": {Arch: ArchV8, Profile: ProfileCortexA},
	"Cortex-A17": {Arch: ArchV7, Profile: ProfileCortexA},
	"Cortex-A15": {Arch: ArchV7, Profile: ProfileCortexA},
	"Cortex-A12": {Arch: ArchV7, Profile: ProfileCortexA},
	"Cortex-A9":  {Arch: ArchV7, Profile: ProfileCortexA},
	"Cortex-A8":  {Arch: ArchV7, Profile: ProfileCortexA},
	"Cortex-A7":  {Arch: ArchV7, Profile: ProfileCortexA},
	"Cortex-A5":  {Arch: ArchV7, Profile: ProfileCortexA},

	// Cortex-R Series
	"Cortex-R52": {Arch: ArchV8, Profile: ProfileCortexR},
	"Cortex-R8":  {Arch: ArchV7, Profile: ProfileCortexR},
	"Cortex-R7":  {Arch: ArchV7, Profile: ProfileCortexR},
	"Cortex-R5":  {Arch: ArchV7, Profile: ProfileCortexR},
	"Cortex-R4":  {Arch: ArchV7, Profile: ProfileCortexR},

	// Cortex-M Series
	"Cortex-M55": {Arch: ArchV8, Profile: ProfileCortexM},
	"Cortex-M33": {Arch: ArchV8, Profile: ProfileCortexM},
	"Cortex-M23": {Arch: ArchV8, Profile: ProfileCortexM},
	"Cortex-M4":  {Arch: ArchV7, Profile: ProfileCortexM},
	"Cortex-M3":  {Arch: ArchV7, Profile: ProfileCortexM},
	"Cortex-M0+": {Arch: ArchV7, Profile: ProfileCortexM},
	"Cortex-M0":  {Arch: ArchV7, Profile: ProfileCortexM},
}

var unknownArchProfile = archProfile{Arch: ArchUnknown, Profile: ProfileUnknown}

// coreArchProfileMap maps core names to architecture profiles.
type coreArchProfileMap struct {
	coreMap map[string]archProfile
}

// newCoreArchProfileMap creates a new map.
func newCoreArchProfileMap() *coreArchProfileMap {
	m := make(map[string]archProfile, len(defaultCoreMap))
	maps.Copy(m, defaultCoreMap)

	return &coreArchProfileMap{coreMap: m}
}

// archProfileMap is a package-level cache of the core architecture map (shared, read-only after init).
var archProfileMap = newCoreArchProfileMap()

// LookupCoreProfile maps a core device type name (e.g. "Cortex-A57") to its
// ArchVersion and CoreProfile.
func LookupCoreProfile(coreName string) (ArchVersion, CoreProfile) {
	if ap, ok := archProfileMap.ArchProfile(coreName); ok {
		return ap.Arch, ap.Profile
	}
	return ArchUnknown, ProfileUnknown
}

// ArchProfile returns the architecture profile for a given core name.
func (m *coreArchProfileMap) ArchProfile(coreName string) (archProfile, bool) {
	if val, ok := m.coreMap[coreName]; ok {
		return val, true
	}

	return getPatternMatchCoreName(coreName)
}

func getPatternMatchCoreName(coreName string) (archProfile, bool) {
	if rest, ok := strings.CutPrefix(coreName, "ARMv"); ok {
		return parseARMvCoreName(rest)
	}
	if rest, ok := strings.CutPrefix(coreName, "ARM-"); ok {
		return parseARMDashCoreName(rest)
	}
	return unknownArchProfile, false
}

func parseARMvCoreName(rest string) (archProfile, bool) {
	version, profile, ok := strings.Cut(rest, "-")
	if !ok || profile == "" {
		return unknownArchProfile, false
	}

	major, minor, ok := parseARMVersion(version)
	if !ok {
		return unknownArchProfile, false
	}

	ap := archProfile{}
	if !setProfileFromByte(&ap, profile[0]) {
		return unknownArchProfile, false
	}
	if !setArchFromARMVersion(&ap, major, minor) {
		return unknownArchProfile, false
	}
	return ap, true
}

func parseARMDashCoreName(rest string) (archProfile, bool) {
	archName, profile, hasProfile := strings.Cut(rest, "-")
	if !strings.EqualFold(archName, "aa64") {
		return unknownArchProfile, false
	}

	ap := archProfile{Arch: ArchAA64, Profile: ProfileCortexA}
	if !hasProfile || profile == "" {
		return ap, true
	}

	switch profile[0] {
	case 'R':
		ap.Profile = ProfileCortexR
	case 'M':
		ap.Profile = ProfileCortexM
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

func setArchFromARMVersion(ap *archProfile, major, minor int) bool {
	switch {
	case major == 7:
		ap.Arch = ArchV7
	case major == 8 && minor < 3:
		ap.Arch = ArchV8
	case major == 8 && minor == 3:
		ap.Arch = ArchV8r3
	case major >= 8:
		ap.Arch = ArchAA64
	default:
		return false
	}
	return true
}

func setProfileFromByte(ap *archProfile, profile byte) bool {
	switch profile {
	case 'A':
		ap.Profile = ProfileCortexA
	case 'R':
		ap.Profile = ProfileCortexR
	case 'M':
		ap.Profile = ProfileCortexM
	default:
		return false
	}
	return true
}
