package coresight

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

const SnapshotINIFilename = "snapshot.ini"
const TraceINIFilename = "trace.ini"

// SnapshotReader reads a snapshot directory
type SnapshotReader struct {
	FS               fs.FS
	SnapshotPath     string
	SnapshotFound    bool
	ReadOK           bool
	ParsedDeviceList map[string]*Device
	Trace            *Trace
	SourceTrees      map[string]*TraceBufferSourceTree
	Warnings         []error
}

func (r *SnapshotReader) warn(err error) {
	if err != nil {
		r.Warnings = append(r.Warnings, err)
	}
}

func (r *SnapshotReader) reset() {
	r.SnapshotFound = false
	r.ReadOK = false
	r.ParsedDeviceList = make(map[string]*Device)
	r.Trace = nil
	r.SourceTrees = make(map[string]*TraceBufferSourceTree)
	r.Warnings = nil
}

// NewSnapshotReader creates a new SnapshotReader
func NewSnapshotReader() *SnapshotReader {
	r := &SnapshotReader{}
	r.reset()
	return r
}

// Read loads as much of the snapshot as possible.
// It returns an error only if ini cannot be opened or parsed.
// Optional or trace-only content failures are recorded in r.Warnings.
func (r *SnapshotReader) Read() error {
	r.reset()

	iniPath := r.snapshotFileName(SnapshotINIFilename)
	file, err := r.openSnapshotFile(SnapshotINIFilename)
	if err != nil {
		return fmt.Errorf("open snapshot ini %s: %w", iniPath, err)
	}
	defer file.Close()

	r.SnapshotFound = true

	devList, err := parseDeviceList(file)
	if err != nil {
		return fmt.Errorf("parse device list %s: %w", iniPath, err)
	}

	for devName, iniFileName := range devList.DeviceList {
		r.warn(r.loadDevice(devName, iniFileName))
	}

	if len(devList.DeviceList) == 0 {
		r.loadLegacyDevices()
	}

	r.warn(r.readTraceMetadata(devList.TraceMetaDataName))

	r.ReadOK = true
	return nil
}

func (r *SnapshotReader) loadDevice(devName string, iniFileName string) error {
	devIniPath := r.snapshotFileName(iniFileName)
	devFile, err := r.openSnapshotFile(iniFileName)
	if err != nil {
		return fmt.Errorf("failed to open device ini %s: %w", devIniPath, err)
	}
	defer devFile.Close()

	parsedDev, err := parseSingleDevice(devFile)
	if err != nil {
		return fmt.Errorf("failed to parse device %s: %w", devName, err)
	}

	targetName := devName
	if parsedDev.Name != "" {
		targetName = parsedDev.Name
	}
	r.ParsedDeviceList[targetName] = parsedDev
	return nil
}

func (r *SnapshotReader) loadLegacyDevices() {
	for i := 0; ; i++ {
		name := fmt.Sprintf("device_%d.ini", i)
		path := r.snapshotFileName(name)

		if _, err := fs.Stat(r.snapshotFS(), r.fsPath(name)); err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				r.warn(fmt.Errorf("stat legacy device %s: %w", path, err))
			}
			return
		}

		r.warn(r.loadDevice(fmt.Sprintf("device_%d", i), name))
	}
}

func (r *SnapshotReader) readTraceMetadata(name string) error {
	if name == "" {
		name = TraceINIFilename
	}

	path := r.snapshotFileName(name)
	file, err := r.openSnapshotFile(name)
	if err != nil {
		return fmt.Errorf("open trace metadata %s: %w", path, err)
	}
	defer file.Close()

	trace, err := parseTraceMetaData(file)
	if err != nil {
		return fmt.Errorf("parse trace metadata %s: %w", path, err)
	}

	r.Trace = trace
	for _, buf := range trace.Buffers {
		tree, ok := sourceTree(buf.BufferName, trace)
		if ok {
			r.SourceTrees[buf.BufferName] = tree
		}
	}

	return nil
}

func (r *SnapshotReader) openSnapshotFile(name string) (fs.File, error) {
	return r.snapshotFS().Open(r.fsPath(name))
}

func (r *SnapshotReader) snapshotFS() fs.FS {
	if r.FS != nil {
		return r.FS
	}
	if r.SnapshotPath == "" {
		return os.DirFS(".")
	}
	return os.DirFS(r.SnapshotPath)
}

func (r *SnapshotReader) fsPath(name string) string {
	if r.FS == nil || r.SnapshotPath == "" {
		return filepath.ToSlash(name)
	}
	return filepath.ToSlash(filepath.Join(r.SnapshotPath, name))
}

func (r *SnapshotReader) snapshotFileName(name string) string {
	if r.SnapshotPath == "" {
		return name
	}
	return filepath.Join(r.SnapshotPath, name)
}
