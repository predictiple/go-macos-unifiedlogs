// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// LocalFile is a SourceFile backed by a file on the local filesystem.
type LocalFile struct {
	source string
}

// NewLocalFile returns a LocalFile for the provided path.
func NewLocalFile(path string) *LocalFile {
	return &LocalFile{source: path}
}

// Reader opens the source file and returns a reader for it.
func (f *LocalFile) Reader() (io.ReadCloser, error) {
	return os.Open(f.source)
}

// SourcePath returns the source path of the file.
func (f *LocalFile) SourcePath() string {
	return f.source
}

// LogFileType is the type of a unified log file.
type LogFileType string

const (
	// LogFileTraceV3 is a .tracev3 file.
	LogFileTraceV3 LogFileType = "TraceV3"
	// LogFileUUIDText is a uuidtext string file.
	LogFileUUIDText LogFileType = "UUIDText"
	// LogFileDsc is a shared string cache file.
	LogFileDsc LogFileType = "Dsc"
	// LogFileTimesync is a .timesync file.
	LogFileTimesync LogFileType = "Timesync"
	// LogFileInvalid is an unrecognized file type.
	LogFileInvalid LogFileType = "Invalid"
)

var traceFolders = []string{"HighVolume", "Special", "Signpost", "Persist"}

func onlyHexChars(val string) bool {
	for _, c := range val {
		if !isASCIIHexDigit(c) {
			return false
		}
	}
	return true
}

func isASCIIHexDigit(c rune) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// LogFileTypeFromPath determines the LogFileType from a filesystem path by inspecting the
// final two path components.
func LogFileTypeFromPath(path string) LogFileType {
	parent := filepath.Base(filepath.Dir(path))
	filename := filepath.Base(path)

	if filename == "logdata.LiveData.tracev3" ||
		(strings.HasSuffix(filename, ".tracev3") && containsString(traceFolders, parent)) {
		return LogFileTraceV3
	}

	if len(filename) == 30 && onlyHexChars(filename) && len(parent) == 2 && onlyHexChars(parent) {
		return LogFileUUIDText
	}

	if len(filename) == 32 && onlyHexChars(filename) && parent == "dsc" {
		return LogFileDsc
	}

	if strings.HasSuffix(filename, ".timesync") && parent == "timesync" {
		return LogFileTimesync
	}

	return LogFileInvalid
}

func containsString(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}

// sortPaths sorts files by their source path in order to have deterministic output of the
// parser. macOS does not guarantee order of files returned by the filesystem.
func sortPaths(paths []string) []string {
	sort.Strings(paths)
	return paths
}

// walkMatching walks root and returns LocalFile sources for every file matching fileType,
// sorted by path.
func walkMatching(root string, fileType LogFileType) []SourceFile {
	var paths []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if LogFileTypeFromPath(path) == fileType {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		logger.Printf("[macos-unifiedlogs] Failed to walk %s: %v", root, err)
	}

	sortPaths(paths)

	sources := make([]SourceFile, 0, len(paths))
	for _, path := range paths {
		sources = append(sources, NewLocalFile(path))
	}
	return sources
}

func readSource(source SourceFile) ([]byte, error) {
	reader, err := source.Reader()
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(reader)
}

func normalizeUUID(uuid string) (string, error) {
	const uuidLen = 32
	switch len(uuid) {
	case uuidLen - 1:
		return "0" + uuid, nil
	case uuidLen - 2:
		return "00" + uuid, nil
	case uuidLen:
		return uuid, nil
	default:
		return "", fmt.Errorf("uuid length not correct: %s", uuid)
	}
}

// LiveSystemProvider provides a FileProvider that enumerates the required files at the correct
// paths on a live macOS system. These files are only present on macOS Sierra (10.12) and above.
// The implemented methods emit error log messages if any are encountered while enumerating
// files or creating readers, but are otherwise infallible.
type LiveSystemProvider struct{}

// NewLiveSystemProvider returns a new LiveSystemProvider.
func NewLiveSystemProvider() *LiveSystemProvider {
	return &LiveSystemProvider{}
}

// Tracev3Files provides the .tracev3 files on a live system.
func (p *LiveSystemProvider) Tracev3Files() []SourceFile {
	return walkMatching("/private/var/db/diagnostics", LogFileTraceV3)
}

// UUIDTextFiles provides the uuidtext string files on a live system.
func (p *LiveSystemProvider) UUIDTextFiles() []SourceFile {
	return walkMatching("/private/var/db/uuidtext", LogFileUUIDText)
}

// ReadUUIDText reads a UUIDText file on a live system.
func (p *LiveSystemProvider) ReadUUIDText(uuid string) (*UUIDText, error) {
	normalized, err := normalizeUUID(uuid)
	if err != nil {
		return nil, err
	}

	dirName := normalized[0:2]
	filename := normalized[2:]

	path := filepath.Join("/private/var/db/uuidtext", dirName, filename)
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	results, err := parseUUIDText(buf)
	if err != nil {
		logger.Printf("[macos-unifiedlogs] Failed to parse UUID file %s: %v", path, err)
		return nil, fmt.Errorf("failed to read: %s", uuid)
	}

	return results, nil
}

// ReadDSCUUID reads a shared string cache file on a live system.
func (p *LiveSystemProvider) ReadDSCUUID(uuid string) (*SharedCacheStrings, error) {
	normalized, err := normalizeUUID(uuid)
	if err != nil {
		return nil, err
	}

	path := filepath.Join("/private/var/db/uuidtext/dsc", normalized)
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	results, err := parseDSC(buf)
	if err != nil {
		logger.Printf("[macos-unifiedlogs] Failed to parse dsc UUID file %s: %v", path, err)
		return nil, fmt.Errorf("failed to read: %s", uuid)
	}

	return results, nil
}

// DSCFiles provides the shared string cache files on a live system.
func (p *LiveSystemProvider) DSCFiles() []SourceFile {
	return walkMatching("/private/var/db/uuidtext/dsc", LogFileDsc)
}

// TimesyncFiles provides the .timesync files on a live system.
func (p *LiveSystemProvider) TimesyncFiles() []SourceFile {
	return walkMatching("/private/var/db/diagnostics/timesync", LogFileTimesync)
}

// LogarchiveProvider provides a FileProvider that enumerates the required files from a
// provided logarchive.
type LogarchiveProvider struct {
	base string
}

// NewLogarchiveProvider returns a new LogarchiveProvider rooted at path.
func NewLogarchiveProvider(path string) *LogarchiveProvider {
	return &LogarchiveProvider{base: path}
}

// Tracev3Files provides the .tracev3 files from the logarchive.
func (p *LogarchiveProvider) Tracev3Files() []SourceFile {
	return walkMatching(p.base, LogFileTraceV3)
}

// UUIDTextFiles provides the uuidtext string files from the logarchive.
func (p *LogarchiveProvider) UUIDTextFiles() []SourceFile {
	return walkMatching(p.base, LogFileUUIDText)
}

// ReadUUIDText reads a UUIDText file from the logarchive.
func (p *LogarchiveProvider) ReadUUIDText(uuid string) (*UUIDText, error) {
	normalized, err := normalizeUUID(uuid)
	if err != nil {
		return nil, err
	}

	dirName := normalized[0:2]
	filename := normalized[2:]

	path := filepath.Join(p.base, dirName, filename)
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	results, err := parseUUIDText(buf)
	if err != nil {
		logger.Printf("[macos-unifiedlogs] Failed to parse UUID file %s: %v", path, err)
		return nil, fmt.Errorf("failed to read: %s", uuid)
	}

	return results, nil
}

// ReadDSCUUID reads a shared string cache file from the logarchive.
func (p *LogarchiveProvider) ReadDSCUUID(uuid string) (*SharedCacheStrings, error) {
	normalized, err := normalizeUUID(uuid)
	if err != nil {
		return nil, err
	}

	path := filepath.Join(p.base, "dsc", normalized)
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	results, err := parseDSC(buf)
	if err != nil {
		logger.Printf("[macos-unifiedlogs] Failed to parse dsc UUID file %s: %v", path, err)
		return nil, fmt.Errorf("failed to read: %s", uuid)
	}

	return results, nil
}

// DSCFiles provides the shared string cache files from the logarchive.
func (p *LogarchiveProvider) DSCFiles() []SourceFile {
	return walkMatching(p.base, LogFileDsc)
}

// TimesyncFiles provides the .timesync files from the logarchive.
func (p *LogarchiveProvider) TimesyncFiles() []SourceFile {
	return walkMatching(p.base, LogFileTimesync)
}
