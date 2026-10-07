// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

import "io"

// SourceFile provides a single unified log file source. Parsing unified logs requires the
// name of the original file in order to reconstruct format strings.
type SourceFile interface {
	// Reader returns a reader for the source file.
	Reader() (io.ReadCloser, error)
	// SourcePath returns the source path of the file on the machine from which it was
	// collected, distinct from any secondary storage location where, for instance, a file
	// backing the reader might exist.
	SourcePath() string
}

// FileProvider allows library consumers to provide the files required by the parser in
// arbitrary formats.
type FileProvider interface {
	// Tracev3Files provides the .tracev3 files from the
	// /private/var/db/diagnostics/(HighVolume|Signpost|Trace|Special)/ directories, plus the
	// livedata.LogData.tracev3 file if it was collected via log collect.
	Tracev3Files() []SourceFile
	// UUIDTextFiles provides the UUIDText string files from the /var/db/uuidtext/XX/
	// directories.
	UUIDTextFiles() []SourceFile
	// ReadUUIDText reads a provided UUID file at runtime. The UUID is obtained by parsing the
	// tracev3 files. Reads will fail if the UUID does not exist.
	ReadUUIDText(uuid string) (*UUIDText, error)
	// DSCFiles provides the shared string files from the /var/db/uuidtext/dsc subdirectory.
	DSCFiles() []SourceFile
	// ReadDSCUUID reads a provided UUID file at runtime.
	ReadDSCUUID(uuid string) (*SharedCacheStrings, error)
	// TimesyncFiles provides the .timesync files from the /var/db/diagnostics/timesync
	// subdirectory.
	TimesyncFiles() []SourceFile
}

// StringCache defines an interface for caching string values parsed from the dsc or uuidtext
// directories.
type StringCache interface {
	// GetOrLoadUUIDText returns the cached UUIDText for uuid, loading it via provider if absent.
	GetOrLoadUUIDText(uuid string, provider FileProvider) (*UUIDText, error)
	// GetOrLoadDSC returns the cached SharedCacheStrings for uuid, loading it via provider if
	// absent.
	GetOrLoadDSC(uuid string, provider FileProvider) (*SharedCacheStrings, error)
}
