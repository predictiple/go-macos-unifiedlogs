// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

// Package unifiedlogs is a small, cross-platform library to parse Apple Unified Logs
// (tracev3) on a live macOS system or from a collected logarchive.
//
// It is a Go port of the Rust crate
// github.com/mandiant/macos-UnifiedLogs. No Apple APIs are used, so the library
// can parse Unified Log data on any platform.
//
// # Overview
//
// A unified log bundle is spread across several files, so parsing happens in stages:
//
//  1. Collect the auxiliary string and time data:
//     [CollectTimesync], [CollectStrings], and [CollectSharedStrings].
//  2. Read each .tracev3 file and iterate its chunks. Either use [ParseLog] to
//     parse a single reader into an [*UnifiedLogData], or drive the chunk stream
//     directly with a [UnifiedLogIterator] and its [UnifiedLogIterator.Next] method.
//  3. Resolve each chunk into log records with [BuildLog], passing a [FileProvider],
//     a [StringCache], and the timesync data collected in step 1.
//
// Oversize entries hold large strings that do not fit in a normal log record. They
// must be carried forward across chunks, so retain the returned [UnifiedLogData]
// and append its Oversize field to the next chunk before calling [BuildLog]
// (see the example below).
//
// # Providers
//
// Two [FileProvider] implementations ship with the library: [NewLiveSystemProvider],
// which reads from a running macOS system, and [NewLogarchiveProvider], which reads
// from an extracted logarchive directory. Callers may implement [FileProvider] and
// [SourceFile] to supply data from arbitrary formats. [NewMemoryStringCache] provides
// the default [StringCache].
//
// # Example
//
// The following reads every tracev3 file from a logarchive and prints the number of
// resolved log entries in each chunk:
//
//	provider := unifiedlogs.NewLogarchiveProvider("/path/to/system_logs.logarchive")
//	cache := unifiedlogs.NewMemoryStringCache()
//
//	timesyncData, err := unifiedlogs.CollectTimesync(provider)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Oversize entries must be persisted across chunks.
//	oversize := &unifiedlogs.UnifiedLogData{}
//	for _, entry := range provider.Tracev3Files() {
//		r, err := entry.Reader()
//		if err != nil {
//			log.Fatal(err)
//		}
//		data, err := io.ReadAll(r)
//		r.Close()
//		if err != nil {
//			log.Fatal(err)
//		}
//
//		it := &unifiedlogs.UnifiedLogIterator{
//			Data:     data,
//			Evidence: entry.SourcePath(),
//		}
//		for {
//			chunk, ok := it.Next()
//			if !ok {
//				break
//			}
//			chunk.Oversize = append(chunk.Oversize, oversize.Oversize...)
//			logs, missing := unifiedlogs.BuildLog(chunk, provider, cache, timesyncData, true)
//			oversize.Oversize = chunk.Oversize
//			log.Printf("%s: %d log entries", entry.SourcePath(), len(logs))
//			_ = missing
//		}
//	}
package unifiedlogs
