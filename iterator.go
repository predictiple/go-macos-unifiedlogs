// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

// UnifiedLogIterator iterates through the chunks in a tracev3 file. Each call
// to Next returns the data (header, catalog(s), oversize) for one catalog
// chunk, mirroring the Rust crate's UnifiedLogIterator.
type UnifiedLogIterator struct {
	Data     []byte
	Header   []HeaderChunk
	Evidence string
}

// Next returns the parsed Unified Log data for the next catalog. It returns
// false when there is no more data to process.
//
// If a catalog chunk is encountered while a catalog is already loaded, the
// iterator stops and rewinds to that chunk so it will be processed on the next
// call.
func (u *UnifiedLogIterator) Next() (*UnifiedLogData, bool) {
	if len(u.Data) == 0 {
		return nil, false
	}
	unifiedLogData := UnifiedLogData{
		Header:   append([]HeaderChunk{}, u.Header...),
		Evidence: u.Evidence,
	}

	// Keep a local copy of the catalog so we know when a new catalog chunk starts
	var catalogData UnifiedLogCatalogData

	input := u.Data
	const chunkPreambleSize = 16 // Include preamble size in total chunk size

	const headerChunk = 0x1000
	const catalogChunk = 0x600b
	const chunksetChunk = 0x600d

loop:
	for {
		preamble, err := detectPreamble(input)
		if err != nil {
			logger.Printf("Failed to determine preamble chunk")
			return nil, false
		}
		chunkSize := preamble.ChunkDataSize

		// Grab all data associated with Unified Log entry (chunk)
		data, chunkData, err := nomBytes(input, chunkSize+chunkPreambleSize)
		if err != nil {
			logger.Printf("Failed to nom chunk bytes")
			return nil, false
		}

		switch preamble.ChunkTag {
		case headerChunk:
			getHeaderData(chunkData, &unifiedLogData)
		case catalogChunk:
			if catalogData.Catalog.ChunkTag != 0 {
				u.Data = input
				break loop
			}
			getCatalogData(chunkData, &catalogData)
		case chunksetChunk:
			getChunksetLogData(chunkData, &catalogData, &unifiedLogData)
		default:
			logger.Printf("[macos-unifiedlogs] Unknown chunk type: %v", preamble.ChunkTag)
		}

		paddingSize := paddingSize8(preamble.ChunkDataSize)
		if uint64(len(u.Data)) < paddingSize {
			u.Data = nil
			break
		}
		data, _, err = nomBytes(data, paddingSize)
		if err != nil {
			logger.Printf("Failed to nom log end padding")
			return nil, false
		}
		if len(data) == 0 {
			u.Data = nil
			break
		}
		input = data
		if len(input) < chunkPreambleSize {
			logger.Printf("Not enough data for preamble header, needed 16 bytes. Got: %d", len(input))
			u.Data = nil
			break
		}
	}

	// Make sure to get the last catalog
	if catalogData.Catalog.ChunkTag != 0 {
		unifiedLogData.CatalogData = append(unifiedLogData.CatalogData, catalogData)
	}
	u.Header = unifiedLogData.Header
	return &unifiedLogData, true
}

// nomBytes takes size bytes from data, returning the remaining data and the
// taken bytes. Mirrors the Rust crate's nom_bytes helper.
func nomBytes(data []byte, size uint64) ([]byte, []byte, error) {
	return nomTake(data, size)
}
