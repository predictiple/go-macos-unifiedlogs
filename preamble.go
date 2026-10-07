// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

// LogPreamble is the preamble (first 16 bytes) of all Unified Log entries (chunks).
type LogPreamble struct {
	ChunkTag      uint32 `json:"chunk_tag"`
	ChunkSubTag   uint32 `json:"chunk_sub_tag"`
	ChunkDataSize uint64 `json:"chunk_data_size"`
}

// detectPreamble gets the preamble (first 16 bytes of all Unified Log entries
// (chunks)) to detect the log (chunk) type. Ex: Firehose, Statedump,
// Simpledump, Catalog, etc. Does not consume the input.
func detectPreamble(data []byte) (*LogPreamble, error) {
	return parsePreamble(data)
}

// parsePreamble gets the preamble (first 16 bytes of all Unified Log entries
// (chunks)) to detect the log (chunk) type and consumes the input.
func parsePreamble(data []byte) (*LogPreamble, error) {
	c := newCursor(data)
	chunkTag, err := c.u32()
	if err != nil {
		return nil, err
	}
	chunkSubTag, err := c.u32()
	if err != nil {
		return nil, err
	}
	chunkDataSize, err := c.u64()
	if err != nil {
		return nil, err
	}
	return &LogPreamble{
		ChunkTag:      chunkTag,
		ChunkSubTag:   chunkSubTag,
		ChunkDataSize: chunkDataSize,
	}, nil
}
