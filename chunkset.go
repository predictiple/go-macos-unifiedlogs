// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

import (
	"fmt"

	"github.com/pierrec/lz4/v4"
)

// ChunksetChunk is the decompressed Chunkset data that contains the actual log
// entries.
type ChunksetChunk struct {
	ChunkTag         uint32 `json:"chunk_tag"`
	ChunkSubTag      uint32 `json:"chunk_sub_tag"`
	ChunkDataSize    uint64 `json:"chunk_data_size"`
	Signature        uint32 `json:"signature"` // should be "bv41"
	UncompressSize   uint32 `json:"uncompress_size"`
	BlockSize        uint32 `json:"block_size"`
	DecompressedData []byte `json:"decompressed_data"`
	Footer           uint32 `json:"footer"` // should be "bv4$"
}

// ParseChunkset parses the Chunkset data that contains the actual log entries.
func ParseChunkset(data []byte) ([]byte, ChunksetChunk, error) {
	var chunksetChunk ChunksetChunk

	c := newCursor(data)
	chunksetChunkTag, err := c.u32()
	if err != nil {
		return nil, chunksetChunk, err
	}
	chunksetChunkSubTag, err := c.u32()
	if err != nil {
		return nil, chunksetChunk, err
	}
	chunksetChunkDataSize, err := c.u64()
	if err != nil {
		return nil, chunksetChunk, err
	}

	// chunk_input is the input starting at the compression signature.
	chunkInput := c.rest()

	chunksetSig, err := c.u32()
	if err != nil {
		return nil, chunksetChunk, err
	}
	chunksetUncompressSize, err := c.u32()
	if err != nil {
		return nil, chunksetChunk, err
	}

	const bv41 = 825521762             // bv41 signature
	const bv41Uncompressed = 758412898 // bv41- signature

	// Data is already decompressed (Observed in tracev3 files in /var/db/diagnostics/Special)
	if chunksetSig == bv41Uncompressed {
		uncompressedData, err := c.take(int(chunksetUncompressSize))
		if err != nil {
			return nil, chunksetChunk, err
		}
		chunksetChunk.DecompressedData = uncompressedData
		chunksetFooter, err := c.u32()
		if err != nil {
			return nil, chunksetChunk, err
		}
		chunksetChunk.Footer = chunksetFooter
		return c.rest(), chunksetChunk, nil
	}

	// Only two likely to exist
	lzbitmapSigs := []uint32{206389850, 156058202, 223167066, 139280986}
	if containsU32(lzbitmapSigs, chunksetSig) {
		remaining, decomBytes, err := lzbitmapDecompressRemaining(chunkInput)
		if err != nil {
			return nil, chunksetChunk, err
		}
		// Always [6, 0, 0, 0, 0, 0]?
		// Maybe its a version number?
		fc := newCursor(remaining)
		chunksetFooter, err := fc.u32()
		if err != nil {
			return nil, chunksetChunk, err
		}

		chunksetChunk.DecompressedData = decomBytes
		chunksetChunk.Footer = chunksetFooter

		return fc.rest(), chunksetChunk, nil
	}

	// Compressed data signature should be bv41
	if chunksetSig != bv41 {
		logger.Printf("[macos-unifiedlogs] Incorrect compression signature expected bv41, got: %v", chunksetSig)
		return nil, chunksetChunk, ErrIncomplete
	}

	chunksetBlockSize, err := c.u32()
	if err != nil {
		return nil, chunksetChunk, err
	}

	chunksetChunk.ChunkTag = chunksetChunkTag
	chunksetChunk.ChunkSubTag = chunksetChunkSubTag
	chunksetChunk.ChunkDataSize = chunksetChunkDataSize
	chunksetChunk.Signature = chunksetSig
	chunksetChunk.UncompressSize = chunksetUncompressSize
	chunksetChunk.BlockSize = chunksetBlockSize

	compressedData, err := c.take(int(chunksetBlockSize))
	if err != nil {
		return nil, chunksetChunk, err
	}

	// The decompressed data contains multiple log entries
	decompressedData := make([]byte, chunksetUncompressSize)
	if _, err := lz4.UncompressBlock(compressedData, decompressedData); err != nil {
		logger.Printf("[macos-unifiedlogs] Failed to decompress log data: %v", err)
		return nil, chunksetChunk, ErrIncomplete
	}
	chunksetChunk.DecompressedData = decompressedData

	chunksetFooter, err := c.u32()
	if err != nil {
		return nil, chunksetChunk, err
	}
	chunksetChunk.Footer = chunksetFooter

	return c.rest(), chunksetChunk, nil
}

// ParseChunksetData parses each log (chunk) in the decompressed Chunkset data.
func ParseChunksetData(data []byte, unifiedLogData *UnifiedLogCatalogData) ([]byte, error) {
	c := newCursor(data)
	const chunkPreambleSize = 16 // Include preamble size in total chunk size

	// Loop through decompressed chunkset data until all log entries (chunks) are read
	for !c.isEmpty() {
		preamble, err := detectPreamble(c.rest())
		if err != nil {
			return nil, err
		}
		chunkSize := preamble.ChunkDataSize

		// Grab all data associated with log (chunk) data
		chunkSizeInt, ok := u64ToUint(chunkSize)
		if !ok {
			logger.Printf("[macos-unifiedlogs] u64 is bigger than system usize")
			return nil, fmt.Errorf("chunk size too large: %w", ErrTooLarge)
		}
		chunkData, err := c.take(chunkSizeInt + chunkPreambleSize)
		if err != nil {
			return nil, err
		}
		getChunksetData(chunkData, preamble.ChunkTag, unifiedLogData)

		// Nom all zero padding
		c.takeWhile(func(b byte) bool { return b == 0 })
		if c.remaining() == 0 {
			break
		}

		if c.remaining() < chunkPreambleSize {
			logger.Printf("[macos-unifiedlogs] Not enough data for Chunkset preamble header, needed 16 bytes. Got: %d", c.remaining())
			break
		}
	}
	return c.rest(), nil
}

// getChunksetData parses the log entry (chunk) chunk based on type.
func getChunksetData(data []byte, chunkType uint32, unifiedLogData *UnifiedLogCatalogData) {
	const firehoseChunk = 0x6001
	const oversizeChunk = 0x6002
	const statedumpChunk = 0x6003
	const simpledumpChunk = 0x6004

	switch chunkType {
	case firehoseChunk:
		_, firehoseData, err := parseFirehosePreamble(data)
		if err != nil {
			logger.Printf("[macos-unifiedlogs] Failed to parse firehose log entry (chunk): %v", err)
			return
		}
		unifiedLogData.Firehose = append(unifiedLogData.Firehose, *firehoseData)
	case oversizeChunk:
		_, oversize, err := parseOversize(data)
		if err != nil {
			logger.Printf("[macos-unifiedlogs] Failed to parse oversize log entry (chunk): %v", err)
			return
		}
		unifiedLogData.Oversize = append(unifiedLogData.Oversize, oversize)
	case statedumpChunk:
		_, statedump, err := ParseStatedump(data)
		if err != nil {
			logger.Printf("[macos-unifiedlogs] Failed to parse statedump log entry (chunk): %v", err)
			return
		}
		unifiedLogData.Statedump = append(unifiedLogData.Statedump, statedump)
	case simpledumpChunk:
		_, simpledump, err := parseSimpledump(data)
		if err != nil {
			logger.Printf("[macos-unifiedlogs] Failed to parse simpledump log entry (chunk): %v", err)
			return
		}
		unifiedLogData.Simpledump = append(unifiedLogData.Simpledump, simpledump)
	default:
		logger.Printf("[macos-unifiedlogs] Unknown chunkset type: %v", chunkType)
	}
}

// containsU32 reports whether v is present in values.
func containsU32(values []uint32, v uint32) bool {
	for _, value := range values {
		if value == v {
			return true
		}
	}
	return false
}
