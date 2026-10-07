// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

import "testing"

func TestDetectPreamble(t *testing.T) {
	testPreambleHeader := []byte{
		0, 16, 0, 0, 17, 0, 0, 0, 208, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0,
	}

	preambleData, err := detectPreamble(testPreambleHeader)
	if err != nil {
		t.Fatalf("detectPreamble returned error: %v", err)
	}
	if preambleData.ChunkTag != 0x1000 {
		t.Errorf("chunk_tag = %#x, want %#x", preambleData.ChunkTag, 0x1000)
	}
	if preambleData.ChunkSubTag != 0x11 {
		t.Errorf("chunk_sub_tag = %#x, want %#x", preambleData.ChunkSubTag, 0x11)
	}
	if preambleData.ChunkDataSize != 0xd0 {
		t.Errorf("chunk_data_size = %#x, want %#x", preambleData.ChunkDataSize, uint64(0xd0))
	}

	testCatalogChunk := []byte{11, 96, 0, 0, 17, 0, 0, 0, 176, 31, 0, 0, 0, 0, 0, 0}
	preambleData, err = parsePreamble(testCatalogChunk)
	if err != nil {
		t.Fatalf("parsePreamble returned error: %v", err)
	}
	if preambleData.ChunkTag != 0x600b {
		t.Errorf("chunk_tag = %#x, want %#x", preambleData.ChunkTag, 0x600b)
	}
	if preambleData.ChunkSubTag != 0x11 {
		t.Errorf("chunk_sub_tag = %#x, want %#x", preambleData.ChunkSubTag, 0x11)
	}
	if preambleData.ChunkDataSize != 0x1fb0 {
		t.Errorf("chunk_data_size = %#x, want %#x", preambleData.ChunkDataSize, uint64(0x1fb0))
	}
}
