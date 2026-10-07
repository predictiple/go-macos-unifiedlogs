// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

// Oversize represents an oversize log entry. Oversize entries contain strings
// that are too large to fit in a normal Firehose log entry.
type Oversize struct {
	ChunkTag        uint32           `json:"chunk_tag"`
	ChunkSubtag     uint32           `json:"chunk_subtag"`
	ChunkDataSize   uint64           `json:"chunk_data_size"`
	FirstProcID     uint64           `json:"first_proc_id"`
	SecondProcID    uint32           `json:"second_proc_id"`
	TTL             uint8            `json:"ttl"`
	Reserved        []byte           `json:"reserved"` // 3 bytes
	ContinuousTime  uint64           `json:"continous_time"`
	DataRefIndex    uint32           `json:"data_ref_index"`
	PublicDataSize  uint16           `json:"public_data_size"`
	PrivateDataSize uint16           `json:"private_data_size"`
	MessageItems    FirehoseItemData `json:"message_items"`
}

// parseOversize parses the oversize log entry.
// Ex: tp 2368 + 200: oversize log entry
func parseOversize(data []byte) ([]byte, Oversize, error) {
	var oversizeResults Oversize
	c := newCursor(data)

	oversizeChunkTag, err := c.u32()
	if err != nil {
		return nil, oversizeResults, err
	}
	oversizeChunkSubtag, err := c.u32()
	if err != nil {
		return nil, oversizeResults, err
	}
	oversizeChunkDataSize, err := c.u64()
	if err != nil {
		return nil, oversizeResults, err
	}
	oversizeFirstProcID, err := c.u64()
	if err != nil {
		return nil, oversizeResults, err
	}
	oversizeSecondProcID, err := c.u32()
	if err != nil {
		return nil, oversizeResults, err
	}
	oversizeTTL, err := c.u8()
	if err != nil {
		return nil, oversizeResults, err
	}

	oversizeResults.ChunkTag = oversizeChunkTag
	oversizeResults.ChunkSubtag = oversizeChunkSubtag
	oversizeResults.ChunkDataSize = oversizeChunkDataSize
	oversizeResults.FirstProcID = oversizeFirstProcID
	oversizeResults.SecondProcID = oversizeSecondProcID
	oversizeResults.TTL = oversizeTTL

	const reservedSize uint8 = 3
	reserved, err := c.take(int(reservedSize))
	if err != nil {
		return nil, oversizeResults, err
	}
	oversizeResults.Reserved = reserved

	oversizeContinousTime, err := c.u64()
	if err != nil {
		return nil, oversizeResults, err
	}
	oversizeDataRefIndex, err := c.u32()
	if err != nil {
		return nil, oversizeResults, err
	}
	oversizePublicDataSize, err := c.u16()
	if err != nil {
		return nil, oversizeResults, err
	}
	oversizePrivateDataSize, err := c.u16()
	if err != nil {
		return nil, oversizeResults, err
	}

	oversizeResults.ContinuousTime = oversizeContinousTime
	oversizeResults.DataRefIndex = oversizeDataRefIndex
	oversizeResults.PublicDataSize = oversizePublicDataSize
	oversizeResults.PrivateDataSize = oversizePrivateDataSize

	var oversizeDataSize = int(oversizeResults.PublicDataSize) + int(oversizeResults.PrivateDataSize)

	// Contains item data like firehose (ex: 0x42)
	if oversizeDataSize > len(c.rest()) {
		logger.Printf("[macos-unifiedlogs] Oversize data size greater than Oversize remaining string size. Using remaining string size")
		oversizeDataSize = len(c.rest())
	}
	pubData, err := c.take(oversizeDataSize)
	if err != nil {
		return nil, oversizeResults, err
	}

	messageData := pubData

	var oversizeItemCount uint8
	if len(messageData) < 2 {
		return nil, oversizeResults, ErrIncomplete
	}
	oversizeItemCount = messageData[1] // first byte is the unused item type
	messageData = messageData[2:]

	const emptyFlags uint16 = 0
	// Grab all message items from oversize data
	oversizePrivateData, firehoseItemData, err := collectFirehoseItems(messageData, oversizeItemCount, emptyFlags)
	if err != nil {
		return nil, oversizeResults, err
	}
	_, err = parsePrivateFirehoseData(oversizePrivateData, &firehoseItemData)
	if err != nil {
		return nil, oversizeResults, err
	}

	oversizeResults.MessageItems = firehoseItemData

	return c.rest(), oversizeResults, nil
}

// getOversizeStrings gets the firehose item info from the oversize log entry
// based on oversize (data ref) id, first proc id, and second proc id.
func getOversizeStrings(dataRef uint32, firstProcID uint64, secondProcID uint32, oversizeData []Oversize) []FirehoseItemType {
	var itemInfo []FirehoseItemType
	for _, oversize := range oversizeData {
		if dataRef == oversize.DataRefIndex &&
			firstProcID == oversize.FirstProcID &&
			secondProcID == oversize.SecondProcID {
			return append(itemInfo, oversize.MessageItems.ItemInfo...)
		}
	}
	// We may not find any oversize data (data may have rolled from logs?)
	logger.Printf("[macos-unifiedlogs] Did not find any oversize log entries from Data Ref ID: %d, First Proc ID: %d, and Second Proc ID: %d", dataRef, firstProcID, secondProcID)
	return itemInfo
}
