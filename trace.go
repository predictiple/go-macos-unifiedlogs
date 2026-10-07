// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

import (
	"encoding/binary"
	"fmt"
	"slices"
)

// FirehoseTrace is a Trace Firehose log entry.
type FirehoseTrace struct {
	UnknownPCID uint32           `json:"unknown_pc_id"` // Appears to be used to calculate string offset for firehose events with Absolute flag
	MessageData FirehoseItemData `json:"message_data"`
}

// parseFirehoseTrace parses a Trace Firehose log entry.
// Ex: tp 504 + 34: trace default (main_exe)
func parseFirehoseTrace(data []byte) ([]byte, FirehoseTrace, error) {
	var firehoseTrace FirehoseTrace

	c := newCursor(data)
	unknownPCID, err := c.u32()
	if err != nil {
		return nil, firehoseTrace, err
	}
	firehoseTrace.UnknownPCID = unknownPCID

	firehoseInput := c.rest()

	// Trace logs only have message values if more than 4 bytes remaining in log entry
	const minimumMessageSize = 4
	if len(firehoseInput) < minimumMessageSize {
		// Consume the rest of the input (mirrors Rust's take(input.len())).
		firehoseInput = firehoseInput[len(firehoseInput):]
		return firehoseInput, firehoseTrace, nil
	}

	// The rest of the trace log entry appears to be related to log message values
	// But the data is stored differently from other log entries.
	// The data appears to be stored backwards? Ex: Data value, Data size, number of data
	// entries, instead normal: number of data entries, data size, data value.
	messageData := make([]byte, len(firehoseInput))
	copy(messageData, firehoseInput)
	slices.Reverse(messageData)

	firehoseTrace.MessageData = getTraceMessage(messageData)

	return []byte{}, firehoseTrace, nil
}

// getTraceMessage gets the Trace message.
func getTraceMessage(data []byte) FirehoseItemData {
	_, itemData, err := parseTraceMessage(data)
	if err != nil {
		logger.Printf("[macos-unifiedlogs] Could not get Trace message data")
		return FirehoseItemData{}
	}
	return itemData
}

// parseTraceMessage parses the data associated with the trace message.
func parseTraceMessage(data []byte) ([]byte, FirehoseItemData, error) {
	itemData := FirehoseItemData{}

	const minimumMessageSize = 4
	if len(data) < minimumMessageSize {
		return data, itemData, nil
	}

	c := newCursor(data)
	entries, err := c.u8()
	if err != nil {
		return nil, FirehoseItemData{}, err
	}

	// Based on number of entries get the size for each entry.
	sizesCount := make([]uint8, 0, entries)
	for count := uint8(0); count < entries; count++ {
		size, err := c.u8()
		if err != nil {
			return nil, FirehoseItemData{}, err
		}
		sizesCount = append(sizesCount, size)
	}

	remainingInput := c.rest()
	itemInfo := make([]FirehoseItemType, 0, len(sizesCount))
	for _, entrySize := range sizesCount {
		var itemInfoEntry FirehoseItemType

		// So far all entries appear to be numbers. Using Big Endian because we
		// reversed the data above.
		input, messageData, err := nomTake(remainingInput, uint64(entrySize))
		if err != nil {
			return nil, FirehoseItemData{}, err
		}

		switch entrySize {
		case 1:
			itemInfoEntry.MessageStrings = fmt.Sprintf("%d", messageData[0])
		case 2:
			itemInfoEntry.MessageStrings = fmt.Sprintf("%d", binary.BigEndian.Uint16(messageData))
		case 4:
			itemInfoEntry.MessageStrings = fmt.Sprintf("%d", binary.BigEndian.Uint32(messageData))
		case 8:
			itemInfoEntry.MessageStrings = fmt.Sprintf("%d", binary.BigEndian.Uint64(messageData))
		default:
			logger.Printf("[macos-unifiedlogs] Unhandled size of trace data: %d. Defaulting to size of one", entrySize)
			// Mirrors Rust's le_u8 on the taken slice (errors when the slice is empty).
			sizeCursor := newCursor(messageData)
			unknownSize, err := sizeCursor.u8()
			if err != nil {
				return nil, FirehoseItemData{}, err
			}
			itemInfoEntry.MessageStrings = fmt.Sprintf("%d", unknownSize)
		}

		remainingInput = input
		itemInfo = append(itemInfo, itemInfoEntry)
	}

	// Reverse the data back to expected format.
	slices.Reverse(itemInfo)

	return remainingInput, FirehoseItemData{ItemInfo: itemInfo}, nil
}

// getFirehoseTraceStrings gets the base log message string formatter from shared cache strings
// (dsc) or the UUID text file for firehose trace log entries.
func getFirehoseTraceStrings(provider FileProvider, cache StringCache, stringOffset uint64, firstProcID uint64, secondProcID uint32, catalogs *CatalogChunk) ([]byte, MessageData, error) {
	// Only main_exe flag has been seen for format strings
	return extractFormatStrings(provider, cache, stringOffset, firstProcID, secondProcID, catalogs, 0)
}
