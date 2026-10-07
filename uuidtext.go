// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

import (
	"fmt"
)

// UUIDText contains the parsed UUID file (uuidtext) data.
type UUIDText struct {
	UUID             string          `json:"uuid"`
	Signature        uint32          `json:"signature"`
	MajorVersion     uint32          `json:"major_version"`
	MinorVersion     uint32          `json:"minor_version"`
	NumberEntries    uint32          `json:"number_entries"`
	EntryDescriptors []UUIDTextEntry `json:"entry_descriptors"`
	FooterData       []byte          `json:"footer_data"` // Collection of strings containing sender process/library with end of string characters
}

// UUIDTextEntry is an individual UUIDText entry descriptor.
type UUIDTextEntry struct {
	RangeStartOffset uint32 `json:"range_start_offset"`
	EntrySize        uint32 `json:"entry_size"`
}

// parseUUIDText parses the UUID files in the uuidinfo directory.
// Contains the base log message string.
func parseUUIDText(data []byte) (*UUIDText, error) {
	uuidtextData := &UUIDText{}

	const expectedUUIDTextSignature uint32 = 0x66778899
	c := newCursor(data)
	uuidtextSignature, err := c.u32()
	if err != nil {
		return nil, err
	}

	if expectedUUIDTextSignature != uuidtextSignature {
		logger.Printf("[macos-unifiedlogs] Incorrect UUIDText header signature. Expected %d. Got: %d",
			expectedUUIDTextSignature, uuidtextSignature)
		return nil, fmt.Errorf("incorrect UUIDText header signature: %w", ErrIncomplete)
	}

	uuidtextMajorVersion, err := c.u32()
	if err != nil {
		return nil, err
	}
	uuidtextMinorVersion, err := c.u32()
	if err != nil {
		return nil, err
	}
	uuidtextNumberEntries, err := c.u32()
	if err != nil {
		return nil, err
	}

	uuidtextData.Signature = uuidtextSignature
	uuidtextData.MajorVersion = uuidtextMajorVersion
	uuidtextData.MinorVersion = uuidtextMinorVersion
	uuidtextData.NumberEntries = uuidtextNumberEntries

	var count uint32
	for count < uuidtextNumberEntries {
		uuidtextRangeStartOffset, err := c.u32()
		if err != nil {
			return nil, err
		}
		uuidtextEntrySize, err := c.u32()
		if err != nil {
			return nil, err
		}

		entryData := UUIDTextEntry{
			RangeStartOffset: uuidtextRangeStartOffset,
			EntrySize:        uuidtextEntrySize,
		}
		uuidtextData.EntryDescriptors = append(uuidtextData.EntryDescriptors, entryData)

		count++
	}
	uuidtextData.FooterData = append([]byte{}, c.rest()...)
	return uuidtextData, nil
}
