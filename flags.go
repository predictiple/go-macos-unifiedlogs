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

// FirehoseFormatters holds the formatter flags of a Firehose log entry.
type FirehoseFormatters struct {
	MainExe          bool   `json:"main_exe"`
	SharedCache      bool   `json:"shared_cache"`
	HasLargeOffset   uint16 `json:"has_large_offset"`
	LargeSharedCache uint16 `json:"large_shared_cache"`
	Absolute         bool   `json:"absolute"`
	UuidRelative     string `json:"uuid_relative"`
	MainPlugin       bool   `json:"main_plugin"`        // Not seen yet
	PcStyle          bool   `json:"pc_style"`           // Not seen yet
	MainExeAltIndex  uint16 `json:"main_exe_alt_index"` // If log entry uses an alternative uuid file index (ex: absolute). This value gets prepended to the pc_id/offset
}

// FirehoseFormatterFlags identifies formatter flags associated with the log entry.
// Formatter flags determine the file where the base format string is located.
func FirehoseFormatterFlags(data []byte, firehoseFlags uint16, flags *[]MessageFlags) ([]byte, FirehoseFormatters, error) {
	var formatterFlags FirehoseFormatters

	const messageStringsUUID = 0x2 // main_exe flag
	const largeSharedCache = 0xc   // large_shared_cache flag
	const sharedCache = 0x4        // shared_cache flag
	const largeOffset = 0x20       // has_large_offset flag

	const flagCheck = 0xe
	c := newCursor(data)

	/*
		0x20 - has_large_offset flag. Offset to format string is larger than normal
		0xc - has_large_shared_cache flag. Offset to format string is larger than normal
		0x8 - absolute flag. The log uses an alterantive index number that points to the UUID file name in the Catalog which contains the format string
		0x2 - main_exe flag. A UUID file contains the format string
		0x4 - shared_cache flag. DSC file contains the format string
		0xa - uuid_relative flag. The UUID file name is in the log data (instead of the Catalog)
	*/
	switch firehoseFlags & flagCheck {
	case 0x20:
		logger.Printf("[macos-unifiedlogs] Firehose flag: has_large_offset")
		firehoseLargeOffset, err := c.u16()
		if err != nil {
			return nil, formatterFlags, err
		}
		formatterFlags.HasLargeOffset = firehoseLargeOffset
		*flags = append(*flags, MessageFlagsHasLargeOffset)
		if firehoseFlags&largeSharedCache != 0 {
			logger.Printf("[macos-unifiedlogs] Firehose flag: large_shared_cache and has_large_offset")
			firehoseLargeSharedCache, err := c.u16()
			if err != nil {
				return nil, formatterFlags, err
			}
			formatterFlags.LargeSharedCache = firehoseLargeSharedCache
			*flags = append(*flags, MessageFlagsLargeSharedCache)
		} else if firehoseFlags&sharedCache != 0 {
			formatterFlags.SharedCache = true
			*flags = append(*flags, MessageFlagsSharedCache)
		}
	case 0xc:
		logger.Printf("[macos-unifiedlogs] Firehose flag: large_shared_cache")
		if firehoseFlags&largeOffset != 0 {
			firehoseLargeOffset, err := c.u16()
			if err != nil {
				return nil, formatterFlags, err
			}
			formatterFlags.HasLargeOffset = firehoseLargeOffset
			*flags = append(*flags, MessageFlagsHasLargeOffset)
		}
		firehoseLargeSharedCache, err := c.u16()
		if err != nil {
			return nil, formatterFlags, err
		}
		formatterFlags.LargeSharedCache = firehoseLargeSharedCache
		*flags = append(*flags, MessageFlagsLargeSharedCache)
	case 0x8:
		logger.Printf("[macos-unifiedlogs] Firehose flag: absolute")
		formatterFlags.Absolute = true
		*flags = append(*flags, MessageFlagsAbsolute)
		if firehoseFlags&messageStringsUUID == 0 {
			logger.Printf("[macos-unifiedlogs] Firehose flag: alt index absolute flag")
			firehoseUUIDFileIndex, err := c.u16()
			if err != nil {
				return nil, formatterFlags, err
			}
			formatterFlags.MainExeAltIndex = firehoseUUIDFileIndex
			*flags = append(*flags, MessageFlagsAltIndex)
		}
	case 0x2:
		logger.Printf("[macos-unifiedlogs] Firehose flag: main_exe")
		formatterFlags.MainExe = true
		*flags = append(*flags, MessageFlagsMainExe)
	case 0x4:
		logger.Printf("[macos-unifiedlogs] Firehose flag: shared_cache")
		formatterFlags.SharedCache = true
		*flags = append(*flags, MessageFlagsSharedCache)
		if firehoseFlags&largeOffset != 0 {
			firehoseLargeOffset, err := c.u16()
			if err != nil {
				return nil, formatterFlags, err
			}
			formatterFlags.HasLargeOffset = firehoseLargeOffset
			*flags = append(*flags, MessageFlagsHasLargeOffset)
		}
	case 0xa:
		logger.Printf("[macos-unifiedlogs] Firehose flag: uuid_relative")
		firehoseUUIDRelative, err := c.u128be()
		if err != nil {
			return nil, formatterFlags, err
		}
		formatterFlags.UuidRelative = u128Hex(firehoseUUIDRelative)
		*flags = append(*flags, MessageFlagsUuidRelative)
	default:
		logger.Printf("[macos-unifiedlogs] Unknown Firehose formatter flag: %d", firehoseFlags)
		logger.Printf("[macos-unifiedlogs] Firehose data: %X", data)
		*flags = append(*flags, MessageFlagsUnknown)
		return nil, formatterFlags, fmt.Errorf("unknown firehose formatter flag: %d: %w", firehoseFlags, ErrIncomplete)
	}
	return c.rest(), formatterFlags, nil
}
