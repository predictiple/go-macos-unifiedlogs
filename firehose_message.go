// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

import (
	"strconv"
)

// MessageData holds the base format string and associated process/library data
// extracted for a firehose log entry.
type MessageData struct {
	Library      string `json:"library"`
	FormatString string `json:"format_string"`
	Process      string `json:"process"`
	LibraryUUID  string `json:"library_uuid"`
	ProcessUUID  string `json:"process_uuid"`
}

// MessageParams holds the arguments needed to extract a message format string.
type MessageParams struct {
	PCID                uint32 `json:"pc_id"`
	StringOffset        uint64 `json:"string_offset"`
	FirstProcID         uint64 `json:"first_proc_id"`
	SecondProcID        uint32 `json:"second_proc_id"`
	SupportsLargeOffset bool   `json:"supports_large_offset"`
}

// getMessage gets the base message for the log entry based on the formatter flags.
func getMessage(formatters FirehoseFormatters, provider FileProvider, cache StringCache, params MessageParams, catalogs *CatalogChunk) ([]byte, MessageData, error) {
	stringOffset := params.StringOffset

	sharedCacheString := formatters.SharedCache ||
		(formatters.LargeSharedCache != 0 && (!params.SupportsLargeOffset || formatters.HasLargeOffset != 0))
	if sharedCacheString {
		if formatters.HasLargeOffset != 0 {
			var largeOffset uint64
			if (formatters.HasLargeOffset == 1 || formatters.HasLargeOffset == 2) &&
				formatters.HasLargeOffset > uint16(formatters.LargeSharedCache) {
				largeOffset = 0x80000000 * uint64(formatters.HasLargeOffset)
			} else if formatters.LargeSharedCache != 0 {
				largeOffset = 0x100000000 * uint64(formatters.LargeSharedCache/2)
			} else {
				largeOffset = 0x100000000 * uint64(formatters.HasLargeOffset)
			}
			realOffset := largeOffset + stringOffset
			return extractSharedStrings(provider, cache, realOffset, params.FirstProcID, params.SecondProcID, catalogs, stringOffset)
		}
		return extractSharedStrings(provider, cache, stringOffset, params.FirstProcID, params.SecondProcID, catalogs, stringOffset)
	}

	if formatters.Absolute {
		offset := (0x100000000 * uint64(formatters.MainExeAltIndex)) + uint64(params.PCID)
		return extractAbsoluteStrings(provider, cache, offset, stringOffset, params.FirstProcID, params.SecondProcID, catalogs, stringOffset)
	}
	if formatters.UuidRelative != "" {
		return extractAltUUIDStrings(provider, cache, stringOffset, formatters.UuidRelative, params.FirstProcID, params.SecondProcID, catalogs, stringOffset)
	}
	return extractFormatStrings(provider, cache, stringOffset, params.FirstProcID, params.SecondProcID, catalogs, stringOffset)
}

// extractSharedStrings extracts a string from the Shared Strings Cache (dsc data).
// Shared strings contain library and message string.
func extractSharedStrings(provider FileProvider, cache StringCache, stringOffset uint64, firstProcID uint64, secondProcID uint32, catalogs *CatalogChunk, originalOffset uint64) ([]byte, MessageData, error) {
	logger.Printf("[macos-unifiedlogs] Extracting format string from shared cache file (dsc)")
	var messageData MessageData

	dscUUID, mainUUID := getCatalogDSC(catalogs, firstProcID, secondProcID)

	// Check if the string offset is "dynamic" (the formatter is "%s")
	if originalOffset&0x80000000 != 0 {
		sharedString, err := cache.GetOrLoadDSC(dscUUID, provider)
		if err == nil && sharedString != nil && len(sharedString.Ranges) > 0 {
			uuidIndex := int(sharedString.Ranges[0].UUIDIndex)
			if uuidIndex >= len(sharedString.UUIDs) {
				logger.Printf("[macos-unifiedlogs] UUID index %d out of bounds (max: %d). Malformed data.", uuidIndex, len(sharedString.UUIDs))
				messageData.FormatString = "Error: Invalid UUID index"
				return []byte{}, messageData, nil
			}

			messageData.Library = sharedString.UUIDs[uuidIndex].PathString
			messageData.LibraryUUID = sharedString.UUIDs[uuidIndex].UUID
			messageData.FormatString = "%s"
			messageData.ProcessUUID = mainUUID

			_, processString, err := getUUIDImagePath(messageData.ProcessUUID, provider, cache)
			if err != nil {
				return nil, messageData, err
			}
			messageData.Process = processString
			return []byte{}, messageData, nil
		}
	}

	sharedString, err := cache.GetOrLoadDSC(dscUUID, provider)
	if err == nil && sharedString != nil {
		for _, ranges := range sharedString.Ranges {
			if stringOffset >= ranges.RangeOffset && stringOffset < (ranges.RangeOffset+uint64(ranges.RangeSize)) {
				offset := stringOffset - ranges.RangeOffset
				stringData := ranges.Strings

				// If the offset and string data are equal then the next range entry contains the string message
				if int(offset) == len(stringData) {
					continue
				}

				if offset > uint64(len(stringData)) {
					logger.Printf("[macos-unifiedlogs] u64 is bigger than system usize")
					return nil, messageData, ErrEof
				}

				_, messageString, err := extractString(stringData[offset:])
				if err != nil {
					return nil, messageData, err
				}
				messageData.FormatString = messageString

				uuidIndex := int(ranges.UUIDIndex)
				if uuidIndex >= len(sharedString.UUIDs) {
					logger.Printf("[macos-unifiedlogs] UUID index %d out of bounds (max: %d). Malformed data.", uuidIndex, len(sharedString.UUIDs))
					messageData.FormatString = "Error: Invalid UUID index"
					return []byte{}, messageData, nil
				}

				messageData.Library = sharedString.UUIDs[uuidIndex].PathString
				messageData.LibraryUUID = sharedString.UUIDs[uuidIndex].UUID
				messageData.ProcessUUID = mainUUID

				_, processString, err := getUUIDImagePath(messageData.ProcessUUID, provider, cache)
				if err != nil {
					return nil, messageData, err
				}
				messageData.Process = processString
				return []byte{}, messageData, nil
			}
		}
	}

	// There is a chance the log entry does not have a valid offset
	// Apple reports as "~~> <Invalid shared cache code pointer offset>" or <Invalid shared cache format string offset>
	if sharedString, err := cache.GetOrLoadDSC(dscUUID, provider); err == nil && sharedString != nil {
		if len(sharedString.Ranges) > 0 {
			uuidIndex := int(sharedString.Ranges[0].UUIDIndex)
			if uuidIndex >= len(sharedString.UUIDs) {
				logger.Printf("[macos-unifiedlogs] UUID index %d out of bounds (max: %d). Malformed data.", uuidIndex, len(sharedString.UUIDs))
				messageData.FormatString = "Error: Invalid UUID index"
				return []byte{}, messageData, nil
			}

			messageData.Library = sharedString.UUIDs[uuidIndex].PathString
			messageData.LibraryUUID = sharedString.UUIDs[uuidIndex].UUID
			messageData.FormatString = "Error: Invalid shared string offset"
			messageData.ProcessUUID = mainUUID

			_, processString, err := getUUIDImagePath(messageData.ProcessUUID, provider, cache)
			if err != nil {
				return nil, messageData, err
			}
			messageData.Process = processString
			return []byte{}, messageData, nil
		}
	}

	logger.Printf("[macos-unifiedlogs] Failed to get message string from Shared Strings DSC file")
	messageData.FormatString = "Unknown shared string message"
	return []byte{}, messageData, nil
}

// extractFormatStrings extracts strings from the UUIDText file associated with the log entry.
// UUIDText file contains process and message string.
func extractFormatStrings(provider FileProvider, cache StringCache, stringOffset uint64, firstProcID uint64, secondProcID uint32, catalogs *CatalogChunk, originalOffset uint64) ([]byte, MessageData, error) {
	logger.Printf("[macos-unifiedlogs] Extracting format string from UUID file")
	_, mainUUID := getCatalogDSC(catalogs, firstProcID, secondProcID)

	// log entries with main_exe flag do not use dsc cache uuid file
	messageData := MessageData{
		LibraryUUID: mainUUID,
		ProcessUUID: mainUUID,
	}

	// If most significant bit is set, the string offset is "dynamic" (the formatter is "%s")
	if originalOffset&0x80000000 != 0 {
		if data, err := cache.GetOrLoadUUIDText(messageData.ProcessUUID, provider); err == nil && data != nil {
			footerData := data.FooterData
			_, processString, err := uuidtextImagePath(footerData, data.EntryDescriptors)
			if err != nil {
				return nil, messageData, err
			}
			messageData.Process = processString
			messageData.Library = processString
			messageData.FormatString = "%s"
			return []byte{}, messageData, nil
		}
	}

	if data, err := cache.GetOrLoadUUIDText(messageData.ProcessUUID, provider); err == nil && data != nil {
		var stringStart uint32
		for _, entry := range data.EntryDescriptors {
			if entry.RangeStartOffset > uint32(stringOffset) {
				stringStart += entry.EntrySize
				continue
			}

			offset := uint32(stringOffset) - entry.RangeStartOffset
			footerData := data.FooterData

			if uint64(len(footerData)) < uint64(offset+stringStart) || offset > entry.EntrySize {
				stringStart += entry.EntrySize
				continue
			}

			messageStart := footerData[offset+stringStart:]
			_, messageString, err := extractString(messageStart)
			if err != nil {
				return nil, messageData, err
			}

			_, processString, err := uuidtextImagePath(footerData, data.EntryDescriptors)
			if err != nil {
				return nil, messageData, err
			}

			messageData.FormatString = messageString
			messageData.Process = processString
			messageData.Library = processString
			return []byte{}, messageData, nil
		}
	}

	// There is a chance the log entry does not have a valid offset
	// Apple labels as "error: ~~> Invalid bounds 4334340 for E502E11E-518F-38A7-9F0B-E129168338E7"
	if data, err := cache.GetOrLoadUUIDText(messageData.ProcessUUID, provider); err == nil && data != nil {
		footerData := data.FooterData
		_, processString, err := uuidtextImagePath(footerData, data.EntryDescriptors)
		if err != nil {
			return nil, messageData, err
		}
		messageData.Process = processString
		messageData.Library = processString
		messageData.FormatString = "Error: Invalid offset " + u64ToString(stringOffset) + " for UUID " + messageData.ProcessUUID
		return []byte{}, messageData, nil
	}

	logger.Printf("[macos-unifiedlogs] Failed to get message string from UUIDText file: %s", messageData.ProcessUUID)
	messageData.FormatString = "Failed to get string message from UUIDText file: " + messageData.ProcessUUID
	return []byte{}, messageData, nil
}

// extractAbsoluteStrings extracts strings from the UUIDText file associated with a log entry
// that has the `absolute` flag set.
func extractAbsoluteStrings(provider FileProvider, cache StringCache, absoluteOffset uint64, stringOffset uint64, firstProcID uint64, secondProcID uint32, catalogs *CatalogChunk, originalOffset uint64) ([]byte, MessageData, error) {
	logger.Printf("[macos-unifiedlogs] Extracting format string from UUID file for log entry with Absolute flag")
	var uuid string
	if entry, ok := catalogs.CatalogProcessInfoEntries[procIDKey(firstProcID, secondProcID)]; ok {
		for _, uuids := range entry.UUIDInfoEntries {
			if absoluteOffset >= uuids.LoadAddress && absoluteOffset <= (uuids.LoadAddress+uint64(uuids.Size)) {
				logger.Printf("[macos-unifiedlogs] Absolute uuid file is: %s", uuids.UUID)
				uuid = uuids.UUID
				break
			}
		}
	}

	_, mainUUID := getCatalogDSC(catalogs, firstProcID, secondProcID)

	messageData := MessageData{
		LibraryUUID: uuid,
		ProcessUUID: mainUUID,
	}

	// If most significant bit is set, the string offset is "dynamic" (the formatter is "%s")
	if (originalOffset&0x80000000 != 0) || stringOffset == absoluteOffset {
		if data, err := cache.GetOrLoadUUIDText(messageData.LibraryUUID, provider); err == nil && data != nil {
			footerData := data.FooterData
			_, libraryString, err := uuidtextImagePath(footerData, data.EntryDescriptors)
			if err != nil {
				return nil, messageData, err
			}
			messageData.Library = libraryString

			_, processString, err := getUUIDImagePath(messageData.ProcessUUID, provider, cache)
			if err != nil {
				return nil, messageData, err
			}
			messageData.Process = processString
			messageData.FormatString = "%s"
			return []byte{}, messageData, nil
		}
	}

	if data, err := cache.GetOrLoadUUIDText(messageData.LibraryUUID, provider); err == nil && data != nil {
		var stringStart uint64
		for _, entry := range data.EntryDescriptors {
			if uint64(entry.RangeStartOffset) > stringOffset {
				stringStart += uint64(entry.EntrySize)
				continue
			}

			footerData := data.FooterData
			offset := stringOffset - uint64(entry.RangeStartOffset)

			if uint64(len(footerData)) < (offset+stringStart) || offset > uint64(entry.EntrySize) {
				stringStart += uint64(entry.EntrySize)
				continue
			}

			if (offset + stringStart) > uint64(len(footerData)) {
				logger.Printf("[macos-unifiedlogs] u64 is bigger than system usize")
				return nil, messageData, ErrEof
			}
			messageStart := footerData[offset+stringStart:]
			_, messageString, err := extractString(messageStart)
			if err != nil {
				return nil, messageData, err
			}

			_, libraryString, err := uuidtextImagePath(footerData, data.EntryDescriptors)
			if err != nil {
				return nil, messageData, err
			}
			messageData.FormatString = messageString
			messageData.Library = libraryString

			_, processString, err := getUUIDImagePath(messageData.ProcessUUID, provider, cache)
			if err != nil {
				return nil, messageData, err
			}
			messageData.Process = processString
			return []byte{}, messageData, nil
		}
	}

	// There is a chance the log entry does not have a valid offset
	if data, err := cache.GetOrLoadUUIDText(messageData.LibraryUUID, provider); err == nil && data != nil {
		footerData := data.FooterData
		_, libraryString, err := uuidtextImagePath(footerData, data.EntryDescriptors)
		if err != nil {
			return nil, messageData, err
		}
		messageData.Library = libraryString
		messageData.FormatString = "Error: Invalid offset " + u64ToString(stringOffset) + " for absolute UUID " + messageData.LibraryUUID

		_, processString, err := getUUIDImagePath(messageData.ProcessUUID, provider, cache)
		if err != nil {
			return nil, messageData, err
		}
		messageData.Process = processString
		return []byte{}, messageData, nil
	}

	logger.Printf("[macos-unifiedlogs] Failed to get message string from absolute UUIDText file: %s", messageData.LibraryUUID)
	messageData.FormatString = "Failed to get string message from absolute UUIDText file: " + messageData.LibraryUUID
	return []byte{}, messageData, nil
}

// extractAltUUIDStrings extracts strings from an alt UUIDText file specified within the log entry
// that has the `uuid_relative` flag set.
func extractAltUUIDStrings(provider FileProvider, cache StringCache, stringOffset uint64, uuid string, firstProcID uint64, secondProcID uint32, catalogs *CatalogChunk, originalOffset uint64) ([]byte, MessageData, error) {
	logger.Printf("[macos-unifiedlogs] Extracting format string from alt uuid")
	// Log entries with uuid_relative flags set have the UUID in the log itself. They do not use the dsc UUID files
	_, mainUUID := getCatalogDSC(catalogs, firstProcID, secondProcID)

	messageData := MessageData{
		LibraryUUID: uuid,
		ProcessUUID: mainUUID,
	}

	// If most significant bit is set, the string offset is "dynamic" (the formatter is "%s")
	if originalOffset&0x80000000 != 0 {
		if data, err := cache.GetOrLoadUUIDText(uuid, provider); err == nil && data != nil {
			footerData := data.FooterData
			_, libraryString, err := uuidtextImagePath(footerData, data.EntryDescriptors)
			if err != nil {
				return nil, messageData, err
			}
			messageData.Library = libraryString

			_, processString, err := getUUIDImagePath(messageData.ProcessUUID, provider, cache)
			if err != nil {
				return nil, messageData, err
			}
			messageData.Process = processString
			messageData.FormatString = "%s"
			return []byte{}, messageData, nil
		}
	}

	if data, err := cache.GetOrLoadUUIDText(uuid, provider); err == nil && data != nil {
		var stringStart uint64
		for _, entry := range data.EntryDescriptors {
			if uint64(entry.RangeStartOffset) > stringOffset {
				stringStart += uint64(entry.EntrySize)
				continue
			}
			offset := stringOffset - uint64(entry.RangeStartOffset)
			footerData := data.FooterData

			if uint64(len(footerData)) < offset || offset > uint64(entry.EntrySize) {
				stringStart += uint64(entry.EntrySize)
				continue
			}
			if (offset + stringStart) > uint64(len(footerData)) {
				logger.Printf("[macos-unifiedlogs] u64 is bigger than system usize")
				return nil, messageData, ErrEof
			}
			messageStart := footerData[offset+stringStart:]
			_, messageString, err := extractString(messageStart)
			if err != nil {
				return nil, messageData, err
			}

			_, libraryString, err := uuidtextImagePath(footerData, data.EntryDescriptors)
			if err != nil {
				return nil, messageData, err
			}

			_, processString, err := getUUIDImagePath(messageData.ProcessUUID, provider, cache)
			if err != nil {
				return nil, messageData, err
			}
			messageData.Process = processString

			messageData.FormatString = messageString
			messageData.Library = libraryString
			return []byte{}, messageData, nil
		}
	}

	// There is a chance the log entry does not have a valid offset
	if data, err := cache.GetOrLoadUUIDText(uuid, provider); err == nil && data != nil {
		footerData := data.FooterData
		_, libraryString, err := uuidtextImagePath(footerData, data.EntryDescriptors)
		if err != nil {
			return nil, messageData, err
		}
		messageData.Library = libraryString
		messageData.FormatString = "Error: Invalid offset " + u64ToString(stringOffset) + " for alternative UUID " + uuid

		_, processString, err := getUUIDImagePath(messageData.ProcessUUID, provider, cache)
		if err != nil {
			return nil, messageData, err
		}
		messageData.Process = processString
		return []byte{}, messageData, nil
	}

	logger.Printf("[macos-unifiedlogs] Failed to get message string from alternative UUIDText file: %s", uuid)
	messageData.FormatString = "Failed to get string message from alternative UUIDText file: " + uuid
	return []byte{}, messageData, nil
}

// uuidtextImagePath gets the image path at the end of the UUIDText file.
func uuidtextImagePath(data []byte, entries []UUIDTextEntry) ([]byte, string, error) {
	var imageLibraryOffset uint32
	for _, entry := range entries {
		imageLibraryOffset += entry.EntrySize
	}
	if uint64(imageLibraryOffset) > uint64(len(data)) {
		return nil, "", ErrEof
	}
	libraryStart := data[imageLibraryOffset:]
	_, result, err := extractString(libraryStart)
	if err != nil {
		return nil, "", err
	}
	return []byte{}, result, nil
}

// getUUIDImagePath gets the image path from the provided main UUID entry.
func getUUIDImagePath(mainUUID string, provider FileProvider, cache StringCache) ([]byte, string, error) {
	// An UUID of all zeros is possible in the Catalog, if this happens there is no process path
	if mainUUID == "00000000000000000000000000000000" {
		logger.Printf("[macos-unifiedlogs] Got UUID of all zeros fom Catalog")
		return []byte{}, "", nil
	}

	if data, err := cache.GetOrLoadUUIDText(mainUUID, provider); err == nil && data != nil {
		return uuidtextImagePath(data.FooterData, data.EntryDescriptors)
	}

	logger.Printf("[macos-unifiedlogs] Failed to get path string from UUIDText file for entry: %s", mainUUID)
	return []byte{}, "Failed to get path string from UUIDText file for entry: " + mainUUID, nil
}

// getCatalogDSC gets the dsc file name from the Catalog data based on first and
// second proc ids from the Firehose log.
func getCatalogDSC(catalogs *CatalogChunk, firstProcID uint64, secondProcID uint32) (string, string) {
	var dscUUID string
	var mainUUID string

	if entry, ok := catalogs.CatalogProcessInfoEntries[procIDKey(firstProcID, secondProcID)]; ok {
		dscUUID = entry.DscUUID
		mainUUID = entry.MainUUID
	}
	return dscUUID, mainUUID
}

func procIDKey(firstProcID uint64, secondProcID uint32) string {
	return u64ToString(firstProcID) + "_" + u32ToString(secondProcID)
}

func u64ToString(v uint64) string {
	return strconv.FormatUint(v, 10)
}

func u32ToString(v uint32) string {
	return strconv.FormatUint(uint64(v), 10)
}
