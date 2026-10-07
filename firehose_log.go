// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

import (
	"fmt"
	"math/big"
	"slices"
)

// FirehosePreamble is the start of Firehose chunk data.
type FirehosePreamble struct {
	ChunkTag                 uint32     `json:"chunk_tag"`
	ChunkSubTag              uint32     `json:"chunk_sub_tag"`
	ChunkDataSize            uint64     `json:"chunk_data_size"`
	FirstNumberProcID        uint64     `json:"first_number_proc_id"`
	SecondNumberProcID       uint32     `json:"second_number_proc_id"`
	TTL                      uint8      `json:"ttl"`
	Collapsed                uint8      `json:"collapsed"`
	Unknown                  []byte     `json:"unknown"`
	PublicDataSize           uint16     `json:"public_data_size"`
	PrivateDataVirtualOffset uint16     `json:"private_data_virtual_offset"`
	Unkonwn2                 uint16     `json:"unkonwn2"`
	Unknown3                 uint16     `json:"unknown3"`
	BaseContinousTime        uint64     `json:"base_continous_time"`
	PublicData               []Firehose `json:"public_data"`
}

// Firehose is a single log entry within a Firehose chunk.
type Firehose struct {
	LogActivityType         uint8            `json:"log_activity_type"`
	LogType                 uint8            `json:"log_type"`
	Flags                   uint16           `json:"flags"`
	FormatStringLocation    uint32           `json:"format_string_location"`
	ThreadID                uint64           `json:"thread_id"`
	ContinousTimeDelta      uint32           `json:"continous_time_delta"`
	ContinousTimeDeltaUpper uint16           `json:"continous_time_delta_upper"`
	DataSize                uint16           `json:"data_size"`
	FirehoseActivity        FirehoseActivity `json:"firehose_activity"`
	FirehoseNonActivity     FirehoseNonActivity
	FirehoseLoss            FirehoseLoss
	FirehoseSignpost        FirehoseSignpost
	FirehoseTrace           FirehoseTrace
	Item                    uint8            `json:"item"`
	NumberItems             uint8            `json:"number_items"`
	MessageFlags            []MessageFlags   `json:"message_flags"`
	Message                 FirehoseItemData `json:"message"`
}

// FirehoseItemType is a Firehose log message entry (string, number, object, or precision).
type FirehoseItemType struct {
	ItemType       uint8        `json:"item_type"`
	ItemTypeSize   uint8        `json:"item_type_size"`
	Offset         uint16       `json:"offset"`
	ItemSize       uint16       `json:"item_size"`
	MessageStrings string       `json:"message_strings"`
	Item           FirehoseItem `json:"item"`
}

// FirehoseItem is the item type as an enum.
type FirehoseItem string

const (
	FirehoseItemString          FirehoseItem = "String"
	FirehoseItemPrivateNumber   FirehoseItem = "PrivateNumber"
	FirehoseItemNumber          FirehoseItem = "Number"
	FirehoseItemPrivateString   FirehoseItem = "PrivateString"
	FirehoseItemPrecision       FirehoseItem = "Precision"
	FirehoseItemSensitive       FirehoseItem = "Sensitive"
	FirehoseItemObject          FirehoseItem = "Object"
	FirehoseItemSensitiveNumber FirehoseItem = "SensitiveNumber"
	FirehoseItemUnknown         FirehoseItem = "Unknown"
)

// MessageFlags mirror the bit flags of the log entry's Lighthouse layout value.
type MessageFlags string

const (
	MessageFlagsSharedCache      MessageFlags = "SharedCache"
	MessageFlagsMainExe          MessageFlags = "MainExe"
	MessageFlagsHasLargeOffset   MessageFlags = "HasLargeOffset"
	MessageFlagsLargeSharedCache MessageFlags = "LargeSharedCache"
	MessageFlagsAbsolute         MessageFlags = "Absolute"
	MessageFlagsUuidRelative     MessageFlags = "UuidRelative"
	MessageFlagsMainPlugin       MessageFlags = "MainPlugin"
	MessageFlagsPcStyle          MessageFlags = "PcStyle"
	MessageFlagsHasUniquePid     MessageFlags = "HasUniquePid"
	MessageFlagsHasCurrentAid    MessageFlags = "HasCurrentAid"
	MessageFlagsHasOtherAid      MessageFlags = "HasOtherAid"
	MessageFlagsHasRules         MessageFlags = "HasRules"
	MessageFlagsHasName          MessageFlags = "HasName"
	MessageFlagsAltIndex         MessageFlags = "AltIndex"
	MessageFlagsUnknown          MessageFlags = "Unknown"
	MessageFlagsHasPrivateData   MessageFlags = "HasPrivateData"
	MessageFlagsHasOversize      MessageFlags = "HasOversize"
	MessageFlagsHasSubsystem     MessageFlags = "HasSubsystem"
	MessageFlagsHasPersona       MessageFlags = "HasPersona"
)

// FirehoseItemData holds the log values extracted for a Firehose entry.
type FirehoseItemData struct {
	ItemInfo         []FirehoseItemType `json:"item_info"`
	BacktraceStrings []string           `json:"backtrace_strings"`
}

// Associated constants from `impl FirehosePreamble` in firehose_log.rs.
const (
	firehosePrivateNumber   uint8 = 0x1
	firehoseSensitiveNumber uint8 = 0x5
	firehoseRemnantData     uint8 = 0x0
)

var (
	// STRING_ITEM: remaining data (if any) after the item types contains strings.
	firehoseStringItems = []uint8{0x20, 0x22, 0x40, 0x42, 0x30, 0x31, 0x32, 0xf2}
	// PRIVATE_STRINGS. 0x81 and 0xf1 added in macOS Sequoia.
	firehosePrivateStrings = []uint8{0x21, 0x25, 0x35, 0x31, 0x41, 0x81, 0xf1}
	// LOG_TYPES: known log activity types.
	firehoseLogTypes = []uint8{0x2, 0x6, 0x4, 0x7, 0x3}
)

// nomTake mirrors nom::bytes::complete::take: returns the remaining input and the
// first n bytes. nom returns ErrorKind::Eof when n exceeds the input length.
func nomTake(data []byte, n uint64) ([]byte, []byte, error) {
	if n > uint64(len(data)) {
		return nil, nil, fmt.Errorf("needed %d bytes, got %d: %w", n, len(data), ErrEof)
	}
	return data[n:], data[:n], nil
}

// nomTakeWhile mirrors nom::bytes::complete::take_while: consumes bytes while fn
// returns true and returns the remaining input and the consumed bytes.
func nomTakeWhile(data []byte, fn func(byte) bool) ([]byte, []byte) {
	i := 0
	for i < len(data) && fn(data[i]) {
		i++
	}
	return data[i:], data[:i]
}

// parseFirehosePreamble parses the start of the Firehose data, returning the
// remaining input after the chunk data (mirrors parse_firehose_preamble).
func parseFirehosePreamble(firehoseInputData []byte) ([]byte, *FirehosePreamble, error) {
	firehoseData := &FirehosePreamble{}

	c := newCursor(firehoseInputData)
	chunkTag, err := c.u32()
	if err != nil {
		return nil, nil, err
	}
	chunkSubTag, err := c.u32()
	if err != nil {
		return nil, nil, err
	}
	chunkDataSize, err := c.u64()
	if err != nil {
		return nil, nil, err
	}
	remaining, chunkData, err := nomTake(c.rest(), chunkDataSize)
	if err != nil {
		return nil, nil, err
	}

	cd := newCursor(chunkData)
	firstProcID, err := cd.u64()
	if err != nil {
		return nil, nil, err
	}
	secondProcID, err := cd.u32()
	if err != nil {
		return nil, nil, err
	}
	ttl, err := cd.u8()
	if err != nil {
		return nil, nil, err
	}
	collapsed, err := cd.u8()
	if err != nil {
		return nil, nil, err
	}
	unknown, err := cd.take(2)
	if err != nil {
		return nil, nil, err
	}
	dataStart := cd.rest()

	// Private data offset starts here. Public data size includes itself.
	publicDataSize, err := cd.u16()
	if err != nil {
		return nil, nil, err
	}
	privateDataVirtualOffset, err := cd.u16()
	if err != nil {
		return nil, nil, err
	}
	unknown2, err := cd.u16()
	if err != nil {
		return nil, nil, err
	}
	unknown3, err := cd.u16()
	if err != nil {
		return nil, nil, err
	}
	baseContinousTime, err := cd.u64()
	if err != nil {
		return nil, nil, err
	}
	logData := cd.rest()

	firehoseData.ChunkTag = chunkTag
	firehoseData.ChunkSubTag = chunkSubTag
	firehoseData.ChunkDataSize = chunkDataSize
	firehoseData.FirstNumberProcID = firstProcID
	firehoseData.SecondNumberProcID = secondProcID
	firehoseData.Collapsed = collapsed
	firehoseData.TTL = ttl
	firehoseData.Unknown = unknown
	firehoseData.PublicDataSize = publicDataSize
	firehoseData.PrivateDataVirtualOffset = privateDataVirtualOffset
	firehoseData.Unkonwn2 = unknown2
	firehoseData.Unknown3 = unknown3
	firehoseData.BaseContinousTime = baseContinousTime
	firehoseData.PublicData = []Firehose{}

	// firehose_public_data_size includes itself and the metadata we nommed above (16 bytes)
	const publicDataNommedSize uint16 = 16
	publicRemaining, publicData, err := nomTake(logData, uint64(publicDataSize-publicDataNommedSize))
	if err != nil {
		return nil, nil, err
	}

	// Go through all the public data associated with the log Firehose entry.
	for len(publicData) > 0 {
		// Start parsing all of them public data.
		firehoseInput, firehosePublicData, err := parseFirehose(publicData)
		if err != nil {
			return nil, nil, err
		}
		publicData = firehoseInput

		// If not enough data remaining. End early.
		if !slices.Contains(firehoseLogTypes, firehosePublicData.LogActivityType) ||
			len(publicData) < 24 {
			if firehoseRemnantData == firehosePublicData.LogActivityType {
				break
			}
			firehoseData.PublicData = append(firehoseData.PublicData, firehosePublicData)
			break
		}

		firehoseData.PublicData = append(firehoseData.PublicData, firehosePublicData)
	}

	const privateDataOffsetDefault uint16 = 0x1000
	// If there is private data, go through and update any logs that have private data items.
	if privateDataVirtualOffset != privateDataOffsetDefault {
		var privateData []byte
		if firehoseData.Collapsed == 1 || int(privateDataVirtualOffset) > len(dataStart) {
			privateDataSize := uint64(privateDataOffsetDefault - privateDataVirtualOffset)
			_, data, err := nomTake(publicRemaining, privateDataSize)
			if err != nil {
				return nil, nil, err
			}
			privateData = data
		} else {
			// Jump to start of private data.
			data, _, err := nomTake(dataStart, uint64(privateDataVirtualOffset))
			if err != nil {
				return nil, nil, err
			}
			privateData = data
		}

		// Only non-activity firehose entries appear to have private strings.
		for i := range firehoseData.PublicData {
			data := &firehoseData.PublicData[i]
			if data.FirehoseNonActivity.PrivateStringsSize == 0 {
				continue
			}
			// Get the start of private string data.
			stringOffset := data.FirehoseNonActivity.PrivateStringsOffset - privateDataVirtualOffset
			privateStringStart, _, err := nomTake(privateData, uint64(stringOffset))
			if err != nil {
				return nil, nil, err
			}
			_, _ = parsePrivateFirehoseData(privateStringStart, &data.Message)
		}
	}

	return remaining, firehoseData, nil
}

// collectFirehoseItems collects all the Firehose items (log message entries) in
// the log entry (chunk). Mirrors collect_items.
func collectFirehoseItems(data []byte, firehoseNumberItems uint8, firehoseFlags uint16) ([]byte, FirehoseItemData, error) {
	var itemCount uint8
	var itemsData []FirehoseItemType

	firehoseInput := data
	firehoseItemData := FirehoseItemData{}

	// Firehose number item values.
	numberItemType := []uint8{0x0, 0x2}
	// Dynamic precision item types?
	precisionItems := []uint8{0x10, 0x12}
	// Likely related to private string. Seen only "<private>" values.
	sensitiveItems := []uint8{0x45, 0x85}
	objectItems := []uint8{0x40, 0x42}

	for itemCount < firehoseNumberItems {
		// Get non-number values first since the values are at the end of the (chunk) entry data.
		itemValueInput, item, err := getFirehoseItems(firehoseInput)
		if err != nil {
			return nil, FirehoseItemData{}, err
		}
		firehoseInput = itemValueInput

		// Precision items just contain the length for the actual item. Ex: %*s
		if slices.Contains(precisionItems, item.ItemType) {
			itemsData = append(itemsData, item)
			itemCount++
			continue
		}

		// Firehose number item values immediately follow the item type.
		if slices.Contains(numberItemType, item.ItemType) {
			itemValueInput, messageNumber, err := parseFirehoseItemNumber(firehoseInput, uint16(item.ItemTypeSize))
			if err != nil {
				return nil, FirehoseItemData{}, err
			}

			item.MessageStrings = fmt.Sprintf("%d", messageNumber)
			firehoseInput = itemValueInput
			itemCount++
			item.Item = FirehoseItemNumber
			itemsData = append(itemsData, item)
			continue
		}

		// A message size of 0 and is an object type is "(null)".
		if item.ItemSize == 0 && slices.Contains(objectItems, item.ItemType) {
			item.MessageStrings = "(null)"
		}
		itemsData = append(itemsData, item)
		itemCount++
	}

	// Backtrace data appears before Firehose item strings. It only exists if the log
	// entry has has_context_data flag set. Backtrace data can also exist in Oversize
	// log entries which do not have the flag; there we check for a possible signature.
	const hasContextData uint16 = 0x1000
	const backtraceSignatureSize = 3

	if (firehoseFlags & hasContextData) != 0 {
		logger.Printf("[macos-unifiedlogs] Identified Backtrace data in Firehose log chunk")
		backtraceInput, backtraceData, err := getFirehoseBacktraceData(firehoseInput)
		if err != nil {
			return nil, FirehoseItemData{}, err
		}
		firehoseInput = backtraceInput
		firehoseItemData.BacktraceStrings = backtraceData
	} else if len(firehoseInput) > backtraceSignatureSize {
		backtraceSignature := []byte{1, 0, 18}
		_, backtraceSig, err := nomTake(firehoseInput, uint64(backtraceSignatureSize))
		if err != nil {
			return nil, FirehoseItemData{}, err
		}
		if slices.Equal(backtraceSignature, backtraceSig) {
			backtraceInput, backtraceData, err := getFirehoseBacktraceData(firehoseInput)
			if err != nil {
				return nil, FirehoseItemData{}, err
			}
			firehoseInput = backtraceInput
			firehoseItemData.BacktraceStrings = backtraceData
		}
	}

	for i := range itemsData {
		item := &itemsData[i]
		// We already got number items above since the values immediately follow the number type.
		if slices.Contains(numberItemType, item.ItemType) {
			continue
		}

		// Check if item type is a private string. This is used for privacy related data.
		if slices.Contains(firehosePrivateStrings, item.ItemType) ||
			slices.Contains(sensitiveItems, item.ItemType) {
			item.Item = FirehoseItemPrivateString
			item.MessageStrings = "<private>"
			continue
		}

		if item.ItemType == firehoseSensitiveNumber {
			item.Item = FirehoseItemSensitiveNumber
			item.MessageStrings = "<private>"
			continue
		}

		if item.ItemType == firehosePrivateNumber {
			continue
		}

		// We already got item precision info above.
		if slices.Contains(precisionItems, item.ItemType) {
			continue
		}

		if item.ItemSize == 0 && item.MessageStrings != "" {
			continue
		}

		if len(firehoseInput) == 0 {
			break
		}
		if slices.Contains(firehoseStringItems, item.ItemType) {
			itemValueInput, messageString, err := parseFirehoseItemString(firehoseInput, item)
			if err != nil {
				return nil, FirehoseItemData{}, err
			}
			firehoseInput = itemValueInput
			item.MessageStrings = messageString
		} else {
			logger.Printf("[macos-unifiedlogs] Unknown Firehose item: %d", item.ItemType)
		}
	}

	firehoseItemData.ItemInfo = itemsData
	return firehoseInput, firehoseItemData, nil
}

// parsePrivateFirehoseData parses any private firehose data and updates any
// firehose items that use private data. Mirrors parse_private_data.
func parsePrivateFirehoseData(data []byte, firehoseItemData *FirehoseItemData) ([]byte, error) {
	privateStrings := []uint8{0x21, 0x25, 0x41, 0x35, 0x31, 0x81, 0xf1}

	privateStringStart := data
	const privateBitwiseSet uint16 = 0x8000

	// Go through all firehose items, for each private item entry get the private value.
	for i := range firehoseItemData.ItemInfo {
		firehoseInfo := &firehoseItemData.ItemInfo[i]

		if slices.Contains(privateStrings, firehoseInfo.ItemType) {
			// Base64 encode arbitrary data. Need to further parse them based on base string formatters.
			if firehoseInfo.ItemType == privateStrings[3] ||
				firehoseInfo.ItemType == privateStrings[4] {
				if len(privateStringStart) < int(firehoseInfo.ItemSize) {
					privateData, pointerObject, err := nomTake(privateStringStart, uint64(len(privateStringStart)))
					if err != nil {
						return nil, err
					}
					privateStringStart = privateData
					firehoseInfo.MessageStrings = encodeStandard(pointerObject)
					continue
				}

				privateData, pointerObject, err := nomTake(privateStringStart, uint64(firehoseInfo.ItemSize))
				if err != nil {
					return nil, err
				}
				privateStringStart = privateData
				firehoseInfo.MessageStrings = encodeStandard(pointerObject)
				continue
			}

			// Even null values are marked private.
			if firehoseInfo.ItemSize == 0 {
				firehoseInfo.MessageStrings = "<private>"
			} else {
				if (privateBitwiseSet & firehoseInfo.ItemSize) != 0 {
					// If the most significant bit is set (0x8000) we need to
					// clear it to get the real size. Ex: 0x83f8 is really 0x3f8.
					realSize := firehoseInfo.ItemSize & 0x7fff
					privateData, privateString, err := extractStringSize(privateStringStart, uint64(realSize))
					if err != nil {
						return nil, err
					}
					privateStringStart = privateData
					firehoseInfo.MessageStrings = privateString
					continue
				}
				privateData, privateString, err := extractStringSize(privateStringStart, uint64(firehoseInfo.ItemSize))
				if err != nil {
					return nil, err
				}
				privateStringStart = privateData
				firehoseInfo.MessageStrings = privateString
			}
		} else if firehoseInfo.ItemType == firehosePrivateNumber ||
			firehoseInfo.ItemType == firehoseSensitiveNumber {
			// Numbers can also be private.
			if firehoseInfo.ItemSize == privateBitwiseSet || firehoseInfo.ItemSize == 0 {
				firehoseInfo.MessageStrings = "<private>"
			} else {
				privateData, privateString, err := parseFirehoseItemNumber(privateStringStart, firehoseInfo.ItemSize)
				if err != nil {
					return nil, err
				}
				privateStringStart = privateData
				firehoseInfo.MessageStrings = fmt.Sprintf("%d", privateString)
			}
		}
	}
	return privateStringStart, nil
}

// parseFirehose parses all the different types of Firehose data (activity,
// non-activity, loss, trace, signpost). Mirrors parse_firehose.
func parseFirehose(data []byte) ([]byte, Firehose, error) {
	firehoseResults := Firehose{}

	c := newCursor(data)
	logActivityType, err := c.u8()
	if err != nil {
		return nil, firehoseResults, err
	}
	logType, err := c.u8()
	if err != nil {
		return nil, firehoseResults, err
	}
	flags, err := c.u16()
	if err != nil {
		return nil, firehoseResults, err
	}
	formatStringLocation, err := c.u32()
	if err != nil {
		return nil, firehoseResults, err
	}
	threadID, err := c.u64()
	if err != nil {
		return nil, firehoseResults, err
	}
	continousDelta, err := c.u32()
	if err != nil {
		return nil, firehoseResults, err
	}
	continousDeltaUpper, err := c.u16()
	if err != nil {
		return nil, firehoseResults, err
	}
	dataSize, err := c.u16()
	if err != nil {
		return nil, firehoseResults, err
	}
	input := c.rest()

	firehoseResults.LogActivityType = logActivityType
	firehoseResults.LogType = logType
	firehoseResults.Flags = flags
	firehoseResults.FormatStringLocation = formatStringLocation
	firehoseResults.ThreadID = threadID
	firehoseResults.ContinousTimeDeltaUpper = continousDeltaUpper
	firehoseResults.ContinousTimeDelta = continousDelta
	firehoseResults.DataSize = dataSize

	input, firehoseInput, err := nomTake(input, uint64(dataSize))
	if err != nil {
		return nil, firehoseResults, err
	}

	// Log activity type (log_activity_type).
	const (
		activity    uint8 = 0x2
		signpost    uint8 = 0x6
		nonactivity uint8 = 0x4
		loss        uint8 = 0x7
		trace       uint8 = 0x3
	)
	// 0x0 appears to be remnant data or garbage data (log command does not parse it either).
	const remnantData uint8 = 0x0

	if logActivityType == activity {
		activityData, act, err := parseActivity(firehoseInput, flags, logType)
		if err != nil {
			return nil, firehoseResults, err
		}
		firehoseInput = activityData
		firehoseResults.FirehoseActivity = act
	} else if logActivityType == nonactivity {
		nonActivityData, nonAct, err := parseNonActivity(firehoseInput, flags)
		if err != nil {
			return nil, firehoseResults, err
		}
		firehoseInput = nonActivityData
		firehoseResults.FirehoseNonActivity = nonAct
	} else if logActivityType == signpost {
		processData, sp, err := parseSignpost(firehoseInput, flags)
		if err != nil {
			return nil, firehoseResults, err
		}
		firehoseInput = processData
		firehoseResults.FirehoseSignpost = sp
	} else if logActivityType == loss {
		lossData, l, err := parseFirehoseLoss(firehoseInput)
		if err != nil {
			return nil, firehoseResults, err
		}
		firehoseResults.FirehoseLoss = l
		firehoseInput = lossData
	} else if logActivityType == trace {
		traceData, tr, err := parseFirehoseTrace(firehoseInput)
		if err != nil {
			return nil, firehoseResults, err
		}
		firehoseResults.FirehoseTrace = tr
		firehoseInput = traceData

		firehoseResults.Message = firehoseResults.FirehoseTrace.MessageData
	} else if logActivityType == remnantData {
		return input, firehoseResults, nil
	} else {
		logger.Printf("[macos-unifiedlogs] Unknown log activity type: %d -  %d bytes left",
			logActivityType, len(input))
		return input, firehoseResults, nil
	}

	const minimumItemSize = 6
	if len(firehoseInput) < minimumItemSize {
		// Nom any zero padding.
		remainingData, _ := nomTakeWhile(input, func(b byte) bool { return b == 0 })
		input = remainingData
		return input, firehoseResults, nil
	}

	firehoseItemCursor := newCursor(firehoseInput)
	item, err := firehoseItemCursor.u8()
	if err != nil {
		return nil, firehoseResults, err
	}
	numberItems, err := firehoseItemCursor.u8()
	if err != nil {
		return nil, firehoseResults, err
	}
	firehoseInput = firehoseItemCursor.rest()

	firehoseResults.Item = item
	firehoseResults.NumberItems = numberItems

	_, firehoseItemData, err := collectFirehoseItems(firehoseInput, numberItems, flags)
	if err != nil {
		return nil, firehoseResults, err
	}

	firehoseResults.Message = firehoseItemData

	// Nom any zero padding.
	remainingData, takenData := nomTakeWhile(input, func(b byte) bool { return b == 0 })

	// Verify we did not nom into remnant/junk data.
	paddingData := paddingSize8(uint64(dataSize))
	paddingDataInt, ok := u64ToUint(paddingData)
	if !ok {
		logger.Printf("[macos-unifiedlogs] u64 is bigger than system usize")
		return nil, firehoseResults, fmt.Errorf("padding size %d too large: %w", paddingData, ErrTooLarge)
	}
	input, _, err = nomTake(input, uint64(paddingDataInt))
	if err != nil {
		return nil, firehoseResults, err
	}
	if paddingDataInt > len(takenData) {
		input = remainingData
	}

	return input, firehoseResults, nil
}

// getFirehoseBacktraceData parses Backtrace data for the log entry (chunk). This
// only exists if the `has_context_data` flag is set. Mirrors get_backtrace_data.
func getFirehoseBacktraceData(data []byte) ([]byte, []string, error) {
	c := newCursor(data)
	if err := c.skip(3); err != nil {
		return nil, nil, err
	}
	uuidCountU8, err := c.u8()
	if err != nil {
		return nil, nil, err
	}
	offsetCountU16, err := c.u16()
	if err != nil {
		return nil, nil, err
	}
	uuidCount := int(uuidCountU8)
	offsetCount := int(offsetCountU16)

	uuidVec := make([][16]byte, 0, uuidCount)
	for i := 0; i < uuidCount; i++ {
		v, err := c.u128be()
		if err != nil {
			return nil, nil, err
		}
		uuidVec = append(uuidVec, v)
	}

	offsetsVec := make([]uint32, 0, offsetCount)
	for i := 0; i < offsetCount; i++ {
		v, err := c.u32()
		if err != nil {
			return nil, nil, err
		}
		offsetsVec = append(offsetsVec, v)
	}

	indexes := make([]int, 0, offsetCount)
	for i := 0; i < offsetCount; i++ {
		v, err := c.u8()
		if err != nil {
			return nil, nil, err
		}
		indexes = append(indexes, int(v))
	}

	backtraceData := make([]string, 0, offsetCount)
	for i, idx := range indexes {
		var uuidVal [16]byte
		var off uint32
		if idx < len(uuidVec) {
			uuidVal = uuidVec[idx]
		}
		if i < len(offsetsVec) {
			off = offsetsVec[i]
		}
		backtraceData = append(backtraceData, fmt.Sprintf("\"%X\" +0x%d",
			new(big.Int).SetBytes(uuidVal[:]), off))
	}

	paddingSize := paddingSizeFour(uint64(offsetCount))
	paddingSizeInt, ok := u64ToUint(paddingSize)
	if !ok {
		logger.Printf("[macos-unifiedlogs] u64 is bigger than system usize")
		return nil, nil, fmt.Errorf("padding size %d too large: %w", paddingSize, ErrTooLarge)
	}
	if err := c.skip(paddingSizeInt); err != nil {
		return nil, nil, err
	}

	return c.rest(), backtraceData, nil
}

// getFirehoseItems gets the strings, precision, and private (sensitive) firehose
// message items. Mirrors get_firehose_items.
func getFirehoseItems(data []byte) ([]byte, FirehoseItemType, error) {
	c := newCursor(data)
	itemType, err := c.u8()
	if err != nil {
		return nil, FirehoseItemType{}, err
	}
	itemTypeSize, err := c.u8()
	if err != nil {
		return nil, FirehoseItemType{}, err
	}

	item := FirehoseItemType{
		ItemType:     itemType,
		ItemTypeSize: itemTypeSize,
	}

	// Firehose string item values.
	stringItem := []uint8{0x20, 0x21, 0x22, 0x25, 0x40, 0x41, 0x42, 0x30, 0x31, 0x32, 0xf2, 0x35, 0x81, 0xf1}

	// String and private number items metadata is 4 bytes. The first two (2)
	// bytes point to the offset of the string data and the last two (2) bytes
	// is the size of the string.
	if slices.Contains(stringItem, item.ItemType) || item.ItemType == firehosePrivateNumber {
		messageOffset, err := c.u16()
		if err != nil {
			return nil, FirehoseItemType{}, err
		}
		messageSize, err := c.u16()
		if err != nil {
			return nil, FirehoseItemType{}, err
		}

		item.Offset = messageOffset
		item.ItemSize = messageSize
		item.Item = FirehoseItemString
	}

	if item.ItemType == firehosePrivateNumber {
		item.Item = FirehoseItemPrivateNumber
	}

	// Precision items just contain the length for the actual item. Ex: %*s.
	precisionItems := []uint8{0x10, 0x12}
	if slices.Contains(precisionItems, item.ItemType) {
		if err := c.skip(int(item.ItemTypeSize)); err != nil {
			return nil, FirehoseItemType{}, err
		}
		item.Item = FirehoseItemPrecision
	}

	sensitiveItems := []uint8{0x5, 0x45, 0x85}
	if slices.Contains(sensitiveItems, item.ItemType) {
		messageOffset, err := c.u16()
		if err != nil {
			return nil, FirehoseItemType{}, err
		}
		messageSize, err := c.u16()
		if err != nil {
			return nil, FirehoseItemType{}, err
		}

		item.Offset = messageOffset
		item.ItemSize = messageSize
		item.Item = FirehoseItemSensitive
	}

	return c.rest(), item, nil
}

// parseFirehoseItemString parses the item string. Mirrors parse_item_string.
func parseFirehoseItemString(data []byte, item *FirehoseItemType) ([]byte, string, error) {
	// If message item size is greater than the remaining data, just use the rest of the data.
	if int(item.ItemSize) > len(data) {
		return extractStringSize(data, uint64(len(data)))
	}

	input, messageData, err := nomTake(data, uint64(item.ItemSize))
	if err != nil {
		return nil, "", err
	}

	// 0x30, 0x31, and 0x32 represent arbitrary data, need to be decoded again.
	arbitrary := []uint8{0x30, 0x31, 0x32}
	if slices.Contains(arbitrary, item.ItemType) {
		item.Item = FirehoseItemObject
		return input, encodeStandard(messageData), nil
	}

	const base64RawBytes uint8 = 0xf2
	if item.ItemType == base64RawBytes {
		return input, encodeStandard(messageData), nil
	}

	_, messageString, err := extractStringSize(messageData, uint64(item.ItemSize))
	if err != nil {
		return nil, "", err
	}
	return input, messageString, nil
}

// parseFirehoseItemNumber parses the Firehose item number. Mirrors parse_item_number.
func parseFirehoseItemNumber(data []byte, itemSize uint16) ([]byte, int64, error) {
	input := data
	switch itemSize {
	case 4:
		c := newCursor(input)
		v, err := c.i32()
		if err != nil {
			return nil, 0, err
		}
		return c.rest(), int64(v), nil
	case 2:
		c := newCursor(input)
		v, err := c.i16()
		if err != nil {
			return nil, 0, err
		}
		return c.rest(), int64(v), nil
	case 8:
		c := newCursor(input)
		v, err := c.i64()
		if err != nil {
			return nil, 0, err
		}
		return c.rest(), v, nil
	case 1:
		c := newCursor(input)
		v, err := c.i8()
		if err != nil {
			return nil, 0, err
		}
		return c.rest(), int64(v), nil
	default:
		logger.Printf("[macos-unifiedlogs] Unknown number size support: %d", itemSize)
		return input, -9999, nil
	}
}
