// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

import (
	"encoding/json"
	"fmt"
	"math/big"

	"howett.net/plist"
)

// Statedump is a Statedump log entry. Statedumps are special log entries that
// may contain a plist file, custom object, or protocol buffer.
type Statedump struct {
	ChunkTag        uint32 `json:"chunk_tag"`
	ChunkSubtag     uint32 `json:"chunk_subtag"`
	ChunkDataSize   uint64 `json:"chunk_data_size"`
	FirstProcID     uint64 `json:"first_proc_id"`
	SecondProcID    uint32 `json:"second_proc_id"`
	TTL             uint8  `json:"ttl"`
	UnknownReserved []byte `json:"unknown_reserved"` // 3 bytes
	ContinuousTime  uint64 `json:"continuous_time"`
	ActivityID      uint64 `json:"activity_id"`
	UUID            string `json:"uuid"`
	UnknownDataType uint32 `json:"unknown_data_type"` // 1 = plist, 3 = custom object?, 2 = (protocol buffer?)
	UnknownDataSize uint32 `json:"unknown_data_size"` // Size of statedump data
	DecoderLibrary  string `json:"decoder_library"`
	DecoderType     string `json:"decoder_type"`
	TitleName       string `json:"title_name"`
	StatedumpData   []byte `json:"statedump_data"`
}

// ParseStatedump parses a Statedump log entry. Statedumps are special log
// entries that may contain a plist file, custom object, or protocol buffer.
func ParseStatedump(data []byte) ([]byte, Statedump, error) {
	var statedumpResults Statedump

	c := newCursor(data)
	statedumpChunkTag, err := c.u32()
	if err != nil {
		return nil, statedumpResults, err
	}
	statedumpChunkSubTag, err := c.u32()
	if err != nil {
		return nil, statedumpResults, err
	}
	statedumpChunkDataSize, err := c.u64()
	if err != nil {
		return nil, statedumpResults, err
	}
	statedumpFirstProcID, err := c.u64()
	if err != nil {
		return nil, statedumpResults, err
	}
	statedumpSecondProcID, err := c.u32()
	if err != nil {
		return nil, statedumpResults, err
	}
	statedumpTTL, err := c.u8()
	if err != nil {
		return nil, statedumpResults, err
	}

	const reservedSize = 3
	reserved, err := c.take(reservedSize)
	if err != nil {
		return nil, statedumpResults, err
	}

	statedumpContinousTime, err := c.u64()
	if err != nil {
		return nil, statedumpResults, err
	}
	statedumpActivityID, err := c.u64()
	if err != nil {
		return nil, statedumpResults, err
	}
	uuid, err := c.u128be()
	if err != nil {
		return nil, statedumpResults, err
	}
	statedumpUnknownDataType, err := c.u32()
	if err != nil {
		return nil, statedumpResults, err
	}
	statedumpUnknownDataSize, err := c.u32()
	if err != nil {
		return nil, statedumpResults, err
	}

	const customDecoder = 3
	const stringSize = 64

	// Nom unknown data if data type is not custom
	if statedumpUnknownDataType != customDecoder {
		if _, err = c.take(stringSize); err != nil {
			return nil, statedumpResults, err
		}
		if _, err = c.take(stringSize); err != nil {
			return nil, statedumpResults, err
		}
	}

	if statedumpUnknownDataType == customDecoder {
		libraryData, err := c.take(stringSize)
		if err != nil {
			return nil, statedumpResults, err
		}
		typeData, err := c.take(stringSize)
		if err != nil {
			return nil, statedumpResults, err
		}
		_, decoderLibrary, err := extractString(libraryData)
		if err != nil {
			return nil, statedumpResults, err
		}
		_, decoderType, err := extractString(typeData)
		if err != nil {
			return nil, statedumpResults, err
		}

		statedumpResults.DecoderLibrary = decoderLibrary
		statedumpResults.DecoderType = decoderType
	}

	titleData, err := c.take(stringSize)
	if err != nil {
		return nil, statedumpResults, err
	}
	_, titleName, err := extractString(titleData)
	if err != nil {
		return nil, statedumpResults, err
	}

	statedumpResults.TitleName = titleName
	statedumpResults.ChunkTag = statedumpChunkTag
	statedumpResults.ChunkSubtag = statedumpChunkSubTag
	statedumpResults.ChunkDataSize = statedumpChunkDataSize
	statedumpResults.FirstProcID = statedumpFirstProcID
	statedumpResults.SecondProcID = statedumpSecondProcID
	statedumpResults.TTL = statedumpTTL
	statedumpResults.UnknownReserved = reserved
	statedumpResults.ContinuousTime = statedumpContinousTime
	statedumpResults.ActivityID = statedumpActivityID
	statedumpResults.UnknownDataType = statedumpUnknownDataType
	statedumpResults.UnknownDataSize = statedumpUnknownDataSize

	statedumpResults.UUID = fmt.Sprintf("%032X", new(big.Int).SetBytes(uuid[:]))

	statedumpData, err := c.take(int(statedumpUnknownDataSize))
	if err != nil {
		return nil, statedumpResults, err
	}
	statedumpResults.StatedumpData = statedumpData

	return c.rest(), statedumpResults, nil
}

// ParseStatedumpPlist parses the binary plist file in the log. The plist may be empty.
func ParseStatedumpPlist(plistData []byte) string {
	if len(plistData) == 0 {
		logger.Printf("[macos-unifiedlogs] Empty plist data in statedump")
		return "Empty plist data"
	}
	var results interface{}
	if _, err := plist.Unmarshal(plistData, &results); err != nil {
		logger.Printf("[macos-unifiedlogs] Failed to parse statedump plist data: %v", err)
		return "Failed to get plist data"
	}
	jsonData, err := json.Marshal(results)
	if err != nil {
		logger.Printf("[macos-unifiedlogs] Failed to convert plist to json: %v", err)
		return "Failed to convert plist data to json"
	}
	return string(jsonData)
}

// parseStatedumpObject parses custom Apple objects.
func parseStatedumpObject(objectData []byte, name string) string {
	var result string
	var err error

	switch name {
	case "CLDaemonStatusStateTracker":
		_, result, err = getDaemonStatusTracker(objectData)
	case "CLClientManagerStateTracker":
		_, result, err = getStateTrackerData(objectData)
	case "CLLocationManagerStateTracker":
		_, result, err = getLocationTrackerState(objectData)
	case "DNS Configuration":
		_, result, err = getDNSConfig(objectData)
	case "Network information":
		_, result, err = getNetworkInterface(objectData)
	default:
		return fmt.Sprintf("Unsupported Statedump object: %s-%s", name, encodeStandard(objectData))
	}

	if err != nil {
		if decoderErr, ok := err.(*DecoderError); ok {
			logger.Printf("[macos-unifiedlogs] Failed to parse statedump object %s: %s", name, decoderErr.Debug())
		} else {
			logger.Printf("[macos-unifiedlogs] Failed to parse statedump object %s: %v", name, err)
		}
		return fmt.Sprintf("Failed to parse statedump object: %s", name)
	}
	return result
}
