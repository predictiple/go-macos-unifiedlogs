// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

import (
	"unicode/utf8"
)

// HeaderChunk is the Unified Log tracev3 header data.
type HeaderChunk struct {
	ChunkTag              uint32 `json:"chunk_tag"`
	ChunkSubTag           uint32 `json:"chunk_sub_tag"`
	ChunkDataSize         uint64 `json:"chunk_data_size"`
	MachTimeNumerator     uint32 `json:"mach_time_numerator"`
	MachTimeDenominator   uint32 `json:"mach_time_denominator"`
	ContinousTime         uint64 `json:"continous_time"`
	UnknownTime           uint64 `json:"unknown_time"` // possibly start time
	Unknown               uint32 `json:"unknown"`
	BiasMin               uint32 `json:"bias_min"`
	DaylightSavings       uint32 `json:"daylight_savings"` // 0 no DST, 1 DST
	UnknownFlags          uint32 `json:"unknown_flags"`
	SubChunkTag           uint32 `json:"sub_chunk_tag"` // 0x6100
	SubChunkDataSize      uint32 `json:"sub_chunk_data_size"`
	SubChunkContinousTime uint64 `json:"sub_chunk_continous_time"`
	SubChunkTag2          uint32 `json:"sub_chunk_tag_2"` // 0x6101
	SubChunkTagDataSize2  uint32 `json:"sub_chunk_tag_data_size_2"`
	Unknown2              uint32 `json:"unknown_2"`
	Unknown3              uint32 `json:"unknown_3"`
	BuildVersionString    string `json:"build_version_string"`
	HardwareModelString   string `json:"hardware_model_string"`
	SubChunkTag3          uint32 `json:"sub_chunk_tag_3"` // 0x6102
	SubChunkTagDataSize3  uint32 `json:"sub_chunk_tag_data_size_3"`
	BootUUID              string `json:"boot_uuid"`
	LogdPid               uint32 `json:"logd_pid"`
	LogdExitStatus        uint32 `json:"logd_exit_status"`
	SubChunkTag4          uint32 `json:"sub_chunk_tag_4"` // 0x6103
	SubChunkTagDataSize4  uint32 `json:"sub_chunk_tag_data_size_4"`
	TimezonePath          string `json:"timezone_path"`
}

// parseHeader parses the Unified Log tracev3 header data.
func parseHeader(c *cursor) (*HeaderChunk, error) {
	headerChunk := &HeaderChunk{}

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
	machTimeNumerator, err := c.u32()
	if err != nil {
		return nil, err
	}
	machTimeDenominator, err := c.u32()
	if err != nil {
		return nil, err
	}
	continousTime, err := c.u64()
	if err != nil {
		return nil, err
	}
	unknownTime, err := c.u64()
	if err != nil {
		return nil, err
	}
	unknown, err := c.u32()
	if err != nil {
		return nil, err
	}
	biasMin, err := c.u32()
	if err != nil {
		return nil, err
	}
	daylightSavings, err := c.u32()
	if err != nil {
		return nil, err
	}
	unknownFlags, err := c.u32()
	if err != nil {
		return nil, err
	}
	subChunkTag, err := c.u32()
	if err != nil {
		return nil, err
	}
	subChunkDataSize, err := c.u32()
	if err != nil {
		return nil, err
	}
	subChunkContinousTime, err := c.u64()
	if err != nil {
		return nil, err
	}
	subChunkTag2, err := c.u32()
	if err != nil {
		return nil, err
	}
	subChunkTagDataSize2, err := c.u32()
	if err != nil {
		return nil, err
	}
	unknown2, err := c.u32()
	if err != nil {
		return nil, err
	}
	unknown3, err := c.u32()
	if err != nil {
		return nil, err
	}

	buildVersionBytes, err := c.take(16) // size_of::<u128>()
	if err != nil {
		return nil, err
	}
	const hardwareModelSize = 32
	hardwareModelBytes, err := c.take(hardwareModelSize)
	if err != nil {
		return nil, err
	}
	subChunkTag3, err := c.u32()
	if err != nil {
		return nil, err
	}
	subChunkTagDataSize3, err := c.u32()
	if err != nil {
		return nil, err
	}
	bootUUIDBE, err := c.u128be()
	if err != nil {
		return nil, err
	}
	logdPid, err := c.u32()
	if err != nil {
		return nil, err
	}
	logdExitStatus, err := c.u32()
	if err != nil {
		return nil, err
	}
	subChunkTag4, err := c.u32()
	if err != nil {
		return nil, err
	}
	subChunkTagDataSize4, err := c.u32()
	if err != nil {
		return nil, err
	}

	const timezonePathSize = 48
	timezonePath, err := c.take(timezonePathSize)
	if err != nil {
		return nil, err
	}

	headerChunk.ChunkTag = chunkTag
	headerChunk.ChunkSubTag = chunkSubTag
	headerChunk.ChunkDataSize = chunkDataSize
	headerChunk.MachTimeNumerator = machTimeNumerator
	headerChunk.MachTimeDenominator = machTimeDenominator
	headerChunk.ContinousTime = continousTime
	headerChunk.UnknownTime = unknownTime
	headerChunk.Unknown = unknown
	headerChunk.BiasMin = biasMin
	headerChunk.DaylightSavings = daylightSavings
	headerChunk.UnknownFlags = unknownFlags
	headerChunk.SubChunkTag = subChunkTag
	headerChunk.SubChunkDataSize = subChunkDataSize
	headerChunk.SubChunkContinousTime = subChunkContinousTime
	headerChunk.SubChunkTag2 = subChunkTag2
	headerChunk.SubChunkTagDataSize2 = subChunkTagDataSize2
	headerChunk.Unknown2 = unknown2
	headerChunk.Unknown3 = unknown3
	headerChunk.SubChunkTag3 = subChunkTag3
	headerChunk.SubChunkTagDataSize3 = subChunkTagDataSize3
	headerChunk.LogdPid = logdPid
	headerChunk.LogdExitStatus = logdExitStatus
	headerChunk.SubChunkTag4 = subChunkTag4
	headerChunk.SubChunkTagDataSize4 = subChunkTagDataSize4
	headerChunk.BootUUID = u128Hex(bootUUIDBE)

	if utf8.Valid(timezonePath) {
		headerChunk.TimezonePath = trimTrailingNulls(string(timezonePath))
	} else {
		logger.Printf("[macos-unifiedlogs] Failed to get timezone path from header: invalid UTF-8")
	}

	if utf8.Valid(buildVersionBytes) {
		headerChunk.BuildVersionString = trimTrailingNulls(string(buildVersionBytes))
	} else {
		logger.Printf("[macos-unifiedlogs] Failed to get build version from header: invalid UTF-8")
	}

	if utf8.Valid(hardwareModelBytes) {
		headerChunk.HardwareModelString = trimTrailingNulls(string(hardwareModelBytes))
	} else {
		logger.Printf("[macos-unifiedlogs] Failed to get hardware info from header: invalid UTF-8")
	}

	return headerChunk, nil
}

// trimTrailingNulls trims all trailing NUL characters (Rust's trim_end_matches('\0')).
func trimTrailingNulls(s string) string {
	for len(s) > 0 && s[len(s)-1] == 0 {
		s = s[:len(s)-1]
	}
	return s
}
