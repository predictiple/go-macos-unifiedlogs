// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

import "testing"

func TestParseHeader(t *testing.T) {
	testChunkHeader := []byte{
		0, 16, 0, 0, 17, 0, 0, 0, 208, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 15, 105,
		217, 162, 204, 126, 0, 0, 48, 215, 18, 98, 0, 0, 0, 0, 203, 138, 9, 0, 44, 1, 0, 0, 0,
		0, 0, 0, 1, 0, 0, 0, 0, 97, 0, 0, 8, 0, 0, 0, 6, 112, 124, 198, 169, 153, 1, 0, 1, 97,
		0, 0, 56, 0, 0, 0, 7, 0, 0, 0, 8, 0, 0, 0, 50, 49, 65, 53, 53, 57, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 77, 97, 99, 66, 111, 111, 107, 80, 114, 111, 49, 54, 44, 49, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 97, 0, 0, 24, 0, 0, 0, 195, 32, 184, 206, 151,
		250, 77, 165, 159, 49, 125, 57, 46, 56, 156, 234, 85, 0, 0, 0, 0, 0, 0, 0, 3, 97, 0, 0,
		48, 0, 0, 0, 47, 118, 97, 114, 47, 100, 98, 47, 116, 105, 109, 101, 122, 111, 110, 101,
		47, 122, 111, 110, 101, 105, 110, 102, 111, 47, 65, 109, 101, 114, 105, 99, 97, 47, 78,
		101, 119, 95, 89, 111, 114, 107, 0, 0, 0, 0, 0, 0,
	}

	headerData, err := parseHeader(newCursor(testChunkHeader))
	if err != nil {
		t.Fatalf("parseHeader returned error: %v", err)
	}

	tests := []struct {
		name string
		got  any
		want any
	}{
		{"chunk_tag", headerData.ChunkTag, uint32(0x1000)},
		{"chunk_sub_tag", headerData.ChunkSubTag, uint32(0x11)},
		{"mach_time_numerator", headerData.MachTimeNumerator, uint32(1)},
		{"mach_time_denominator", headerData.MachTimeDenominator, uint32(1)},
		{"continous_time", headerData.ContinousTime, uint64(139417370585359)},
		{"unknown_time", headerData.UnknownTime, uint64(1645401904)},
		{"unknown", headerData.Unknown, uint32(625355)},
		{"bias_min", headerData.BiasMin, uint32(300)},
		{"daylight_savings", headerData.DaylightSavings, uint32(0)},
		{"unknown_flags", headerData.UnknownFlags, uint32(1)},
		{"sub_chunk_tag", headerData.SubChunkTag, uint32(24832)},
		{"sub_chunk_data_size", headerData.SubChunkDataSize, uint32(8)},
		{"sub_chunk_continous_time", headerData.SubChunkContinousTime, uint64(450429435277318)},
		{"sub_chunk_tag_2", headerData.SubChunkTag2, uint32(24833)},
		{"sub_chunk_tag_data_size_2", headerData.SubChunkTagDataSize2, uint32(56)},
		{"unknown_2", headerData.Unknown2, uint32(7)},
		{"unknown_3", headerData.Unknown3, uint32(8)},
		{"build_version_string", headerData.BuildVersionString, "21A559"},
		{"hardware_model_string", headerData.HardwareModelString, "MacBookPro16,1"},
		{"sub_chunk_tag_3", headerData.SubChunkTag3, uint32(24834)},
		{"sub_chunk_tag_data_size_3", headerData.SubChunkTagDataSize3, uint32(24)},
		{"boot_uuid", headerData.BootUUID, "C320B8CE97FA4DA59F317D392E389CEA"},
		{"logd_pid", headerData.LogdPid, uint32(85)},
		{"logd_exit_status", headerData.LogdExitStatus, uint32(0)},
		{"sub_chunk_tag_4", headerData.SubChunkTag4, uint32(24835)},
		{"sub_chunk_tag_data_size_4", headerData.SubChunkTagDataSize4, uint32(48)},
		{"timezone_path", headerData.TimezonePath, "/var/db/timezone/zoneinfo/America/New_York"},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("%s = %v, want %v", tt.name, tt.got, tt.want)
		}
	}
}
