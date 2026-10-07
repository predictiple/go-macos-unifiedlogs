// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

import "testing"

func TestParseDSCVersionOne(t *testing.T) {
	buffer := requireTestData(t, "DSC Tests/big_sur_version_1_522F6217CB113F8FB845C2A1B784C7C2")

	results, err := parseDSC(buffer)
	if err != nil {
		t.Fatalf("parseDSC returned error: %v", err)
	}
	if len(results.UUIDs) != 532 {
		t.Errorf("uuids length = %d, want 532", len(results.UUIDs))
	}
	if results.UUIDs[0].UUID != "4DF6D8F5D9C23A968DE45E99D6B73DC8" {
		t.Errorf("uuids[0].uuid = %q, want %q", results.UUIDs[0].UUID, "4DF6D8F5D9C23A968DE45E99D6B73DC8")
	}
	if results.UUIDs[0].PathOffset != 19919502 {
		t.Errorf("uuids[0].path_offset = %d, want 19919502", results.UUIDs[0].PathOffset)
	}
	if results.UUIDs[0].TextSize != 8192 {
		t.Errorf("uuids[0].text_size = %d, want 8192", results.UUIDs[0].TextSize)
	}
	if results.UUIDs[0].TextOffset != 73728 {
		t.Errorf("uuids[0].text_offset = %d, want 73728", results.UUIDs[0].TextOffset)
	}
	if results.UUIDs[0].PathString != "/usr/lib/system/libsystem_blocks.dylib" {
		t.Errorf("uuids[0].path_string = %q, want %q", results.UUIDs[0].PathString, "/usr/lib/system/libsystem_blocks.dylib")
	}

	if len(results.Ranges) != 788 {
		t.Errorf("ranges length = %d, want 788", len(results.Ranges))
	}
	if len(results.Ranges[0].Strings) != 1 || results.Ranges[0].Strings[0] != 0 {
		t.Errorf("ranges[0].strings = %v, want [0]", results.Ranges[0].Strings)
	}
	if results.Ranges[0].UUIDIndex != 0 {
		t.Errorf("ranges[0].uuid_index = %d, want 0", results.Ranges[0].UUIDIndex)
	}
	if results.Ranges[0].RangeOffset != 80296 {
		t.Errorf("ranges[0].range_offset = %d, want 80296", results.Ranges[0].RangeOffset)
	}
	if results.Ranges[0].RangeSize != 1 {
		t.Errorf("ranges[0].range_size = %d, want 1", results.Ranges[0].RangeSize)
	}

	if results.Signature != 1685283688 { // hcsd
		t.Errorf("signature = %d, want 1685283688", results.Signature)
	}
	if results.MajorVersion != 1 {
		t.Errorf("major_version = %d, want 1", results.MajorVersion)
	}
	if results.MinorVersion != 0 {
		t.Errorf("minor_version = %d, want 0", results.MinorVersion)
	}
	if results.DSCUUID != "" {
		t.Errorf("dsc_uuid = %q, want empty", results.DSCUUID)
	}
	if results.NumberRanges != 788 {
		t.Errorf("number_ranges = %d, want 788", results.NumberRanges)
	}
	if results.NumberUUIDs != 532 {
		t.Errorf("number_uuids = %d, want 532", results.NumberUUIDs)
	}
}

func TestParseDSCVersionTwo(t *testing.T) {
	buffer := requireTestData(t, "DSC Tests/monterey_version_2_3D05845F3F65358F9EBF2236E772AC01")

	results, err := parseDSC(buffer)
	if err != nil {
		t.Fatalf("parseDSC returned error: %v", err)
	}
	if len(results.UUIDs) != 2250 {
		t.Errorf("uuids length = %d, want 2250", len(results.UUIDs))
	}
	if results.UUIDs[0].UUID != "326DD91B4EF83D80B90BF50EB7D7FDB8" {
		t.Errorf("uuids[0].uuid = %q, want %q", results.UUIDs[0].UUID, "326DD91B4EF83D80B90BF50EB7D7FDB8")
	}
	if results.UUIDs[0].PathOffset != 98376932 {
		t.Errorf("uuids[0].path_offset = %d, want 98376932", results.UUIDs[0].PathOffset)
	}
	if results.UUIDs[0].TextSize != 8192 {
		t.Errorf("uuids[0].text_size = %d, want 8192", results.UUIDs[0].TextSize)
	}
	if results.UUIDs[0].TextOffset != 327680 {
		t.Errorf("uuids[0].text_offset = %d, want 327680", results.UUIDs[0].TextOffset)
	}
	if results.UUIDs[0].PathString != "/usr/lib/system/libsystem_blocks.dylib" {
		t.Errorf("uuids[0].path_string = %q, want %q", results.UUIDs[0].PathString, "/usr/lib/system/libsystem_blocks.dylib")
	}

	if len(results.Ranges) != 3432 {
		t.Errorf("ranges length = %d, want 3432", len(results.Ranges))
	}
	if len(results.Ranges[0].Strings) != 1 || results.Ranges[0].Strings[0] != 0 {
		t.Errorf("ranges[0].strings = %v, want [0]", results.Ranges[0].Strings)
	}
	if results.Ranges[0].UUIDIndex != 0 {
		t.Errorf("ranges[0].uuid_index = %d, want 0", results.Ranges[0].UUIDIndex)
	}
	if results.Ranges[0].RangeOffset != 334248 {
		t.Errorf("ranges[0].range_offset = %d, want 334248", results.Ranges[0].RangeOffset)
	}
	if results.Ranges[0].RangeSize != 1 {
		t.Errorf("ranges[0].range_size = %d, want 1", results.Ranges[0].RangeSize)
	}

	if results.Signature != 1685283688 { // hcsd
		t.Errorf("signature = %d, want 1685283688", results.Signature)
	}
	if results.MajorVersion != 2 {
		t.Errorf("major_version = %d, want 2", results.MajorVersion)
	}
	if results.MinorVersion != 0 {
		t.Errorf("minor_version = %d, want 0", results.MinorVersion)
	}
	if results.DSCUUID != "" {
		t.Errorf("dsc_uuid = %q, want empty", results.DSCUUID)
	}
	if results.NumberRanges != 3432 {
		t.Errorf("number_ranges = %d, want 3432", results.NumberRanges)
	}
	if results.NumberUUIDs != 2250 {
		t.Errorf("number_uuids = %d, want 2250", results.NumberUUIDs)
	}
}

func TestParseDSCBadHeader(t *testing.T) {
	buffer := requireTestData(t, "Bad Data/DSC/bad_header_version_1_522F6217CB113F8FB845C2A1B784C7C2")

	_, err := parseDSC(buffer)
	requireErrIncomplete(t, err)
}

func TestParseDSCBadContent(t *testing.T) {
	buffer := requireTestData(t, "Bad Data/DSC/bad_content_version_1_522F6217CB113F8FB845C2A1B784C7C2")

	_, err := parseDSC(buffer)
	if err == nil {
		t.Fatal("expected error for bad DSC content, got nil")
	}
}

func TestParseDSCBadFile(t *testing.T) {
	buffer := requireTestData(t, "Bad Data/DSC/Badfile")

	_, err := parseDSC(buffer)
	requireErrIncomplete(t, err)
}
