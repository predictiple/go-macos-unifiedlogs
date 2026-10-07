// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

import "testing"

func TestParseActivity(t *testing.T) {
	testData := []byte{
		178, 251, 0, 0, 0, 0, 0, 128, 236, 0, 0, 0, 0, 0, 0, 0, 178, 251, 0, 0, 0, 0, 0, 128,
		179, 251, 0, 0, 0, 0, 0, 128, 64, 63, 24, 18, 1, 0, 2, 0,
	}
	var testFlags uint16 = 573
	var logType uint8 = 0x1

	_, results, err := parseActivity(testData, testFlags, logType)
	if err != nil {
		t.Fatalf("parseActivity returned error: %v", err)
	}

	if results.ActivityID != 64434 {
		t.Errorf("activity_id = %d, want %d", results.ActivityID, 64434)
	}
	if results.Sentinal != 2147483648 {
		t.Errorf("sentinal = %d, want %d", results.Sentinal, 2147483648)
	}
	if results.PID != 236 {
		t.Errorf("pid = %d, want %d", results.PID, 236)
	}
	if results.ActivityID2 != 64434 {
		t.Errorf("activity_id_2 = %d, want %d", results.ActivityID2, 64434)
	}
	if results.Sentinal2 != 2147483648 {
		t.Errorf("sentinal_2 = %d, want %d", results.Sentinal2, 2147483648)
	}
	if results.ActivityID3 != 64435 {
		t.Errorf("activity_id_3 = %d, want %d", results.ActivityID3, 64435)
	}
	if results.Sentinal3 != 2147483648 {
		t.Errorf("sentinal_3 = %d, want %d", results.Sentinal3, 2147483648)
	}
	if results.MessageStringRef != 0 {
		t.Errorf("message_string_ref = %d, want 0", results.MessageStringRef)
	}
	if results.FirehoseFormatters.MainExe {
		t.Error("main_exe = true, want false")
	}
	if results.FirehoseFormatters.Absolute {
		t.Error("absolute = true, want false")
	}
	if results.FirehoseFormatters.SharedCache {
		t.Error("shared_cache = true, want false")
	}
	if results.FirehoseFormatters.MainPlugin {
		t.Error("main_plugin = true, want false")
	}
	if results.FirehoseFormatters.PcStyle {
		t.Error("pc_style = true, want false")
	}
	if results.FirehoseFormatters.MainExeAltIndex != 0 {
		t.Errorf("main_exe_alt_index = %d, want 0", results.FirehoseFormatters.MainExeAltIndex)
	}
	if results.FirehoseFormatters.UuidRelative != "" {
		t.Errorf("uuid_relative = %q, want empty", results.FirehoseFormatters.UuidRelative)
	}
	if results.PCID != 303578944 {
		t.Errorf("pc_id = %d, want %d", results.PCID, 303578944)
	}
	if results.FirehoseFormatters.HasLargeOffset != 1 {
		t.Errorf("has_large_offset = %d, want 1", results.FirehoseFormatters.HasLargeOffset)
	}
	if results.FirehoseFormatters.LargeSharedCache != 2 {
		t.Errorf("large_shared_cache = %d, want 2", results.FirehoseFormatters.LargeSharedCache)
	}
}
