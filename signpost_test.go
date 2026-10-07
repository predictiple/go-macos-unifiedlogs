// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

import (
	"reflect"
	"testing"
)

func TestParseFirehoseSignpost(t *testing.T) {
	testData := []byte{
		225, 244, 2, 0, 1, 0, 238, 238, 178, 178, 181, 176, 238, 238, 176, 63, 27, 0, 0, 0,
	}
	testFlags := uint16(33282)

	_, results, err := parseSignpost(testData, testFlags)
	if err != nil {
		t.Fatalf("parseSignpost returned error: %v", err)
	}

	if results.PCID != 193761 {
		t.Errorf("pc_id = %d, want %d", results.PCID, 193761)
	}
	if results.ActivityID != 0 {
		t.Errorf("activity_id = %d, want 0", results.ActivityID)
	}
	if results.Sentinel != 0 {
		t.Errorf("sentinel = %d, want 0", results.Sentinel)
	}
	if results.Subsystem != 1 {
		t.Errorf("subsystem = %d, want 1", results.Subsystem)
	}
	if results.SignpostID != 17216892719917625070 {
		t.Errorf("signpost_id = %d, want %d", results.SignpostID, uint64(17216892719917625070))
	}
	if results.SignpostName != 1785776 {
		t.Errorf("signpost_name = %d, want %d", results.SignpostName, 1785776)
	}
	if results.TTLValue != 0 {
		t.Errorf("ttl_value = %d, want 0", results.TTLValue)
	}
	if results.DataRefValue != 0 {
		t.Errorf("data_ref_value = %d, want 0", results.DataRefValue)
	}

	if !results.FirehoseFormatters.MainExe {
		t.Error("firehose_formatters.main_exe = false, want true")
	}
	if results.FirehoseFormatters.SharedCache {
		t.Error("firehose_formatters.shared_cache = true, want false")
	}
	if results.FirehoseFormatters.HasLargeOffset != 0 {
		t.Errorf("firehose_formatters.has_large_offset = %d, want 0", results.FirehoseFormatters.HasLargeOffset)
	}
	if results.FirehoseFormatters.LargeSharedCache != 0 {
		t.Errorf("firehose_formatters.large_shared_cache = %d, want 0", results.FirehoseFormatters.LargeSharedCache)
	}
	if results.FirehoseFormatters.Absolute {
		t.Error("firehose_formatters.absolute = true, want false")
	}
	if results.FirehoseFormatters.UuidRelative != "" {
		t.Errorf("firehose_formatters.uuid_relative = %q, want empty", results.FirehoseFormatters.UuidRelative)
	}
	if results.FirehoseFormatters.MainPlugin {
		t.Error("firehose_formatters.main_plugin = true, want false")
	}
	if results.FirehoseFormatters.PcStyle {
		t.Error("firehose_formatters.pc_style = true, want false")
	}
	if results.FirehoseFormatters.MainExeAltIndex != 0 {
		t.Errorf("firehose_formatters.main_exe_alt_index = %d, want 0", results.FirehoseFormatters.MainExeAltIndex)
	}

	expectedFlags := []MessageFlags{MessageFlagsMainExe, MessageFlagsHasSubsystem}
	if !reflect.DeepEqual(results.Flags, expectedFlags) {
		t.Errorf("flags = %v, want %v", results.Flags, expectedFlags)
	}
}

func TestSignpostPersonaFlag(t *testing.T) {
	testData := []byte{
		232, 3, 0, 0, 248, 253, 216, 218, 1, 0, 1, 0, 1, 53, 45, 172, 71, 70, 1, 18, 99, 57,
		219, 90, 1, 0, 0, 3, 0, 4, 1, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 4, 10, 0, 0, 0,
	}
	testFlags := uint16(33380)

	_, results, err := parseSignpost(testData, testFlags)
	if err != nil {
		t.Fatalf("parseSignpost returned error: %v", err)
	}

	expectedFlags := []MessageFlags{
		MessageFlagsHasPersona,
		MessageFlagsSharedCache,
		MessageFlagsHasLargeOffset,
		MessageFlagsHasSubsystem,
	}
	if !reflect.DeepEqual(results.Flags, expectedFlags) {
		t.Errorf("flags = %v, want %v", results.Flags, expectedFlags)
	}
}
