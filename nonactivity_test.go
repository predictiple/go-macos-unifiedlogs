// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

import (
	"slices"
	"testing"
)

func TestParseNonActivity(t *testing.T) {
	testData := []byte{
		122, 179, 12, 13, 2, 0, 4, 0, 41, 0, 34, 9, 32, 4, 0, 0, 1, 0, 32, 4, 1, 0, 1, 0, 32,
		4, 2, 0, 14, 0, 0, 8, 2, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 2, 0,
		0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 4, 1, 0, 0, 0, 0, 4, 1, 0, 0, 0, 0, 0, 100, 105,
		115, 112, 97, 116, 99, 104, 69, 118, 101, 110, 116, 0,
	}
	testFlags := uint16(556)

	_, results, err := parseNonActivity(testData, testFlags)
	if err != nil {
		t.Fatalf("parseNonActivity returned error: %v", err)
	}
	if results.ActivityID != 0 {
		t.Errorf("activity_id = %d, want %d", results.ActivityID, 0)
	}
	if results.Sentinel != 0 {
		t.Errorf("sentinel = %d, want %d", results.Sentinel, 0)
	}
	if results.PrivateStringsOffset != 0 {
		t.Errorf("private_strings_offset = %d, want %d", results.PrivateStringsOffset, 0)
	}
	if results.PrivateStringsSize != 0 {
		t.Errorf("private_strings_size = %d, want %d", results.PrivateStringsSize, 0)
	}
	if results.MessageStringRef != 0 {
		t.Errorf("message_string_ref = %d, want %d", results.MessageStringRef, 0)
	}
	if results.FirehoseFormatters.MainExeAltIndex != 0 {
		t.Errorf("main_exe_alt_index = %d, want %d", results.FirehoseFormatters.MainExeAltIndex, 0)
	}
	if results.FirehoseFormatters.UuidRelative != "" {
		t.Errorf("uuid_relative = %q, want %q", results.FirehoseFormatters.UuidRelative, "")
	}
	if results.FirehoseFormatters.MainExe {
		t.Error("main_exe = true, want false")
	}
	if results.FirehoseFormatters.Absolute {
		t.Error("absolute = true, want false")
	}
	if results.SubsystemValue != 41 {
		t.Errorf("subsystem_value = %d, want %d", results.SubsystemValue, 41)
	}
	if results.TTLValue != 0 {
		t.Errorf("ttl_value = %d, want %d", results.TTLValue, 0)
	}
	if results.DataRefValue != 0 {
		t.Errorf("data_ref_value = %d, want %d", results.DataRefValue, 0)
	}
	if results.FirehoseFormatters.LargeSharedCache != 4 {
		t.Errorf("large_shared_cache = %d, want %d", results.FirehoseFormatters.LargeSharedCache, 4)
	}
	if results.FirehoseFormatters.HasLargeOffset != 2 {
		t.Errorf("has_large_offset = %d, want %d", results.FirehoseFormatters.HasLargeOffset, 2)
	}
	if results.PCID != 218936186 {
		t.Errorf("pc_id = %d, want %d", results.PCID, 218936186)
	}
}

func TestPersonaFlag(t *testing.T) {
	testData := []byte{
		200, 0, 0, 0, 72, 5, 91, 0, 6, 0, 34, 6, 0, 8, 16, 148, 64, 1, 1, 0, 0, 0, 34, 4, 0, 0,
		11, 0, 0, 4, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 4, 1, 0, 0, 0, 34, 4, 11, 0, 54, 0, 97,
		99, 116, 105, 118, 97, 116, 105, 110, 103, 0, 99, 111, 109, 46, 97, 112, 112, 108, 101,
		46, 99, 102, 112, 114, 101, 102, 115, 100, 46, 100, 97, 101, 109, 111, 110, 46, 115,
		121, 115, 116, 101, 109, 46, 112, 101, 101, 114, 91, 54, 53, 93, 46, 48, 120, 49, 48,
		49, 52, 48, 57, 52, 49, 48, 0,
	}
	testFlags := uint16(580)

	_, results, err := parseNonActivity(testData, testFlags)
	if err != nil {
		t.Fatalf("parseNonActivity returned error: %v", err)
	}
	wantFlags := []MessageFlags{MessageFlagsHasPersona, MessageFlagsSharedCache, MessageFlagsHasSubsystem}
	if !slices.Equal(results.Flags, wantFlags) {
		t.Errorf("flags = %v, want %v", results.Flags, wantFlags)
	}
	if results.PersonaID != 200 {
		t.Errorf("persona_id = %d, want %d", results.PersonaID, 200)
	}
	if results.SubsystemValue != 6 {
		t.Errorf("subsystem_value = %d, want %d", results.SubsystemValue, 6)
	}
	if !results.FirehoseFormatters.SharedCache {
		t.Error("shared_cache = false, want true")
	}
	if results.PCID != 5965128 {
		t.Errorf("pc_id = %d, want %d", results.PCID, 5965128)
	}
}
