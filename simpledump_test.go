// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

import "testing"

func TestParseSimpledump(t *testing.T) {
	testData := []byte{
		4, 96, 0, 0, 0, 0, 0, 0, 219, 0, 0, 0,
		0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0,
		1, 0, 0, 0, 0, 0, 0, 0, 45, 182, 196, 71,
		133, 4, 0, 0, 3, 234, 0, 0, 0, 0, 0, 0,
		118, 118, 1, 0, 0, 0, 0, 0, 13, 207, 62, 139,
		73, 35, 50, 62, 179, 229, 84, 115, 7, 207, 14, 172,
		61, 5, 132, 95, 63, 101, 53, 143, 158, 191, 34, 54,
		231, 114, 172, 1, 1, 0, 0, 0, 79, 0, 0, 0,
		56, 0, 0, 0, 117, 115, 101, 114, 47, 53, 48, 49,
		47, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 109,
		100, 119, 111, 114, 107, 101, 114, 46, 115, 104, 97, 114,
		101, 100, 46, 48, 66, 48, 48, 48, 48, 48, 48, 45,
		48, 48, 48, 48, 45, 48, 48, 48, 48, 45, 48, 48,
		48, 48, 45, 48, 48, 48, 48, 48, 48, 48, 48, 48,
		48, 48, 48, 32, 91, 52, 50, 50, 57, 93, 0, 115,
		101, 114, 118, 105, 99, 101, 32, 101, 120, 105, 116, 101,
		100, 58, 32, 100, 105, 114, 116, 121, 32, 61, 32, 48,
		44, 32, 115, 117, 112, 112, 111, 114, 116, 101, 100, 32,
		112, 114, 101, 115, 115, 117, 114, 101, 100, 45, 101, 120,
		105, 116, 32, 61, 32, 49, 0, 0, 0, 0, 0, 0,
	}

	_, results, err := parseSimpledump(testData)
	if err != nil {
		t.Fatalf("parseSimpledump returned error: %v", err)
	}

	if results.ChunkTag != 24580 {
		t.Errorf("chunk_tag = %d, want 24580", results.ChunkTag)
	}
	if results.ChunkSubtag != 0 {
		t.Errorf("chunk_subtag = %d, want 0", results.ChunkSubtag)
	}
	if results.ChunkDataSize != 219 {
		t.Errorf("chunk_data_size = %d, want 219", results.ChunkDataSize)
	}
	if results.FirstProcID != 1 {
		t.Errorf("first_proc_id = %d, want 1", results.FirstProcID)
	}
	if results.SecondProcID != 1 {
		t.Errorf("second_proc_id = %d, want 1", results.SecondProcID)
	}
	if results.ContinousTime != 4970481235501 {
		t.Errorf("continous_time = %d, want 4970481235501", results.ContinousTime)
	}
	if results.ThreadID != 59907 {
		t.Errorf("thread_id = %d, want 59907", results.ThreadID)
	}
	if results.UnknownOffset != 95862 {
		t.Errorf("unknown_offset = %d, want 95862", results.UnknownOffset)
	}
	if results.UnknownTTL != 0 {
		t.Errorf("unknown_ttl = %d, want 0", results.UnknownTTL)
	}
	if results.UnknownType != 0 {
		t.Errorf("unknown_type = %d, want 0", results.UnknownType)
	}
	if results.SenderUUID != "0DCF3E8B4923323EB3E5547307CF0EAC" {
		t.Errorf("sender_uuid = %q, want %q", results.SenderUUID, "0DCF3E8B4923323EB3E5547307CF0EAC")
	}
	if results.DscUUID != "3D05845F3F65358F9EBF2236E772AC01" {
		t.Errorf("dsc_uuid = %q, want %q", results.DscUUID, "3D05845F3F65358F9EBF2236E772AC01")
	}
	if results.UnknownNumberMessageStrings != 1 {
		t.Errorf("unknown_number_message_strings = %d, want 1", results.UnknownNumberMessageStrings)
	}
	if results.UnknownSizeSubsystemString != 79 {
		t.Errorf("unknown_size_subsystem_string = %d, want 79", results.UnknownSizeSubsystemString)
	}
	if results.UnknownSizeMessageString != 56 {
		t.Errorf("unknown_size_message_string = %d, want 56", results.UnknownSizeMessageString)
	}
	if results.Subsystem != "user/501/com.apple.mdworker.shared.0B000000-0000-0000-0000-000000000000 [4229]" {
		t.Errorf("subsystem = %q, want %q", results.Subsystem, "user/501/com.apple.mdworker.shared.0B000000-0000-0000-0000-000000000000 [4229]")
	}
	if results.MessageString != "service exited: dirty = 0, supported pressured-exit = 1" {
		t.Errorf("message_string = %q, want %q", results.MessageString, "service exited: dirty = 0, supported pressured-exit = 1")
	}
}
