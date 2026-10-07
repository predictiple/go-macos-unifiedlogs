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

func TestParseFirehoseTrace(t *testing.T) {
	testData := []byte{106, 139, 3, 0, 0}
	_, results, err := parseFirehoseTrace(testData)
	if err != nil {
		t.Fatalf("parseFirehoseTrace returned error: %v", err)
	}
	if results.UnknownPCID != 232298 {
		t.Errorf("unknown_pc_id = %d, want %d", results.UnknownPCID, 232298)
	}

	testData = []byte{248, 145, 3, 0, 200, 0, 0, 0, 0, 0, 0, 0, 8, 1}
	_, results, err = parseFirehoseTrace(testData)
	if err != nil {
		t.Fatalf("parseFirehoseTrace returned error: %v", err)
	}
	if results.UnknownPCID != 233976 {
		t.Errorf("unknown_pc_id = %d, want %d", results.UnknownPCID, 233976)
	}
	if len(results.MessageData.ItemInfo) != 1 {
		t.Errorf("len(message_data.item_info) = %d, want %d", len(results.MessageData.ItemInfo), 1)
	}
}

func TestParseTraceMessage(t *testing.T) {
	testMessage := []byte{200, 0, 0, 0, 0, 0, 0, 0, 8, 1}
	slices.Reverse(testMessage)
	_, results, err := parseTraceMessage(testMessage)
	if err != nil {
		t.Fatalf("parseTraceMessage returned error: %v", err)
	}
	if len(results.ItemInfo) == 0 {
		t.Fatal("item_info is empty")
	}
	if results.ItemInfo[0].MessageStrings != "200" {
		t.Errorf("item_info[0].message_strings = %q, want %q", results.ItemInfo[0].MessageStrings, "200")
	}
}

func TestParseTraceMessageMultiple(t *testing.T) {
	testMessage := []byte{2, 8, 8, 0, 0, 0, 0, 0, 0, 0, 200, 0, 0, 127, 251, 75, 225, 96, 176}
	_, results, err := parseTraceMessage(testMessage)
	if err != nil {
		t.Fatalf("parseTraceMessage returned error: %v", err)
	}
	if len(results.ItemInfo) != 2 {
		t.Fatalf("len(item_info) = %d, want %d", len(results.ItemInfo), 2)
	}
	if results.ItemInfo[0].MessageStrings != "140717286580400" {
		t.Errorf("item_info[0].message_strings = %q, want %q", results.ItemInfo[0].MessageStrings, "140717286580400")
	}
	if results.ItemInfo[1].MessageStrings != "200" {
		t.Errorf("item_info[1].message_strings = %q, want %q", results.ItemInfo[1].MessageStrings, "200")
	}
}

func TestGetMessage(t *testing.T) {
	testMessage := []byte{200, 0, 0, 0, 0, 0, 0, 0, 8, 1}
	slices.Reverse(testMessage)
	results := getTraceMessage(testMessage)
	if len(results.ItemInfo) == 0 {
		t.Fatal("item_info is empty")
	}
	if results.ItemInfo[0].MessageStrings != "200" {
		t.Errorf("item_info[0].message_strings = %q, want %q", results.ItemInfo[0].MessageStrings, "200")
	}
}
