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

func TestFirehoseFormatterFlagsHasLargeOffset(t *testing.T) {
	testData := []byte{
		1, 0, 2, 0, 14, 0, 34, 2, 0, 4, 135, 16, 0, 0, 34, 4, 0, 0, 5, 0, 100, 101, 110, 121, 0,
	}
	testFlags := uint16(557)

	var flags []MessageFlags
	_, results, err := FirehoseFormatterFlags(testData, testFlags, &flags)
	if err != nil {
		t.Fatalf("FirehoseFormatterFlags returned error: %v", err)
	}
	if results.HasLargeOffset != 1 {
		t.Errorf("has_large_offset = %d, want 1", results.HasLargeOffset)
	}
	if results.LargeSharedCache != 2 {
		t.Errorf("large_shared_cache = %d, want 2", results.LargeSharedCache)
	}
	wantFlags := []MessageFlags{MessageFlagsHasLargeOffset, MessageFlagsLargeSharedCache}
	if !reflect.DeepEqual(flags, wantFlags) {
		t.Errorf("flags = %v, want %v", flags, wantFlags)
	}
}

func TestFirehoseFormatterFlagsMessageStringsUUIDMessageAltIndex(t *testing.T) {
	testData := []byte{8, 0, 17, 166, 251, 2, 128, 255, 0, 0}
	testFlags := uint16(8)

	var flags []MessageFlags
	_, results, err := FirehoseFormatterFlags(testData, testFlags, &flags)
	if err != nil {
		t.Fatalf("FirehoseFormatterFlags returned error: %v", err)
	}
	if results.MainExeAltIndex != 8 {
		t.Errorf("main_exe_alt_index = %d, want 8", results.MainExeAltIndex)
	}
	wantFlags := []MessageFlags{MessageFlagsAbsolute, MessageFlagsAltIndex}
	if !reflect.DeepEqual(flags, wantFlags) {
		t.Errorf("flags = %v, want %v", flags, wantFlags)
	}
}

func TestFirehoseFormatterFlagsMessageStringsUUID(t *testing.T) {
	testData := []byte{186, 0, 0, 0}
	testFlags := uint16(514)

	var flags []MessageFlags
	_, results, err := FirehoseFormatterFlags(testData, testFlags, &flags)
	if err != nil {
		t.Fatalf("FirehoseFormatterFlags returned error: %v", err)
	}
	if !results.MainExe {
		t.Errorf("main_exe = false, want true")
	}
	wantFlags := []MessageFlags{MessageFlagsMainExe}
	if !reflect.DeepEqual(flags, wantFlags) {
		t.Errorf("flags = %v, want %v", flags, wantFlags)
	}
}

func TestFirehoseFormatterFlagsSharedCacheDSCUUID(t *testing.T) {
	testData := []byte{
		23, 1, 34, 1, 66, 4, 0, 0, 35, 0, 83, 65, 83, 83, 101, 115, 115, 105, 111, 110, 83,
		116, 97, 116, 101, 70, 111, 114, 85, 115, 101, 114, 58, 49, 50, 52, 54, 58, 32, 101,
		110, 116, 101, 114, 0,
	}
	testFlags := uint16(516)

	var flags []MessageFlags
	_, results, err := FirehoseFormatterFlags(testData, testFlags, &flags)
	if err != nil {
		t.Fatalf("FirehoseFormatterFlags returned error: %v", err)
	}
	if !results.SharedCache {
		t.Errorf("shared_cache = false, want true")
	}
	wantFlags := []MessageFlags{MessageFlagsSharedCache}
	if !reflect.DeepEqual(flags, wantFlags) {
		t.Errorf("flags = %v, want %v", flags, wantFlags)
	}
}

func TestFirehoseFormatterFlagsAbsoluteMessageAltUUID(t *testing.T) {
	testData := []byte{
		128, 255, 2, 13, 34, 4, 0, 0, 6, 0, 34, 4, 6, 0, 11, 0, 34, 4, 17, 0, 7, 0, 2, 4, 8, 0,
		0, 0, 2, 8, 0, 0, 0, 0, 0, 0, 0, 0, 2, 4, 0, 0, 0, 0, 2, 8, 0, 0, 0, 0, 0, 0, 0, 0, 34,
		4, 24, 0, 3, 0, 34, 4, 27, 0, 3, 0, 2, 8, 156, 17, 7, 98, 0, 0, 0, 0, 2, 8, 156, 17, 7,
		98, 0, 0, 0, 0, 2, 4, 0, 0, 0, 0, 34, 4, 30, 0, 3, 0, 65, 67, 77, 82, 77, 0, 95, 108,
		111, 103, 80, 111, 108, 105, 99, 121, 0, 83, 65, 86, 73, 78, 71, 0, 78, 79, 0, 78, 79,
		0, 78, 79, 0,
	}
	testFlags := uint16(8)

	var flags []MessageFlags
	_, results, err := FirehoseFormatterFlags(testData, testFlags, &flags)
	if err != nil {
		t.Fatalf("FirehoseFormatterFlags returned error: %v", err)
	}
	if !results.Absolute {
		t.Errorf("absolute = false, want true")
	}
	if results.MainExeAltIndex != 65408 {
		t.Errorf("main_exe_alt_index = %d, want 65408", results.MainExeAltIndex)
	}
	wantFlags := []MessageFlags{MessageFlagsAbsolute, MessageFlagsAltIndex}
	if !reflect.DeepEqual(flags, wantFlags) {
		t.Errorf("flags = %v, want %v", flags, wantFlags)
	}
}

func TestFirehoseFormatterFlagsUUIDRelative(t *testing.T) {
	testData := []byte{
		123, 13, 55, 117, 241, 144, 62, 33, 186, 19, 4, 71, 196, 27, 135, 67, 0, 0,
	}
	testFlags := uint16(0xa)

	var flags []MessageFlags
	_, results, err := FirehoseFormatterFlags(testData, testFlags, &flags)
	if err != nil {
		t.Fatalf("FirehoseFormatterFlags returned error: %v", err)
	}
	if results.UuidRelative != "7B0D3775F1903E21BA130447C41B8743" {
		t.Errorf("uuid_relative = %q, want %q", results.UuidRelative, "7B0D3775F1903E21BA130447C41B8743")
	}
	wantFlags := []MessageFlags{MessageFlagsUuidRelative}
	if !reflect.DeepEqual(flags, wantFlags) {
		t.Errorf("flags = %v, want %v", flags, wantFlags)
	}
}
