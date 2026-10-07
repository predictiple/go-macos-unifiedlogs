// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

import "testing"

func TestParseUUIDTextBigSur(t *testing.T) {
	buffer := requireTestData(t, "UUIDText/Big Sur/1FE459BBDC3E19BBF82D58415A2AE9")

	uuidtextData, err := parseUUIDText(buffer)
	if err != nil {
		t.Fatalf("parseUUIDText returned error: %v", err)
	}
	if uuidtextData.Signature != 0x66778899 {
		t.Errorf("signature = %#x, want %#x", uuidtextData.Signature, 0x66778899)
	}
	if uuidtextData.MajorVersion != 2 {
		t.Errorf("major_version = %d, want 2", uuidtextData.MajorVersion)
	}
	if uuidtextData.MinorVersion != 1 {
		t.Errorf("minor_version = %d, want 1", uuidtextData.MinorVersion)
	}
	if uuidtextData.NumberEntries != 2 {
		t.Errorf("number_entries = %d, want 2", uuidtextData.NumberEntries)
	}
	if uuidtextData.EntryDescriptors[0].EntrySize != 617 {
		t.Errorf("entry_descriptors[0].entry_size = %d, want 617", uuidtextData.EntryDescriptors[0].EntrySize)
	}
	if uuidtextData.EntryDescriptors[1].EntrySize != 2301 {
		t.Errorf("entry_descriptors[1].entry_size = %d, want 2301", uuidtextData.EntryDescriptors[1].EntrySize)
	}
	if uuidtextData.EntryDescriptors[0].RangeStartOffset != 32048 {
		t.Errorf("entry_descriptors[0].range_start_offset = %d, want 32048", uuidtextData.EntryDescriptors[0].RangeStartOffset)
	}
	if uuidtextData.EntryDescriptors[1].RangeStartOffset != 29747 {
		t.Errorf("entry_descriptors[1].range_start_offset = %d, want 29747", uuidtextData.EntryDescriptors[1].RangeStartOffset)
	}
	if len(uuidtextData.FooterData) != 2987 {
		t.Errorf("footer_data length = %d, want 2987", len(uuidtextData.FooterData))
	}
}

func TestParseUUIDTextHighSierra(t *testing.T) {
	buffer := requireTestData(t, "UUIDText/High Sierra/425A2E5B5531B98918411B4379EE5F")

	uuidtextData, err := parseUUIDText(buffer)
	if err != nil {
		t.Fatalf("parseUUIDText returned error: %v", err)
	}
	if uuidtextData.Signature != 0x66778899 {
		t.Errorf("signature = %#x, want %#x", uuidtextData.Signature, 0x66778899)
	}
	if uuidtextData.MajorVersion != 2 {
		t.Errorf("major_version = %d, want 2", uuidtextData.MajorVersion)
	}
	if uuidtextData.MinorVersion != 1 {
		t.Errorf("minor_version = %d, want 1", uuidtextData.MinorVersion)
	}
	if uuidtextData.NumberEntries != 1 {
		t.Errorf("number_entries = %d, want 1", uuidtextData.NumberEntries)
	}
	if uuidtextData.EntryDescriptors[0].EntrySize != 2740 {
		t.Errorf("entry_descriptors[0].entry_size = %d, want 2740", uuidtextData.EntryDescriptors[0].EntrySize)
	}
	if uuidtextData.EntryDescriptors[0].RangeStartOffset != 21132 {
		t.Errorf("entry_descriptors[0].range_start_offset = %d, want 21132", uuidtextData.EntryDescriptors[0].RangeStartOffset)
	}
	if len(uuidtextData.FooterData) != 2951 {
		t.Errorf("footer_data length = %d, want 2951", len(uuidtextData.FooterData))
	}
}

func TestParseUUIDTextBadHeader(t *testing.T) {
	buffer := requireTestData(t, "Bad Data/UUIDText/Bad_Header_1FE459BBDC3E19BBF82D58415A2AE9")

	_, err := parseUUIDText(buffer)
	requireErrIncomplete(t, err)
}

func TestParseUUIDTextBadContent(t *testing.T) {
	buffer := requireTestData(t, "Bad Data/UUIDText/Bad_Content_1FE459BBDC3E19BBF82D58415A2AE9")

	_, err := parseUUIDText(buffer)
	if err == nil {
		t.Fatal("expected error for bad UUIDText content, got nil")
	}
}

func TestParseUUIDTextBadFile(t *testing.T) {
	buffer := requireTestData(t, "Bad Data/UUIDText/Badfile.txt")

	_, err := parseUUIDText(buffer)
	requireErrIncomplete(t, err)
}
