// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

import (
	"sort"
	"testing"
)

func TestCollectSharedStringsArchive(t *testing.T) {
	provider := NewLogarchiveProvider(archiveDir(t))
	sharedStrings, err := CollectSharedStrings(provider)
	if err != nil {
		t.Fatalf("CollectSharedStrings: %v", err)
	}

	if len(sharedStrings) != 2 {
		t.Fatalf("len = %d, want 2", len(sharedStrings))
	}
	if sharedStrings[0].NumberUUIDs != 532 || sharedStrings[0].NumberRanges != 788 {
		t.Errorf("shared_strings[0] counts = %d/%d, want 532/788", sharedStrings[0].NumberUUIDs, sharedStrings[0].NumberRanges)
	}
	if sharedStrings[0].DSCUUID != "522F6217CB113F8FB845C2A1B784C7C2" {
		t.Errorf("dsc_uuid = %q", sharedStrings[0].DSCUUID)
	}
	if sharedStrings[0].MajorVersion != 1 || sharedStrings[0].MinorVersion != 0 {
		t.Errorf("version = %d.%d, want 1.0", sharedStrings[0].MajorVersion, sharedStrings[0].MinorVersion)
	}
	if len(sharedStrings[0].Ranges) != 788 || len(sharedStrings[0].UUIDs) != 532 {
		t.Errorf("ranges/uuids = %d/%d, want 788/532", len(sharedStrings[0].Ranges), len(sharedStrings[0].UUIDs))
	}
	if sharedStrings[1].NumberUUIDs != 1976 || sharedStrings[1].NumberRanges != 2993 {
		t.Errorf("dsc[1] counts = %d/%d, want 1976/2993", sharedStrings[1].NumberUUIDs, sharedStrings[1].NumberRanges)
	}
	if sharedStrings[1].DSCUUID != "80896B329EB13A10A7C5449B15305DE2" {
		t.Errorf("dsc_uuid[1] = %q", sharedStrings[1].DSCUUID)
	}
}

func TestCollectStringsArchive(t *testing.T) {
	provider := NewLogarchiveProvider(archiveDir(t))
	stringsResults, err := CollectStrings(provider)
	if err != nil {
		t.Fatalf("CollectStrings: %v", err)
	}
	if len(stringsResults) != 536 {
		t.Fatalf("len = %d, want 536", len(stringsResults))
	}

	sort.Slice(stringsResults, func(i, j int) bool {
		return stringsResults[i].UUID < stringsResults[j].UUID
	})

	if stringsResults[0].Signature != 1719109785 {
		t.Errorf("signature = %d, want 1719109785", stringsResults[0].Signature)
	}
	if stringsResults[0].UUID != "004EAF1C2B310DA0383BE3D60B80E8" {
		t.Errorf("uuid = %q", stringsResults[0].UUID)
	}
	if len(stringsResults[0].EntryDescriptors) != 1 {
		t.Errorf("entry_descriptors = %d, want 1", len(stringsResults[0].EntryDescriptors))
	}
	if len(stringsResults[0].FooterData) != 2847 {
		t.Errorf("footer_data = %d, want 2847", len(stringsResults[0].FooterData))
	}
	if stringsResults[0].NumberEntries != 1 {
		t.Errorf("number_entries = %d, want 1", stringsResults[0].NumberEntries)
	}
	if stringsResults[0].MinorVersion != 1 || stringsResults[0].MajorVersion != 2 {
		t.Errorf("version = %d.%d, want 2.1", stringsResults[0].MajorVersion, stringsResults[0].MinorVersion)
	}
	if len(stringsResults[1].FooterData) != 2164 {
		t.Errorf("dsc[1] footer = %d, want 2164", len(stringsResults[1].FooterData))
	}
	if len(stringsResults[2].FooterData) != 19011 {
		t.Errorf("dsc[2] footer = %d, want 19011", len(stringsResults[2].FooterData))
	}
}

func TestCollectTimesyncArchive(t *testing.T) {
	provider := NewLogarchiveProvider(archiveDir(t))
	timesyncData, err := CollectTimesync(provider)
	if err != nil {
		t.Fatalf("CollectTimesync: %v", err)
	}
	if len(timesyncData) != 5 {
		t.Fatalf("len = %d, want 5", len(timesyncData))
	}
	boot := timesyncData["9A6A3124274A44B29ABF2BC9E4599B3B"]
	if boot == nil {
		t.Fatal("missing boot 9A6A3124274A44B29ABF2BC9E4599B3B")
	}
	if boot.Signature != 48048 {
		t.Errorf("signature = %d, want 48048", boot.Signature)
	}
	if boot.Unknown != 0 {
		t.Errorf("unknown = %d, want 0", boot.Unknown)
	}
	if boot.BootUUID != "9A6A3124274A44B29ABF2BC9E4599B3B" {
		t.Errorf("boot_uuid = %q", boot.BootUUID)
	}
	if len(boot.Timesync) != 5 {
		t.Errorf("timesync = %d, want 5", len(boot.Timesync))
	}
	if boot.BootTime != 1642302206000000000 {
		t.Errorf("boot_time = %d", boot.BootTime)
	}
	if boot.HeaderSize != 48 {
		t.Errorf("header_size = %d, want 48", boot.HeaderSize)
	}
	if boot.TimebaseNumerator != 1 || boot.TimebaseDenominator != 1 {
		t.Errorf("timebase = %d/%d, want 1/1", boot.TimebaseNumerator, boot.TimebaseDenominator)
	}
	if boot.TimezoneOffsetMins != 0 {
		t.Errorf("timezone_offset_mins = %d, want 0", boot.TimezoneOffsetMins)
	}
}
