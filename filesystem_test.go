// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

import (
	"path/filepath"
	"testing"
)

func TestOnlyHexChars(t *testing.T) {
	cases := []string{
		"A7563E1D7A043ED29587044987205172",
		"DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD",
	}
	for _, c := range cases {
		if !onlyHexChars(c) {
			t.Errorf("onlyHexChars(%q) = false, want true", c)
		}
	}
	if onlyHexChars("ZZZZ") {
		t.Error("onlyHexChars(ZZZZ) = true, want false")
	}
}

func TestValidateUUIDTextPath(t *testing.T) {
	validDsc := []string{
		"/private/var/db/uuidtext/dsc/A7563E1D7A043ED29587044987205172",
		"/private/var/db/uuidtext/dsc/DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD",
		"./dsc/A7563E1D7A043ED29587044987B05172",
	}
	for _, c := range validDsc {
		if got := LogFileTypeFromPath(c); got != LogFileDsc {
			t.Errorf("LogFileTypeFromPath(%q) = %s, want %s", c, got, LogFileDsc)
		}
	}

	tracev3 := []string{
		"/private/var/db/diagnostics/Persist/0000000000000002.tracev3",
		"/private/var/db/diagnostics/HighVolume/0000000000000002.tracev3",
		"/private/var/db/diagnostics/Signpost/0000000000000002.tracev3",
		"/private/var/db/diagnostics/Special/0000000000000002.tracev3",
		"/somewhere/logdata.LiveData.tracev3",
	}
	for _, c := range tracev3 {
		if got := LogFileTypeFromPath(c); got != LogFileTraceV3 {
			t.Errorf("LogFileTypeFromPath(%q) = %s, want %s", c, got, LogFileTraceV3)
		}
	}

	timesync := "/somewhere/timesync/0000000000000002.timesync"
	if got := LogFileTypeFromPath(timesync); got != LogFileTimesync {
		t.Errorf("LogFileTypeFromPath(%q) = %s, want %s", timesync, got, LogFileTimesync)
	}

	uuidtext := "/somewhere/uuidtext/25/A8CFC3A9C035F19DBDC16F994EA948"
	if got := LogFileTypeFromPath(uuidtext); got != LogFileUUIDText {
		t.Errorf("LogFileTypeFromPath(%q) = %s, want %s", uuidtext, got, LogFileUUIDText)
	}

	if got := LogFileTypeFromPath("/tmp/foo.txt"); got != LogFileInvalid {
		t.Errorf("LogFileTypeFromPath(/tmp/foo.txt) = %s, want %s", got, LogFileInvalid)
	}
}

func archiveDir(t *testing.T) string {
	t.Helper()
	file := requireTestDataFile(t, "system_logs_big_sur.logarchive/Persist/0000000000000002.tracev3")
	return filepath.Dir(filepath.Dir(file))
}

func TestReadUUIDTextArchive(t *testing.T) {
	provider := NewLogarchiveProvider(archiveDir(t))
	uuid, err := provider.ReadUUIDText("25A8CFC3A9C035F19DBDC16F994EA948")
	if err != nil {
		t.Fatalf("ReadUUIDText: %v", err)
	}
	if len(uuid.EntryDescriptors) != 2 {
		t.Errorf("entry_descriptors = %d, want 2", len(uuid.EntryDescriptors))
	}
	if uuid.UUID != "" {
		t.Errorf("uuid = %q, want empty", uuid.UUID)
	}
	if len(uuid.FooterData) != 76544 {
		t.Errorf("footer_data = %d, want 76544", len(uuid.FooterData))
	}
	if uuid.Signature != 1719109785 {
		t.Errorf("signature = %d, want 1719109785", uuid.Signature)
	}
	if uuid.MajorVersion != 2 || uuid.MinorVersion != 1 {
		t.Errorf("version = %d.%d, want 2.1", uuid.MajorVersion, uuid.MinorVersion)
	}
	if uuid.NumberEntries != 2 {
		t.Errorf("number_entries = %d, want 2", uuid.NumberEntries)
	}
}

func TestReadDSCUUIDArchive(t *testing.T) {
	provider := NewLogarchiveProvider(archiveDir(t))
	dsc, err := provider.ReadDSCUUID("80896B329EB13A10A7C5449B15305DE2")
	if err != nil {
		t.Fatalf("ReadDSCUUID: %v", err)
	}
	if dsc.DSCUUID != "" {
		t.Errorf("dsc_uuid = %q, want empty", dsc.DSCUUID)
	}
	if dsc.MajorVersion != 1 || dsc.MinorVersion != 0 {
		t.Errorf("version = %d.%d, want 1.0", dsc.MajorVersion, dsc.MinorVersion)
	}
	if dsc.NumberRanges != 2993 || dsc.NumberUUIDs != 1976 {
		t.Errorf("number_ranges/uuids = %d/%d, want 2993/1976", dsc.NumberRanges, dsc.NumberUUIDs)
	}
	if len(dsc.Ranges) != 2993 || len(dsc.UUIDs) != 1976 {
		t.Errorf("ranges/uuids len = %d/%d, want 2993/1976", len(dsc.Ranges), len(dsc.UUIDs))
	}
	if dsc.Signature != 1685283688 {
		t.Errorf("signature = %d, want 1685283688", dsc.Signature)
	}
}

func TestNormalizeUUID(t *testing.T) {
	cases := map[string]string{
		"25A8CFC3A9C035F19DBDC16F994EA94":  "025A8CFC3A9C035F19DBDC16F994EA94",
		"25A8CFC3A9C035F19DBDC16F994EA9":   "0025A8CFC3A9C035F19DBDC16F994EA9",
		"25A8CFC3A9C035F19DBDC16F994EA948": "25A8CFC3A9C035F19DBDC16F994EA948",
	}
	for in, want := range cases {
		got, err := normalizeUUID(in)
		if err != nil {
			t.Fatalf("normalizeUUID(%q): %v", in, err)
		}
		if got != want {
			t.Errorf("normalizeUUID(%q) = %q, want %q", in, got, want)
		}
	}
	if _, err := normalizeUUID("short"); err == nil {
		t.Error("normalizeUUID(short) = nil error, want error")
	}
}
