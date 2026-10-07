// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

import "testing"

func TestParseTimesyncData(t *testing.T) {
	buffer := requireTestData(t, "system_logs_big_sur.logarchive/timesync/0000000000000002.timesync")

	timesyncData, err := parseTimesyncData(buffer)
	if err != nil {
		t.Fatalf("parseTimesyncData returned error: %v", err)
	}
	if len(timesyncData) != 5 {
		t.Errorf("timesync data length = %d, want 5", len(timesyncData))
	}
	boot, ok := timesyncData["9A6A3124274A44B29ABF2BC9E4599B3B"]
	if !ok {
		t.Fatal("expected boot UUID 9A6A3124274A44B29ABF2BC9E4599B3B in timesync data")
	}
	if len(boot.Timesync) != 5 {
		t.Errorf("timesync records = %d, want 5", len(boot.Timesync))
	}
}

func TestTimesyncBadBootHeader(t *testing.T) {
	buffer := requireTestData(t, "Bad Data/Timesync/Bad_Boot_header_0000000000000002.timesync")

	_, err := parseTimesyncData(buffer)
	requireErrIncomplete(t, err)
}

func TestTimesyncBadRecordHeader(t *testing.T) {
	buffer := requireTestData(t, "Bad Data/Timesync/Bad_Record_header_0000000000000002.timesync")

	_, err := parseTimesyncData(buffer)
	requireErrIncomplete(t, err)
}

func TestTimesyncBadContent(t *testing.T) {
	buffer := requireTestData(t, "Bad Data/Timesync/Bad_content_0000000000000002.timesync")

	_, err := parseTimesyncData(buffer)
	requireErrIncomplete(t, err)
}

func TestTimesyncBadFile(t *testing.T) {
	buffer := requireTestData(t, "Bad Data/Timesync/BadFile.timesync")

	_, err := parseTimesyncData(buffer)
	if err == nil {
		t.Fatal("expected error for bad timesync file, got nil")
	}
}

func TestParseTimesync(t *testing.T) {
	testData := []byte{
		84, 115, 32, 0, 0, 0, 0, 0, 165, 196, 104, 252, 1, 0, 0, 0, 216, 189, 100, 108, 116,
		158, 131, 22, 0, 0, 0, 0, 0, 0, 0, 0,
	}
	c := newCursor(testData)
	timesync, err := parseTimesync(c)
	if err != nil {
		t.Fatalf("parseTimesync returned error: %v", err)
	}
	tests := []struct {
		name string
		got  any
		want any
	}{
		{"signature", timesync.Signature, uint32(0x207354)},
		{"flags", timesync.Flags, uint32(0)},
		{"kernel_time", timesync.KernelTime, uint64(8529691813)},
		{"walltime", timesync.Walltime, int64(1622314513655447000)},
		{"timezone", timesync.Timezone, uint32(0)},
		{"daylight_savings", timesync.DaylightSavings, uint32(0)},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("%s = %v, want %v", tt.name, tt.got, tt.want)
		}
	}
}

func TestParseTimesyncBoot(t *testing.T) {
	testData := []byte{
		176, 187, 48, 0, 0, 0, 0, 0, 132, 91, 13, 213, 1, 96, 69, 62, 172, 224, 56, 118, 12,
		123, 92, 29, 1, 0, 0, 0, 1, 0, 0, 0, 168, 167, 19, 176, 114, 158, 131, 22, 0, 0, 0, 0,
		0, 0, 0, 0,
	}
	c := newCursor(testData)
	timesyncBoot, err := parseTimesyncBoot(c)
	if err != nil {
		t.Fatalf("parseTimesyncBoot returned error: %v", err)
	}
	tests := []struct {
		name string
		got  any
		want any
	}{
		{"signature", timesyncBoot.Signature, uint16(0xbbb0)},
		{"header_size", timesyncBoot.HeaderSize, uint16(48)},
		{"unknown", timesyncBoot.Unknown, uint32(0)},
		{"boot_uuid", timesyncBoot.BootUUID, "845B0DD50160453EACE038760C7B5C1D"},
		{"timebase_numerator", timesyncBoot.TimebaseNumerator, uint32(1)},
		{"timebase_denominator", timesyncBoot.TimebaseDenominator, uint32(1)},
		{"boot_time", timesyncBoot.BootTime, int64(1622314506201049000)},
		{"timezone_offset_mins", timesyncBoot.TimezoneOffsetMins, uint32(0)},
		{"daylight_savings", timesyncBoot.DaylightSavings, uint32(0)},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("%s = %v, want %v", tt.name, tt.got, tt.want)
		}
	}
}
