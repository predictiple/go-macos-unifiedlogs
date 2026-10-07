// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

import "testing"

func TestUnifiedLogIterator(t *testing.T) {
	buffer := requireTestData(t, "system_logs_big_sur.logarchive/Persist/0000000000000002.tracev3")

	it := UnifiedLogIterator{
		Data:     buffer,
		Header:   nil,
		Evidence: "0000000000000002.tracev3",
	}

	total := 0
	for {
		chunk, ok := it.Next()
		if !ok {
			break
		}

		if len(chunk.CatalogData) > 0 && len(chunk.CatalogData[0].Firehose) == 99 {
			if len(chunk.CatalogData[0].Firehose) != 99 {
				t.Errorf("firehose len = %d, want 99", len(chunk.CatalogData[0].Firehose))
			}
			if len(chunk.CatalogData[0].Simpledump) != 0 {
				t.Errorf("simpledump len = %d, want 0", len(chunk.CatalogData[0].Simpledump))
			}
			if len(chunk.Header) != 1 {
				t.Errorf("header len = %d, want 1", len(chunk.Header))
			}
			if len(chunk.CatalogData[0].Catalog.CatalogProcessInfoEntries) <= 40 {
				t.Errorf("process_info_entries len = %d, want > 40", len(chunk.CatalogData[0].Catalog.CatalogProcessInfoEntries))
			}
			if len(chunk.CatalogData[0].Statedump) != 0 {
				t.Errorf("statedump len = %d, want 0", len(chunk.CatalogData[0].Statedump))
			}
		}

		total += len(chunk.CatalogData)
	}

	if total != 56 {
		t.Errorf("total = %d, want 56", total)
	}
}

func TestUnifiedLogIteratorBuildLog(t *testing.T) {
	path := requireTestDataFile(t, "system_logs_big_sur.logarchive")
	provider := NewLogarchiveProvider(path)
	timesyncData, err := CollectTimesync(provider)
	if err != nil {
		t.Fatalf("CollectTimesync failed: %v", err)
	}

	buffer := requireTestData(t, "system_logs_big_sur.logarchive/Persist/0000000000000002.tracev3")
	it := UnifiedLogIterator{
		Data:     buffer,
		Header:   nil,
		Evidence: "0000000000000002.tracev3",
	}

	cache := NewMemoryStringCache()

	total := 0
	for {
		chunk, ok := it.Next()
		if !ok {
			break
		}

		excludeMissing := false
		results, _ := BuildLog(chunk, provider, cache, timesyncData, excludeMissing)

		if len(results) > 10 && results[10].Time == 1642302327364384800.0 {
			if len(results) != 3805 {
				t.Errorf("results len = %d, want 3805", len(results))
			}
			if results[10].Process != "/usr/libexec/lightsoutmanagementd" {
				t.Errorf("process = %q", results[10].Process)
			}
			if results[10].Subsystem != "com.apple.lom" {
				t.Errorf("subsystem = %q", results[10].Subsystem)
			}
			if results[10].Time != 1642302327364384800.0 {
				t.Errorf("time = %f", results[10].Time)
			}
			if results[10].ActivityID != 0 {
				t.Errorf("activity_id = %d", results[10].ActivityID)
			}
			if results[10].Library != "/System/Library/PrivateFrameworks/AppleLOM.framework/Versions/A/AppleLOM" {
				t.Errorf("library = %q", results[10].Library)
			}
			if results[10].Message != "<private> LOM isSupported : No" {
				t.Errorf("message = %q", results[10].Message)
			}
			if results[10].PID != 45 {
				t.Errorf("pid = %d", results[10].PID)
			}
			if results[10].ThreadID != 588 {
				t.Errorf("thread_id = %d", results[10].ThreadID)
			}
			if results[10].Category != "device" {
				t.Errorf("category = %q", results[10].Category)
			}
			if results[10].LogType != LogTypeDefault {
				t.Errorf("log_type = %q", results[10].LogType)
			}
			if results[10].EventType != EventTypeLog {
				t.Errorf("event_type = %q", results[10].EventType)
			}
			if results[10].EUID != 0 {
				t.Errorf("euid = %d", results[10].EUID)
			}
			if results[10].BootUUID != "80D194AF56A34C54867449D2130D41BB" {
				t.Errorf("boot_uuid = %q", results[10].BootUUID)
			}
			if results[10].TimezoneName != "Pacific" {
				t.Errorf("timezone_name = %q", results[10].TimezoneName)
			}
			if results[10].LibraryUUID != "D8E5AF1CAF4F3CEB8731E6F240E8EA7D" {
				t.Errorf("library_uuid = %q", results[10].LibraryUUID)
			}
			if results[10].ProcessUUID != "6C3ADF991F033C1C96C4ADFAA12D8CED" {
				t.Errorf("process_uuid = %q", results[10].ProcessUUID)
			}
			if results[10].RawMessage != "%@ LOM isSupported : %s" {
				t.Errorf("raw_message = %q", results[10].RawMessage)
			}
		}

		total += len(results)
	}

	if total != 207366 {
		t.Errorf("total = %d, want 207366", total)
	}
}

func TestNomBytes(t *testing.T) {
	test := []byte{1, 0, 0, 0}
	left, _, err := nomBytes(test, 1)
	if err != nil {
		t.Fatalf("nomBytes failed: %v", err)
	}
	if len(left) != 3 {
		t.Errorf("left len = %d, want 3", len(left))
	}
}
