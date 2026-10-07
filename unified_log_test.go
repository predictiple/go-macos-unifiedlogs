// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

import (
	"bytes"
	"reflect"
	"testing"
)

func TestParseUnifiedLog(t *testing.T) {
	path := requireTestDataFile(t, "system_logs_big_sur.logarchive/Persist/0000000000000002.tracev3")
	buffer := requireTestData(t, "system_logs_big_sur.logarchive/Persist/0000000000000002.tracev3")

	_, results, err := parseUnifiedLog(buffer, path)
	if err != nil {
		t.Fatalf("parseUnifiedLog failed: %v", err)
	}
	if len(results.CatalogData) != 56 {
		t.Errorf("catalog_data.len() = %d, want 56", len(results.CatalogData))
	}
	if len(results.Header) != 1 {
		t.Errorf("header.len() = %d, want 1", len(results.Header))
	}
	if len(results.Oversize) != 12 {
		t.Errorf("oversize.len() = %d, want 12", len(results.Oversize))
	}
}

func TestBadLogHeader(t *testing.T) {
	path := requireTestDataFile(t, "Bad Data/TraceV3/Bad_header_0000000000000005.tracev3")
	buffer := requireTestData(t, "Bad Data/TraceV3/Bad_header_0000000000000005.tracev3")

	_, results, err := parseUnifiedLog(buffer, path)
	if err != nil {
		t.Fatalf("parseUnifiedLog returned error: %v", err)
	}
	if len(results.CatalogData) != 36 {
		t.Errorf("catalog_data len = %d, want 36", len(results.CatalogData))
	}
	if len(results.Header) != 0 {
		t.Errorf("header len = %d, want 0", len(results.Header))
	}
	if len(results.Oversize) != 28 {
		t.Errorf("oversize len = %d, want 28", len(results.Oversize))
	}
}

func TestBadLogContent(t *testing.T) {
	path := requireTestDataFile(t, "Bad Data/TraceV3/Bad_content_0000000000000005.tracev3")
	buffer := requireTestData(t, "Bad Data/TraceV3/Bad_content_0000000000000005.tracev3")

	if _, _, err := parseUnifiedLog(buffer, path); err == nil {
		t.Fatal("expected error parsing bad log content, got nil")
	}
}

func TestBadLogFile(t *testing.T) {
	path := requireTestDataFile(t, "Bad Data/TraceV3/00.tracev3")
	buffer := requireTestData(t, "Bad Data/TraceV3/00.tracev3")

	if _, _, err := parseUnifiedLog(buffer, path); err == nil {
		t.Fatal("expected error parsing bad log file, got nil")
	}
}

func TestBuildLog(t *testing.T) {
	archive := requireTestDataFile(t, "system_logs_big_sur.logarchive")
	provider := NewLogarchiveProvider(archive)
	cache := NewMemoryStringCache()
	timesyncData, err := CollectTimesync(provider)
	if err != nil {
		t.Fatalf("CollectTimesync: %v", err)
	}

	path := requireTestDataFile(t, "system_logs_big_sur.logarchive/Persist/0000000000000002.tracev3")
	buffer := requireTestData(t, "system_logs_big_sur.logarchive/Persist/0000000000000002.tracev3")
	logData, err := ParseLog(bytes.NewReader(buffer), path)
	if err != nil {
		t.Fatalf("ParseLog: %v", err)
	}

	results, _ := BuildLog(logData, provider, cache, timesyncData, false)
	if len(results) != 207366 {
		t.Fatalf("results len = %d, want 207366", len(results))
	}
	r := results[0]
	if r.Process != "/usr/libexec/lightsoutmanagementd" {
		t.Errorf("process = %q", r.Process)
	}
	if r.Subsystem != "com.apple.lom" {
		t.Errorf("subsystem = %q", r.Subsystem)
	}
	if r.Time != 1642302326434850800.0 {
		t.Errorf("time = %v", r.Time)
	}
	if r.ActivityID != 0 {
		t.Errorf("activity_id = %d", r.ActivityID)
	}
	if r.Library != "/usr/libexec/lightsoutmanagementd" {
		t.Errorf("library = %q", r.Library)
	}
	if r.LibraryUUID != "6C3ADF991F033C1C96C4ADFAA12D8CED" {
		t.Errorf("library_uuid = %q", r.LibraryUUID)
	}
	if r.ProcessUUID != "6C3ADF991F033C1C96C4ADFAA12D8CED" {
		t.Errorf("process_uuid = %q", r.ProcessUUID)
	}
	if r.Message != "LOMD Start" {
		t.Errorf("message = %q", r.Message)
	}
	if r.PID != 45 {
		t.Errorf("pid = %d", r.PID)
	}
	if r.ThreadID != 588 {
		t.Errorf("thread_id = %d", r.ThreadID)
	}
	if r.Category != "device" {
		t.Errorf("category = %q", r.Category)
	}
	if r.LogType != LogTypeDefault {
		t.Errorf("log_type = %q", r.LogType)
	}
	if r.EventType != EventTypeLog {
		t.Errorf("event_type = %q", r.EventType)
	}
	if r.EUID != 0 {
		t.Errorf("euid = %d", r.EUID)
	}
	if r.BootUUID != "80D194AF56A34C54867449D2130D41BB" {
		t.Errorf("boot_uuid = %q", r.BootUUID)
	}
	if r.TimezoneName != "Pacific" {
		t.Errorf("timezone_name = %q", r.TimezoneName)
	}
	if r.RawMessage != "LOMD Start" {
		t.Errorf("raw_message = %q", r.RawMessage)
	}
	if r.Timestamp != "2022-01-16T03:05:26.434850816Z" {
		t.Errorf("timestamp = %q", r.Timestamp)
	}
}

func TestGetLogType(t *testing.T) {
	if got := getLogType(0x2, 0x2); got != LogTypeDebug {
		t.Errorf("getLogType(0x2, 0x2) = %q, want %q", got, LogTypeDebug)
	}
	if got := getLogType(0x1, 0x2); got != LogTypeCreate {
		t.Errorf("getLogType(0x1, 0x2) = %q, want %q", got, LogTypeCreate)
	}
}

func TestGetEventType(t *testing.T) {
	if got := getEventType(0x2); got != EventTypeActivity {
		t.Errorf("getEventType(0x2) = %q", got)
	}
}

func TestGetHeaderData(t *testing.T) {
	testChunkHeader := []byte{
		0, 16, 0, 0, 17, 0, 0, 0, 208, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 15, 105, 217, 162,
		204, 126, 0, 0, 48, 215, 18, 98, 0, 0, 0, 0, 203, 138, 9, 0, 44, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0,
		0, 0, 97, 0, 0, 8, 0, 0, 0, 6, 112, 124, 198, 169, 153, 1, 0, 1, 97, 0, 0, 56, 0, 0, 0, 7, 0,
		0, 0, 8, 0, 0, 0, 50, 49, 65, 53, 53, 57, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 77, 97, 99, 66, 111,
		111, 107, 80, 114, 111, 49, 54, 44, 49, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		2, 97, 0, 0, 24, 0, 0, 0, 195, 32, 184, 206, 151, 250, 77, 165, 159, 49, 125, 57, 46, 56, 156,
		234, 85, 0, 0, 0, 0, 0, 0, 0, 3, 97, 0, 0, 48, 0, 0, 0, 47, 118, 97, 114, 47, 100, 98, 47,
		116, 105, 109, 101, 122, 111, 110, 101, 47, 122, 111, 110, 101, 105, 110, 102, 111, 47, 65,
		109, 101, 114, 105, 99, 97, 47, 78, 101, 119, 95, 89, 111, 114, 107, 0, 0, 0, 0, 0, 0,
	}
	data := UnifiedLogData{}

	getHeaderData(testChunkHeader, &data)
	if len(data.Header) != 1 {
		t.Fatalf("header len = %d, want 1", len(data.Header))
	}
}

func TestGetCatalogData(t *testing.T) {
	testChunkCatalog := []byte{
		11, 96, 0, 0, 17, 0, 0, 0, 208, 1, 0, 0, 0, 0, 0, 0, 32, 0, 96, 0, 1, 0, 160, 0, 7, 0, 0, 0,
		0, 0, 0, 0, 20, 165, 44, 35, 253, 233, 2, 0, 43, 239, 210, 12, 24, 236, 56, 56, 129, 79, 43,
		78, 90, 243, 188, 236, 61, 5, 132, 95, 63, 101, 53, 143, 158, 191, 34, 54, 231, 114, 172, 1,
		99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 83, 107, 121, 76, 105, 103, 104, 116, 0, 112,
		101, 114, 102, 111, 114, 109, 97, 110, 99, 101, 95, 105, 110, 115, 116, 114, 117, 109, 101,
		110, 116, 97, 116, 105, 111, 110, 0, 116, 114, 97, 99, 105, 110, 103, 46, 115, 116, 97, 108,
		108, 115, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 158, 0, 0, 0, 0, 0, 0, 0, 55, 1, 0, 0, 158, 0, 0,
		0, 88, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 87, 0, 0, 0, 19,
		0, 78, 0, 0, 0, 47, 0, 0, 0, 0, 0, 246, 113, 118, 43, 250, 233, 2, 0, 62, 195, 90, 26, 9, 234,
		2, 0, 120, 255, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 19, 0, 47, 0, 48, 89,
		60, 28, 9, 234, 2, 0, 99, 50, 207, 40, 18, 234, 2, 0, 112, 240, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0,
		0, 0, 3, 0, 0, 0, 0, 0, 19, 0, 47, 0, 153, 6, 208, 41, 18, 234, 2, 0, 0, 214, 108, 78, 32,
		234, 2, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 19, 0, 47, 0, 128, 0,
		87, 79, 32, 234, 2, 0, 137, 5, 2, 205, 41, 234, 2, 0, 88, 255, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0,
		0, 0, 3, 0, 0, 0, 0, 0, 19, 0, 47, 0, 185, 11, 2, 205, 41, 234, 2, 0, 172, 57, 107, 20, 56,
		234, 2, 0, 152, 255, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 19, 0, 47, 0, 53,
		172, 105, 21, 56, 234, 2, 0, 170, 167, 194, 43, 68, 234, 2, 0, 144, 255, 0, 0, 0, 1, 0, 0, 1,
		0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 19, 0, 47, 0, 220, 202, 171, 57, 68, 234, 2, 0, 119, 171,
		170, 119, 76, 234, 2, 0, 240, 254, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 19,
		0, 47, 0,
	}
	data := UnifiedLogCatalogData{}

	getCatalogData(testChunkCatalog, &data)
	if data.Catalog.ChunkTag != 0x600b {
		t.Errorf("chunk_tag = %#x, want 0x600b", data.Catalog.ChunkTag)
	}
	if data.Catalog.ChunkSubTag != 17 {
		t.Errorf("chunk_sub_tag = %d", data.Catalog.ChunkSubTag)
	}
	if data.Catalog.ChunkDataSize != 464 {
		t.Errorf("chunk_data_size = %d", data.Catalog.ChunkDataSize)
	}
	if data.Catalog.CatalogSubsystemStringsOffset != 32 {
		t.Errorf("catalog_subsystem_strings_offset = %d", data.Catalog.CatalogSubsystemStringsOffset)
	}
	if data.Catalog.CatalogProcessInfoEntriesOffset != 96 {
		t.Errorf("catalog_process_info_entries_offset = %d", data.Catalog.CatalogProcessInfoEntriesOffset)
	}
	if data.Catalog.NumberProcessInformationEntries != 1 {
		t.Errorf("number_process_information_entries = %d", data.Catalog.NumberProcessInformationEntries)
	}
	if data.Catalog.CatalogOffsetSubChunks != 160 {
		t.Errorf("catalog_offset_sub_chunks = %d", data.Catalog.CatalogOffsetSubChunks)
	}
	if data.Catalog.NumberSubChunks != 7 {
		t.Errorf("number_sub_chunks = %d", data.Catalog.NumberSubChunks)
	}
	if data.Catalog.PersonaOffset != 0 {
		t.Errorf("persona_offset = %d", data.Catalog.PersonaOffset)
	}
	if data.Catalog.PersonaCount != 0 {
		t.Errorf("persona_count = %d", data.Catalog.PersonaCount)
	}
	if data.Catalog.EarliestFirehoseTimestamp != 820223379547412 {
		t.Errorf("earliest_firehose_timestamp = %d", data.Catalog.EarliestFirehoseTimestamp)
	}
	wantUUIDs := []string{
		"2BEFD20C18EC3838814F2B4E5AF3BCEC",
		"3D05845F3F65358F9EBF2236E772AC01",
	}
	if !reflect.DeepEqual(data.Catalog.CatalogUUIDs, wantUUIDs) {
		t.Errorf("catalog_uuids = %v, want %v", data.Catalog.CatalogUUIDs, wantUUIDs)
	}
	wantSubsystem := []byte{
		99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 83, 107, 121, 76, 105, 103, 104, 116,
		0, 112, 101, 114, 102, 111, 114, 109, 97, 110, 99, 101, 95, 105, 110, 115, 116,
		114, 117, 109, 101, 110, 116, 97, 116, 105, 111, 110, 0, 116, 114, 97, 99, 105,
		110, 103, 46, 115, 116, 97, 108, 108, 115, 0, 0, 0,
	}
	if !reflect.DeepEqual(data.Catalog.CatalogSubsystemStrings, wantSubsystem) {
		t.Errorf("catalog_subsystem_strings = %v", data.Catalog.CatalogSubsystemStrings)
	}
	if len(data.Catalog.CatalogProcessInfoEntries) != 1 {
		t.Errorf("process_info_entries len = %d", len(data.Catalog.CatalogProcessInfoEntries))
	}
	entry, ok := data.Catalog.CatalogProcessInfoEntries["158_311"]
	if !ok {
		t.Fatalf("missing process info entry 158_311, have %v", data.Catalog.CatalogProcessInfoEntries)
	}
	if entry.MainUUID != "2BEFD20C18EC3838814F2B4E5AF3BCEC" {
		t.Errorf("main_uuid = %q", entry.MainUUID)
	}
	if entry.DscUUID != "3D05845F3F65358F9EBF2236E772AC01" {
		t.Errorf("dsc_uuid = %q", entry.DscUUID)
	}
	if len(data.Catalog.CatalogSubchunks) != 7 {
		t.Errorf("catalog_subchunks len = %d", len(data.Catalog.CatalogSubchunks))
	}
}

func TestGetChunksetData(t *testing.T) {
	buffer := requireTestData(t, "Chunkset Tests/high_sierra_compressed_chunkset.raw")

	var unifiedLog UnifiedLogCatalogData
	var logData UnifiedLogData

	getChunksetLogData(buffer, &unifiedLog, &logData)
	if unifiedLog.Catalog.ChunkTag != 0 {
		t.Errorf("chunk_tag = %d, want 0", unifiedLog.Catalog.ChunkTag)
	}
	if len(unifiedLog.Firehose) != 21 {
		t.Errorf("firehose len = %d, want 21", len(unifiedLog.Firehose))
	}
	if len(unifiedLog.Statedump) != 0 {
		t.Errorf("statedump len = %d", len(unifiedLog.Statedump))
	}
	if len(unifiedLog.Simpledump) != 0 {
		t.Errorf("simpledump len = %d", len(unifiedLog.Simpledump))
	}
	if len(unifiedLog.Oversize) != 0 {
		t.Errorf("oversize len = %d", len(unifiedLog.Oversize))
	}
	if unifiedLog.Firehose[0].PublicData[0].Message.ItemInfo[0].MessageStrings != "483.700" {
		t.Errorf("message_strings = %q", unifiedLog.Firehose[0].PublicData[0].Message.ItemInfo[0].MessageStrings)
	}
	if unifiedLog.Firehose[0].BaseContinousTime != 0 {
		t.Errorf("base_continous_time = %d", unifiedLog.Firehose[0].BaseContinousTime)
	}
	if unifiedLog.Firehose[0].FirstNumberProcID != 70 {
		t.Errorf("first_number_proc_id = %d", unifiedLog.Firehose[0].FirstNumberProcID)
	}
	if unifiedLog.Firehose[0].SecondNumberProcID != 71 {
		t.Errorf("second_number_proc_id = %d", unifiedLog.Firehose[0].SecondNumberProcID)
	}
	if unifiedLog.Firehose[0].PublicDataSize != 4040 {
		t.Errorf("public_data_size = %d", unifiedLog.Firehose[0].PublicDataSize)
	}
	if unifiedLog.Firehose[0].PrivateDataVirtualOffset != 4096 {
		t.Errorf("private_data_virtual_offset = %d", unifiedLog.Firehose[0].PrivateDataVirtualOffset)
	}
}

func TestTrackMissing(t *testing.T) {
	var firstProcID uint64 = 1
	var secondProcID uint32 = 2
	var time uint64 = 11
	testFirehose := Firehose{}

	missingFirehose := trackMissing(firstProcID, secondProcID, time, testFirehose)
	if missingFirehose.FirstNumberProcID != firstProcID {
		t.Errorf("first_number_proc_id = %d", missingFirehose.FirstNumberProcID)
	}
	if missingFirehose.SecondNumberProcID != secondProcID {
		t.Errorf("second_number_proc_id = %d", missingFirehose.SecondNumberProcID)
	}
	if missingFirehose.BaseContinousTime != time {
		t.Errorf("base_continous_time = %d", missingFirehose.BaseContinousTime)
	}
}

func TestAddMissing(t *testing.T) {
	var missing UnifiedLogData

	path := requireTestDataFile(t, "system_logs_big_sur.logarchive/Persist/0000000000000002.tracev3")
	buffer := requireTestData(t, "system_logs_big_sur.logarchive/Persist/0000000000000002.tracev3")
	logData, err := ParseLog(bytes.NewReader(buffer), path)
	if err != nil {
		t.Fatalf("ParseLog: %v", err)
	}

	addMissing(&logData.CatalogData[0], 0, 0, logData.Header, &missing, logData.CatalogData[0].Firehose[0])
	if len(missing.Header) != 1 {
		t.Fatalf("header len = %d", len(missing.Header))
	}
	if missing.Header[0].BootUUID != "80D194AF56A34C54867449D2130D41BB" {
		t.Errorf("boot_uuid = %q", missing.Header[0].BootUUID)
	}
	if missing.Header[0].LogdPid != 42 {
		t.Errorf("logd_pid = %d", missing.Header[0].LogdPid)
	}
	if len(missing.CatalogData) != 1 {
		t.Fatalf("catalog_data len = %d", len(missing.CatalogData))
	}
	if missing.CatalogData[0].Catalog.CatalogSubsystemStringsOffset != 848 {
		t.Errorf("subsystem offset = %d", missing.CatalogData[0].Catalog.CatalogSubsystemStringsOffset)
	}
	if len(missing.CatalogData[0].Firehose) != 1 {
		t.Fatalf("firehose len = %d", len(missing.CatalogData[0].Firehose))
	}
	if missing.CatalogData[0].Firehose[0].FirstNumberProcID != 45 {
		t.Errorf("first_number_proc_id = %d", missing.CatalogData[0].Firehose[0].FirstNumberProcID)
	}
	if missing.CatalogData[0].Firehose[0].SecondNumberProcID != 188 {
		t.Errorf("second_number_proc_id = %d", missing.CatalogData[0].Firehose[0].SecondNumberProcID)
	}
}
