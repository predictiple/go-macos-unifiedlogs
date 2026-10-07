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

var catalogTestChunkCatalog = []byte{
	11, 96, 0, 0, 17, 0, 0, 0, 208, 1, 0, 0, 0, 0, 0, 0,
	32, 0, 96, 0, 1, 0, 160, 0, 7, 0, 0, 0, 0, 0, 0, 0,
	20, 165, 44, 35, 253, 233, 2, 0, 43, 239, 210, 12, 24, 236, 56, 56,
	129, 79, 43, 78, 90, 243, 188, 236, 61, 5, 132, 95, 63, 101, 53, 143,
	158, 191, 34, 54, 231, 114, 172, 1, 99, 111, 109, 46, 97, 112, 112, 108,
	101, 46, 83, 107, 121, 76, 105, 103, 104, 116, 0, 112, 101, 114, 102, 111,
	114, 109, 97, 110, 99, 101, 95, 105, 110, 115, 116, 114, 117, 109, 101, 110,
	116, 97, 116, 105, 111, 110, 0, 116, 114, 97, 99, 105, 110, 103, 46, 115,
	116, 97, 108, 108, 115, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0,
	158, 0, 0, 0, 0, 0, 0, 0, 55, 1, 0, 0, 158, 0, 0, 0,
	88, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	2, 0, 0, 0, 0, 0, 0, 0, 87, 0, 0, 0, 19, 0, 78, 0,
	0, 0, 47, 0, 0, 0, 0, 0, 246, 113, 118, 43, 250, 233, 2, 0,
	62, 195, 90, 26, 9, 234, 2, 0, 120, 255, 0, 0, 0, 1, 0, 0,
	1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 19, 0, 47, 0,
	48, 89, 60, 28, 9, 234, 2, 0, 99, 50, 207, 40, 18, 234, 2, 0,
	112, 240, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 3, 0,
	0, 0, 0, 0, 19, 0, 47, 0, 153, 6, 208, 41, 18, 234, 2, 0,
	0, 214, 108, 78, 32, 234, 2, 0, 0, 0, 1, 0, 0, 1, 0, 0,
	1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 19, 0, 47, 0,
	128, 0, 87, 79, 32, 234, 2, 0, 137, 5, 2, 205, 41, 234, 2, 0,
	88, 255, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 3, 0,
	0, 0, 0, 0, 19, 0, 47, 0, 185, 11, 2, 205, 41, 234, 2, 0,
	172, 57, 107, 20, 56, 234, 2, 0, 152, 255, 0, 0, 0, 1, 0, 0,
	1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 19, 0, 47, 0,
	53, 172, 105, 21, 56, 234, 2, 0, 170, 167, 194, 43, 68, 234, 2, 0,
	144, 255, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 3, 0,
	0, 0, 0, 0, 19, 0, 47, 0, 220, 202, 171, 57, 68, 234, 2, 0,
	119, 171, 170, 119, 76, 234, 2, 0, 240, 254, 0, 0, 0, 1, 0, 0,
	1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 19, 0, 47, 0,
}

var catalogTestSubsystemData = []byte{
	0, 0, 0, 0, 0, 0, 1, 0, 158, 0, 0, 0, 0, 0, 0, 0,
	55, 1, 0, 0, 158, 0, 0, 0, 88, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0,
	87, 0, 0, 0, 19, 0, 78, 0, 0, 0, 47, 0, 0, 0, 0, 0,
	246, 113, 118, 43, 250, 233, 2, 0, 62, 195, 90, 26, 9, 234, 2, 0,
	120, 255, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 3, 0,
	0, 0, 0, 0, 19, 0, 47, 0, 48, 89, 60, 28, 9, 234, 2, 0,
	99, 50, 207, 40, 18, 234, 2, 0, 112, 240, 0, 0, 0, 1, 0, 0,
	1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 19, 0, 47, 0,
	153, 6, 208, 41, 18, 234, 2, 0, 0, 214, 108, 78, 32, 234, 2, 0,
	0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 3, 0,
	0, 0, 0, 0, 19, 0, 47, 0, 128, 0, 87, 79, 32, 234, 2, 0,
	137, 5, 2, 205, 41, 234, 2, 0, 88, 255, 0, 0, 0, 1, 0, 0,
	1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 19, 0, 47, 0,
	185, 11, 2, 205, 41, 234, 2, 0, 172, 57, 107, 20, 56, 234, 2, 0,
	152, 255, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 3, 0,
	0, 0, 0, 0, 19, 0, 47, 0, 53, 172, 105, 21, 56, 234, 2, 0,
	170, 167, 194, 43, 68, 234, 2, 0, 144, 255, 0, 0, 0, 1, 0, 0,
	1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 19, 0, 47, 0,
	220, 202, 171, 57, 68, 234, 2, 0, 119, 171, 170, 119, 76, 234, 2, 0,
	240, 254, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 3, 0,
	0, 0, 0, 0, 19, 0, 47, 0,
}

var catalogTestSubsystemData2 = []byte{
	87, 0, 0, 0, 19, 0, 78, 0, 0, 0, 47, 0, 0, 0, 0, 0,
	246, 113, 118, 43, 250, 233, 2, 0, 62, 195, 90, 26, 9, 234, 2, 0,
	120, 255, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 3, 0,
	0, 0, 0, 0, 19, 0, 47, 0, 48, 89, 60, 28, 9, 234, 2, 0,
	99, 50, 207, 40, 18, 234, 2, 0, 112, 240, 0, 0, 0, 1, 0, 0,
	1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 19, 0, 47, 0,
	153, 6, 208, 41, 18, 234, 2, 0, 0, 214, 108, 78, 32, 234, 2, 0,
	0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 3, 0,
	0, 0, 0, 0, 19, 0, 47, 0, 128, 0, 87, 79, 32, 234, 2, 0,
	137, 5, 2, 205, 41, 234, 2, 0, 88, 255, 0, 0, 0, 1, 0, 0,
	1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 19, 0, 47, 0,
	185, 11, 2, 205, 41, 234, 2, 0, 172, 57, 107, 20, 56, 234, 2, 0,
	152, 255, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 3, 0,
	0, 0, 0, 0, 19, 0, 47, 0, 53, 172, 105, 21, 56, 234, 2, 0,
	170, 167, 194, 43, 68, 234, 2, 0, 144, 255, 0, 0, 0, 1, 0, 0,
	1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 19, 0, 47, 0,
	220, 202, 171, 57, 68, 234, 2, 0, 119, 171, 170, 119, 76, 234, 2, 0,
	240, 254, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 3, 0,
	0, 0, 0, 0, 19, 0, 47, 0,
}

var catalogTestSubchunks = []byte{
	246, 113, 118, 43, 250, 233, 2, 0, 62, 195, 90, 26, 9, 234, 2, 0,
	120, 255, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 3, 0,
	0, 0, 0, 0, 19, 0, 47, 0, 48, 89, 60, 28, 9, 234, 2, 0,
	99, 50, 207, 40, 18, 234, 2, 0, 112, 240, 0, 0, 0, 1, 0, 0,
	1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 19, 0, 47, 0,
	153, 6, 208, 41, 18, 234, 2, 0, 0, 214, 108, 78, 32, 234, 2, 0,
	0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 3, 0,
	0, 0, 0, 0, 19, 0, 47, 0, 128, 0, 87, 79, 32, 234, 2, 0,
	137, 5, 2, 205, 41, 234, 2, 0, 88, 255, 0, 0, 0, 1, 0, 0,
	1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 19, 0, 47, 0,
	185, 11, 2, 205, 41, 234, 2, 0, 172, 57, 107, 20, 56, 234, 2, 0,
	152, 255, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 3, 0,
	0, 0, 0, 0, 19, 0, 47, 0, 53, 172, 105, 21, 56, 234, 2, 0,
	170, 167, 194, 43, 68, 234, 2, 0, 144, 255, 0, 0, 0, 1, 0, 0,
	1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 19, 0, 47, 0,
	220, 202, 171, 57, 68, 234, 2, 0, 119, 171, 170, 119, 76, 234, 2, 0,
	240, 254, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 3, 0,
	0, 0, 0, 0, 19, 0, 47, 0,
}

var catalogTestBadCompression = []byte{
	246, 113, 118, 43, 250, 233, 2, 0, 62, 195, 90, 26, 9, 234, 2, 0,
	120, 255, 0, 0, 0, 2, 0, 0, 1, 0, 0, 0, 0, 0, 3, 0,
	0, 0, 0, 0, 19, 0, 47, 0, 48, 89, 60, 28, 9, 234, 2, 0,
	99, 50, 207, 40, 18, 234, 2, 0, 112, 240, 0, 0, 0, 1, 0, 0,
	1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 19, 0, 47, 0,
	153, 6, 208, 41, 18, 234, 2, 0, 0, 214, 108, 78, 32, 234, 2, 0,
	0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 3, 0,
	0, 0, 0, 0, 19, 0, 47, 0, 128, 0, 87, 79, 32, 234, 2, 0,
	137, 5, 2, 205, 41, 234, 2, 0, 88, 255, 0, 0, 0, 1, 0, 0,
	1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 19, 0, 47, 0,
	185, 11, 2, 205, 41, 234, 2, 0, 172, 57, 107, 20, 56, 234, 2, 0,
	152, 255, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 3, 0,
	0, 0, 0, 0, 19, 0, 47, 0, 53, 172, 105, 21, 56, 234, 2, 0,
	170, 167, 194, 43, 68, 234, 2, 0, 144, 255, 0, 0, 0, 1, 0, 0,
	1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 19, 0, 47, 0,
	220, 202, 171, 57, 68, 234, 2, 0, 119, 171, 170, 119, 76, 234, 2, 0,
	240, 254, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 3, 0,
	0, 0, 0, 0, 19, 0, 47, 0,
}

var catalogTestPersona = []byte{
	16, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 232, 99, 0, 0,
	5, 0, 0, 0, 37, 0, 0, 0, 101, 0, 0, 0, 4, 0, 0, 0,
	74, 0, 0, 0, 0, 0, 0, 0, 89, 69, 69, 68, 69, 69, 69, 69,
	45, 68, 68, 68, 68, 45, 67, 67, 67, 67, 45, 66, 66, 66, 66, 45,
	53, 53, 53, 53, 48, 48, 48, 48, 48, 49, 70, 53, 0, 89, 69, 69,
	68, 69, 69, 69, 69, 45, 68, 68, 68, 68, 45, 67, 67, 67, 67, 45,
	66, 66, 66, 66, 45, 48, 48, 48, 48, 48, 48, 48, 48, 48, 49, 70,
	53, 0, 89, 69, 69, 68, 69, 69, 69, 69, 45, 68, 68, 68, 68, 45,
	67, 67, 67, 67, 45, 66, 66, 66, 66, 45, 51, 51, 51, 51, 48, 48,
	48, 48, 48, 49, 70, 53, 0, 0,
}

func TestParseCatalog(t *testing.T) {
	_, catalogData, err := parseCatalog(catalogTestChunkCatalog)
	if err != nil {
		t.Fatalf("parseCatalog returned error: %v", err)
	}

	if catalogData.ChunkTag != 0x600b {
		t.Fatalf("unexpected chunk_tag: %d", catalogData.ChunkTag)
	}
	if catalogData.ChunkSubTag != 17 {
		t.Fatalf("unexpected chunk_sub_tag: %d", catalogData.ChunkSubTag)
	}
	if catalogData.ChunkDataSize != 464 {
		t.Fatalf("unexpected chunk_data_size: %d", catalogData.ChunkDataSize)
	}
	if catalogData.CatalogSubsystemStringsOffset != 32 {
		t.Fatalf("unexpected catalog_subsystem_strings_offset: %d", catalogData.CatalogSubsystemStringsOffset)
	}
	if catalogData.CatalogProcessInfoEntriesOffset != 96 {
		t.Fatalf("unexpected catalog_process_info_entries_offset: %d", catalogData.CatalogProcessInfoEntriesOffset)
	}
	if catalogData.NumberProcessInformationEntries != 1 {
		t.Fatalf("unexpected number_process_information_entries: %d", catalogData.NumberProcessInformationEntries)
	}
	if catalogData.CatalogOffsetSubChunks != 160 {
		t.Fatalf("unexpected catalog_offset_sub_chunks: %d", catalogData.CatalogOffsetSubChunks)
	}
	if catalogData.NumberSubChunks != 7 {
		t.Fatalf("unexpected number_sub_chunks: %d", catalogData.NumberSubChunks)
	}
	if catalogData.PersonaOffset != 0 {
		t.Fatalf("unexpected persona_offset: %d", catalogData.PersonaOffset)
	}
	if catalogData.PersonaCount != 0 {
		t.Fatalf("unexpected persona_count: %d", catalogData.PersonaCount)
	}
	if catalogData.EarliestFirehoseTimestamp != 820223379547412 {
		t.Fatalf("unexpected earliest_firehose_timestamp: %d", catalogData.EarliestFirehoseTimestamp)
	}

	expectedUUIDs := []string{
		"2BEFD20C18EC3838814F2B4E5AF3BCEC",
		"3D05845F3F65358F9EBF2236E772AC01",
	}
	if !reflect.DeepEqual(catalogData.CatalogUUIDs, expectedUUIDs) {
		t.Fatalf("unexpected catalog_uuids: %v", catalogData.CatalogUUIDs)
	}

	expectedSubsystemStrings := []byte("com.apple.SkyLight\x00performance_instrumentation\x00tracing.stalls\x00\x00\x00")
	if !bytes.Equal(catalogData.CatalogSubsystemStrings, expectedSubsystemStrings) {
		t.Fatalf("unexpected catalog_subsystem_strings: %v", catalogData.CatalogSubsystemStrings)
	}

	if len(catalogData.CatalogProcessInfoEntries) != 1 {
		t.Fatalf("unexpected catalog_process_info_entries length: %d", len(catalogData.CatalogProcessInfoEntries))
	}
	entry, ok := catalogData.CatalogProcessInfoEntries["158_311"]
	if !ok {
		t.Fatal("missing process entry 158_311")
	}
	if entry.MainUUID != "2BEFD20C18EC3838814F2B4E5AF3BCEC" {
		t.Fatalf("unexpected main_uuid: %s", entry.MainUUID)
	}
	if entry.DscUUID != "3D05845F3F65358F9EBF2236E772AC01" {
		t.Fatalf("unexpected dsc_uuid: %s", entry.DscUUID)
	}

	if len(catalogData.CatalogSubchunks) != 7 {
		t.Fatalf("unexpected catalog_subchunks: %d", len(catalogData.CatalogSubchunks))
	}
}

func TestParseCatalogProcessEntry(t *testing.T) {
	testData := []string{"MAIN", "DSC", "OTHER"}

	c := newCursor(catalogTestSubsystemData)
	processEntry, err := parseCatalogProcessEntry(c, testData)
	if err != nil {
		t.Fatalf("parseCatalogProcessEntry returned error: %v", err)
	}

	if processEntry.Index != 0 {
		t.Fatalf("unexpected index: %d", processEntry.Index)
	}
	if processEntry.Unknown != 0 {
		t.Fatalf("unexpected unknown: %d", processEntry.Unknown)
	}
	if processEntry.CatalogMainUUIDIndex != 0 {
		t.Fatalf("unexpected catalog_main_uuid_index: %d", processEntry.CatalogMainUUIDIndex)
	}
	if processEntry.CatalogDscUUIDIndex != 1 {
		t.Fatalf("unexpected catalog_dsc_uuid_index: %d", processEntry.CatalogDscUUIDIndex)
	}
	if processEntry.FirstNumberProcID != 158 {
		t.Fatalf("unexpected first_number_proc_id: %d", processEntry.FirstNumberProcID)
	}
	if processEntry.SecondNumberProcID != 311 {
		t.Fatalf("unexpected second_number_proc_id: %d", processEntry.SecondNumberProcID)
	}
	if processEntry.PID != 158 {
		t.Fatalf("unexpected pid: %d", processEntry.PID)
	}
	if processEntry.EffectiveUserID != 88 {
		t.Fatalf("unexpected effective_user_id: %d", processEntry.EffectiveUserID)
	}
	if processEntry.PersonaID != 0 {
		t.Fatalf("unexpected persona_id: %d", processEntry.PersonaID)
	}
	if processEntry.NumberUUIDsEntries != 0 {
		t.Fatalf("unexpected number_uuids_entries: %d", processEntry.NumberUUIDsEntries)
	}
	if processEntry.Unknown3 != 0 {
		t.Fatalf("unexpected unknown3: %d", processEntry.Unknown3)
	}
	if len(processEntry.UUIDInfoEntries) != 0 {
		t.Fatalf("unexpected uuid_info_entries length: %d", len(processEntry.UUIDInfoEntries))
	}
	if processEntry.NumberSubsystems != 2 {
		t.Fatalf("unexpected number_subsystems: %d", processEntry.NumberSubsystems)
	}
	if processEntry.Unknown4 != 0 {
		t.Fatalf("unexpected unknown4: %d", processEntry.Unknown4)
	}
	if len(processEntry.SubsystemEntries) != 2 {
		t.Fatalf("unexpected subsystem_entries length: %d", len(processEntry.SubsystemEntries))
	}
	if processEntry.MainUUID != "MAIN" {
		t.Fatalf("unexpected main_uuid: %s", processEntry.MainUUID)
	}
	if processEntry.DscUUID != "DSC" {
		t.Fatalf("unexpected dsc_uuid: %s", processEntry.DscUUID)
	}
}

func TestParseProcessInfoUUIDEntry(t *testing.T) {
	c := newCursor(catalogTestSubsystemData2)
	subsystems, err := parseProcessInfoSubystem(c)
	if err != nil {
		t.Fatalf("parseProcessInfoSubystem returned error: %v", err)
	}
	if subsystems.Identifier != 87 {
		t.Fatalf("unexpected identifier: %d", subsystems.Identifier)
	}
	if subsystems.SubsystemOffset != 0 {
		t.Fatalf("unexpected subsystem_offset: %d", subsystems.SubsystemOffset)
	}
	if subsystems.CategoryOffset != 19 {
		t.Fatalf("unexpected category_offset: %d", subsystems.CategoryOffset)
	}

	subsystems, err = parseProcessInfoSubystem(c)
	if err != nil {
		t.Fatalf("parseProcessInfoSubystem returned error: %v", err)
	}
	if subsystems.Identifier != 78 {
		t.Fatalf("unexpected identifier: %d", subsystems.Identifier)
	}
	if subsystems.SubsystemOffset != 0 {
		t.Fatalf("unexpected subsystem_offset: %d", subsystems.SubsystemOffset)
	}
	if subsystems.CategoryOffset != 47 {
		t.Fatalf("unexpected category_offset: %d", subsystems.CategoryOffset)
	}
}

func TestParseCatalogSubchunk(t *testing.T) {
	c := newCursor(catalogTestSubchunks)

	subchunk, err := parseCatalogSubchunk(c)
	if err != nil {
		t.Fatalf("parseCatalogSubchunk returned error: %v", err)
	}
	if subchunk.Start != 820210633699830 {
		t.Fatalf("unexpected start: %d", subchunk.Start)
	}
	if subchunk.End != 820274771182398 {
		t.Fatalf("unexpected end: %d", subchunk.End)
	}
	if subchunk.UncompressedSize != 65400 {
		t.Fatalf("unexpected uncompressed_size: %d", subchunk.UncompressedSize)
	}
	if subchunk.CompressionAlgorithm != 256 {
		t.Fatalf("unexpected compression_algorithm: %d", subchunk.CompressionAlgorithm)
	}
	if subchunk.NumberIndex != 1 {
		t.Fatalf("unexpected number_index: %d", subchunk.NumberIndex)
	}
	if !reflect.DeepEqual(subchunk.Indexes, []uint16{0}) {
		t.Fatalf("unexpected indexes: %v", subchunk.Indexes)
	}
	if subchunk.NumberStringOffsets != 3 {
		t.Fatalf("unexpected number_string_offsets: %d", subchunk.NumberStringOffsets)
	}
	if !reflect.DeepEqual(subchunk.StringOffsets, []uint16{0, 19, 47}) {
		t.Fatalf("unexpected string_offsets: %v", subchunk.StringOffsets)
	}

	subchunk, err = parseCatalogSubchunk(c)
	if err != nil {
		t.Fatalf("parseCatalogSubchunk returned error: %v", err)
	}
	if subchunk.Start != 820274802743600 {
		t.Fatalf("unexpected start: %d", subchunk.Start)
	}
	if subchunk.End != 820313668399715 {
		t.Fatalf("unexpected end: %d", subchunk.End)
	}
	if subchunk.UncompressedSize != 61552 {
		t.Fatalf("unexpected uncompressed_size: %d", subchunk.UncompressedSize)
	}

	subchunk, err = parseCatalogSubchunk(c)
	if err != nil {
		t.Fatalf("parseCatalogSubchunk returned error: %v", err)
	}
	if subchunk.Start != 820313685231257 {
		t.Fatalf("unexpected start: %d", subchunk.Start)
	}
	if subchunk.End != 820374429029888 {
		t.Fatalf("unexpected end: %d", subchunk.End)
	}
	if subchunk.UncompressedSize != 65536 {
		t.Fatalf("unexpected uncompressed_size: %d", subchunk.UncompressedSize)
	}
}

func TestParseCatalogSubchunkBadCompression(t *testing.T) {
	c := newCursor(catalogTestBadCompression)
	if _, err := parseCatalogSubchunk(c); err == nil {
		t.Fatal("expected error for bad compression")
	}
}

func TestParseCatalogPersona(t *testing.T) {
	results, err := parseCatalogPersona(catalogTestPersona, 3)
	if err != nil {
		t.Fatalf("parseCatalogPersona returned error: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("unexpected persona length: %d", len(results))
	}

	expected := []CatalogPersona{
		{PersonaID: 16, PersonaType: 6, UUIDOffset: 0, UUID: "YEEDEEEE-DDDD-CCCC-BBBB-5555000001F5"},
		{PersonaID: 25576, PersonaType: 5, UUIDOffset: 37, UUID: "YEEDEEEE-DDDD-CCCC-BBBB-0000000001F5"},
		{PersonaID: 101, PersonaType: 4, UUIDOffset: 74, UUID: "YEEDEEEE-DDDD-CCCC-BBBB-3333000001F5"},
	}
	if !reflect.DeepEqual(results, expected) {
		t.Fatalf("unexpected personas: %+v", results)
	}
}

func TestGetBigSurSubsystem(t *testing.T) {
	buffer := requireTestData(t, "Catalog Tests/big_sur_catalog.raw")

	_, catalog, err := parseCatalog(buffer)
	if err != nil {
		t.Fatalf("parseCatalog returned error: %v", err)
	}

	results, err := catalog.GetSubsystem(4, 165, 406)
	if err != nil {
		t.Fatalf("GetSubsystem returned error: %v", err)
	}
	if results.Subsystem != "com.apple.containermanager" {
		t.Fatalf("unexpected subsystem: %s", results.Subsystem)
	}
	if results.Category != "xpc" {
		t.Fatalf("unexpected category: %s", results.Category)
	}
}
