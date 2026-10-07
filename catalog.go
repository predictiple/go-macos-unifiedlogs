// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

import (
	"encoding/binary"
	"fmt"
)

// CatalogChunk is the parsed log Catalog data.
type CatalogChunk struct {
	ChunkTag      uint32 `json:"chunk_tag"`
	ChunkSubTag   uint32 `json:"chunk_sub_tag"`
	ChunkDataSize uint64 `json:"chunk_data_size"`
	// offset relative to start of catalog UUIDs
	CatalogSubsystemStringsOffset uint16 `json:"catalog_subsystem_strings_offset"`
	// offset relative to start of catalog UUIDs
	CatalogProcessInfoEntriesOffset uint16 `json:"catalog_process_info_entries_offset"`
	NumberProcessInformationEntries uint16 `json:"number_process_information_entries"`
	// offset relative to start of catalog UUIDs
	CatalogOffsetSubChunks uint16 `json:"catalog_offset_sub_chunks"`
	NumberSubChunks        uint16 `json:"number_sub_chunks"`
	PersonaOffset          uint16 `json:"persona_offset"`
	PersonaCount           uint16 `json:"persona_count"`
	// Added in Golden Gate/iOS 27
	Personas                  []CatalogPersona `json:"personas"`
	EarliestFirehoseTimestamp uint64           `json:"earliest_firehose_timestamp"`
	// array of UUIDs in big endian
	CatalogUUIDs []string `json:"catalog_uuids"`
	// array of strings with end-of-string character
	CatalogSubsystemStrings   []byte                      `json:"catalog_subsystem_strings"`
	CatalogProcessInfoEntries map[string]ProcessInfoEntry `json:"catalog_process_info_entries"`
	CatalogSubchunks          []CatalogSubchunk           `json:"catalog_subchunks"`
}

// ProcessInfoEntry is a Catalog process information entry.
type ProcessInfoEntry struct {
	Index uint16 `json:"index"`
	// flags?
	Unknown              uint16 `json:"unknown"`
	CatalogMainUUIDIndex uint16 `json:"catalog_main_uuid_index"`
	CatalogDscUUIDIndex  uint16 `json:"catalog_dsc_uuid_index"`
	FirstNumberProcID    uint64 `json:"first_number_proc_id"`
	SecondNumberProcID   uint32 `json:"second_number_proc_id"`
	PID                  uint32 `json:"pid"`
	// euid
	EffectiveUserID uint32 `json:"effective_user_id"`
	// This may be Persona ID. Added in Golden Gate/iOS 27
	//
	// So far log raw-dump sets this to zero
	//
	// But similar values seen in the Persona section. Ex: 0xC8 and 0x3e8
	PersonaID          uint32 `json:"persona_id"`
	NumberUUIDsEntries uint32 `json:"number_uuids_entries"`
	Unknown3           uint32 `json:"unknown3"`
	// Catalog process information UUID information entry
	UUIDInfoEntries  []ProcessUUIDEntry `json:"uuid_info_entries"`
	NumberSubsystems uint32             `json:"number_subsystems"`
	Unknown4         uint32             `json:"unknown4"`
	// Catalog process information sub system
	SubsystemEntries []ProcessInfoSubsystem `json:"subsystem_entries"`
	// main UUID from `catalog_uuids`. Points to `UUIDinfo` file that contains strings
	MainUUID string `json:"main_uuid"`
	// dsc UUID from `catalog_uuids`. Points to dsc shared string file that contains strings
	DscUUID string `json:"dsc_uuid"`
}

// ProcessUUIDEntry is part of `ProcessInfoEntry`.
type ProcessUUIDEntry struct {
	Size             uint32 `json:"size"`
	Unknown          uint32 `json:"unknown"`
	CatalogUUIDIndex uint16 `json:"catalog_uuid_index"`
	LoadAddress      uint64 `json:"load_address"`
	UUID             string `json:"uuid"`
}

// ProcessInfoSubsystem is part of `ProcessInfoEntry`.
type ProcessInfoSubsystem struct {
	Identifier uint16 `json:"identifier"`
	// Represents the offset to the subsystem from the start of the subsystem entries
	SubsystemOffset uint16 `json:"subsystem_offset"`
	// Represents the offset to the subsystem category from the start of the subsystem entries
	CategoryOffset uint16 `json:"category_offset"`
}

// CatalogSubchunk is part of `CatalogChunk`, possible 64-bit alignment padding at end.
type CatalogSubchunk struct {
	Start            uint64 `json:"start"`
	End              uint64 `json:"end"`
	UncompressedSize uint32 `json:"uncompressed_size"`
	// Should always be LZ4 (0x100) or LZBITMAP (0x700)
	CompressionAlgorithm uint32 `json:"compression_algorithm"`
	NumberIndex          uint32 `json:"number_index"`
	// indexes size = `number_index` * u16
	Indexes             []uint16 `json:"indexes"`
	NumberStringOffsets uint32   `json:"number_string_offsets"`
	// `string_offsets` size = `number_string_offsets` * u16
	StringOffsets []uint16 `json:"string_offsets"`
}

// SubsystemInfo holds a subsystem and category pair.
type SubsystemInfo struct {
	Subsystem string `json:"subsystem"`
	Category  string `json:"category"`
}

// CatalogPersona is Golden Gate/iOS 27 persona data in the Catalog.
type CatalogPersona struct {
	PersonaID   uint32 `json:"persona_id"`
	PersonaType uint32 `json:"persona_type"`
	UUIDOffset  uint32 `json:"uuid_offset"`
	UUID        string `json:"uuid"`
}

// parseCatalog parses log Catalog data. The log Catalog contains metadata
// related to log entries such as Process info, Subsystem info, and the
// compressed log entries.
func parseCatalog(input []byte) ([]byte, CatalogChunk, error) {
	var catalog CatalogChunk

	preamble, err := parsePreamble(input)
	if err != nil {
		return nil, catalog, err
	}

	c := newCursor(input)
	if err := c.skip(16); err != nil {
		return nil, catalog, err
	}

	fields := make([]uint16, 8)
	for i := range fields {
		value, err := c.u16()
		if err != nil {
			return nil, catalog, err
		}
		fields[i] = value
	}
	catalogSubsystemStringsOffset := fields[0]
	catalogProcessInfoEntriesOffset := fields[1]
	numberProcessInformationEntries := fields[2]
	catalogOffsetSubChunks := fields[3]
	numberSubChunks := fields[4]
	personaOffset := fields[5]
	personaCount := fields[6]
	// fields[7] is _unknown

	earliestFirehoseTimestamp, err := c.u64()
	if err != nil {
		return nil, catalog, err
	}
	// All offsets start after the earliest firehose timestamp

	const uuidLength = 16
	numberCatalogUUIDs := int(catalogSubsystemStringsOffset) / uuidLength

	catalogUUIDs := make([]string, 0, numberCatalogUUIDs)
	for i := 0; i < numberCatalogUUIDs; i++ {
		value, err := c.u128be()
		if err != nil {
			return nil, catalog, err
		}
		catalogUUIDs = append(catalogUUIDs, u128Hex(value))
	}

	subsystemsStringsLength := int(catalogProcessInfoEntriesOffset) - int(catalogSubsystemStringsOffset)
	subsystemStringsData, err := c.take(subsystemsStringsLength)
	if err != nil {
		return nil, catalog, err
	}
	catalogSubsystemStrings := append([]byte{}, subsystemStringsData...)

	processInfoEntriesVec := make([]ProcessInfoEntry, 0, numberProcessInformationEntries)
	for i := 0; i < int(numberProcessInformationEntries); i++ {
		entry, err := parseCatalogProcessEntry(c, catalogUUIDs)
		if err != nil {
			return nil, catalog, err
		}
		processInfoEntriesVec = append(processInfoEntriesVec, entry)
	}

	catalogProcessInfoEntries := make(map[string]ProcessInfoEntry)
	for _, entry := range processInfoEntriesVec {
		key := fmt.Sprintf("%d_%d", entry.FirstNumberProcID, entry.SecondNumberProcID)
		catalogProcessInfoEntries[key] = entry
	}

	var personas []CatalogPersona
	if personaCount != 0 {
		// Persona data occurs prior to catalog subchunk offset
		// We can determine the size by subtracting persona offset from the catalog subchunk offset
		personaDataSize := int(catalogOffsetSubChunks) - int(personaOffset)
		personaData, err := c.take(personaDataSize)
		if err != nil {
			return nil, catalog, err
		}

		parsedPersonas, err := parseCatalogPersona(personaData, personaCount)
		if err != nil {
			return nil, catalog, err
		}
		personas = parsedPersonas
	}

	catalogSubchunks := make([]CatalogSubchunk, 0, numberSubChunks)
	for i := 0; i < int(numberSubChunks); i++ {
		subchunk, err := parseCatalogSubchunk(c)
		if err != nil {
			return nil, catalog, err
		}
		catalogSubchunks = append(catalogSubchunks, subchunk)
	}

	catalog = CatalogChunk{
		ChunkTag:                        preamble.ChunkTag,
		ChunkSubTag:                     preamble.ChunkSubTag,
		ChunkDataSize:                   preamble.ChunkDataSize,
		CatalogSubsystemStringsOffset:   catalogSubsystemStringsOffset,
		CatalogProcessInfoEntriesOffset: catalogProcessInfoEntriesOffset,
		NumberProcessInformationEntries: numberProcessInformationEntries,
		CatalogOffsetSubChunks:          catalogOffsetSubChunks,
		NumberSubChunks:                 numberSubChunks,
		PersonaOffset:                   personaOffset,
		PersonaCount:                    personaCount,
		Personas:                        personas,
		EarliestFirehoseTimestamp:       earliestFirehoseTimestamp,
		CatalogUUIDs:                    catalogUUIDs,
		CatalogSubsystemStrings:         catalogSubsystemStrings,
		CatalogProcessInfoEntries:       catalogProcessInfoEntries,
		CatalogSubchunks:                catalogSubchunks,
	}

	return c.rest(), catalog, nil
}

// parseCatalogProcessEntry parses the Catalog Process Information entry.
func parseCatalogProcessEntry(c *cursor, uuids []string) (ProcessInfoEntry, error) {
	var entry ProcessInfoEntry

	index, err := c.u16()
	if err != nil {
		return entry, err
	}
	unknown, err := c.u16()
	if err != nil {
		return entry, err
	}
	catalogMainUUIDIndex, err := c.u16()
	if err != nil {
		return entry, err
	}
	catalogDscUUIDIndex, err := c.u16()
	if err != nil {
		return entry, err
	}

	firstNumberProcID, err := c.u64()
	if err != nil {
		return entry, err
	}
	secondNumberProcID, err := c.u32()
	if err != nil {
		return entry, err
	}

	pid, err := c.u32()
	if err != nil {
		return entry, err
	}
	effectiveUserID, err := c.u32()
	if err != nil {
		return entry, err
	}
	personaID, err := c.u32()
	if err != nil {
		return entry, err
	}
	numberUUIDsEntries, err := c.u32()
	if err != nil {
		return entry, err
	}
	unknown3, err := c.u32()
	if err != nil {
		return entry, err
	}

	numUUIDs := int(numberUUIDsEntries)
	if numUUIDs > 10_000_000 { // clamp unreasonably large values
		numUUIDs = 10_000_000
	}
	uuidInfoEntries := make([]ProcessUUIDEntry, 0, numUUIDs)
	for i := 0; i < numUUIDs; i++ {
		uuidEntry, err := parseProcessInfoUUIDEntry(c, uuids)
		if err != nil {
			return entry, err
		}
		uuidInfoEntries = append(uuidInfoEntries, uuidEntry)
	}

	numberSubsystems, err := c.u32()
	if err != nil {
		return entry, err
	}
	unknown4, err := c.u32()
	if err != nil {
		return entry, err
	}

	subsystemEntries := make([]ProcessInfoSubsystem, 0, numberSubsystems)
	for i := 0; i < int(numberSubsystems); i++ {
		subsystem, err := parseProcessInfoSubystem(c)
		if err != nil {
			return entry, err
		}
		subsystemEntries = append(subsystemEntries, subsystem)
	}

	// Grab parsed UUIDs from Catalog array based on process entry uuid index
	mainUUID := ""
	if int(catalogMainUUIDIndex) < len(uuids) {
		mainUUID = uuids[catalogMainUUIDIndex]
	} else {
		logger.Printf("[macos-unifiedlogs] Could not find main UUID in catalog")
	}

	dscUUID := ""
	if int(catalogDscUUIDIndex) < len(uuids) {
		dscUUID = uuids[catalogDscUUIDIndex]
	}

	const subsystemSize uint64 = 6
	padding := anticipatedPaddingSize8(uint64(numberSubsystems), subsystemSize)
	paddingInt, ok := u64ToUint(padding)
	if !ok {
		logger.Printf("[macos-unifiedlogs] u64 is bigger than system usize")
		return entry, ErrTooLarge
	}
	if err := c.skip(paddingInt); err != nil {
		return entry, err
	}

	entry = ProcessInfoEntry{
		Index:                index,
		Unknown:              unknown,
		CatalogMainUUIDIndex: catalogMainUUIDIndex,
		CatalogDscUUIDIndex:  catalogDscUUIDIndex,
		FirstNumberProcID:    firstNumberProcID,
		SecondNumberProcID:   secondNumberProcID,
		PID:                  pid,
		EffectiveUserID:      effectiveUserID,
		PersonaID:            personaID,
		NumberUUIDsEntries:   numberUUIDsEntries,
		Unknown3:             unknown3,
		UUIDInfoEntries:      uuidInfoEntries,
		NumberSubsystems:     numberSubsystems,
		Unknown4:             unknown4,
		SubsystemEntries:     subsystemEntries,
		MainUUID:             mainUUID,
		DscUUID:              dscUUID,
	}
	return entry, nil
}

// parseProcessInfoUUIDEntry parses the UUID metadata in the Catalog Process
// Entry (the Catalog Process Entry references the UUIDs array parsed in
// `parseCatalog` by index value).
func parseProcessInfoUUIDEntry(c *cursor, uuids []string) (ProcessUUIDEntry, error) {
	var entry ProcessUUIDEntry

	size, err := c.u32()
	if err != nil {
		return entry, err
	}
	unknown, err := c.u32()
	if err != nil {
		return entry, err
	}
	catalogUUIDIndex, err := c.u16()
	if err != nil {
		return entry, err
	}

	const loadAddressSize = 6
	loadAddressBytes, err := c.take(loadAddressSize)
	if err != nil {
		return entry, err
	}
	var loadAddressVec [8]byte
	copy(loadAddressVec[:], loadAddressBytes)
	loadAddress := binary.LittleEndian.Uint64(loadAddressVec[:])

	if int(catalogUUIDIndex) >= len(uuids) {
		return entry, ErrEof
	}
	uuid := uuids[catalogUUIDIndex]

	entry = ProcessUUIDEntry{
		Size:             size,
		Unknown:          unknown,
		CatalogUUIDIndex: catalogUUIDIndex,
		LoadAddress:      loadAddress,
		UUID:             uuid,
	}
	return entry, nil
}

// parseProcessInfoSubystem parses the Catalog Subsystem metadata. This helps
// get the subsystem (App Bundle ID) and the log entry category.
func parseProcessInfoSubystem(c *cursor) (ProcessInfoSubsystem, error) {
	var subsystem ProcessInfoSubsystem

	identifier, err := c.u16()
	if err != nil {
		return subsystem, err
	}
	subsystemOffset, err := c.u16()
	if err != nil {
		return subsystem, err
	}
	categoryOffset, err := c.u16()
	if err != nil {
		return subsystem, err
	}

	subsystem = ProcessInfoSubsystem{
		Identifier:      identifier,
		SubsystemOffset: subsystemOffset,
		CategoryOffset:  categoryOffset,
	}
	return subsystem, nil
}

// parseCatalogPersona parses the new Catalog section data added in Golden Gate
// and iOS 27. This may match with Kernel Persona info from the umtool.
func parseCatalogPersona(data []byte, count uint16) ([]CatalogPersona, error) {
	c := newCursor(data)
	personaDataCount := uint16(0)

	personas := []CatalogPersona{}
	for personaDataCount < count {
		// Persona ID always matches with a UUID?
		// 0xc8 is always "FEEDEEEE-DDDD-CCCC-BBBB-5555000001F5"?
		// 0xc7 is always "FEEDEEEE-DDDD-CCCC-BBBB-550000000000"?
		// These are guest personas? However, 0x1F5 = 501 which is a common UID
		personaID, err := c.u32()
		if err != nil {
			return nil, err
		}
		// I think these are kernel persona id types
		// https://github.com/apple/darwin-xnu/blob/2ff845c2e033bd0ff64b5b6aa6063a1f8f65aa32/bsd/sys/persona.h#L38
		personaType, err := c.u32()
		if err != nil {
			return nil, err
		}
		uuidOffset, err := c.u32()
		if err != nil {
			return nil, err
		}
		persona := CatalogPersona{
			PersonaID:   personaID,
			PersonaType: personaType,
			UUIDOffset:  uuidOffset,
			UUID:        "",
		}

		personaDataCount++
		personas = append(personas, persona)
	}

	// The first part of the persona data seems to align with 8 byte offsets
	// So there may be padding at the end
	const personaHeaderSize = 12
	paddingSize := paddingSize8(uint64(count) * personaHeaderSize)
	paddingSizeInt, ok := u64ToUint(paddingSize)
	if !ok {
		logger.Printf("[macos-unifiedlogs] u64 is bigger than system usize")
		return nil, ErrTooLarge
	}
	if err := c.skip(paddingSizeInt); err != nil {
		return nil, err
	}

	// Includes end of string character
	const uuidStringSize = 37

	// Now get the UUIDs
	// Each is 37 bytes in size (UUID size + end of string character ('0'))
	for i := range personas {
		uuidData, err := c.take(uuidStringSize)
		if err != nil {
			return nil, err
		}
		_, uuid, err := extractString(uuidData)
		if err != nil {
			return nil, err
		}

		personas[i].UUID = uuid
		logger.Printf("Persona info: '%+v'", personas[i])
	}

	paddingSize = paddingSize8(uint64(count) * uuidStringSize)
	paddingSizeInt, ok = u64ToUint(paddingSize)
	if !ok {
		logger.Printf("[macos-unifiedlogs] u64 is bigger than system usize")
		return nil, ErrTooLarge
	}
	if err := c.skip(paddingSizeInt); err != nil {
		return nil, err
	}

	return personas, nil
}

// parseCatalogSubchunk parses the Catalog Subchunk metadata. This metadata is
// related to the compressed (typically) Chunkset data.
func parseCatalogSubchunk(c *cursor) (CatalogSubchunk, error) {
	var subchunk CatalogSubchunk

	start, err := c.u64()
	if err != nil {
		return subchunk, err
	}
	end, err := c.u64()
	if err != nil {
		return subchunk, err
	}
	uncompressedSize, err := c.u32()
	if err != nil {
		return subchunk, err
	}
	compressionAlgorithm, err := c.u32()
	if err != nil {
		return subchunk, err
	}
	numberIndex, err := c.u32()
	if err != nil {
		return subchunk, err
	}

	const lz4Compression uint32 = 256
	lzbitmapCompression := [2]uint32{1792, 1793}
	if compressionAlgorithm != lz4Compression &&
		!(compressionAlgorithm == lzbitmapCompression[0] || compressionAlgorithm == lzbitmapCompression[1]) {
		logger.Printf("[macos-unifiedlogs] Unexpected compression aglorithm: %d", compressionAlgorithm)
		return subchunk, ErrFail
	}

	indexes := make([]uint16, 0, numberIndex)
	for i := 0; i < int(numberIndex); i++ {
		value, err := c.u16()
		if err != nil {
			return subchunk, err
		}
		indexes = append(indexes, value)
	}

	numberStringOffsets, err := c.u32()
	if err != nil {
		return subchunk, err
	}

	stringOffsets := make([]uint16, 0, numberStringOffsets)
	for i := 0; i < int(numberStringOffsets); i++ {
		value, err := c.u16()
		if err != nil {
			return subchunk, err
		}
		stringOffsets = append(stringOffsets, value)
	}

	// calculate amount of padding needed based on number_string_offsets and number_index
	const offsetSize uint64 = 2
	padding := anticipatedPaddingSize8(uint64(numberIndex)+uint64(numberStringOffsets), offsetSize)
	paddingInt, ok := u64ToUint(padding)
	if !ok {
		logger.Printf("[macos-unifiedlogs] u64 is bigger than system usize")
		return subchunk, ErrTooLarge
	}
	if err := c.skip(paddingInt); err != nil {
		return subchunk, err
	}

	subchunk = CatalogSubchunk{
		Start:                start,
		End:                  end,
		UncompressedSize:     uncompressedSize,
		CompressionAlgorithm: compressionAlgorithm,
		NumberIndex:          numberIndex,
		Indexes:              indexes,
		NumberStringOffsets:  numberStringOffsets,
		StringOffsets:        stringOffsets,
	}
	return subchunk, nil
}

// GetSubsystem gets the subsystem and category based on the log entry
// `first_proc_id`, `second_proc_id`, log entry subsystem id and the associated
// Catalog.
func (catalog *CatalogChunk) GetSubsystem(subsystemValue uint16, firstProcID uint64, secondProcID uint32) (SubsystemInfo, error) {
	var subsystemInfo SubsystemInfo

	key := fmt.Sprintf("%d_%d", firstProcID, secondProcID)
	if entry, ok := catalog.CatalogProcessInfoEntries[key]; ok {
		for _, subsystems := range entry.SubsystemEntries {
			if subsystemValue == subsystems.Identifier {
				subsystemData := catalog.CatalogSubsystemStrings

				subsystemCursor := newCursor(subsystemData)
				if err := subsystemCursor.skip(int(subsystems.SubsystemOffset)); err != nil {
					return subsystemInfo, err
				}
				_, subsystemString, err := extractString(subsystemCursor.rest())
				if err != nil {
					return subsystemInfo, err
				}

				categoryCursor := newCursor(subsystemData)
				if err := categoryCursor.skip(int(subsystems.CategoryOffset)); err != nil {
					return subsystemInfo, err
				}
				_, categoryString, err := extractString(categoryCursor.rest())
				if err != nil {
					return subsystemInfo, err
				}

				subsystemInfo.Subsystem = subsystemString
				subsystemInfo.Category = categoryString
				return subsystemInfo, nil
			}
		}
	}

	subsystemInfo.Subsystem = "Unknown subsystem"
	return subsystemInfo, nil
}

// GetPID gets the actual Process ID associated with log entry.
func (catalog *CatalogChunk) GetPID(firstProcID uint64, secondProcID uint32) uint64 {
	key := fmt.Sprintf("%d_%d", firstProcID, secondProcID)
	if entry, ok := catalog.CatalogProcessInfoEntries[key]; ok {
		return uint64(entry.PID)
	}

	logger.Printf("[macos-unifiedlogs] Did not find PID in log Catalog")
	return 0
}

// GetEUID gets the effective user id associated with log entry. Can be mapped
// to an account name.
func (catalog *CatalogChunk) GetEUID(firstProcID uint64, secondProcID uint32) uint32 {
	key := fmt.Sprintf("%d_%d", firstProcID, secondProcID)
	if entry, ok := catalog.CatalogProcessInfoEntries[key]; ok {
		return entry.EffectiveUserID
	}

	logger.Printf("[macos-unifiedlogs] Did not find EUID in log Catalog")
	return 0
}
