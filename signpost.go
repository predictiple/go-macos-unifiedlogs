// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

// FirehoseSignpost represents a signpost firehose log entry.
type FirehoseSignpost struct {
	PCID                 uint32             `json:"pc_id"`
	ActivityID           uint32             `json:"activity_id"`
	Sentinel             uint32             `json:"sentinel"`
	PersonaID            uint32             `json:"persona_id"`
	Subsystem            uint16             `json:"subsystem"`
	SignpostID           uint64             `json:"signpost_id"`
	SignpostName         uint32             `json:"signpost_name"`
	PrivateStringsOffset uint16             `json:"private_strings_offset"`
	PrivateStringsSize   uint16             `json:"private_strings_size"`
	TTLValue             uint8              `json:"ttl_value"`
	DataRefValue         uint32             `json:"data_ref_value"`
	FirehoseFormatters   FirehoseFormatters `json:"firehose_formatters"`
	Flags                []MessageFlags     `json:"flags"`
}

// parseSignpost parses a Signpost Firehose log entry.
// Ex: tp 2368 + 92: process signpost event (shared_cache, has_name, has_subsystem)
func parseSignpost(data []byte, firehoseFlags uint16) ([]byte, FirehoseSignpost, error) {
	var firehoseSignpost FirehoseSignpost
	c := newCursor(data)

	const activityIDCurrent uint16 = 0x1 // has_current_aid flag
	if (firehoseFlags & activityIDCurrent) != 0 {
		// debug!("[macos-unifiedlogs] Signpost Firehose has has_current_aid flag")
		firehoseActivityID, err := c.u32()
		if err != nil {
			return nil, firehoseSignpost, err
		}
		firehoseSentinel, err := c.u32()
		if err != nil {
			return nil, firehoseSignpost, err
		}
		firehoseSignpost.ActivityID = firehoseActivityID
		firehoseSignpost.Sentinel = firehoseSentinel
		firehoseSignpost.Flags = append(firehoseSignpost.Flags, MessageFlagsHasCurrentAid)
	}

	const hasPersona uint16 = 0x40
	if (firehoseFlags & hasPersona) != 0 {
		// debug!("[macos-unifiedlogs] Signpost Firehose has has_persona flag")
		personaID, err := c.u32()
		if err != nil {
			return nil, firehoseSignpost, err
		}
		firehoseSignpost.PersonaID = personaID
		firehoseSignpost.Flags = append(firehoseSignpost.Flags, MessageFlagsHasPersona)
	}

	const privateStringRange uint16 = 0x100 // has_private_data flag
	// Entry has private string data. The private data is found after parsing all the public data first
	if (firehoseFlags & privateStringRange) != 0 {
		// debug!("[macos-unifiedlogs] Signpost Firehose has has_private_data flag")
		firehosePrivateStringsOffset, err := c.u16()
		if err != nil {
			return nil, firehoseSignpost, err
		}
		firehosePrivateStringsSize, err := c.u16()
		if err != nil {
			return nil, firehoseSignpost, err
		}
		// Offset points to private string values found after parsing the public data. Size is the data size
		firehoseSignpost.PrivateStringsOffset = firehosePrivateStringsOffset
		firehoseSignpost.PrivateStringsSize = firehosePrivateStringsSize
		firehoseSignpost.Flags = append(firehoseSignpost.Flags, MessageFlagsHasPrivateData)
	}

	firehosePCID, err := c.u32()
	if err != nil {
		return nil, firehoseSignpost, err
	}
	firehoseSignpost.PCID = firehosePCID

	// Check for flags related to base string format location (shared string file (dsc) or UUID file)
	remaining, formatters, err := FirehoseFormatterFlags(c.rest(), firehoseFlags, &firehoseSignpost.Flags)
	if err != nil {
		return nil, firehoseSignpost, err
	}
	c.reset(remaining)
	firehoseSignpost.FirehoseFormatters = formatters

	const subsystem uint16 = 0x200 // has_subsystem flag. In Signpost log entries this is the subsystem flag
	if (firehoseFlags & subsystem) != 0 {
		// debug!("[macos-unifiedlogs] Signpost Firehose log chunk has has_subsystem flag")
		firehoseSubsystem, err := c.u16()
		if err != nil {
			return nil, firehoseSignpost, err
		}
		firehoseSignpost.Subsystem = firehoseSubsystem
		firehoseSignpost.Flags = append(firehoseSignpost.Flags, MessageFlagsHasSubsystem)
	}

	firehoseSignpostID, err := c.u64()
	if err != nil {
		return nil, firehoseSignpost, err
	}
	firehoseSignpost.SignpostID = firehoseSignpostID

	const hasRules uint16 = 0x400 // has_rules flag
	if (firehoseFlags & hasRules) != 0 {
		// debug!("[macos-unifiedlogs] Signpost Firehose log chunk has has_rules flag")
		firehoseTTL, err := c.u8()
		if err != nil {
			return nil, firehoseSignpost, err
		}
		firehoseSignpost.TTLValue = firehoseTTL
		firehoseSignpost.Flags = append(firehoseSignpost.Flags, MessageFlagsHasRules)
	}

	const dataRef uint16 = 0x800 // has_oversize flag
	if (firehoseFlags & dataRef) != 0 {
		// debug!("[macos-unifiedlogs] Signpost Firehose log chunk has has_oversize flag")
		firehoseDataRef, err := c.u32()
		if err != nil {
			return nil, firehoseSignpost, err
		}
		firehoseSignpost.DataRefValue = firehoseDataRef
		firehoseSignpost.Flags = append(firehoseSignpost.Flags, MessageFlagsHasOversize)
	}

	const hasName uint16 = 0x8000
	if (firehoseFlags & hasName) != 0 {
		// debug!("[macos-unifiedlogs] Signpost Firehose log chunk has has_name flag")
		firehoseSignpostName, err := c.u32()
		if err != nil {
			return nil, firehoseSignpost, err
		}
		firehoseSignpost.SignpostName = firehoseSignpostName
		// If the signpost log has large_shared_cache or shared_cache flag
		// Then need to add 0x80000000 to signpost name
		if (firehoseSignpost.FirehoseFormatters.SharedCache &&
			firehoseSignpost.FirehoseFormatters.HasLargeOffset != 0) ||
			firehoseSignpost.FirehoseFormatters.LargeSharedCache != 0 {
			_, err := c.u16()
			if err != nil {
				return nil, firehoseSignpost, err
			}
			const cache uint32 = 0x80000000
			firehoseSignpost.SignpostName += cache
		}
	}

	return c.rest(), firehoseSignpost, nil
}

// getFirehoseSignpost gets the base log message string formatter from shared cache strings
// (dsc) or the UUID text file for firehose signpost log entries.
func getFirehoseSignpost(firehose *FirehoseSignpost, provider FileProvider, cache StringCache, stringOffset uint64, firstProcID uint64, secondProcID uint32, catalogs *CatalogChunk) ([]byte, MessageData, error) {
	params := MessageParams{
		PCID:                firehose.PCID,
		StringOffset:        stringOffset,
		FirstProcID:         firstProcID,
		SecondProcID:        secondProcID,
		SupportsLargeOffset: true,
	}
	return getMessage(firehose.FirehoseFormatters, provider, cache, params, catalogs)
}
