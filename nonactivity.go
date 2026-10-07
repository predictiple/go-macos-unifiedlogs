// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

// FirehoseNonActivity represents a non-activity firehose log entry.
type FirehoseNonActivity struct {
	ActivityID           uint32             `json:"activity_id"`
	Sentinel             uint32             `json:"sentinel"`
	PersonaID            uint32             `json:"persona_id"`
	PrivateStringsOffset uint16             `json:"private_strings_offset"`
	PrivateStringsSize   uint16             `json:"private_strings_size"`
	MessageStringRef     uint32             `json:"message_string_ref"`
	SubsystemValue       uint16             `json:"subsystem_value"`
	TTLValue             uint8              `json:"ttl_value"`
	DataRefValue         uint32             `json:"data_ref_value"`
	PCID                 uint32             `json:"pc_id"`
	FirehoseFormatters   FirehoseFormatters `json:"firehose_formatters"`
	Flags                []MessageFlags     `json:"flags"`
}

// parseNonActivity parses a Non-Activity Type Firehose log entry.
// Ex: tp 728 + 202: log debug (has_current_aid, main_exe, has_subsystem, has_rules)
func parseNonActivity(data []byte, firehoseFlags uint16) ([]byte, FirehoseNonActivity, error) {
	var nonActivity FirehoseNonActivity
	c := newCursor(data)

	const activityIDCurrent uint16 = 0x1 // has_current_aid flag
	if (firehoseFlags & activityIDCurrent) != 0 {
		logger.Printf("[macos-unifiedlogs] Non-Activity Firehose log chunk has has_current_aid flag")
		firehoseActivityID, err := c.u32()
		if err != nil {
			return nil, nonActivity, err
		}
		firehoseUnknownSentinel, err := c.u32()
		if err != nil {
			return nil, nonActivity, err
		}
		nonActivity.ActivityID = firehoseActivityID
		nonActivity.Sentinel = firehoseUnknownSentinel
		nonActivity.Flags = append(nonActivity.Flags, MessageFlagsHasCurrentAid)
	}

	const hasPersona uint16 = 0x40
	if (firehoseFlags & hasPersona) != 0 {
		logger.Printf("[macos-unifiedlogs] Non-Activity Firehose log chunk has has_persona flag")
		personaID, err := c.u32()
		if err != nil {
			return nil, nonActivity, err
		}
		nonActivity.PersonaID = personaID
		nonActivity.Flags = append(nonActivity.Flags, MessageFlagsHasPersona)
	}

	const privateStringRange uint16 = 0x100 // has_private_data flag
	// Entry has private string data. The private data is found after parsing all the public data first
	if (firehoseFlags & privateStringRange) != 0 {
		logger.Printf("[macos-unifiedlogs] Non-Activity Firehose log chunk has has_private_data flag")
		firehosePrivateStringsOffset, err := c.u16()
		if err != nil {
			return nil, nonActivity, err
		}
		firehosePrivateStringsSize, err := c.u16()
		if err != nil {
			return nil, nonActivity, err
		}
		nonActivity.Flags = append(nonActivity.Flags, MessageFlagsHasPrivateData)

		// Offset points to private string values found after parsing the public data. Size is the data size
		nonActivity.PrivateStringsOffset = firehosePrivateStringsOffset
		nonActivity.PrivateStringsSize = firehosePrivateStringsSize
	}

	firehosePCID, err := c.u32()
	if err != nil {
		return nil, nonActivity, err
	}
	nonActivity.PCID = firehosePCID

	// Check for flags related to base string format location (shared string file (dsc) or UUID file)
	remaining, formatters, err := FirehoseFormatterFlags(c.rest(), firehoseFlags, &nonActivity.Flags)
	if err != nil {
		return nil, nonActivity, err
	}
	c.reset(remaining)
	nonActivity.FirehoseFormatters = formatters

	const subsystem uint16 = 0x200 // has_subsystem flag. In Non-Activity log entries this is the subsystem flag
	if (firehoseFlags & subsystem) != 0 {
		logger.Printf("[macos-unifiedlogs] Non-Activity Firehose log chunk has has_subsystem flag")
		firehoseSubsystem, err := c.u16()
		if err != nil {
			return nil, nonActivity, err
		}
		nonActivity.SubsystemValue = firehoseSubsystem
		nonActivity.Flags = append(nonActivity.Flags, MessageFlagsHasSubsystem)
	}

	const ttl uint16 = 0x400 // has_rules flag
	if (firehoseFlags & ttl) != 0 {
		logger.Printf("[macos-unifiedlogs] Non-Activity Firehose log chunk has has_rules flag")
		firehoseTTL, err := c.u8()
		if err != nil {
			return nil, nonActivity, err
		}
		nonActivity.TTLValue = firehoseTTL
		nonActivity.Flags = append(nonActivity.Flags, MessageFlagsHasRules)
	}

	const dataRef uint16 = 0x800 // has_oversize flag
	if (firehoseFlags & dataRef) != 0 {
		logger.Printf("[macos-unifiedlogs] Non-Activity Firehose log chunk has has_oversize flag")
		firehoseDataRef, err := c.u32()
		if err != nil {
			return nil, nonActivity, err
		}
		nonActivity.DataRefValue = firehoseDataRef
		nonActivity.Flags = append(nonActivity.Flags, MessageFlagsHasOversize)
	}

	return c.rest(), nonActivity, nil
}

// getFirehoseNonactivityStrings gets the base log message string formatter from shared cache
// strings (dsc) or the UUID text file for firehose non-activity log entries.
func getFirehoseNonactivityStrings(firehose *FirehoseNonActivity, provider FileProvider, cache StringCache, stringOffset uint64, firstProcID uint64, secondProcID uint32, catalogs *CatalogChunk) ([]byte, MessageData, error) {
	params := MessageParams{
		PCID:                firehose.PCID,
		StringOffset:        stringOffset,
		FirstProcID:         firstProcID,
		SecondProcID:        secondProcID,
		SupportsLargeOffset: false,
	}
	return getMessage(firehose.FirehoseFormatters, provider, cache, params, catalogs)
}
