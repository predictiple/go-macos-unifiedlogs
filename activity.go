// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

// FirehoseActivity holds an Activity Type Firehose log entry.
//
// Phase 3b: the Rust get_firehose_activity_strings / get_message methods
// (FileProvider, StringCache, CatalogChunk, MessageData) are not ported yet.
type FirehoseActivity struct {
	ActivityID         uint32             `json:"activity_id"`
	Sentinal           uint32             `json:"sentinal"`
	PID                uint64             `json:"pid"`
	ActivityID2        uint32             `json:"activity_id_2"`
	PersonaID          uint32             `json:"persona_id"`
	Sentinal2          uint32             `json:"sentinal_2"`
	ActivityID3        uint32             `json:"activity_id_3"`
	Sentinal3          uint32             `json:"sentinal_3"`
	MessageStringRef   uint32             `json:"message_string_ref"`
	PCID               uint32             `json:"pc_id"`
	FirehoseFormatters FirehoseFormatters `json:"firehose_formatters"`
	Flags              []MessageFlags     `json:"flags"`
}

// parseActivity parses an Activity Type Firehose log entry.
// Ex: tp 3536 + 60: activity create (has_current_aid, has_unique_pid, shared_cache, has_other_aid)
func parseActivity(data []byte, firehoseFlags uint16, firehoseLogType uint8) ([]byte, FirehoseActivity, error) {
	var activity FirehoseActivity
	c := newCursor(data)

	// Useraction activity type does not have first Activity ID or sentinel
	const userAction uint8 = 0x3
	// Get first activity_id (if not useraction type)
	if firehoseLogType != userAction {
		firehoseActivityID, err := c.u32()
		if err != nil {
			return nil, activity, err
		}
		firehoseSentinel, err := c.u32()
		if err != nil {
			return nil, activity, err
		}
		activity.ActivityID = firehoseActivityID
		activity.Sentinal = firehoseSentinel
	}

	const uniquePID uint16 = 0x10 // has_unique_pid flag
	if (firehoseFlags & uniquePID) != 0 {
		logger.Printf("[macos-unifiedlogs] Activity Firehose log chunk has unique_pid flag")
		firehoseUniquePID, err := c.u64()
		if err != nil {
			return nil, activity, err
		}
		activity.PID = firehoseUniquePID
		activity.Flags = append(activity.Flags, MessageFlagsHasUniquePid)
	}

	const activityIDCurrent uint16 = 0x1 // has_current_aid flag
	if (firehoseFlags & activityIDCurrent) != 0 {
		logger.Printf("[macos-unifiedlogs] Activity Firehose log chunk has has_current_aid flag")
		firehoseActivityID, err := c.u32()
		if err != nil {
			return nil, activity, err
		}
		firehoseSentinel, err := c.u32()
		if err != nil {
			return nil, activity, err
		}
		activity.ActivityID2 = firehoseActivityID
		activity.Sentinal2 = firehoseSentinel
		activity.Flags = append(activity.Flags, MessageFlagsHasCurrentAid)
	}

	const hasPersona uint16 = 0x40
	if (firehoseFlags & hasPersona) != 0 {
		logger.Printf("[macos-unifiedlogs] Activity Firehose log chunk has has_persona flag")
		personaID, err := c.u32()
		if err != nil {
			return nil, activity, err
		}
		activity.PersonaID = personaID
		activity.Flags = append(activity.Flags, MessageFlagsHasPersona)
	}

	// has_other_current_aid flag. In Activity log entries this is another activity id flag
	const activityIDOther uint16 = 0x200
	if (firehoseFlags & activityIDOther) != 0 {
		logger.Printf("[macos-unifiedlogs] Activity Firehose log chunk has has_other_current_aid flag")
		firehoseActivityID, err := c.u32()
		if err != nil {
			return nil, activity, err
		}
		firehoseSentinel, err := c.u32()
		if err != nil {
			return nil, activity, err
		}
		activity.ActivityID3 = firehoseActivityID
		activity.Sentinal3 = firehoseSentinel
		activity.Flags = append(activity.Flags, MessageFlagsHasOtherAid)
	}

	firehosePCID, err := c.u32()
	if err != nil {
		return nil, activity, err
	}
	activity.PCID = firehosePCID // Message string reference?

	// Check for flags related to base string format location (shared string file (dsc) or UUID file)
	firehoseInput := c.rest()
	firehoseInput, formatters, err := FirehoseFormatterFlags(firehoseInput, firehoseFlags, &activity.Flags)
	if err != nil {
		return nil, activity, err
	}
	activity.FirehoseFormatters = formatters

	return firehoseInput, activity, nil
}

// getFirehoseActivityStrings gets the base log message string formatter from shared cache
// strings (dsc) or the UUID text file for firehose activity log entries.
func getFirehoseActivityStrings(firehose *FirehoseActivity, provider FileProvider, cache StringCache, stringOffset uint64, firstProcID uint64, secondProcID uint32, catalogs *CatalogChunk) ([]byte, MessageData, error) {
	params := MessageParams{
		PCID:                firehose.PCID,
		StringOffset:        stringOffset,
		FirstProcID:         firstProcID,
		SecondProcID:        secondProcID,
		SupportsLargeOffset: true,
	}
	return getMessage(firehose.FirehoseFormatters, provider, cache, params, catalogs)
}
