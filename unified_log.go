// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/predictiple/go-macos-unifiedlogs/internal/sunlight"
)

// LogType is the log type of a parsed firehose log entry.
type LogType string

// LogType values, matching the Rust crate's LogType enum.
const (
	LogTypeDebug                LogType = "Debug"
	LogTypeInfo                 LogType = "Info"
	LogTypeDefault              LogType = "Default"
	LogTypeError                LogType = "Error"
	LogTypeFault                LogType = "Fault"
	LogTypeCreate               LogType = "Create"
	LogTypeUseraction           LogType = "Useraction"
	LogTypeProcessSignpostEvent LogType = "ProcessSignpostEvent"
	LogTypeProcessSignpostStart LogType = "ProcessSignpostStart"
	LogTypeProcessSignpostEnd   LogType = "ProcessSignpostEnd"
	LogTypeSystemSignpostEvent  LogType = "SystemSignpostEvent"
	LogTypeSystemSignpostStart  LogType = "SystemSignpostStart"
	LogTypeSystemSignpostEnd    LogType = "SystemSignpostEnd"
	LogTypeThreadSignpostEvent  LogType = "ThreadSignpostEvent"
	LogTypeThreadSignpostStart  LogType = "ThreadSignpostStart"
	LogTypeThreadSignpostEnd    LogType = "ThreadSignpostEnd"
	LogTypeSimpledump           LogType = "Simpledump"
	LogTypeStatedump            LogType = "Statedump"
	LogTypeLoss                 LogType = "Loss"
)

// EventType is the event type of a log entry.
type EventType string

// EventType values, matching the Rust crate's EventType enum.
const (
	EventTypeUnknown    EventType = "Unknown"
	EventTypeLog        EventType = "Log"
	EventTypeActivity   EventType = "Activity"
	EventTypeTrace      EventType = "Trace"
	EventTypeSignpost   EventType = "Signpost"
	EventTypeSimpledump EventType = "Simpledump"
	EventTypeStatedump  EventType = "Statedump"
	EventTypeLoss       EventType = "Loss"
)

// UnifiedLogData holds the parsed Unified Log data from a tracev3 file.
type UnifiedLogData struct {
	Header      []HeaderChunk           `json:"header"`
	CatalogData []UnifiedLogCatalogData `json:"catalog_data"`
	Oversize    []Oversize              `json:"oversize"`
	Evidence    string                  `json:"evidence"`
}

// UnifiedLogCatalogData holds all of the chunk data (log entries) associated
// with a catalog chunk in a tracev3 file.
type UnifiedLogCatalogData struct {
	Catalog    CatalogChunk       `json:"catalog"`
	Firehose   []FirehosePreamble `json:"firehose"`
	Simpledump []SimpleDump       `json:"simpledump"`
	Statedump  []Statedump        `json:"statedump"`
	Oversize   []Oversize         `json:"oversize"`
}

// LogData is a single parsed Unified Log entry.
type LogData struct {
	Subsystem        string             `json:"subsystem"`
	ThreadID         uint64             `json:"thread_id"`
	PID              uint64             `json:"pid"`
	EUID             uint32             `json:"euid"`
	Library          string             `json:"library"`
	LibraryUUID      string             `json:"library_uuid"`
	ActivityID       uint64             `json:"activity_id"`
	ParentActivityID uint64             `json:"parent_activity_id"`
	Time             float64            `json:"time"`
	Category         string             `json:"category"`
	EventType        EventType          `json:"event_type"`
	LogType          LogType            `json:"log_type"`
	Process          string             `json:"process"`
	ProcessUUID      string             `json:"process_uuid"`
	Message          string             `json:"message"`
	RawMessage       string             `json:"raw_message"`
	BootUUID         string             `json:"boot_uuid"`
	TimezoneName     string             `json:"timezone_name"`
	MessageEntries   []FirehoseItemType `json:"message_entries"`
	Timestamp        string             `json:"timestamp"`
	MessageFlags     []MessageFlags     `json:"message_flags"`
	Evidence         string             `json:"evidence"`
}

// parseUnifiedLog parses the Unified log data read from a tracev3 file.
func parseUnifiedLog(data []byte, evidence string) ([]byte, *UnifiedLogData, error) {
	unifiedLogData := &UnifiedLogData{
		Evidence: evidence,
	}

	catalogData := UnifiedLogCatalogData{}

	input := data
	const chunkPreambleSize = 16 // Include preamble size in total chunk size

	const headerChunk = 0x1000
	const catalogChunk = 0x600b
	const chunksetChunk = 0x600d

	// Loop through traceV3 file until all file contents are read
	for len(input) != 0 {
		preamble, err := detectPreamble(input)
		if err != nil {
			return nil, nil, err
		}
		chunkSize := preamble.ChunkDataSize

		// Check for overflow/wrap in chunk size
		if chunkSize > ^uint64(0)-chunkPreambleSize {
			return nil, nil, ErrTooLarge
		}

		// Grab all data associated with Unified Log entry (chunk)
		if uint64(len(input)) < chunkSize+chunkPreambleSize {
			return nil, nil, ErrTooLarge
		}
		chunkData := input[:chunkSize+chunkPreambleSize]
		data = input[chunkSize+chunkPreambleSize:]

		switch preamble.ChunkTag {
		case headerChunk:
			getHeaderData(chunkData, unifiedLogData)
		case catalogChunk:
			if catalogData.Catalog.ChunkTag != 0 {
				unifiedLogData.CatalogData = append(unifiedLogData.CatalogData, catalogData)
			}
			catalogData = UnifiedLogCatalogData{}
			getCatalogData(chunkData, &catalogData)
		case chunksetChunk:
			getChunksetLogData(chunkData, &catalogData, unifiedLogData)
		default:
			logger.Printf("[macos-unifiedlogs] Unknown chunk type: %v", preamble.ChunkTag)
		}

		paddingSize := paddingSize8(preamble.ChunkDataSize)
		if uint64(len(data)) < paddingSize {
			break
		}
		nextData := data[paddingSize:]
		if len(nextData) == 0 {
			break
		}
		if len(nextData) == len(input) {
			break
		}
		input = nextData
		if len(input) < chunkPreambleSize {
			logger.Printf("Not enough data for preamble header, needed 16 bytes. Got: %d", len(input))
			break
		}
	}

	// Make sure to get the last catalog
	if catalogData.Catalog.ChunkTag != 0 {
		unifiedLogData.CatalogData = append(unifiedLogData.CatalogData, catalogData)
	}

	return data, unifiedLogData, nil
}

// BuildLog reconstructs Unified Log entries using the binary strings data,
// cached strings data, timesync data, and unified log. If excludeMissing is
// true, log entries that cannot be reconstructed (data in additional tracev3
// files) are skipped. It returns the reconstructed log entries and any leftover
// Unified Log entries that could not be reconstructed.
func BuildLog(unifiedLogData *UnifiedLogData, provider FileProvider, cache StringCache, timesyncData map[string]*TimesyncBoot, excludeMissing bool) ([]LogData, UnifiedLogData) {
	return buildLog(unifiedLogData, provider, cache, timesyncData, excludeMissing)
}

// buildLog builds the reconstructed LogData entries from parsed UnifiedLogData.
func buildLog(unifiedLogData *UnifiedLogData, provider FileProvider, cache StringCache, timesyncData map[string]*TimesyncBoot, excludeMissing bool) ([]LogData, UnifiedLogData) {
	logDataVec := []LogData{}
	// Need to keep track of any log entries that fail to find Oversize strings
	// (sometimes the strings may be in other log files that have not been parsed yet)
	missingUnifiedLogData := UnifiedLogData{
		Evidence: unifiedLogData.Evidence,
	}

	for catalogIndex := range unifiedLogData.CatalogData {
		catalogData := &unifiedLogData.CatalogData[catalogIndex]

		// Parse the firehose (log) entries
		for preambleIndex, preamble := range catalogData.Firehose {
			for firehoseIndex, firehose := range preamble.PublicData {
				// The continous time is actually 6 bytes long. Combining 4 bytes and 2 bytes
				firehoseLogEntryContinousTime := uint64(firehose.ContinousTimeDelta) | (uint64(firehose.ContinousTimeDeltaUpper) << 32)
				continousTime := preamble.BaseContinousTime + firehoseLogEntryContinousTime

				bootUUID := ""
				timezoneName := "Unknown Timezone Name"
				if len(unifiedLogData.Header) > 0 {
					bootUUID = unifiedLogData.Header[0].BootUUID
					timezoneName = timezoneBase(unifiedLogData.Header[0].TimezonePath)
				}

				// Calculate the timestamp for the log entry
				timestamp := getTimestamp(timesyncData, bootUUID, continousTime, preamble.BaseContinousTime)

				// Our struct format to hold and show the log data
				logData := LogData{
					ThreadID:       firehose.ThreadID,
					PID:            catalogData.Catalog.GetPID(preamble.FirstNumberProcID, preamble.SecondNumberProcID),
					Time:           timestamp,
					Timestamp:      unixEpochToISO(int64(timestamp)),
					LogType:        getLogType(firehose.LogType, firehose.LogActivityType),
					EventType:      getEventType(firehose.LogActivityType),
					EUID:           catalogData.Catalog.GetEUID(preamble.FirstNumberProcID, preamble.SecondNumberProcID),
					BootUUID:       bootUUID,
					TimezoneName:   timezoneName,
					MessageEntries: firehose.Message.ItemInfo,
					Evidence:       unifiedLogData.Evidence,
				}

				// 0x4 - Non-activity log entry. Ex: log default, log error, etc
				// 0x2 - Activity log entry. Ex: activity create
				// 0x7 - Loss log entry. Ex: loss
				// 0x6 - Signpost entry. Ex: process signpost, thread signpost, system signpost
				// 0x3 - Trace log entry. Ex: trace default
				switch firehose.LogActivityType {
				case 0x4:
					logData.ActivityID = uint64(firehose.FirehoseNonActivity.ActivityID)
					_, messageData, err := getFirehoseNonactivityStrings(
						&firehose.FirehoseNonActivity,
						provider,
						cache,
						uint64(firehose.FormatStringLocation),
						preamble.FirstNumberProcID,
						preamble.SecondNumberProcID,
						&catalogData.Catalog,
					)
					logData.MessageFlags = firehose.FirehoseNonActivity.Flags
					if err == nil {
						logData.Library = messageData.Library
						logData.LibraryUUID = messageData.LibraryUUID
						logData.Process = messageData.Process
						logData.ProcessUUID = messageData.ProcessUUID
						logData.RawMessage = messageData.FormatString

						// If the non-activity log entry has a data ref value then the
						// message strings are stored in an oversize log entry
						var logMessage string
						if firehose.FirehoseNonActivity.DataRefValue != 0 {
							oversizeStrings := getOversizeStrings(
								firehose.FirehoseNonActivity.DataRefValue,
								preamble.FirstNumberProcID,
								preamble.SecondNumberProcID,
								unifiedLogData.Oversize,
							)
							logMessage = FormatFirehoseLogMessage(messageData.FormatString, oversizeStrings, firehoseMessageRegex)
						} else {
							logMessage = FormatFirehoseLogMessage(messageData.FormatString, firehose.Message.ItemInfo, firehoseMessageRegex)
						}

						// If we are tracking missing data (due to it being stored in
						// another log file), add missing data to track and parse again.
						if excludeMissing && strings.Contains(logMessage, "<Missing message data>") {
							addMissing(catalogData, preambleIndex, firehoseIndex, unifiedLogData.Header, &missingUnifiedLogData, preamble)
							continue
						}

						if len(firehose.Message.BacktraceStrings) != 0 {
							logData.Message = "Backtrace:\n" + strings.Join(firehose.Message.BacktraceStrings, "\n") + "\n" + logMessage
						} else {
							logData.Message = logMessage
						}
					} else {
						logger.Printf("[macos-unifiedlogs] Failed to get message string data for firehose non-activity log entry: %v", err)
					}

					if firehose.FirehoseNonActivity.SubsystemValue != 0 {
						subsystem, err := catalogData.Catalog.GetSubsystem(
							firehose.FirehoseNonActivity.SubsystemValue,
							preamble.FirstNumberProcID,
							preamble.SecondNumberProcID,
						)
						if err == nil {
							logData.Subsystem = subsystem.Subsystem
							logData.Category = subsystem.Category
						} else {
							logger.Printf("[macos-unifiedlogs] Failed to get subsystem: %v", err)
						}
					}
				case 0x7:
					// No message data in loss entries
					logData.EventType = EventTypeLoss
					logData.LogType = LogTypeLoss
				case 0x2:
					// When has_other_current_aid (0x200) is set, id3 is the new
					// activity and id1 is the parent. Otherwise id1 is the new
					// activity with no parent.
					if firehose.FirehoseActivity.ActivityID3 != 0 {
						logData.ActivityID = uint64(firehose.FirehoseActivity.ActivityID3)
						logData.ParentActivityID = uint64(firehose.FirehoseActivity.ActivityID)
					} else {
						logData.ActivityID = uint64(firehose.FirehoseActivity.ActivityID)
					}
					logData.MessageFlags = firehose.FirehoseActivity.Flags
					_, messageData, err := getFirehoseActivityStrings(
						&firehose.FirehoseActivity,
						provider,
						cache,
						uint64(firehose.FormatStringLocation),
						preamble.FirstNumberProcID,
						preamble.SecondNumberProcID,
						&catalogData.Catalog,
					)
					if err == nil {
						logData.Library = messageData.Library
						logData.LibraryUUID = messageData.LibraryUUID
						logData.Process = messageData.Process
						logData.ProcessUUID = messageData.ProcessUUID
						logData.RawMessage = messageData.FormatString

						logMessage := FormatFirehoseLogMessage(messageData.FormatString, firehose.Message.ItemInfo, firehoseMessageRegex)
						if excludeMissing && strings.Contains(logMessage, "<Missing message data>") {
							addMissing(catalogData, preambleIndex, firehoseIndex, unifiedLogData.Header, &missingUnifiedLogData, preamble)
							continue
						}
						if len(firehose.Message.BacktraceStrings) != 0 {
							logData.Message = "Backtrace:\n" + strings.Join(firehose.Message.BacktraceStrings, "\n") + "\n" + logMessage
						} else {
							logData.Message = logMessage
						}
					} else {
						logger.Printf("[macos-unifiedlogs] Failed to get message string data for firehose activity log entry: %v", err)
					}
				case 0x6:
					logData.ActivityID = uint64(firehose.FirehoseSignpost.ActivityID)
					logData.MessageFlags = firehose.FirehoseSignpost.Flags
					_, messageData, err := getFirehoseSignpost(
						&firehose.FirehoseSignpost,
						provider,
						cache,
						uint64(firehose.FormatStringLocation),
						preamble.FirstNumberProcID,
						preamble.SecondNumberProcID,
						&catalogData.Catalog,
					)
					if err == nil {
						logData.Library = messageData.Library
						logData.LibraryUUID = messageData.LibraryUUID
						logData.Process = messageData.Process
						logData.ProcessUUID = messageData.ProcessUUID
						logData.RawMessage = messageData.FormatString

						var logMessage string
						if firehose.FirehoseNonActivity.DataRefValue != 0 {
							oversizeStrings := getOversizeStrings(
								firehose.FirehoseNonActivity.DataRefValue,
								preamble.FirstNumberProcID,
								preamble.SecondNumberProcID,
								unifiedLogData.Oversize,
							)
							logMessage = FormatFirehoseLogMessage(messageData.FormatString, oversizeStrings, firehoseMessageRegex)
						} else {
							logMessage = FormatFirehoseLogMessage(messageData.FormatString, firehose.Message.ItemInfo, firehoseMessageRegex)
						}
						if excludeMissing && strings.Contains(logMessage, "<Missing message data>") {
							addMissing(catalogData, preambleIndex, firehoseIndex, unifiedLogData.Header, &missingUnifiedLogData, preamble)
							continue
						}

						logMessage = "Signpost ID: " + upperHex(firehose.FirehoseSignpost.SignpostID) +
							" - Signpost Name: " + upperHex(uint64(firehose.FirehoseSignpost.SignpostName)) +
							"\n " + logMessage

						if len(firehose.Message.BacktraceStrings) != 0 {
							logData.Message = "Backtrace:\n" + strings.Join(firehose.Message.BacktraceStrings, "\n") + "\n" + logMessage
						} else {
							logData.Message = logMessage
						}
					} else {
						logger.Printf("[macos-unifiedlogs] Failed to get message string data for firehose signpost log entry: %v", err)
					}
					if firehose.FirehoseSignpost.Subsystem != 0 {
						subsystem, err := catalogData.Catalog.GetSubsystem(
							firehose.FirehoseSignpost.Subsystem,
							preamble.FirstNumberProcID,
							preamble.SecondNumberProcID,
						)
						if err == nil {
							logData.Subsystem = subsystem.Subsystem
							logData.Category = subsystem.Category
						} else {
							logger.Printf("[macos-unifiedlogs] Failed to get subsystem: %v", err)
						}
					}
				case 0x3:
					_, messageData, err := getFirehoseTraceStrings(
						provider,
						cache,
						uint64(firehose.FormatStringLocation),
						preamble.FirstNumberProcID,
						preamble.SecondNumberProcID,
						&catalogData.Catalog,
					)
					if err == nil {
						logData.Library = messageData.Library
						logData.LibraryUUID = messageData.LibraryUUID
						logData.Process = messageData.Process
						logData.ProcessUUID = messageData.ProcessUUID

						logMessage := FormatFirehoseLogMessage(messageData.FormatString, firehose.Message.ItemInfo, firehoseMessageRegex)
						if excludeMissing && strings.Contains(logMessage, "<Missing message data>") {
							addMissing(catalogData, preambleIndex, firehoseIndex, unifiedLogData.Header, &missingUnifiedLogData, preamble)
							continue
						}
						if len(firehose.Message.BacktraceStrings) != 0 {
							logData.Message = "Backtrace:\n" + strings.Join(firehose.Message.BacktraceStrings, "\n") + "\n" + logMessage
						} else {
							logData.Message = logMessage
						}
					} else {
						logger.Printf("[macos-unifiedlogs] Failed to get message string data for firehose activity log entry: %v", err)
					}
				default:
					logger.Printf("[macos-unifiedlogs] Parsed unknown log firehose data: %+v", firehose)
				}
				logDataVec = append(logDataVec, logData)
			}
		}

		// Parse the simpledump entries
		for _, simpledump := range catalogData.Simpledump {
			const noFirehosePreamble = 1

			bootUUID := ""
			timezoneName := "Unknown Timezone Name"
			if len(unifiedLogData.Header) > 0 {
				bootUUID = unifiedLogData.Header[0].BootUUID
				timezoneName = timezoneBase(unifiedLogData.Header[0].TimezonePath)
			}

			timestamp := getTimestamp(timesyncData, bootUUID, simpledump.ContinousTime, noFirehosePreamble)

			logData := LogData{
				Subsystem:    simpledump.Subsystem,
				ThreadID:     simpledump.ThreadID,
				PID:          simpledump.FirstProcID,
				Time:         timestamp,
				Timestamp:    unixEpochToISO(int64(timestamp)),
				LogType:      LogTypeSimpledump,
				EventType:    EventTypeSimpledump,
				Message:      simpledump.MessageString,
				BootUUID:     bootUUID,
				TimezoneName: timezoneName,
				LibraryUUID:  simpledump.SenderUUID,
				Evidence:     unifiedLogData.Evidence,
			}

			// Extract Process info from shared strings
			if _, procLib, err := extractSharedStrings(
				provider,
				cache,
				uint64(simpledump.UnknownOffset),
				simpledump.FirstProcID,
				uint32(simpledump.SecondProcID),
				&catalogData.Catalog,
				0,
			); err == nil {
				logData.ProcessUUID = procLib.ProcessUUID
				logData.Process = procLib.Process
			}

			logDataVec = append(logDataVec, logData)
		}

		// Parse the statedump entries
		for _, statedump := range catalogData.Statedump {
			const noFirehosePreamble = 1

			dataString := ""
			switch statedump.UnknownDataType {
			// Check for binary plist (bplist)
			case 0x1:
				if bytes.HasPrefix(statedump.StatedumpData, []byte("bplist")) {
					dataString = ParseStatedumpPlist(statedump.StatedumpData)
				} else {
					// plist could also just be plaintext
					_, stringData, err := extractString(statedump.StatedumpData)
					if err != nil {
						logger.Printf("[macos-unifiedlogs] Failed to extract plist string from statedump: %v", err)
						dataString = "Failed to extract plist string from statedump"
					} else {
						dataString = stringData
					}
				}
			case 0x2:
				if mapData, err := sunlight.ExtractProtobuf(statedump.StatedumpData); err == nil {
					dataString = jsonSerializeMap(mapData)
				} else {
					dataString = "Failed to parse StateDump protobuf: " + encodeStandard(statedump.StatedumpData)
				}
			case 0x3:
				dataString = parseStatedumpObject(statedump.StatedumpData, statedump.TitleName)
			default:
				logger.Printf("Unknown statedump data type: %v", statedump.UnknownDataType)
				_, stringData, err := extractString(statedump.StatedumpData)
				if err != nil {
					logger.Printf("[macos-unifiedlogs] Failed to extract string from statedump: %v", err)
					dataString = "Failed to extract string from statedump"
				} else {
					dataString = stringData
				}
			}

			bootUUID := ""
			timezoneName := "Unknown Timezone Name"
			if len(unifiedLogData.Header) > 0 {
				bootUUID = unifiedLogData.Header[0].BootUUID
				timezoneName = timezoneBase(unifiedLogData.Header[0].TimezonePath)
			}

			timestamp := getTimestamp(timesyncData, bootUUID, statedump.ContinuousTime, noFirehosePreamble)

			logData := LogData{
				PID:          statedump.FirstProcID,
				ActivityID:   statedump.ActivityID,
				Time:         timestamp,
				Timestamp:    unixEpochToISO(int64(timestamp)),
				EventType:    EventTypeStatedump,
				Message:      "title: " + statedump.TitleName + "\nObject Type: " + statedump.DecoderLibrary + "\nObject Type: " + statedump.DecoderType + "\n" + dataString,
				LogType:      LogTypeStatedump,
				EUID:         catalogData.Catalog.GetEUID(statedump.FirstProcID, statedump.SecondProcID),
				BootUUID:     bootUUID,
				TimezoneName: timezoneName,
				LibraryUUID:  statedump.UUID,
				Evidence:     unifiedLogData.Evidence,
			}

			_, processUUID := getCatalogDSC(&catalogData.Catalog, statedump.FirstProcID, statedump.SecondProcID)
			logData.ProcessUUID = processUUID

			if _, process, err := getUUIDImagePath(logData.ProcessUUID, provider, cache); err == nil {
				logData.Process = process
			}

			logDataVec = append(logDataVec, logData)
		}
	}

	return logDataVec, missingUnifiedLogData
}

// getLogType returns the LogType based on the firehose log type and activity type.
func getLogType(logType uint8, activityType uint8) LogType {
	switch logType {
	case 0x1:
		const activity = 0x2
		if activityType == activity {
			return LogTypeCreate
		}
		return LogTypeInfo
	case 0x2:
		return LogTypeDebug
	case 0x3:
		return LogTypeUseraction
	case 0x10:
		return LogTypeError
	case 0x11:
		return LogTypeFault
	case 0x80:
		return LogTypeProcessSignpostEvent
	case 0x81:
		return LogTypeProcessSignpostStart
	case 0x82:
		return LogTypeProcessSignpostEnd
	case 0xc0:
		return LogTypeSystemSignpostEvent
	case 0xc1:
		return LogTypeSystemSignpostStart
	case 0xc2:
		return LogTypeSystemSignpostEnd
	case 0x40:
		return LogTypeThreadSignpostEvent
	case 0x41:
		return LogTypeThreadSignpostStart
	case 0x42:
		return LogTypeThreadSignpostEnd
	default:
		return LogTypeDefault
	}
}

// getEventType returns the EventType based on the firehose activity type.
func getEventType(eventType uint8) EventType {
	switch eventType {
	case 0x4:
		return EventTypeLog
	case 0x2:
		return EventTypeActivity
	case 0x3:
		return EventTypeTrace
	case 0x6:
		return EventTypeSignpost
	case 0x7:
		return EventTypeLoss
	default:
		return EventTypeUnknown
	}
}

// getHeaderData gets the header of the Unified Log data (tracev3 file).
func getHeaderData(data []byte, unifiedLogData *UnifiedLogData) {
	header, err := parseHeader(newCursor(data))
	if err != nil {
		logger.Printf("[macos-unifiedlogs] Failed to parse header data: %v", err)
		return
	}
	unifiedLogData.Header = append(unifiedLogData.Header, *header)
}

// getCatalogData gets the catalog data of the Unified Log data (tracev3 file).
func getCatalogData(data []byte, catalogData *UnifiedLogCatalogData) {
	_, catalog, err := parseCatalog(data)
	if err != nil {
		logger.Printf("[macos-unifiedlogs] Failed to parse catalog data: %v", err)
		return
	}
	catalogData.Catalog = catalog
}

// getChunksetLogData gets the chunkset data of the Unified Log data (tracev3
// file). Parses and decompresses the chunkset entries, then moves the oversize
// entries into the parent UnifiedLogData.
//
// Named getChunksetLogData to avoid colliding with ChunksetChunk's
// getChunksetData (the per-chunk dispatcher).
func getChunksetLogData(data []byte, catalogData *UnifiedLogCatalogData, unifiedLogData *UnifiedLogData) {
	_, chunkset, err := ParseChunkset(data)
	if err != nil {
		logger.Printf("[macos-unifiedlogs] Failed to parse chunkset data: %v", err)
		return
	}
	if _, err := ParseChunksetData(chunkset.DecompressedData, catalogData); err != nil {
		logger.Printf("[macos-unifiedlogs] Failed to parse chunkset data: %v", err)
		return
	}
	unifiedLogData.Oversize = append(unifiedLogData.Oversize, catalogData.Oversize...)
	// Drain the catalog oversize entries (mirrors Rust's append(&mut ...))
	catalogData.Oversize = nil
}

// trackMissing builds a FirehosePreamble for a log entry that is missing data
// which may be in another tracev3 file.
func trackMissing(firstProcID uint64, secondProcID uint32, time uint64, firehose Firehose) FirehosePreamble {
	return FirehosePreamble{
		ChunkTag:                 0,
		ChunkSubTag:              0,
		ChunkDataSize:            0,
		FirstNumberProcID:        firstProcID,
		SecondNumberProcID:       secondProcID,
		TTL:                      0,
		Collapsed:                0,
		Unknown:                  []byte{},
		PublicDataSize:           0,
		PrivateDataVirtualOffset: 0,
		Unkonwn2:                 0,
		Unknown3:                 0,
		BaseContinousTime:        time,
		PublicData:               []Firehose{firehose},
	}
}

// addMissing adds a missing log entry to the log data tracker. Log data may be
// in another file. Mainly related to logs that have Oversize data.
func addMissing(catalogData *UnifiedLogCatalogData, preambleIndex int, firehoseIndex int, header []HeaderChunk, missing *UnifiedLogData, preamble FirehosePreamble) {
	missingFirehose := trackMissing(
		catalogData.Firehose[preambleIndex].FirstNumberProcID,
		catalogData.Firehose[preambleIndex].SecondNumberProcID,
		catalogData.Firehose[preambleIndex].BaseContinousTime,
		preamble.PublicData[firehoseIndex],
	)
	missingCatalogData := UnifiedLogCatalogData{
		Catalog: catalogData.Catalog,
	}
	missingCatalogData.Firehose = append(missingCatalogData.Firehose, missingFirehose)

	missing.Header = append([]HeaderChunk{}, header...)
	missing.CatalogData = append(missing.CatalogData, missingCatalogData)
}

// timezoneBase returns the timezone name from a timezone path.
func timezoneBase(path string) string {
	idx := strings.LastIndex(path, "/")
	if idx != -1 {
		return path[idx+1:]
	}
	return path
}

// upperHex returns the uppercase hexadecimal representation of value (Rust {:X}).
func upperHex(value uint64) string {
	return strings.ToUpper(strconv.FormatUint(value, 16))
}

// jsonSerializeMap serializes a map to JSON.
func jsonSerializeMap(m map[string]any) string {
	serialized, err := json.Marshal(m)
	if err != nil {
		return "Failed to serialize Protobuf HashMap"
	}
	return string(serialized)
}
