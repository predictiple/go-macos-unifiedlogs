package filtering

import (
	unifiedlogs "github.com/predictiple/go-macos-unifiedlogs"
	"www.velocidex.com/golang/vfilter/types"
)

/*
   The following are VQL protocols for handling the custom types in
   this library.

   You can get the complete list of additional protocols by calling
   the GetProtocols() function below.
*/

// All the custom protocols to handle the types in this library.
func GetProtocols() []interface{} {
	return []interface{}{
		&EventTypeEq{},
		&LogTypeEq{},
		&LogDataAssociative{},
	}
}

// EventType is an enum so we need special eq handling.
type EventTypeEq struct{}

func (self EventTypeEq) Applicable(a types.Any, b types.Any) bool {
	_, a_ok := a.(unifiedlogs.EventType)
	_, b_ok := b.(string)

	return a_ok && b_ok
}

func (self EventTypeEq) Eq(scope types.Scope, a types.Any, b types.Any) bool {
	log, a_ok := a.(unifiedlogs.EventType)
	if !a_ok {
		return false
	}
	match, b_ok := b.(string)
	if !b_ok {
		return false
	}

	return string(log) == match
}

type LogTypeEq struct{}

func (self LogTypeEq) Applicable(a types.Any, b types.Any) bool {
	_, a_ok := a.(unifiedlogs.LogType)
	_, b_ok := b.(string)

	return a_ok && b_ok
}

func (self LogTypeEq) Eq(scope types.Scope, a types.Any, b types.Any) bool {
	log, a_ok := a.(unifiedlogs.LogType)
	if !a_ok {
		return false
	}
	match, b_ok := b.(string)
	if !b_ok {
		return false
	}

	return string(log) == match
}

type LogDataAssociative struct{}

func (self LogDataAssociative) Applicable(a types.Any, b types.Any) bool {
	_, a_ok := a.(*unifiedlogs.LogData)
	_, b_ok := b.(string)

	return a_ok && b_ok
}

func (self LogDataAssociative) Associative(
	scope types.Scope, a types.Any, b types.Any) (types.Any, bool) {
	log, a_ok := a.(*unifiedlogs.LogData)
	if !a_ok {
		return types.Null{}, false
	}

	element, b_ok := b.(string)
	if !b_ok {
		return types.Null{}, false
	}

	switch element {
	case "Subsystem", "subsystem":
		return log.Subsystem, true
	case "ThreadID", "thread_id":
		return log.ThreadID, true
	case "PID", "pid":
		return log.PID, true
	case "EUID", "euid":
		return log.EUID, true
	case "Library", "library":
		return log.Library, true
	case "LibraryUUID", "library_uuid":
		return log.LibraryUUID, true
	case "ActivityID", "activity_id":
		return log.ActivityID, true
	case "ParentActivityID", "parent_activity_id":
		return log.ParentActivityID, true

		// Hide this field.
	case "Time", "time":
		return types.Null{}, false

	case "Category", "category":
		return log.Category, true
	case "EventType", "event_type":
		return log.EventType, true
	case "LogType", "log_type":
		return log.EventType, true
	case "Process", "process":
		return log.Process, true
	case "ProcessUUID", "process_uuid":
		return log.ProcessUUID, true
	case "Message", "message":
		return log.Message, true
	case "RawMessage", "raw_message":
		return log.RawMessage, true
	case "BootUUID", "boot_uuid":
		return log.BootUUID, true
	case "TimezoneName", "timezone_name":
		return log.TimezoneName, true

		// Simplify these fields.
	case "MessageEntries", "message_entries":
		return WrapLogData(log).MessageEntries, true
	case "Timestamp", "timestamp":
		return WrapLogData(log).Timestamp, true

	case "MessageFlags", "message_flags":
		return log.MessageFlags, true
	case "Evidence", "evidence":
		return log.Evidence, true
	}

	return types.Null{}, false
}

func (self LogDataAssociative) GetMembers(
	scope types.Scope, a types.Any) []string {
	return []string{
		"subsystem", "thread_id", "pid", "euid",
		"library", "library_uuid", "activity_id",
		"parent_activity_id", "time",
		"category", "event_type", "log_type",
		"process", "process_uuid", "message",
		"raw_message", "boot_uuid", "timezone_name",
		"message_entries", "timestamp", "message_flags",
		"evidence",
	}
}
