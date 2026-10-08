package filtering

import (
	"time"

	unifiedlogs "github.com/predictiple/go-macos-unifiedlogs"
)

// A wrapper to the LogData object to present data in a more user
// friendly way.
type LogDataWrapper struct {
	// Timestamp should always be first!
	Timestamp time.Time `json:"timestamp"`
	Time      float64   `json:"time,omitempty"`

	*unifiedlogs.LogData

	// No point having this twice so remove this field.
	MessageEntries []string `json:"message_entries"`
	MessageFlags   []string `json:"message_flags"`
}

func WrapLogData(log *unifiedlogs.LogData) *LogDataWrapper {
	res := &LogDataWrapper{
		LogData:   log,
		Timestamp: time.Unix(0, int64(log.Time)).UTC(),
	}

	for _, e := range log.MessageEntries {
		res.MessageEntries = append(res.MessageEntries, e.MessageStrings)
	}

	for _, m := range log.MessageFlags {
		res.MessageFlags = append(res.MessageFlags, string(m))
	}
	return res
}
