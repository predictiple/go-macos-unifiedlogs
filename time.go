// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

import (
	"strconv"
	"time"
)

// parseTime parses the time associated with a log entry and returns it in the
// RFC3339 format. UTC is used because the Rust crate emits UTC time.
func parseTime(data string) (string, error) {
	timeInt, err := strconv.ParseInt(data, 10, 64)
	if err != nil {
		return "", &DecoderError{
			Input:      []byte(data),
			ParserName: "parse time",
			Message:    "Failed to parse time string to int",
		}
	}

	dateTime := time.Unix(timeInt, 0).UTC()
	return dateTime.Format("2006-01-02T15:04:05.000Z"), nil
}
