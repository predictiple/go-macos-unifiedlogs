// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

import "fmt"

// ParserError mirrors the Rust crate's ParserError enum.
type ParserError int

// ParserError values, matching the original Rust enum variants.
const (
	ErrPath ParserError = iota + 1
	ErrDir
	ErrTracev3Parse
	ErrRead
	ErrTimesync
	ErrDsc
	ErrUUIDText
)

func (e ParserError) Error() string {
	switch e {
	case ErrPath:
		return "Failed to open file path"
	case ErrDir:
		return "Failed to open directory path"
	case ErrTracev3Parse:
		return "Failed to parse tracev3 file"
	case ErrRead:
		return "Failed to read file"
	case ErrTimesync:
		return "Failed to parse timesync file"
	case ErrDsc:
		return "Failed to parse dsc file"
	case ErrUUIDText:
		return "Failedto parse UUIDtext file"
	default:
		return fmt.Sprintf("unknown parser error %d", int(e))
	}
}
