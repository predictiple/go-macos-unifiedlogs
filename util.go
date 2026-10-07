// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

import (
	"encoding/base64"
	"fmt"
	"math"
	"strings"
	"time"
	"unicode/utf8"
)

// anticipatedPaddingSize8 returns the padding to consume in order to align to 8 bytes.
// Actual total size is computed as itemsCount * itemsSize.
func anticipatedPaddingSize8(itemsCount, itemsSize uint64) uint64 {
	return anticipatedPaddingSize(itemsCount, itemsSize, 8)
}

// anticipatedPaddingSize returns the padding to consume in order to align to
// alignment bytes. Actual total size is computed as itemsCount * itemsSize.
func anticipatedPaddingSize(itemsCount, itemsSize, alignment uint64) uint64 {
	totalSize := itemsCount * itemsSize
	return paddingSize(totalSize, alignment)
}

// paddingSize8 calculates 8 byte padding.
func paddingSize8(dataSize uint64) uint64 {
	return paddingSize(dataSize, 8)
}

// paddingSizeFour calculates 4 byte padding.
func paddingSizeFour(dataSize uint64) uint64 {
	return paddingSize(dataSize, 4)
}

// paddingSize calculates padding based on the provided alignment.
func paddingSize(dataSize, alignment uint64) uint64 {
	return (alignment - (dataSize & (alignment - 1))) & (alignment - 1)
}

// u64ToUint converts a u64 to int, mirroring Rust's u64_to_usize Option return.
// Returns false when the value does not fit in a non-negative int.
func u64ToUint(n uint64) (int, bool) {
	if n > math.MaxInt64 {
		return 0, false
	}
	return int(n), true
}

// extractStringSize extracts a size based on the provided string size from
// Firehose string item entries.
func extractStringSize(data []byte, messageSize uint64) ([]byte, string, error) {
	const nullString uint64 = 0
	if messageSize == nullString {
		return data, "(null)", nil
	}

	// If our remaining data is smaller than the message string size just go
	// until the end of the remaining data
	if uint64(len(data)) < messageSize {
		// Get whole string message except end of string (0s)
		path := data
		if utf8.Valid(path) {
			return []byte{}, strings.TrimRight(string(path), "\x00"), nil
		}
		logger.Printf("[macos-unifiedlogs] Failed to get extract specific string size: invalid UTF-8")
	}

	// Get whole string message except end of string (0s)
	messageSizeInt, ok := u64ToUint(messageSize)
	if !ok {
		logger.Printf("[macos-unifiedlogs] u64 is bigger than system usize")
		return nil, "", fmt.Errorf("string size %d too large: %w", messageSize, ErrEof)
	}
	if len(data) < messageSizeInt {
		return nil, "", fmt.Errorf("needed %d bytes, got %d: %w", messageSizeInt, len(data), ErrEof)
	}
	path := data[:messageSizeInt]
	if utf8.Valid(path) {
		return data[messageSizeInt:], strings.TrimRight(string(path), "\x00"), nil
	}
	logger.Printf("[macos-unifiedlogs] Failed to get specific string: invalid UTF-8")

	return data[messageSizeInt:], "[macos-unifiedlogs Could not extract string", nil
}

const nullByte = 0

// nonEmptyCString extracts an UTF8 string from a byte array, stops at NULL_BYTE
// or END OF STRING. Consumes the end byte. Fails if the string is empty.
func nonEmptyCString(c *cursor) (string, error) {
	if c.isEmpty() {
		return "", nil
	}
	strPart := c.takeWhile(func(b byte) bool { return b != nullByte })
	// opt(take(1)) - consume a single byte (the NULL terminator) when present
	if !c.isEmpty() {
		c.pos++
	}
	if s := string(strPart); utf8.Valid(strPart) && s != "" {
		return s, nil
	}
	return "", fmt.Errorf("non-empty cstring expected: %w", ErrFail)
}

// extractString extracts strings that contain end of string characters.
func extractString(data []byte) ([]byte, string, error) {
	if len(data) == 0 {
		logger.Printf("[macos-unifiedlogs] Cannot extract string. Empty input.")
		return data, "Cannot extract string. Empty input.", nil
	}

	// If message data does not end with end of string character (0)
	// just grab everything and convert what we have to string
	if data[len(data)-1] != nullByte {
		if utf8.Valid(data) {
			return []byte{}, string(data), nil
		}
		logger.Printf("[macos-unifiedlogs] Failed to extract full string: invalid UTF-8")
		return []byte{}, "Could not extract string", nil
	}

	c := newCursor(data)
	path := c.takeWhile(func(b byte) bool { return b != 0 })
	if utf8.Valid(path) {
		return c.rest(), string(path), nil
	}
	logger.Printf("[macos-unifiedlogs] Failed to get string: invalid UTF-8")
	return c.rest(), "Could not extract string", nil
}

// encodeStandard base64 encodes data using the STANDARD engine (alphabet along with "+" and "/").
func encodeStandard(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// decodeStandard base64 decodes data using the STANDARD engine (alphabet along with "+" and "/").
func decodeStandard(data string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(data)
}

// unixEpochToISO converts a UnixEpoch timestamp (nanoseconds) to ISO RFC 3339
// with nanosecond precision and a Z suffix.
func unixEpochToISO(timestamp int64) string {
	t := time.Unix(0, timestamp).UTC()
	return t.Format("2006-01-02T15:04:05.000000000Z")
}
