// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

// Package sunlight ports the Mandiant sunlight crate: a generic Protobuf
// wire-format tag decoder. It is used to turn Statedump protocol buffer blobs
// into a JSON-serializable map.
//
// Deviation from Rust: serde_json serializes nested Value::Objects with keys in
// sorted (BTreeMap) order but serializes direct struct/map results in an
// unspecified order. This port always emits sorted keys via encoding/json,
// which matches the nested representation (the one exercised by tests).
package sunlight

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ErrParser mirrors sunlight::error::SunlightError::Parser.
var ErrParser = errors.New("Could not parse provided protobuf bytes")

var errEof = errors.New("Eof")

// WireType mirrors sunlight::light::WireType.
type WireType string

// WireType variants.
const (
	WireTypeVarInt     WireType = "VarInt"
	WireTypeFixed64    WireType = "Fixed64"
	WireTypeLen        WireType = "Len"
	WireTypeStartGroup WireType = "StartGroup"
	WireTypeEndGroup   WireType = "EndGroup"
	WireTypeFixed32    WireType = "Fixed32"
	WireTypeUnknown    WireType = "Unknown"
)

// tag mirrors sunlight::light::Tag.
type tag struct {
	tagByte  uint8
	wireType WireType
	field    uint64
}

// ExtractProtobuf attempts to extract data from the provided Protobuf bytes.
// It returns a map keyed by the (decimal) field number. Each value is a
// ProtoTag object: {"tag": {"tag_byte":.., "wire_type":.., "field":..}, "value":..}.
func ExtractProtobuf(data []byte) (map[string]any, error) {
	protoMap, err := parseTag(data)
	if err != nil {
		logger.Printf("[sunlight] could not parse provided protobuf bytes: %v", err)
		return nil, ErrParser
	}
	return protoMap, nil
}

// parseTag extracts the Protobuf values from the provided data.
func parseTag(data []byte) (map[string]any, error) {
	protoData := data
	protoMap := map[string]any{}

	for len(protoData) > 0 {
		input, t, err := getTagType(protoData)
		if err != nil {
			return nil, err
		}

		var value any
		switch t.wireType {
		case WireTypeVarInt:
			input, value, err = parseVar(input)
		case WireTypeFixed64:
			input, value, err = parseFixed64(input)
		case WireTypeLen:
			input, value, err = parseLengthTag(input)
		case WireTypeStartGroup:
			logger.Printf("[sunlight] got start group wiretype. This is deprecated, ending parsing now. Returning base64 as final result")
			value = base64.StdEncoding.EncodeToString(input)
			input = nil
		case WireTypeEndGroup:
			logger.Printf("[sunlight] got end group wiretype. This is deprecated, ending parsing now. Returning base64 as final result")
			value = base64.StdEncoding.EncodeToString(input)
			input = nil
		case WireTypeFixed32:
			input, value, err = parseFixed32(input)
		default:
			logger.Printf("[sunlight] got unknown wire type. Protobuf data may be corrupted or this is not protobuf data, ending parsing now. Returning base64 as final result")
			value = base64.StdEncoding.EncodeToString(input)
			input = nil
		}
		if err != nil {
			return nil, err
		}

		key := strconv.FormatUint(t.field, 10)
		if existing, ok := protoMap[key]; ok {
			// Existing field found. Its value should become/remain an array.
			pt := existing.(map[string]any)
			if arr, ok := pt["value"].([]any); ok {
				pt["value"] = append(arr, value)
			} else {
				pt["value"] = []any{pt["value"], value}
			}
		} else {
			protoMap[key] = protoTag(t, value)
		}

		protoData = input
	}

	return protoMap, nil
}

// protoTag builds the JSON representation of a ProtoTag.
func protoTag(t tag, value any) map[string]any {
	return map[string]any{
		"tag": map[string]any{
			"tag_byte":  t.tagByte,
			"wire_type": t.wireType,
			"field":     t.field,
		},
		"value": value,
	}
}

// getTagType determines the Protobuf Tag type.
func getTagType(data []byte) ([]byte, tag, error) {
	input, tagByte, err := nomUnsignedOneByte(data)
	if err != nil {
		return nil, tag{}, err
	}
	const fieldNumber = 3

	t := tag{
		tagByte:  tagByte,
		wireType: getWireType(tagByte),
		field:    uint64(tagByte >> fieldNumber),
	}

	// If the most significant bit is set, the next byte is part of the tag.
	checkMsb := tagByte
	for (checkMsb>>7)&1 != 0 {
		var check uint8
		input, check, err = nomUnsignedOneByte(input)
		if err != nil {
			return nil, tag{}, err
		}
		t.field *= uint64(check)
		checkMsb = check
	}

	return input, t, nil
}

// getWireType determines the Tag WireType.
func getWireType(value uint8) WireType {
	const wire = 7
	switch value & wire {
	case 0:
		return WireTypeVarInt
	case 1:
		return WireTypeFixed64
	case 2:
		return WireTypeLen
	case 3:
		return WireTypeStartGroup
	case 4:
		return WireTypeEndGroup
	case 5:
		return WireTypeFixed32
	default:
		return WireTypeUnknown
	}
}

// parseVar parses var based tags (int32/int64/uint32/uint64/sint32/sint64/bool/enum).
func parseVar(data []byte) ([]byte, any, error) {
	input, value, err := parseVarLen(data)
	if err != nil {
		return nil, nil, err
	}
	return input, value, nil
}

// parseVarLen parses a base-128 varint.
func parseVarLen(data []byte) ([]byte, int64, error) {
	protoData := data
	var varValue int64

	shift := 0
	const adjust = 0x7f
	const wire = 7
	const done = 0x80
	for len(protoData) > 0 {
		var value byte
		var err error
		protoData, value, err = nomUnsignedOneByte(protoData)
		if err != nil {
			return nil, 0, err
		}
		varValue += int64(value&adjust) << (shift * wire)
		shift++

		if value&done == 0 {
			break
		}
	}

	return protoData, varValue, nil
}

// jsonFloat marshals non-finite floats as null (matching serde_json).
type jsonFloat float64

// Float returns the underlying float64 value.
func (f jsonFloat) Float() float64 { return float64(f) }

func (f jsonFloat) MarshalJSON() ([]byte, error) {
	if math.IsNaN(float64(f)) || math.IsInf(float64(f), 0) {
		return []byte("null"), nil
	}
	return json.Marshal(float64(f))
}

// parseFixed64 parses a fixed 8 byte value (signed, unsigned, or f64).
func parseFixed64(data []byte) ([]byte, any, error) {
	input, valueData, err := nomTake(data, 8)
	if err != nil {
		return nil, nil, err
	}
	unsigned := binary.LittleEndian.Uint64(valueData)
	signed := int64(unsigned)
	double := math.Float64frombits(unsigned)

	return input, map[string]any{
		"signed":   signed,
		"unsigned": unsigned,
		"double":   jsonFloat(double),
	}, nil
}

// parseFixed32 parses a fixed 4 byte value. It can be signed, unsigned or float32.
func parseFixed32(data []byte) ([]byte, any, error) {
	input, valueData, err := nomTake(data, 4)
	if err != nil {
		return nil, nil, err
	}
	unsigned := binary.LittleEndian.Uint32(valueData)
	signed := int32(unsigned)
	float := math.Float32frombits(unsigned)

	return input, map[string]any{
		"signed":   signed,
		"unsigned": unsigned,
		"float":    jsonFloat(float64(float)),
	}, nil
}

// parseLengthTag parses length based tags. The value can be either a string or
// a nested object (sub-message).
func parseLengthTag(data []byte) ([]byte, any, error) {
	input, valueLength, err := parseVarLen(data)
	if err != nil {
		return nil, nil, err
	}
	input, valueData, err := nomTake(input, uint64(valueLength))
	if err != nil {
		return nil, nil, err
	}

	// Try string parsing first.
	message := extractUTF8String(valueData)

	// If we fail, fallback to sub-message parsing.
	if strings.HasPrefix(message, "Failed to get UTF8 string") {
		sub, err := parseTag(valueData)
		if err != nil {
			// If not string or submessage might be raw bytes.
			return input, base64.StdEncoding.EncodeToString(valueData), nil
		}
		return input, sub, nil
	}

	return input, message, nil
}

// extractUTF8String gets a UTF8 string from the provided bytes. Invalid UTF8 is
// base64 encoded.
func extractUTF8String(data []byte) string {
	if utf8.Valid(data) {
		return strings.TrimRight(string(data), "\x00")
	}
	logger.Printf("Failed to get UTF8 string for Protobuf")
	const maxSize = 2097152
	issue := ""
	if len(data) < maxSize {
		issue = base64.StdEncoding.EncodeToString(data)
	} else {
		issue = fmt.Sprintf("Binary data size larger than 2MB, size: %d", len(data))
	}
	return "Failed to get UTF8 string: " + issue
}

// nomUnsignedOneByte reads a single byte.
func nomUnsignedOneByte(data []byte) ([]byte, uint8, error) {
	if len(data) < 1 {
		return nil, 0, fmt.Errorf("needed 1 byte: %w", errEof)
	}
	return data[1:], data[0], nil
}

// nomTake returns the remaining input and the first n bytes.
func nomTake(data []byte, n uint64) ([]byte, []byte, error) {
	if n > uint64(len(data)) {
		return nil, nil, fmt.Errorf("needed %d bytes, got %d: %w", n, len(data), errEof)
	}
	return data[n:], data[:n], nil
}
