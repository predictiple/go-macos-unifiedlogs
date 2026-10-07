// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package sunlight

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"
)

func numEq(t *testing.T, got any, want int64) {
	t.Helper()
	switch v := got.(type) {
	case int64:
		if v != want {
			t.Fatalf("got %d, want %d", v, want)
		}
	case uint64:
		if int64(v) != want {
			t.Fatalf("got %d, want %d", v, want)
		}
	case int32:
		if int64(v) != want {
			t.Fatalf("got %d, want %d", v, want)
		}
	case uint32:
		if int64(v) != want {
			t.Fatalf("got %d, want %d", v, want)
		}
	case float64:
		if int64(v) != want {
			t.Fatalf("got %f, want %d", v, want)
		}
	default:
		t.Fatalf("unexpected number type %T", got)
	}
}

func TestGetWireType(t *testing.T) {
	for _, b := range []byte{0, 1, 2, 3, 4, 5} {
		if getWireType(b) == WireTypeUnknown {
			t.Errorf("getWireType(%d) is Unknown", b)
		}
	}
}

func TestGetTagType(t *testing.T) {
	test := []byte{
		10, 45, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 97, 112, 112, 115, 116, 111, 114, 101,
		100, 46, 77, 105, 103, 114, 97, 116, 111, 114, 77, 105, 115, 99, 101, 108, 108, 97, 110, 101,
		111, 117, 115, 84, 97, 115, 107, 10, 40, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 97,
		112, 112, 115, 116, 111, 114, 101, 100, 46, 77, 105, 103, 114, 97, 116, 111, 114, 65, 112,
		112, 85, 115, 97, 103, 101, 84, 97, 115, 107, 10, 38, 99, 111, 109, 46, 97, 112, 112, 108,
		101, 46, 97, 112, 112, 115, 116, 111, 114, 101, 100, 46, 77, 105, 103, 114, 97, 116, 111, 114,
		65, 114, 99, 97, 100, 101, 84, 97, 115, 107,
	}

	_, result, err := getTagType(test)
	if err != nil {
		t.Fatalf("getTagType: %v", err)
	}
	if result.field != 1 {
		t.Errorf("field = %d, want 1", result.field)
	}
	if result.wireType != WireTypeLen {
		t.Errorf("wire_type = %q, want Len", result.wireType)
	}
	if result.tagByte != 10 {
		t.Errorf("tag_byte = %d, want 10", result.tagByte)
	}
}

func TestParseVar(t *testing.T) {
	test := []byte{
		240, 249, 7, 24, 61, 32, 1, 42, 10, 66, 105, 111, 109, 101, 65, 103, 101, 110, 116, 0, 0, 0,
	}
	remaining, result, err := parseVar(test)
	if err != nil {
		t.Fatalf("parseVar: %v", err)
	}
	if len(remaining) != 19 {
		t.Errorf("remaining = %d, want 19", len(remaining))
	}
	numEq(t, result, 130288)
}

func TestParseFixed64(t *testing.T) {
	test := []byte{
		217, 236, 52, 46, 208, 118, 198, 65, 50, 28, 99, 111, 109, 46, 100, 117, 99, 107, 100, 117,
		99, 107, 103, 111, 46, 109, 97, 99, 111, 115, 46, 98, 114, 111, 119, 115, 101, 114, 74, 7, 49,
		46, 49, 49, 52, 46, 48, 82, 3, 51, 48, 56, 88, 1, 96, 1, 0, 0, 0,
	}
	remaining, result, err := parseFixed64(test)
	if err != nil {
		t.Fatalf("parseFixed64: %v", err)
	}
	if len(remaining) != 51 {
		t.Errorf("remaining = %d, want 51", len(remaining))
	}
	m := result.(map[string]any)
	if math.Abs(m["double"].(jsonFloat).Float()-753770588.413478) > 1e-6 {
		t.Errorf("double = %v", m["double"])
	}
	numEq(t, m["signed"], 4739606294354521305)
	numEq(t, m["unsigned"], 4739606294354521305)
}

func TestParseFixed32(t *testing.T) {
	test := []byte{
		217, 236, 52, 46,
	}
	remaining, result, err := parseFixed32(test)
	if err != nil {
		t.Fatalf("parseFixed32: %v", err)
	}
	if len(remaining) != 0 {
		t.Errorf("remaining = %d, want 0", len(remaining))
	}
	m := result.(map[string]any)
	if math.Abs(m["float"].(jsonFloat).Float()-4.1137624556819574e-11) > 1e-25 {
		t.Errorf("float = %v", m["float"])
	}
	numEq(t, m["signed"], 775220441)
	numEq(t, m["unsigned"], 775220441)
}

func TestParseLengthTag(t *testing.T) {
	test := []byte{
		45, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 97, 112, 112, 115, 116, 111, 114, 101, 100,
		46, 77, 105, 103, 114, 97, 116, 111, 114, 77, 105, 115, 99, 101, 108, 108, 97, 110, 101, 111,
		117, 115, 84, 97, 115, 107, 10, 40, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 97, 112,
		112, 115, 116, 111, 114, 101, 100, 46, 77, 105, 103, 114, 97, 116, 111, 114, 65, 112, 112, 85,
		115, 97, 103, 101, 84, 97, 115, 107, 10, 38, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 97,
		112, 112, 115, 116, 111, 114, 101, 100, 46, 77, 105, 103, 114, 97, 116, 111, 114, 65, 114, 99,
		97, 100, 101, 84, 97, 115, 107,
	}
	remaining, result, err := parseLengthTag(test, 0)
	if err != nil {
		t.Fatalf("parseLengthTag: %v", err)
	}
	if result != "com.apple.appstored.MigratorMiscellaneousTask" {
		t.Errorf("result = %v", result)
	}
	if len(remaining) != 82 {
		t.Errorf("remaining = %d, want 82", len(remaining))
	}
}

func TestExtractUTF8String(t *testing.T) {
	testData := []byte{
		112, 112, 115, 116, 111, 114, 101, 100, 46, 77, 105, 103, 114, 97, 116, 111, 114, 77, 105,
		115, 99, 101, 108, 108,
	}
	if extractUTF8String(testData) != "ppstored.MigratorMiscell" {
		t.Errorf("unexpected string")
	}
}

func TestParseTag(t *testing.T) {
	test := []byte{
		10, 45, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 97, 112, 112, 115, 116, 111, 114, 101,
		100, 46, 77, 105, 103, 114, 97, 116, 111, 114, 77, 105, 115, 99, 101, 108, 108, 97, 110, 101,
		111, 117, 115, 84, 97, 115, 107, 10, 40, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 97,
		112, 112, 115, 116, 111, 114, 101, 100, 46, 77, 105, 103, 114, 97, 116, 111, 114, 65, 112,
		112, 85, 115, 97, 103, 101, 84, 97, 115, 107, 10, 38, 99, 111, 109, 46, 97, 112, 112, 108,
		101, 46, 97, 112, 112, 115, 116, 111, 114, 101, 100, 46, 77, 105, 103, 114, 97, 116, 111, 114,
		65, 114, 99, 97, 100, 101, 84, 97, 115, 107,
	}

	result, err := parseTag(test)
	if err != nil {
		t.Fatalf("parseTag: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("result.len() = %d, want 1", len(result))
	}
	field1 := result["1"].(map[string]any)
	if field1["tag"].(map[string]any)["wire_type"] != WireTypeLen {
		t.Errorf("wire_type = %v, want Len", field1["tag"].(map[string]any)["wire_type"])
	}
	arr := field1["value"].([]any)
	want := []string{
		"com.apple.appstored.MigratorMiscellaneousTask",
		"com.apple.appstored.MigratorAppUsageTask",
		"com.apple.appstored.MigratorArcadeTask",
	}
	if len(arr) != len(want) {
		t.Fatalf("array len = %d, want %d", len(arr), len(want))
	}
	for i := range want {
		if arr[i] != want[i] {
			t.Errorf("array[%d] = %v, want %s", i, arr[i], want[i])
		}
	}
}

func TestParseTagFields(t *testing.T) {
	test := []byte{
		10, 10, 112, 114, 111, 100, 117, 99, 116, 105, 111, 110, 18, 32, 99, 52, 52, 101, 49, 48, 50,
		57, 57, 57, 57, 51, 101, 101, 53, 100, 97, 56, 48, 56, 48, 98, 51, 57, 53, 51, 57, 57, 101,
		56, 50, 54,
	}

	result, err := parseTag(test)
	if err != nil {
		t.Fatalf("parseTag: %v", err)
	}
	if len(result) != 2 {
		t.Fatalf("result len = %d, want 2", len(result))
	}
	if result["1"].(map[string]any)["value"] != "production" {
		t.Errorf("field 1 = %v", result["1"].(map[string]any)["value"])
	}
	if result["2"].(map[string]any)["value"] != "c44e10299993ee5da8080b395399e826" {
		t.Errorf("field 2 = %v", result["2"].(map[string]any)["value"])
	}
}

func TestParseTagBiome(t *testing.T) {
	test := []byte{
		10, 15, 55, 53, 48, 48, 53, 54, 55, 57, 57, 54, 48, 56, 53, 57, 56, 16, 240, 249, 7, 24, 61,
		32, 1, 42, 10, 66, 105, 111, 109, 101, 65, 103, 101, 110, 116, 0, 0, 0,
	}
	result, err := parseTag(test)
	if err != nil {
		t.Fatalf("parseTag: %v", err)
	}
	if len(result) != 6 {
		t.Fatalf("result len = %d, want 6", len(result))
	}
	numEq(t, result["4"].(map[string]any)["value"], 1)
	arr := result["0"].(map[string]any)["value"].([]any)
	if len(arr) != 2 {
		t.Fatalf("field 0 = %v, want [0 0]", arr)
	}
	numEq(t, arr[0], 0)
	numEq(t, arr[1], 0)
	if result["5"].(map[string]any)["value"] != "BiomeAgent" {
		t.Errorf("field 5 = %v", result["5"].(map[string]any)["value"])
	}
	if result["1"].(map[string]any)["value"] != "750056799608598" {
		t.Errorf("field 1 = %v", result["1"].(map[string]any)["value"])
	}
}

func TestParseTagBiomeApp(t *testing.T) {
	test := []byte{
		16, 1, 24, 1, 33, 217, 236, 52, 46, 208, 118, 198, 65, 50, 28, 99, 111, 109, 46, 100, 117, 99,
		107, 100, 117, 99, 107, 103, 111, 46, 109, 97, 99, 111, 115, 46, 98, 114, 111, 119, 115, 101,
		114, 74, 7, 49, 46, 49, 49, 52, 46, 48, 82, 3, 51, 48, 56, 88, 1, 96, 1, 0, 0, 0,
	}
	result, err := parseTag(test)
	if err != nil {
		t.Fatalf("parseTag: %v", err)
	}
	if len(result) != 9 {
		t.Fatalf("result len = %d, want 9", len(result))
	}
	field4 := result["4"].(map[string]any)["value"].(map[string]any)
	if math.Abs(field4["double"].(jsonFloat).Float()-753770588.413478) < 1e-6 {
		// ok
	} else {
		t.Errorf("field 4 double = %v", field4["double"])
	}
	numEq(t, field4["signed"], 4739606294354521305)
	numEq(t, result["0"].(map[string]any)["value"].([]any)[0], 0)
	if result["6"].(map[string]any)["value"] != "com.duckduckgo.macos.browser" {
		t.Errorf("field 6 = %v", result["6"].(map[string]any)["value"])
	}
	if result["9"].(map[string]any)["value"] != "1.114.0" {
		t.Errorf("field 9 = %v", result["9"].(map[string]any)["value"])
	}
}

func TestParseTagBiomeMicrosoft(t *testing.T) {
	test := []byte{
		16, 1, 24, 0, 33, 19, 41, 57, 157, 203, 118, 198, 65, 50, 25, 99, 111, 109, 46, 109, 105, 99,
		114, 111, 115, 111, 102, 116, 46, 97, 117, 116, 111, 117, 112, 100, 97, 116, 101, 50, 74, 4,
		52, 46, 55, 54, 82, 13, 52, 46, 55, 54, 46, 50, 52, 49, 48, 49, 51, 56, 55, 88, 1, 96, 1, 0,
		0, 0,
	}
	result, err := parseTag(test)
	if err != nil {
		t.Fatalf("parseTag: %v", err)
	}
	if len(result) != 9 {
		t.Fatalf("result len = %d, want 9", len(result))
	}
	if result["6"].(map[string]any)["value"] != "com.microsoft.autoupdate2" {
		t.Errorf("field 6 = %v", result["6"].(map[string]any)["value"])
	}
	if result["10"].(map[string]any)["value"] != "4.76.24101387" {
		t.Errorf("field 10 = %v", result["10"].(map[string]any)["value"])
	}
	if result["9"].(map[string]any)["value"] != "4.76" {
		t.Errorf("field 9 = %v", result["9"].(map[string]any)["value"])
	}
}

func TestParseTagBiomeSiri(t *testing.T) {
	test := []byte{
		8, 1, 18, 55, 99, 111, 109, 46, 97, 112, 112, 108, 101, 46, 115, 105, 114, 105, 46, 109, 101,
		116, 114, 105, 99, 115, 46, 77, 101, 116, 114, 105, 99, 115, 69, 120, 116, 101, 110, 115, 105,
		111, 110, 46, 115, 99, 111, 114, 101, 99, 97, 114, 100, 46, 100, 97, 105, 108, 121, 26, 11,
		78, 111, 116, 32, 83, 116, 97, 114, 116, 101, 100,
	}
	result, err := parseTag(test)
	if err != nil {
		t.Fatalf("parseTag: %v", err)
	}
	if len(result) != 3 {
		t.Fatalf("result len = %d, want 3", len(result))
	}
	if result["2"].(map[string]any)["value"] != "com.apple.siri.metrics.MetricsExtension.scorecard.daily" {
		t.Errorf("field 2 = %v", result["2"].(map[string]any)["value"])
	}
	if result["3"].(map[string]any)["value"] != "Not Started" {
		t.Errorf("field 3 = %v", result["3"].(map[string]any)["value"])
	}
	numEq(t, result["1"].(map[string]any)["value"], 1)
}

func TestParseTagBiomeSiriMetrics(t *testing.T) {
	test := []byte{
		8, 1, 17, 0, 0, 0, 128, 76, 206, 217, 65, 25, 0, 0, 0, 32, 155, 208, 217, 65, 34, 55, 99, 111,
		109, 46, 97, 112, 112, 108, 101, 46, 115, 105, 114, 105, 46, 109, 101, 116, 114, 105, 99, 115,
		46, 77, 101, 116, 114, 105, 99, 115, 69, 120, 116, 101, 110, 115, 105, 111, 110, 46, 115, 99,
		111, 114, 101, 99, 97, 114, 100, 46, 100, 97, 105, 108, 121, 42, 11, 78, 111, 116, 32, 83,
		116, 97, 114, 116, 101, 100, 49, 134, 227, 69, 236, 1, 207, 217, 65, 56, 1, 64, 0, 72, 0, 81,
		0, 0, 0, 192, 204, 255, 42, 64, 89, 0, 0, 0, 0, 0, 0, 240, 191, 97, 0, 0, 0, 192, 204, 255,
		42, 64, 105, 0, 0, 0, 0, 0, 0, 240, 191, 113, 0, 0, 0, 0, 0, 0, 240, 191, 0, 0,
	}
	result, err := parseTag(test)
	if err != nil {
		t.Fatalf("parseTag: %v", err)
	}
	if len(result) != 15 {
		t.Fatalf("result len = %d, want 15", len(result))
	}
	if result["4"].(map[string]any)["value"] != "com.apple.siri.metrics.MetricsExtension.scorecard.daily" {
		t.Errorf("field 4 = %v", result["4"].(map[string]any)["value"])
	}
	field3 := result["3"].(map[string]any)["value"].(map[string]any)
	if math.Abs(field3["double"].(jsonFloat).Float()-1732406400.0) > 1e-6 {
		t.Errorf("field 3 double = %v", field3["double"])
	}
	field12 := result["12"].(map[string]any)["value"].(map[string]any)
	if math.Abs(field12["double"].(jsonFloat).Float()-13.499608993530273) > 1e-6 {
		t.Errorf("field 12 double = %v", field12["double"])
	}
	numEq(t, field12["signed"], 4623789222308872192)
}

func TestParseBlackboxProtobuf(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "blackboxprotobuf", "test_message.out"))
	if err != nil {
		t.Skipf("sunlight test data not available: %v", err)
	}
	result, err := parseTag(data)
	if err != nil {
		t.Fatalf("parseTag: %v", err)
	}
	numEq(t, result["128"].(map[string]any)["value"], 1)
	field1024 := result["1024"].(map[string]any)["value"].(map[string]any)
	numEq(t, field1024["signed"], -20)
	numEq(t, field1024["unsigned"], 4294967276)
	if !math.IsNaN(field1024["float"].(jsonFloat).Float()) {
		t.Errorf("field 1024 float = %v, want NaN", field1024["float"])
	}
	field32768 := result["32768"].(map[string]any)["value"].(map[string]any)
	sub2 := field32768["2"].(map[string]any)["value"]
	if sub2 != "Test1234" {
		t.Errorf("field 32768.2 = %v", sub2)
	}
}

func TestExtractProtobufBadData(t *testing.T) {
	badData := []byte{
		0, 0, 1, 4, 5, 0, 0,
	}
	if _, err := ExtractProtobuf(badData); err != ErrParser {
		t.Errorf("err = %v, want ErrParser", err)
	}
}

func TestProtobufParserStats(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "stats", "proto.raw"))
	if err != nil {
		t.Skipf("sunlight test data not available: %v", err)
	}
	value, err := ExtractProtobuf(data)
	if err != nil {
		t.Fatalf("ExtractProtobuf: %v", err)
	}
	if len(value) != 7 {
		t.Fatalf("value len = %d, want 7", len(value))
	}
	arr := value["23"].(map[string]any)["value"].([]any)
	if len(arr) != 1736 {
		t.Fatalf("field 23 array len = %d, want 1736", len(arr))
	}
	nested := arr[23].(map[string]any)["10"].(map[string]any)["value"]
	numEq(t, nested, 4099380458)
	_ = json.Marshal
}

func TestProtobufParserCoalitions(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "stats", "coalitions.raw"))
	if err != nil {
		t.Skipf("sunlight test data not available: %v", err)
	}
	value, err := ExtractProtobuf(data)
	if err != nil {
		t.Fatalf("ExtractProtobuf: %v", err)
	}
	if len(value) != 7 {
		t.Fatalf("value len = %d, want 7", len(value))
	}
	arr := value["62"].(map[string]any)["value"].([]any)
	if len(arr) != 1271 {
		t.Fatalf("field 62 array len = %d, want 1271", len(arr))
	}
	str := arr[252].(map[string]any)["7"].(map[string]any)["value"]
	if str != "com.apple.localizationswitcherd" {
		t.Errorf("field 62[252].7 = %v", str)
	}
}
