// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

import "testing"

func i64p(v int64) *int64 { return &v }
func intp(v int) *int     { return &v }

func TestFormatFirehoseLogMessage(t *testing.T) {
	testData := "opendirectoryd (build %{public}s) launched..."
	itemMessage := []FirehoseItemType{
		{MessageStrings: "796.100", ItemType: 34, ItemSize: 0},
	}
	logString := FormatFirehoseLogMessage(testData, itemMessage, firehoseMessageRegex)
	want := "opendirectoryd (build 796.100) launched..."
	if logString != want {
		t.Errorf("got %q, want %q", logString, want)
	}
}

func TestFormatFirehoseLogMessageTricky(t *testing.T) {
	test := "<%{public}@:%p> creating new multiplexing view controller controller <%{public}@:%p> for %{public}@ at level: %.f"
	items := []FirehoseItemType{
		{ItemType: 66, ItemTypeSize: 4, Offset: 0, ItemSize: 23, MessageStrings: "SBHMultiplexingManager"},
		{ItemType: 0, ItemTypeSize: 8, Offset: 0, ItemSize: 0, MessageStrings: "936749223363120960"},
		{ItemType: 66, ItemTypeSize: 4, Offset: 23, ItemSize: 30, MessageStrings: "SBHMultiplexingViewController"},
		{ItemType: 0, ItemTypeSize: 8, Offset: 0, ItemSize: 0, MessageStrings: "1008806817370365440"},
		{ItemType: 66, ItemTypeSize: 4, Offset: 53, ItemSize: 37, MessageStrings: "D8F2438E-AACF-4ED9-AD47-F5A1598215C7"},
		{ItemType: 0, ItemTypeSize: 8, Offset: 0, ItemSize: 0, MessageStrings: "0"},
	}
	logString := FormatFirehoseLogMessage(test, items, firehoseMessageRegex)
	want := "<SBHMultiplexingManager:D0000749E2E8F40> creating new multiplexing view controller controller <SBHMultiplexingViewController:E0000749C5A5E00> for D8F2438E-AACF-4ED9-AD47-F5A1598215C7 at level: 0"
	if logString != want {
		t.Errorf("got  %q\nwant %q", logString, want)
	}
}

func TestFormatFirehoseLogMessageTrickyPrecision(t *testing.T) {
	test := "%p - ProcessThrottlerTimedActivity::activityTimedOut: %{public}s (timeout: %.f sec)"
	items := []FirehoseItemType{
		{ItemType: 0, ItemTypeSize: 8, ItemSize: 0, MessageStrings: "4833657296"},
		{ItemType: 34, ItemTypeSize: 4, ItemSize: 26, MessageStrings: "View was recently visible"},
		{ItemType: 0, ItemTypeSize: 8, ItemSize: 0, MessageStrings: "4642648265865560064"},
	}
	logString := FormatFirehoseLogMessage(test, items, firehoseMessageRegex)
	want := "1201BC1D0 - ProcessThrottlerTimedActivity::activityTimedOut: View was recently visible (timeout: 240 sec)"
	if logString != want {
		t.Errorf("got  %q\nwant %q", logString, want)
	}
}

func TestBadFormatOptions(t *testing.T) {
	message := "PAVAbstractVideoInterface.cpp::%d] DCPAV[%d] %s::%s Setting %s syncWidth = %u"
	items := []FirehoseItemType{
		{MessageStrings: "406", ItemType: 0, ItemSize: 0},
		{MessageStrings: "258", ItemType: 0, ItemSize: 0},
		{MessageStrings: "DCPAVSimpleVideoInterface", ItemType: 32, ItemSize: 25},
		{MessageStrings: "setColorElement", ItemType: 32, ItemSize: 15},
		{MessageStrings: "3", ItemType: 0, ItemSize: 0},
		{MessageStrings: "All", ItemType: 32, ItemSize: 3},
		{MessageStrings: "89", ItemType: 0, ItemSize: 0},
	}
	logString := FormatFirehoseLogMessage(message, items, firehoseMessageRegex)
	want := "PAVAbstractVideoInterface.cpp::406] DCPAV[258] DCPAVSimpleVideoInterface::setColorElement Setting 3 syncWidth = 0"
	if logString != want {
		t.Errorf("got  %q\nwant %q", logString, want)
	}
}

func TestParseFormatter(t *testing.T) {
	testMessage := []FirehoseItemType{
		{MessageStrings: "2", ItemType: 2, ItemSize: 2},
	}

	check := func(format string, want string) {
		t.Helper()
		got, err := parseFormatter(format, testMessage, testMessage[0].ItemType, 0)
		if err != nil {
			t.Fatalf("parseFormatter(%q): %v", format, err)
		}
		if got != want {
			t.Errorf("parseFormatter(%q) = %q, want %q", format, got, want)
		}
	}

	check("%+04d", "+002")
	check("%04d", "0002")
	check("%#4x", " 0x2")

	testMessage[0].MessageStrings = "100"
	check("%#04o", "0o144")
	check("%07o", "0000144")

	testMessage[0].MessageStrings = "10"
	check("%x", "A")

	testMessage[0].MessageStrings = "4570111009880014848"
	check("%+09.4f", "+000.0035")
	check("%9.4f", "   0.0035")
	check("%-8.4f", "0.0035  ")

	testMessage[0].MessageStrings = "4614286721111404799"
	check("%f", "3.154944")

	testMessage[0].MessageStrings = "-248"
	check("%d", "-248")

	testMessage[0].MessageStrings = "-4611686018427387904"
	check("%f", "-2")

	testMessage[0].MessageStrings = "-4484628366119329180"
	check("%f", "-650937839.633862")

	testMessage[0].MessageStrings = "The big red dog jumped over the crab"
	check("%s", "The big red dog jumped over the crab")

	testMessage[0].MessageStrings = "aaabbbb"
	check("%.2@", "aa")

	testMessage[0].ItemSize = 10
	testMessage[0].ItemType = 0x12
	testMessage = append(testMessage, FirehoseItemType{MessageStrings: "hi", ItemType: 2, ItemSize: 2})
	got, err := parseFormatter("%*s", testMessage, testMessage[0].ItemType, 0)
	if err != nil {
		t.Fatalf("parseFormatter(%%*s): %v", err)
	}
	if got != "        hi" {
		t.Errorf("parseFormatter(%%*s) = %q, want %q", got, "        hi")
	}
}

func TestParseTypeFormatter(t *testing.T) {
	testMessage := []FirehoseItemType{
		{MessageStrings: "test", ItemType: 2, ItemSize: 4},
	}
	got, err := parseTypeFormatter("%{public}s", testMessage, testMessage[0].ItemType, 0)
	if err != nil {
		t.Fatalf("parseTypeFormatter: %v", err)
	}
	if got != "test" {
		t.Errorf("got %q, want test", got)
	}

	signpost := []FirehoseItemType{
		{MessageStrings: "1", ItemType: 2, ItemSize: 4},
	}
	got, err = parseTypeFormatter("%{public, signpost.description:begin_time}llu", signpost, signpost[0].ItemType, 0)
	if err != nil {
		t.Fatalf("parseTypeFormatter signpost: %v", err)
	}
	if got != "1 (signpost.description:begin_time)" {
		t.Errorf("got %q, want %q", got, "1 (signpost.description:begin_time)")
	}
}

func TestParseSignpostFormat(t *testing.T) {
	results := parseSignpostFormat("%{public, signpost.description:begin_time")
	if results != "signpost.description:begin_time" {
		t.Errorf("got %q, want signpost.description:begin_time", results)
	}
}

func TestFormatMessagePadding(t *testing.T) {
	message := messageFormatters{
		itemFormat:   "d",
		itemNumber:   i64p(2),
		precision:    nil,
		width:        4,
		plusMinus:    false,
		hashtag:      false,
		alignment:    alignmentLeft,
		message:      "2",
		numberFormat: numberFormatDecimal,
		padding:      paddingZero,
	}
	formatMessagePadding(&message)
	if message.message != "2000" {
		t.Errorf("got %q, want 2000", message.message)
	}
}

func TestFormatMessagePaddingRight(t *testing.T) {
	message := messageFormatters{
		itemFormat:   "d",
		itemNumber:   i64p(2),
		width:        4,
		alignment:    alignmentRight,
		message:      "2",
		numberFormat: numberFormatDecimal,
		padding:      paddingZero,
	}
	formatMessagePadding(&message)
	if message.message != "0002" {
		t.Errorf("got %q, want 0002", message.message)
	}
}

func TestFormatMessagePaddingSpaceLeft(t *testing.T) {
	message := messageFormatters{
		itemNumber:   i64p(2),
		precision:    intp(0),
		width:        4,
		itemFormat:   "d",
		alignment:    alignmentLeft,
		message:      "2",
		numberFormat: numberFormatDecimal,
		padding:      paddingSpace,
	}
	formatMessagePadding(&message)
	if message.message != "2   " {
		t.Errorf("got %q, want %q", message.message, "2   ")
	}
}

func TestFormatMessagePaddingRightSpace(t *testing.T) {
	message := messageFormatters{
		itemNumber:   i64p(2),
		precision:    intp(0),
		width:        4,
		itemFormat:   "d",
		alignment:    alignmentRight,
		message:      "2",
		numberFormat: numberFormatDecimal,
		padding:      paddingSpace,
	}
	formatMessagePadding(&message)
	if message.message != "   2" {
		t.Errorf("got %q, want %q", message.message, "   2")
	}
}

func TestFormatLeft(t *testing.T) {
	message := messageFormatters{
		itemNumber:   i64p(2),
		precision:    intp(0),
		width:        4,
		itemFormat:   "d",
		alignment:    alignmentLeft,
		message:      "2",
		numberFormat: numberFormatDecimal,
		padding:      paddingZero,
	}
	formatMessage(&message)
	if message.message != "2" {
		t.Errorf("got %q, want 2", message.message)
	}
}

func TestFormatRight(t *testing.T) {
	message := messageFormatters{
		itemNumber:   i64p(2),
		precision:    intp(0),
		width:        4,
		itemFormat:   "d",
		alignment:    alignmentRight,
		message:      "2",
		numberFormat: numberFormatDecimal,
		padding:      paddingZero,
	}
	formatMessage(&message)
	if message.message != "2" {
		t.Errorf("got %q, want 2", message.message)
	}
}

func TestParseFloat(t *testing.T) {
	if got := parseFloat("4611911198408756429"); got != 2.1 {
		t.Errorf("got %v, want 2.1", got)
	}
}

func TestParseInt(t *testing.T) {
	if got := parseInt("2"); got != 2 {
		t.Errorf("got %v, want 2", got)
	}
}
