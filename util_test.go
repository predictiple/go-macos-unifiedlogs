// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

import "testing"

func TestAnticipatedPaddingSize(t *testing.T) {
	tests := []struct {
		n, size, alignment, want uint64
	}{
		{0, 8, 8, 0},
		{1, 8, 8, 0},
		{2, 16, 8, 0},
		{2, 5, 8, 6},
	}
	for _, tt := range tests {
		if got := anticipatedPaddingSize(tt.n, tt.size, tt.alignment); got != tt.want {
			t.Errorf("anticipatedPaddingSize(%d, %d, %d) = %d, want %d", tt.n, tt.size, tt.alignment, got, tt.want)
		}
	}
}

func TestPaddingSize8(t *testing.T) {
	tests := []struct{ dataSize, want uint64 }{
		{0, 0},
		{7, 1},
		{8, 0},
		{16, 0},
	}
	for _, tt := range tests {
		if got := paddingSize8(tt.dataSize); got != tt.want {
			t.Errorf("paddingSize8(%d) = %d, want %d", tt.dataSize, got, tt.want)
		}
	}
}

func TestPaddingSizeFour(t *testing.T) {
	tests := []struct{ dataSize, want uint64 }{
		{0, 0},
		{3, 1},
		{4, 0},
		{8, 0},
	}
	for _, tt := range tests {
		if got := paddingSizeFour(tt.dataSize); got != tt.want {
			t.Errorf("paddingSizeFour(%d) = %d, want %d", tt.dataSize, got, tt.want)
		}
	}
}

func TestExtractStringSize(t *testing.T) {
	testData := []byte{55, 57, 54, 46, 49, 48, 48, 0}
	_, results, err := extractStringSize(testData, 8)
	if err != nil {
		t.Fatalf("extractStringSize returned error: %v", err)
	}
	if results != "796.100" {
		t.Errorf("extractStringSize = %q, want %q", results, "796.100")
	}
}

func TestExtractString(t *testing.T) {
	testData := []byte{55, 57, 54, 46, 49, 48, 48, 0}
	_, results, err := extractString(testData)
	if err != nil {
		t.Fatalf("extractString returned error: %v", err)
	}
	if results != "796.100" {
		t.Errorf("extractString = %q, want %q", results, "796.100")
	}
}

func TestEncodeStandard(t *testing.T) {
	test := []byte("Hello word!")
	result := encodeStandard(test)
	if result != "SGVsbG8gd29yZCE=" {
		t.Errorf("encodeStandard = %q, want %q", result, "SGVsbG8gd29yZCE=")
	}
}

func TestDecodeStandard(t *testing.T) {
	test := "SGVsbG8gd29yZCE="
	result, err := decodeStandard(test)
	if err != nil {
		t.Fatalf("decodeStandard returned error: %v", err)
	}
	if string(result) != "Hello word!" {
		t.Errorf("decodeStandard = %q, want %q", result, "Hello word!")
	}
}

func TestUnixEpochToISO(t *testing.T) {
	result := unixEpochToISO(1650767813342574583)
	if result != "2022-04-24T02:36:53.342574583Z" {
		t.Errorf("unixEpochToISO = %q, want %q", result, "2022-04-24T02:36:53.342574583Z")
	}
}

func TestNonEmptyCString(t *testing.T) {
	input := []byte{55, 57, 54, 46, 49, 48, 48, 0}
	c := newCursor(input)
	s, err := nonEmptyCString(c)
	if err != nil {
		t.Fatalf("nonEmptyCString returned error: %v", err)
	}
	if !c.isEmpty() {
		t.Errorf("expected empty remainder, got %d bytes", c.remaining())
	}
	if s != "796.100" {
		t.Errorf("nonEmptyCString = %q, want %q", s, "796.100")
	}

	input = []byte{55, 57, 54, 46, 49, 48, 48}
	c = newCursor(input)
	s, err = nonEmptyCString(c)
	if err != nil {
		t.Fatalf("nonEmptyCString returned error: %v", err)
	}
	if !c.isEmpty() {
		t.Errorf("expected empty remainder, got %d bytes", c.remaining())
	}
	if s != "796.100" {
		t.Errorf("nonEmptyCString = %q, want %q", s, "796.100")
	}

	input = []byte{55, 57, 54, 46, 49, 48, 48, 0, 42, 42, 42}
	c = newCursor(input)
	s, err = nonEmptyCString(c)
	if err != nil {
		t.Fatalf("nonEmptyCString returned error: %v", err)
	}
	if string(c.rest()) != string([]byte{42, 42, 42}) {
		t.Errorf("remainder = %v, want [42 42 42]", c.rest())
	}
	if s != "796.100" {
		t.Errorf("nonEmptyCString = %q, want %q", s, "796.100")
	}

	input = []byte{0, 42, 42, 42}
	c = newCursor(input)
	if _, err = nonEmptyCString(c); err == nil {
		t.Error("nonEmptyCString expected error for leading NULL byte, got nil")
	}
}
