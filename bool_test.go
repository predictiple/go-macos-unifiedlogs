// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

import "testing"

func TestUppercaseBool(t *testing.T) {
	testData := "0"
	if results := uppercaseBool(testData); results != "NO" {
		t.Fatalf("unexpected results: %s", results)
	}

	testData = "1"
	if results := uppercaseBool(testData); results != "YES" {
		t.Fatalf("unexpected results: %s", results)
	}
}

func TestLowercaseBool(t *testing.T) {
	testData := "0"
	if results := lowercaseBool(testData); results != "false" {
		t.Fatalf("unexpected results: %s", results)
	}

	testData = "1"
	if results := lowercaseBool(testData); results != "true" {
		t.Fatalf("unexpected results: %s", results)
	}
}

func TestLowercaseIntBool(t *testing.T) {
	var testData uint8 = 0
	if results := lowercaseIntBool(testData); results != "false" {
		t.Fatalf("unexpected results: %s", results)
	}
}
