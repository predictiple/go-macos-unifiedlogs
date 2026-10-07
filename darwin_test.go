// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

import "testing"

func TestErrnoCodes(t *testing.T) {
	testData := "1"
	result := errnoCodes(testData)
	if result != "Operation not permitted" {
		t.Errorf("errnoCodes = %q, want Operation not permitted", result)
	}

	testData = "35"
	result = errnoCodes(testData)
	if result != "Resource temporarily unavailable, operation would block" {
		t.Errorf("errnoCodes = %q", result)
	}

	testData = "58"
	result = errnoCodes(testData)
	if result != "Can't send after socket shutdown" {
		t.Errorf("errnoCodes = %q", result)
	}

	testData = "82"
	result = errnoCodes(testData)
	if result != "Device power is off" {
		t.Errorf("errnoCodes = %q", result)
	}
}

func TestMachErrnoCodes(t *testing.T) {
	testData := "268435465"
	result := machCodes(testData)
	if result != "invalid reply" {
		t.Errorf("machCodes = %q", result)
	}

	testData = "268435470"
	result = machCodes(testData)
	if result != "too large" {
		t.Errorf("machCodes = %q", result)
	}

	testData = "268435469"
	result = machCodes(testData)
	if result != "no buffer" {
		t.Errorf("machCodes = %q", result)
	}

	testData = "268435468"
	result = machCodes(testData)
	if result != "invalid memory" {
		t.Errorf("machCodes = %q", result)
	}
}

func TestPermission(t *testing.T) {
	testData := "111"
	result := permission(testData)
	if result != "---x--x--x" {
		t.Errorf("permission = %q", result)
	}

	testData = "448"
	result = permission(testData)
	if result != "-r--r-----" {
		t.Errorf("permission = %q", result)
	}

	testData = "777"
	result = permission(testData)
	if result != "-rwxrwxrwx" {
		t.Errorf("permission = %q", result)
	}

	testData = "400"
	result = permission(testData)
	if result != "-r--------" {
		t.Errorf("permission = %q", result)
	}
}
