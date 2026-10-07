// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

import "testing"

func TestParseTime(t *testing.T) {
	testData := "1642302428"
	result, err := parseTime(testData)
	if err != nil {
		t.Fatalf("parseTime failed: %v", err)
	}
	if result != "2022-01-16T03:07:08.000Z" {
		t.Errorf("parseTime = %q, want %q", result, "2022-01-16T03:07:08.000Z")
	}
}
