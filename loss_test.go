// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

import "testing"

func TestParseFirehoseLossMonterey(t *testing.T) {
	testData := []byte{
		72, 56, 43, 42, 0, 0, 0, 0, 231, 207, 114, 187, 0, 0, 0, 0, 63, 0, 0, 0, 0, 0, 0, 0,
	}

	_, results, err := parseFirehoseLoss(testData)
	if err != nil {
		t.Fatalf("parseFirehoseLoss returned error: %v", err)
	}
	if results.StartTime != 707475528 {
		t.Errorf("start_time = %d, want %d", results.StartTime, 707475528)
	}
	if results.EndTime != 3144863719 {
		t.Errorf("end_time = %d, want %d", results.EndTime, 3144863719)
	}
	if results.Count != 63 {
		t.Errorf("count = %d, want %d", results.Count, 63)
	}
}
