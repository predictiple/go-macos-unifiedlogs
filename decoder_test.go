// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

import "testing"

func TestCheckObjectsLowercaseBool(t *testing.T) {
	testFormat := "%{bool}d"
	testItemInfo := []FirehoseItemType{
		{MessageStrings: "1", ItemType: 0, ItemSize: 4},
	}
	results := checkObjects(testFormat, testItemInfo, 0, 0)
	if results != "true" {
		t.Errorf("checkObjects = %q, want true", results)
	}
}

func TestCheckObjectsUppercaseBool(t *testing.T) {
	testFormat := "%{BOOL}d"
	testItemInfo := []FirehoseItemType{
		{MessageStrings: "1", ItemType: 0, ItemSize: 4},
	}
	results := checkObjects(testFormat, testItemInfo, 0, 0)
	if results != "YES" {
		t.Errorf("checkObjects = %q, want YES", results)
	}
}

func TestCheckObjectsOdtypes(t *testing.T) {
	testFormat := "%{odtypes:mbr_details}d"
	testItemInfo := []FirehoseItemType{
		{MessageStrings: "I/7///8vTG9jYWwvRGVmYXVsdAA=", ItemType: 50, ItemSize: 0},
	}
	results := checkObjects(testFormat, testItemInfo, 50, 0)
	if results != "user: -2@/Local/Default" {
		t.Errorf("checkObjects = %q, want user: -2@/Local/Default", results)
	}
}

func TestCheckObjectsUuid(t *testing.T) {
	testFormat := "%{public,uuid_t}.16P"
	testItemInfo := []FirehoseItemType{
		{MessageStrings: "hZV+HTbETtKGqAZXvN3ikw==", ItemType: 50, ItemSize: 16},
	}
	results := checkObjects(testFormat, testItemInfo, 50, 0)
	if results != "85957E1D36C44ED286A80657BCDDE293" {
		t.Errorf("checkObjects = %q, want 85957E1D36C44ED286A80657BCDDE293", results)
	}
}

func TestCheckObjectsPrivate(t *testing.T) {
	testFormat := "%{public,uuid_t}.16P"
	testItemInfo := []FirehoseItemType{
		{MessageStrings: "<private>", ItemType: 50, ItemSize: 16},
	}
	results := checkObjects(testFormat, testItemInfo, 50, 0)
	if results != "<private>" {
		t.Errorf("checkObjects = %q, want <private>", results)
	}
}

func TestCheckObjectsHash(t *testing.T) {
	testFormat := "%{public,mask.hash}.16P"
	testItemInfo := []FirehoseItemType{
		{MessageStrings: "hash", ItemType: 242, ItemSize: 16},
	}
	results := checkObjects(testFormat, testItemInfo, 242, 0)
	if results != "hash" {
		t.Errorf("checkObjects = %q, want hash", results)
	}
}
