// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

import "testing"

func TestErrnoCodesOpenDirectory(t *testing.T) {
	testData := "1101"
	result := openDirectoryErrors(testData)
	if result != "ODErrorSessionProxyVersionMismatch" {
		t.Errorf("openDirectoryErrors = %q", result)
	}

	testData = "10000"
	result = openDirectoryErrors(testData)
	if result != "ODErrorPluginOperationNotSupported" {
		t.Errorf("openDirectoryErrors = %q", result)
	}
}

func TestMemberIdType(t *testing.T) {
	testData := "8"
	result := memberIDType(testData)
	if result != "USER NFS" {
		t.Errorf("memberIDType = %q", result)
	}

	testData = "1"
	result = memberIDType(testData)
	if result != "GID" {
		t.Errorf("memberIDType = %q", result)
	}
}

func TestMemberDetailsUser(t *testing.T) {
	testData := "I/7///8vTG9jYWwvRGVmYXVsdAA="
	result, err := memberDetails(testData)
	if err != nil {
		t.Fatalf("memberDetails failed: %v", err)
	}
	if result != "user: -2@/Local/Default" {
		t.Errorf("memberDetails = %q, want user: -2@/Local/Default", result)
	}
}

func TestMemberDetailsGroup(t *testing.T) {
	testData := "RGNvbS5hcHBsZS5zaGFyZXBvaW50Lmdyb3VwLjEAL0xvY2FsL0RlZmF1bHQA"
	result, err := memberDetails(testData)
	if err != nil {
		t.Fatalf("memberDetails failed: %v", err)
	}
	if result != "group: com.apple.sharepoint.group.1@/Local/Default" {
		t.Errorf("memberIDType = %q, want %q", result, "group: com.apple.sharepoint.group.1@/Local/Default")
	}
}

func TestGetMemberData(t *testing.T) {
	testData := "I/7///8vTG9jYWwvRGVmYXVsdAA="
	decodedData, err := decodeStandard(testData)
	if err != nil {
		t.Fatalf("decodeStandard failed: %v", err)
	}

	_, result, err := getMemberData(decodedData)
	if err != nil {
		t.Fatalf("getMemberData failed: %v", err)
	}
	if result != "user: -2@/Local/Default" {
		t.Errorf("getMemberData = %q, want user: -2@/Local/Default", result)
	}
}

func TestGetMemberString(t *testing.T) {
	testData := []byte{
		110, 111, 98, 111, 100, 121, 0, 47, 76, 111, 99, 97, 108, 47, 68, 101, 102, 97, 117,
		108, 116, 0,
	}

	c := newCursor(testData)
	result, err := nonEmptyCString(c)
	if err != nil {
		t.Fatalf("nonEmptyCString failed: %v", err)
	}
	if result != "nobody" {
		t.Errorf("nonEmptyCString = %q, want nobody", result)
	}
}

func TestGetMemberID(t *testing.T) {
	testData := []byte{232, 3, 0, 0, 0}
	c := newCursor(testData)
	result, err := c.i32()
	if err != nil {
		t.Fatalf("get member id failed: %v", err)
	}
	if result != 1000 {
		t.Errorf("getMemberID = %d, want 1000", result)
	}
}

func TestSidDetails(t *testing.T) {
	testData := "AQUAAAAAAAUVAAAAxbsdAg3Yp1FTmi50HAYAAA=="
	result, err := sidDetails(testData)
	if err != nil {
		t.Fatalf("sidDetails failed: %v", err)
	}
	if result != "S-1-5-21-35503045-1369954317-1949211219-1564" {
		t.Errorf("sidDetails = %q", result)
	}
}

func TestGetSidData(t *testing.T) {
	testData := "AQUAAAAAAAUVAAAAxbsdAg3Yp1FTmi50HAYAAA=="
	decodedData, err := decodeStandard(testData)
	if err != nil {
		t.Fatalf("decodeStandard failed: %v", err)
	}

	_, result, err := getSIDData(decodedData)
	if err != nil {
		t.Fatalf("getSIDData failed: %v", err)
	}
	if result != "S-1-5-21-35503045-1369954317-1949211219-1564" {
		t.Errorf("getSIDData = %q", result)
	}
}
