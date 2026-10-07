// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

import "testing"

func TestIPvSix(t *testing.T) {
	testData := "/wIAAAAAAAAAAAAAAAAA+w=="
	result, err := ipvSix(testData)
	if err != nil {
		t.Fatalf("ipvSix returned error: %v", err)
	}
	if result.String() != "ff02::fb" {
		t.Fatalf("unexpected results: %s", result.String())
	}
}

func TestGetIPSix(t *testing.T) {
	testData := "/wIAAAAAAAAAAAAAAAAA+w=="
	decodedData, err := decodeStandard(testData)
	if err != nil {
		t.Fatalf("decodeStandard returned error: %v", err)
	}

	_, result, err := getIPSix(decodedData)
	if err != nil {
		t.Fatalf("getIPSix returned error: %v", err)
	}
	if result.String() != "ff02::fb" {
		t.Fatalf("unexpected results: %s", result.String())
	}
}

func TestIPvFour(t *testing.T) {
	testData := "4AAA+w=="
	result, err := ipvFour(testData)
	if err != nil {
		t.Fatalf("ipvFour returned error: %v", err)
	}
	if result.String() != "224.0.0.251" {
		t.Fatalf("unexpected results: %s", result.String())
	}
}

func TestGetIPFour(t *testing.T) {
	testData := "4AAA+w=="
	decodedData, err := decodeStandard(testData)
	if err != nil {
		t.Fatalf("decodeStandard returned error: %v", err)
	}

	_, result, err := getIPFour(decodedData)
	if err != nil {
		t.Fatalf("getIPFour returned error: %v", err)
	}
	if result.String() != "224.0.0.251" {
		t.Fatalf("unexpected results: %s", result.String())
	}
}

func TestSockaddr(t *testing.T) {
	testData := "EAIAALgciWcAAAAAAAAAAA=="
	result, err := sockaddr(testData)
	if err != nil {
		t.Fatalf("sockaddr returned error: %v", err)
	}
	if result != "184.28.137.103" {
		t.Fatalf("unexpected results: %s", result)
	}

	testData = "HB4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
	result, err = sockaddr(testData)
	if err != nil {
		t.Fatalf("sockaddr returned error: %v", err)
	}
	if result != "::, Flow ID: 0, Scope ID: 0" {
		t.Fatalf("unexpected results: %s", result)
	}
}

func TestGetSockaddrData(t *testing.T) {
	testData := "EAIAALgciWcAAAAAAAAAAA=="
	decodedData, err := decodeStandard(testData)
	if err != nil {
		t.Fatalf("decodeStandard returned error: %v", err)
	}

	_, result, err := getSockaddrData(decodedData)
	if err != nil {
		t.Fatalf("getSockaddrData returned error: %v", err)
	}
	if result != "184.28.137.103" {
		t.Fatalf("unexpected results: %s", result)
	}
}
