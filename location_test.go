// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

import "testing"

func TestClientAuthorizationStatus(t *testing.T) {
	testData := "0"
	result, err := clientAuthorizationStatus(testData)
	if err != nil {
		t.Fatalf("clientAuthorizationStatus returned error: %v", err)
	}
	if result != "Not Determined" {
		t.Fatalf("unexpected results: %s", result)
	}
}

func TestDaemonStatusType(t *testing.T) {
	testData := "2"
	result, err := daemonStatusType(testData)
	if err != nil {
		t.Fatalf("daemonStatusType returned error: %v", err)
	}
	if result != "Reachability Large" {
		t.Fatalf("unexpected results: %s", result)
	}
}

func TestSubharvesterIdentifier(t *testing.T) {
	testData := "2"
	result, err := subharvesterIdentifier(testData)
	if err != nil {
		t.Fatalf("subharvesterIdentifier returned error: %v", err)
	}
	if result != "\"Wifi\"" {
		t.Fatalf("unexpected results: %s", result)
	}
}

func TestSqlite(t *testing.T) {
	testData := "AAAAAA=="
	result, err := sqliteLocation(testData)
	if err != nil {
		t.Fatalf("sqliteLocation returned error: %v", err)
	}
	if result != "SQLITE OK" {
		t.Fatalf("unexpected results: %s", result)
	}
}

func TestGetSqliteData(t *testing.T) {
	testData := "AAAAAA=="
	decodedData, err := decodeStandard(testData)
	if err != nil {
		t.Fatalf("decodeStandard returned error: %v", err)
	}

	_, result, err := getSqliteData(decodedData)
	if err != nil {
		t.Fatalf("getSqliteData returned error: %v", err)
	}
	if result != "SQLITE OK" {
		t.Fatalf("unexpected results: %s", result)
	}
}

func TestClientManagerStateTrackerState(t *testing.T) {
	testData := "AQAAAAAAAAA="
	result, err := clientManagerStateTrackerState(testData)
	if err != nil {
		t.Fatalf("clientManagerStateTrackerState returned error: %v", err)
	}
	expected := "{\"locationRestricted\":false, \"locationServicesEnabledStatus\":1}"
	if result != expected {
		t.Fatalf("unexpected results: %s", result)
	}
}

func TestLocationTrackerObject(t *testing.T) {
	var testData LocationTrackerState

	result := locationTrackerObject(&testData)

	expected := "{\n            \"distanceFilter\":0, \n            \"desiredAccuracy\":0, \n            \"updatingLocation\":false, \n            \"requestingLocation\":false, \n            \"requestingRanging\":false, \n            \"updatingRanging\":false,\n            \"updatingHeading\":false,\n            \"headingFilter\":0,\n            \"allowsLocationPrompts\":false,\n            \"allowsAlteredAccessoryLocations\":false,\n            \"dynamicAccuracyReductionEnabled\":false,\n            \"previousAuthorizationStatusValid\":false,\n            \"previousAuthorizationStatus\":0,\n            \"limitsPrecision\":false,\n            \"activityType\":0,\n            \"pausesLocationUpdatesAutomatically\":0,\n            \"paused\":false,\n            \"allowsBackgroundLocationUpdates\":false,\n            \"showsBackgroundLocationIndicator\":false,\n            \"allowsMapCorrection\":false,\n            \"batchingLocation\":false,\n            \"updatingVehicleSpeed\":false,\n            \"updatingVehicleHeading\":false,\n            \"matchInfoEnabled\":false,\n            \"groundAltitudeEnabled\":false,\n            \"fusionInfoEnabled\":false,\n            \"courtesyPromptNeeded\":false,\n            \"isAuthorizedForWidgetUpdates\":false,\n        }"
	if result != expected {
		t.Fatalf("unexpected results: %s", result)
	}
}

func TestGetStateTrackerData(t *testing.T) {
	testData := "AQAAAAAAAAA="
	decodedData, err := decodeStandard(testData)
	if err != nil {
		t.Fatalf("decodeStandard returned error: %v", err)
	}

	_, result, err := getStateTrackerData(decodedData)
	if err != nil {
		t.Fatalf("getStateTrackerData returned error: %v", err)
	}
	expected := "{\"locationRestricted\":false, \"locationServicesEnabledStatus\":1}"
	if result != expected {
		t.Fatalf("unexpected results: %s", result)
	}
}

func TestLocationManagerStateTrackerState(t *testing.T) {
	testData := "AAAAAAAA8L8AAAAAAABZQAAAAAAAAAAAAAAAAAAA8D8BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAQAAAAAAAAAA"
	result, err := locationManagerStateTrackerState(testData)
	if err != nil {
		t.Fatalf("locationManagerStateTrackerState returned error: %v", err)
	}
	expected := "{\n            \"distanceFilter\":-1, \n            \"desiredAccuracy\":100, \n            \"updatingLocation\":false, \n            \"requestingLocation\":false, \n            \"requestingRanging\":false, \n            \"updatingRanging\":false,\n            \"updatingHeading\":false,\n            \"headingFilter\":1,\n            \"allowsLocationPrompts\":true,\n            \"allowsAlteredAccessoryLocations\":false,\n            \"dynamicAccuracyReductionEnabled\":false,\n            \"previousAuthorizationStatusValid\":false,\n            \"previousAuthorizationStatus\":0,\n            \"limitsPrecision\":false,\n            \"activityType\":0,\n            \"pausesLocationUpdatesAutomatically\":1,\n            \"paused\":false,\n            \"allowsBackgroundLocationUpdates\":false,\n            \"showsBackgroundLocationIndicator\":false,\n            \"allowsMapCorrection\":true,\n            \"batchingLocation\":false,\n            \"updatingVehicleSpeed\":false,\n            \"updatingVehicleHeading\":false,\n            \"matchInfoEnabled\":false,\n            \"groundAltitudeEnabled\":false,\n            \"fusionInfoEnabled\":false,\n            \"courtesyPromptNeeded\":false,\n            \"isAuthorizedForWidgetUpdates\":false,\n        }"
	if result != expected {
		t.Fatalf("unexpected results: %s", result)
	}
}

func TestGetLocationTrackerState(t *testing.T) {
	testData := "AAAAAAAA8L8AAAAAAABZQAAAAAAAAAAAAAAAAAAA8D8BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAQAAAAAAAAAA"
	decodedData, err := decodeStandard(testData)
	if err != nil {
		t.Fatalf("decodeStandard returned error: %v", err)
	}

	_, result, err := getLocationTrackerState(decodedData)
	if err != nil {
		t.Fatalf("getLocationTrackerState returned error: %v", err)
	}
	expected := "{\n            \"distanceFilter\":-1, \n            \"desiredAccuracy\":100, \n            \"updatingLocation\":false, \n            \"requestingLocation\":false, \n            \"requestingRanging\":false, \n            \"updatingRanging\":false,\n            \"updatingHeading\":false,\n            \"headingFilter\":1,\n            \"allowsLocationPrompts\":true,\n            \"allowsAlteredAccessoryLocations\":false,\n            \"dynamicAccuracyReductionEnabled\":false,\n            \"previousAuthorizationStatusValid\":false,\n            \"previousAuthorizationStatus\":0,\n            \"limitsPrecision\":false,\n            \"activityType\":0,\n            \"pausesLocationUpdatesAutomatically\":1,\n            \"paused\":false,\n            \"allowsBackgroundLocationUpdates\":false,\n            \"showsBackgroundLocationIndicator\":false,\n            \"allowsMapCorrection\":true,\n            \"batchingLocation\":false,\n            \"updatingVehicleSpeed\":false,\n            \"updatingVehicleHeading\":false,\n            \"matchInfoEnabled\":false,\n            \"groundAltitudeEnabled\":false,\n            \"fusionInfoEnabled\":false,\n            \"courtesyPromptNeeded\":false,\n            \"isAuthorizedForWidgetUpdates\":false,\n        }"
	if result != expected {
		t.Fatalf("unexpected results: %s", result)
	}
}

func TestIOMessage(t *testing.T) {
	testData := "3758096981"
	result, err := ioMessage(testData)
	if err != nil {
		t.Fatalf("ioMessage returned error: %v", err)
	}
	if result != "SystemPagingOff" {
		t.Fatalf("unexpected results: %s", result)
	}
}

func TestGetDaemonStatusTracker(t *testing.T) {
	testData := []byte{
		0, 0, 0, 0, 0, 0, 240, 191, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0,
		255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0,
	}
	_, result, err := getDaemonStatusTracker(testData)
	if err != nil {
		t.Fatalf("getDaemonStatusTracker returned error: %v", err)
	}
	expected := "{\"thermalLevel\": -1, \"reachability\": \"kReachabilityLarge\", \"airplaneMode\": false, \"batteryData\":{\"wasConnected\": false, \"charged\": false, \"level\": -1, \"connected\": false, \"chargerType\": \"kChargerTypeUnknown\"}, \"restrictedMode\": false, \"batterySaverModeEnabled\": false, \"push_service\":false}"
	if result != expected {
		t.Fatalf("unexpected results: %s", result)
	}
}

func TestGetDaemonStatusTrackerWasConnectedTrue(t *testing.T) {
	testData := []byte{
		0, 0, 0, 0, 0, 0, 89, 64, 0, 1, 19, 4, 2, 0, 0, 0, 1, 192, 243, 246, 5, 64, 0, 224, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	}
	_, result, err := getDaemonStatusTracker(testData)
	if err != nil {
		t.Fatalf("getDaemonStatusTracker returned error: %v", err)
	}
	expected := "{\"thermalLevel\": 0, \"reachability\": \"kReachabilityLarge\", \"airplaneMode\": false, \"batteryData\":{\"wasConnected\": true, \"charged\": false, \"level\": 100, \"connected\": true, \"chargerType\": \"kChargerTypeUsb\"}, \"restrictedMode\": false, \"batterySaverModeEnabled\": false, \"push_service\":false}"
	if result != expected {
		t.Fatalf("unexpected results: %s", result)
	}
}
