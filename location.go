// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

import (
	"fmt"
	"math"
)

// LocationTrackerState mirrors the Rust `LocationTrackerState` struct in
// location.rs. Field names keep the Rust snake_case names in CamelCase; JSON
// tags mirror the Rust field names. The struct itself is not serde-serialized
// in Rust (it is formatted to JSON by locationTrackerObject).
type LocationTrackerState struct {
	DistanceFilter                   float64 `json:"distance_filter"`
	DesiredAccuracy                  float64 `json:"desired_accuracy"`
	UpdatingLocation                 uint8   `json:"updating_location"`
	RequestingLocation               uint8   `json:"requesting_location"`
	RequestingRanging                uint8   `json:"requesting_ranging"`
	UpdatingRanging                  uint8   `json:"updating_ranging"`
	UpdatingHeading                  uint8   `json:"updating_heading"`
	HeadingFilter                    float64 `json:"heading_filter"`
	AllowsLocationPrompts            uint8   `json:"allows_location_prompts"`
	AllowsAlteredLocations           uint8   `json:"allows_altered_locations"`
	DynamicAccuracy                  uint8   `json:"dynamic_accuracy"`
	PreviousAuthorizationStatusValid uint8   `json:"previous_authorization_status_valid"`
	PreviousAuthorizationStatus      int32   `json:"previous_authorization_status"`
	LimitsPrecision                  uint8   `json:"limits_precision"`
	ActivityType                     int64   `json:"activity_type"`
	PausesLocationUpdates            int32   `json:"pauses_location_updates"`
	Paused                           uint8   `json:"paused"`
	AllowsBackgroundUpdates          uint8   `json:"allows_background_updates"`
	ShowsBackgroundLocation          uint8   `json:"shows_background_location"`
	AllowsMapCorrection              uint8   `json:"allows_map_correction"`
	BatchingLocation                 uint8   `json:"batching_location"`
	UpdatingVehicleSpeed             uint8   `json:"updating_vehicle_speed"`
	UpdatingVehicleHeading           uint8   `json:"updating_vehicle_heading"`
	MatchInfo                        uint8   `json:"match_info"`
	GroundAltitude                   uint8   `json:"ground_altitude"`
	FusionInfo                       uint8   `json:"fusion_info"`
	CourtesyPrompt                   uint8   `json:"courtesy_prompt"`
	IsAuthorizedForWidgets           uint8   `json:"is_authorized_for_widgets"`
}

// locationF64 reads a little-endian f64 (nom's le_f64) from the cursor.
// The Rust file imports le_f64 (little endian); cursor.go only exposes u64/i64,
// so this location-prefixed helper converts bits without editing cursor.go.
func locationF64(c *cursor) (float64, error) {
	raw, err := c.u64()
	if err != nil {
		return 0, err
	}
	return math.Float64frombits(raw), nil
}

// Convert Core Location Client Autherization Status code to string
func clientAuthorizationStatus(status string) (string, error) {
	var message string
	switch status {
	case "0":
		message = "Not Determined"
	case "1":
		message = "Restricted"
	case "2":
		message = "Denied"
	case "3":
		message = "Authorized Always"
	case "4":
		message = "Authorized When In Use"
	default:
		return "", &DecoderError{
			Input:      []byte(status),
			ParserName: "client authorization status",
			Message:    "Unknown Core Location client authorization status",
		}
	}
	return message, nil
}

// Convert Core Location Daemon Status type to string
func daemonStatusType(status string) (string, error) {
	// Found in dyldcache liblog
	var message string
	switch status {
	case "0":
		message = "Reachability Unavailable"
	case "1":
		message = "Reachability Small"
	case "2":
		message = "Reachability Large"
	case "56":
		message = "Reachability Unachievable"
	default:
		return "", &DecoderError{
			Input:      []byte(status),
			ParserName: "daemon status type",
			Message:    "Unknown Core Location daemon status type",
		}
	}
	return message, nil
}

// Convert Core Location Subhaverester id to string
func subharvesterIdentifier(status string) (string, error) {
	// Found in dyldcache liblog
	var message string
	switch status {
	case "0":
		message = "CellLegacy"
	case "1":
		message = "Cell"
	case "2":
		message = "Wifi"
	case "3":
		message = "Tracks"
	case "4":
		message = "Realtime"
	case "5":
		message = "App"
	case "6":
		message = "Pass"
	case "7":
		message = "Indoor"
	case "8":
		message = "Pressure"
	case "9":
		message = "Poi"
	case "10":
		message = "Trace"
	case "11":
		message = "Avenger"
	case "12":
		message = "Altimeter"
	case "13":
		message = "Ionosphere"
	case "14":
		message = "Unknown"
	default:
		return "", &DecoderError{
			Input:      []byte(status),
			ParserName: "subharvester identifier",
			Message:    "Unknown Core Location subhaverster identifier type",
		}
	}
	// Rust: Ok(format!("{:?}", message.to_string())) — Debug-quoted string.
	return fmt.Sprintf("%q", message), nil
}

// Convert Core Location SQLITE code to string
func sqliteLocation(input string) (string, error) {
	decodedData, err := decodeStandard(input)
	if err != nil {
		return "", &DecoderError{
			Input:      []byte(input),
			ParserName: "sqlite location",
			Message:    "Failed to base64 decode sqlite details",
		}
	}

	_, result, err := getSqliteData(decodedData)
	if err != nil {
		return "", &DecoderError{
			Input:      []byte(input),
			ParserName: "sqlite location",
			Message:    "Failed to get sqlite error",
		}
	}

	return result, nil
}

// Get the SQLITE error message
func getSqliteData(input []byte) ([]byte, string, error) {
	c := newCursor(input)
	sqliteCode, err := c.u32()
	if err != nil {
		return nil, "", err
	}

	// Found at https://www.sqlite.org/rescode.html
	var message string
	switch sqliteCode {
	case 0:
		message = "SQLITE OK"
	case 1:
		message = "SQLITE ERROR"
	case 2:
		message = "SQLITE INTERNAL"
	case 3:
		message = "SQLITE PERM"
	case 4:
		message = "SQLITE ABORT"
	case 5:
		message = "SQLITE BUSY"
	case 6:
		message = "SQLITE LOCKED"
	case 7:
		message = "SQLITE NOMEM"
	case 8:
		message = "SQLITE READ ONLY"
	case 9:
		message = "SQLITE INTERRUPT"
	case 10:
		message = "SQLITE IO ERR"
	case 11:
		message = "SQLITE CORRUPT"
	case 12:
		message = "SQLITE NOT FOUND"
	case 13:
		message = "SQLITE FULL"
	case 14:
		message = "SQLITE CAN'T OPEN"
	case 15:
		message = "SQLITE PROTOCOL"
	case 16:
		message = "SQLITE EMPTY"
	case 17:
		message = "SQLITE SCHEMA"
	case 18:
		message = "SQLITE TOO BIG"
	case 19:
		message = "SQLITE CONSTRAINT"
	case 20:
		message = "SQLITE MISMATCH"
	case 21:
		message = "SQLITE MISUSE"
	case 22:
		message = "SQLITE NO LFS"
	case 23:
		message = "SQLITE AUTH"
	case 24:
		message = "SQLITE FORMAT"
	case 25:
		message = "SQLITE RANGE"
	case 26:
		message = "SQLITE NOT A DB"
	case 27:
		message = "SQLITE NOTICE"
	case 28:
		message = "SQLITE WARNING"
	case 100:
		message = "SQLITE ROW"
	case 101:
		message = "SQLITE DONE"
	case 266:
		message = "SQLITE IO ERR READ"
	default:
		logger.Printf("[macos-unifiedlogs] Unknown Core Location sqlite error: %d", sqliteCode)
		message = "Unknown Core Location sqlite error"
	}

	return c.rest(), message, nil
}

// Parse the manager tracker state data
func clientManagerStateTrackerState(input string) (string, error) {
	decodedData, err := decodeStandard(input)
	if err != nil {
		return "", &DecoderError{
			Input:      []byte(input),
			ParserName: "client manager state tracker state",
			Message:    "Failed to base64 decode client manager tracker state",
		}
	}

	_, result, err := getStateTrackerData(decodedData)
	if err != nil {
		return "", &DecoderError{
			Input:      []byte(input),
			ParserName: "client manager state tracker state",
			Message:    "Failed to get client tracker data",
		}
	}

	return result, nil
}

// Get the tracker data
func getStateTrackerData(input []byte) ([]byte, string, error) {
	c := newCursor(input)
	locationEnabled, err := c.u32()
	if err != nil {
		return nil, "", err
	}
	locationRestricted, err := c.u32()
	if err != nil {
		return nil, "", err
	}

	result := fmt.Sprintf(
		`{"locationRestricted":%v, "locationServicesEnabledStatus":%v}`,
		lowercaseBool(fmt.Sprintf("%d", locationRestricted)),
		locationEnabled,
	)
	return c.rest(), result, nil
}

// Parse location tracker state data
func locationManagerStateTrackerState(input string) (string, error) {
	decodedData, err := decodeStandard(input)
	if err != nil {
		return "", &DecoderError{
			Input:      []byte(input),
			ParserName: "location manager state tracker state",
			Message:    "Failed to base64 decode logon manager trackder data",
		}
	}

	_, result, err := getLocationTrackerState(decodedData)
	if err != nil {
		return "", &DecoderError{
			Input:      []byte(input),
			ParserName: "location manager state tracker state",
			Message:    "Failed to get logon manager tracker data",
		}
	}

	return result, nil
}

// Get the location state data
func getLocationTrackerState(input []byte) ([]byte, string, error) {
	// https://github.com/cmsj/ApplePrivateHeaders/blob/main/macOS/11.3/System/Library/Frameworks/CoreLocation.framework/Versions/A/CoreLocation/CoreLocation-Structs.h and in dyldcache

	// Padding? Reserved?
	const unknownDataLength = 3
	// padding? Reserved?
	const unkonwnDataLength2 = 7

	c := newCursor(input)

	distanceFilter, err := locationF64(c)
	if err != nil {
		return nil, "", err
	}
	desiredAccuracy, err := locationF64(c)
	if err != nil {
		return nil, "", err
	}
	updatingLocation, err := c.u8()
	if err != nil {
		return nil, "", err
	}
	requestingLocation, err := c.u8()
	if err != nil {
		return nil, "", err
	}
	requestingRanging, err := c.u8()
	if err != nil {
		return nil, "", err
	}
	updatingRanging, err := c.u8()
	if err != nil {
		return nil, "", err
	}
	updatingHeading, err := c.u8()
	if err != nil {
		return nil, "", err
	}

	// _unknown
	if _, err = c.take(unknownDataLength); err != nil {
		return nil, "", err
	}
	headingFilter, err := locationF64(c)
	if err != nil {
		return nil, "", err
	}
	allowsLocationPrompts, err := c.u8()
	if err != nil {
		return nil, "", err
	}
	allowsAlteredLocations, err := c.u8()
	if err != nil {
		return nil, "", err
	}
	dynamicAccuracy, err := c.u8()
	if err != nil {
		return nil, "", err
	}

	previousAuthorizationStatusValid, err := c.u8()
	if err != nil {
		return nil, "", err
	}
	previousAuthorizationStatus, err := c.i32()
	if err != nil {
		return nil, "", err
	}
	limitsPrecision, err := c.u8()
	if err != nil {
		return nil, "", err
	}
	// _unknown2
	if _, err = c.take(unkonwnDataLength2); err != nil {
		return nil, "", err
	}
	activityType, err := c.i64()
	if err != nil {
		return nil, "", err
	}
	pausesLocationUpdates, err := c.i32()
	if err != nil {
		return nil, "", err
	}

	paused, err := c.u8()
	if err != nil {
		return nil, "", err
	}
	allowsBackgroundUpdates, err := c.u8()
	if err != nil {
		return nil, "", err
	}
	showsBackgroundLocation, err := c.u8()
	if err != nil {
		return nil, "", err
	}
	allowsMapCorrection, err := c.u8()
	if err != nil {
		return nil, "", err
	}

	locationData := c.rest()

	tracker := &LocationTrackerState{
		DistanceFilter:                   distanceFilter,
		DesiredAccuracy:                  desiredAccuracy,
		UpdatingLocation:                 updatingLocation,
		RequestingLocation:               requestingLocation,
		RequestingRanging:                requestingRanging,
		UpdatingRanging:                  updatingRanging,
		UpdatingHeading:                  updatingHeading,
		HeadingFilter:                    headingFilter,
		AllowsLocationPrompts:            allowsLocationPrompts,
		AllowsAlteredLocations:           allowsAlteredLocations,
		DynamicAccuracy:                  dynamicAccuracy,
		PreviousAuthorizationStatusValid: previousAuthorizationStatusValid,
		PreviousAuthorizationStatus:      previousAuthorizationStatus,
		LimitsPrecision:                  limitsPrecision,
		ActivityType:                     activityType,
		PausesLocationUpdates:            pausesLocationUpdates,
		Paused:                           paused,
		AllowsBackgroundUpdates:          allowsBackgroundUpdates,
		ShowsBackgroundLocation:          showsBackgroundLocation,
		AllowsMapCorrection:              allowsMapCorrection,
	}

	// Sometimes location data only has 64 bytes of data. Seen only on Catalina. Though this might be a setting configuration?
	// All other systems have 72 bytes of location data even systems before Catalina (ex: Mojave)
	// Return early if we only have 64 bytes to work with
	const catalinaSize = 64
	if len(locationData) == catalinaSize {
		return locationData, locationTrackerObject(tracker), nil
	}

	batchingLocation, err := c.u8()
	if err != nil {
		return nil, "", err
	}
	updatingVehicleSpeed, err := c.u8()
	if err != nil {
		return nil, "", err
	}
	updatingVehicleHeading, err := c.u8()
	if err != nil {
		return nil, "", err
	}
	matchInfo, err := c.u8()
	if err != nil {
		return nil, "", err
	}
	groundAltitude, err := c.u8()
	if err != nil {
		return nil, "", err
	}
	fusionInfo, err := c.u8()
	if err != nil {
		return nil, "", err
	}
	courtesyPrompt, err := c.u8()
	if err != nil {
		return nil, "", err
	}
	isAuthorizedForWidgets, err := c.u8()
	if err != nil {
		return nil, "", err
	}

	tracker.BatchingLocation = batchingLocation
	tracker.UpdatingVehicleSpeed = updatingVehicleSpeed
	tracker.UpdatingVehicleHeading = updatingVehicleHeading
	tracker.MatchInfo = matchInfo
	tracker.GroundAltitude = groundAltitude
	tracker.FusionInfo = fusionInfo
	tracker.CourtesyPrompt = courtesyPrompt
	tracker.IsAuthorizedForWidgets = isAuthorizedForWidgets

	return c.rest(), locationTrackerObject(tracker), nil
}

// Create the location tracker json object
func locationTrackerObject(tracker *LocationTrackerState) string {
	return fmt.Sprintf(
		`{
            "distanceFilter":%v, 
            "desiredAccuracy":%v, 
            "updatingLocation":%v, 
            "requestingLocation":%v, 
            "requestingRanging":%v, 
            "updatingRanging":%v,
            "updatingHeading":%v,
            "headingFilter":%v,
            "allowsLocationPrompts":%v,
            "allowsAlteredAccessoryLocations":%v,
            "dynamicAccuracyReductionEnabled":%v,
            "previousAuthorizationStatusValid":%v,
            "previousAuthorizationStatus":%v,
            "limitsPrecision":%v,
            "activityType":%v,
            "pausesLocationUpdatesAutomatically":%v,
            "paused":%v,
            "allowsBackgroundLocationUpdates":%v,
            "showsBackgroundLocationIndicator":%v,
            "allowsMapCorrection":%v,
            "batchingLocation":%v,
            "updatingVehicleSpeed":%v,
            "updatingVehicleHeading":%v,
            "matchInfoEnabled":%v,
            "groundAltitudeEnabled":%v,
            "fusionInfoEnabled":%v,
            "courtesyPromptNeeded":%v,
            "isAuthorizedForWidgetUpdates":%v,
        }`,
		tracker.DistanceFilter,
		tracker.DesiredAccuracy,
		lowercaseIntBool(tracker.UpdatingLocation),
		lowercaseIntBool(tracker.RequestingLocation),
		lowercaseIntBool(tracker.RequestingRanging),
		lowercaseIntBool(tracker.UpdatingRanging),
		lowercaseIntBool(tracker.UpdatingHeading),
		tracker.HeadingFilter,
		lowercaseIntBool(tracker.AllowsLocationPrompts),
		lowercaseIntBool(tracker.AllowsAlteredLocations),
		lowercaseIntBool(tracker.DynamicAccuracy),
		lowercaseIntBool(tracker.PreviousAuthorizationStatusValid),
		tracker.PreviousAuthorizationStatus,
		lowercaseIntBool(tracker.LimitsPrecision),
		tracker.ActivityType,
		tracker.PausesLocationUpdates,
		lowercaseIntBool(tracker.Paused),
		lowercaseIntBool(tracker.AllowsBackgroundUpdates),
		lowercaseIntBool(tracker.ShowsBackgroundLocation),
		lowercaseIntBool(tracker.AllowsMapCorrection),
		lowercaseIntBool(tracker.BatchingLocation),
		lowercaseIntBool(tracker.UpdatingVehicleSpeed),
		lowercaseIntBool(tracker.UpdatingVehicleHeading),
		lowercaseIntBool(tracker.MatchInfo),
		lowercaseIntBool(tracker.GroundAltitude),
		lowercaseIntBool(tracker.FusionInfo),
		lowercaseIntBool(tracker.CourtesyPrompt),
		lowercaseIntBool(tracker.IsAuthorizedForWidgets),
	)
}

// Parse location tracker state data
func ioMessage(data string) (string, error) {
	// Found in dyldcache
	var message string
	switch data {
	case "3758097008":
		message = "CanSystemSleep"
	case "3758097024":
		message = "SystemWillSleep"
	case "3758097040":
		message = "SystemWillNotSleep"
	case "3758097184":
		message = "SystemWillPowerOn"
	case "3758097168":
		message = "SystemWillRestart"
	case "3758097152":
		message = "SystemHasPoweredOn"
	case "3758097200":
		message = "CopyClientID"
	case "3758097216":
		message = "SystemCapabilityChange"
	case "3758097232":
		message = "DeviceSignaledWakeup"
	case "3758096400":
		message = "ServiceIsTerminated"
	case "3758096416":
		message = "ServiceIsSuspended"
	case "3758096432":
		message = "ServiceIsResumed"
	case "3758096640":
		message = "ServiceIsRequestingClose"
	case "3758096641":
		message = "ServiceIsAttemptingOpen"
	case "3758096656":
		message = "ServiceWasClosed"
	case "3758096672":
		message = "ServiceBusyStateChange"
	case "3758096680":
		message = "ConsoleSecurityChange"
	case "3758096688":
		message = "ServicePropertyChange"
	case "3758096896":
		message = "CanDevicePowerOff"
	case "3758096912":
		message = "DeviceWillPowerOff"
	case "3758096928":
		message = "DeviceWillNotPowerOff"
	case "3758096944":
		message = "DeviceHasPoweredOn"
	case "3758096976":
		message = "SystemWillPowerOff"
	case "3758096981":
		message = "SystemPagingOff"
	default:
		return "", &DecoderError{
			Input:      []byte(data),
			ParserName: "io message",
			Message:    "Unknown IO Message",
		}
	}
	return message, nil
}

// Parse and get the location Daemon tracker
func getDaemonStatusTracker(input []byte) ([]byte, string, error) {
	// Slightly outdated but still helpful: https://gist.github.com/razvand/578f94748b624f4d47c1533f5a02b095
	c := newCursor(input)

	level, err := locationF64(c)
	if err != nil {
		return nil, "", err
	}
	charged, err := c.u8()
	if err != nil {
		return nil, "", err
	}
	connected, err := c.u8()
	if err != nil {
		return nil, "", err
	}
	unknown, err := c.u8()
	if err != nil {
		return nil, "", err
	}
	unknown2, err := c.u8()
	if err != nil {
		return nil, "", err
	}
	chargerType, err := c.u32()
	if err != nil {
		return nil, "", err
	}
	unknown3, err := c.u32()
	if err != nil {
		return nil, "", err
	}
	// _unknown4
	if _, err = c.u32(); err != nil {
		return nil, "", err
	}
	reachability, err := c.u32()
	if err != nil {
		return nil, "", err
	}
	thermalLevel, err := c.i32()
	if err != nil {
		return nil, "", err
	}
	airplane, err := c.u8()
	if err != nil {
		return nil, "", err
	}
	batterySaver, err := c.u8()
	if err != nil {
		return nil, "", err
	}
	pushService, err := c.u8()
	if err != nil {
		return nil, "", err
	}
	restricted, err := c.u8()
	if err != nil {
		return nil, "", err
	}

	wasConnected := false
	// When these unknown values are not 0 `was_connected` is always true
	// Not 100% sure the significance or what they represent
	if unknown != 0 && unknown2 != 0 && unknown3 != 0 {
		wasConnected = true
	}

	// Values found in dyldcache logd_location
	var reachabilityStr string
	switch reachability {
	case 0:
		reachabilityStr = "kReachabilityUnavailable"
	case 1:
		reachabilityStr = "kReachabilitySmall"
	case 2:
		reachabilityStr = "kReachabilityLarge"
	case 1000:
		reachabilityStr = "kReachabilityUnachievable"
	default:
		logger.Printf("[macos-unifiedlogs] Unknown reachability value: %d", reachability)
		reachabilityStr = "Unknown reachability value"
	}

	// Values found in dyldcache logd_location
	// Other values seen are:
	// kChargerTypeNone, kChargerTypeExternal, and kChargerTypeArcas.
	// But have not observed the numerical value for these types
	var chargerTypeStr string
	switch chargerType {
	case 0:
		chargerTypeStr = "kChargerTypeUnknown"
	case 2:
		chargerTypeStr = "kChargerTypeUsb"
	default:
		logger.Printf("[macos-unifiedlogs] Unknown charger type value: %d", chargerType)
		chargerTypeStr = "Unknown charger type value"
	}

	message := fmt.Sprintf(
		`{"thermalLevel": %v, "reachability": "%v", "airplaneMode": %v, "batteryData":{"wasConnected": %v, "charged": %v, "level": %v, "connected": %v, "chargerType": "%v"}, "restrictedMode": %v, "batterySaverModeEnabled": %v, "push_service":%v}`,
		thermalLevel,
		reachabilityStr,
		lowercaseIntBool(airplane),
		wasConnected,
		lowercaseIntBool(charged),
		level,
		lowercaseIntBool(connected),
		chargerTypeStr,
		lowercaseIntBool(restricted),
		lowercaseIntBool(batterySaver),
		lowercaseIntBool(pushService),
	)

	return c.rest(), message, nil
}
