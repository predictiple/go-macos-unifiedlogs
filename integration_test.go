// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Integration tests ported from the upstream tests/{big_sur,high_sierra,monterey,tahoe}_tests.rs
// harnesses. Each test drives the public API over a real logarchive under tests/test_data and
// skips when that reference data is unavailable.

const (
	bigSurArchive        = "system_logs_big_sur.logarchive"
	bigSurPrivateArchive = "system_logs_big_sur_private_enabled.logarchive"
	bigSurMixArchive     = "system_logs_big_sur_public_private_data_mix.logarchive"
	highSierraArchive    = "system_logs_high_sierra.logarchive"
	montereyArchive      = "system_logs_monterey.logarchive"
	tahoeArchive         = "system_logs_tahoe.logarchive"
)

// logarchiveProvider returns a provider for the named logarchive, skipping the test
// when the reference data is not present.
func logarchiveProvider(t *testing.T, name, probe string) *LogarchiveProvider {
	t.Helper()
	requireTestDataFile(t, name+"/"+probe)
	return NewLogarchiveProvider(filepath.Join("tests", "test_data", name))
}

// parseTracev3 parses a single .tracev3 file within the named logarchive.
func parseTracev3(t *testing.T, archive, rel string) *UnifiedLogData {
	t.Helper()
	path := requireTestDataFile(t, archive+"/"+rel)
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	logData, err := ParseLog(f, path)
	if err != nil {
		t.Fatalf("ParseLog(%s): %v", path, err)
	}
	return logData
}

// collectLogs mirrors the Rust collect_logs helper: parse every tracev3 file.
func collectLogs(t *testing.T, provider FileProvider) []*UnifiedLogData {
	t.Helper()
	var out []*UnifiedLogData
	for _, entry := range provider.Tracev3Files() {
		r, err := entry.Reader()
		if err != nil {
			t.Fatalf("reader %s: %v", entry.SourcePath(), err)
		}
		logData, err := ParseLog(r, entry.SourcePath())
		r.Close()
		if err != nil {
			t.Fatalf("ParseLog(%s): %v", entry.SourcePath(), err)
		}
		out = append(out, logData)
	}
	return out
}

// isSignpost mirrors the Rust is_signpost helper.
func isSignpost(lt LogType) bool {
	switch lt {
	case LogTypeProcessSignpostEvent, LogTypeProcessSignpostStart, LogTypeProcessSignpostEnd,
		LogTypeSystemSignpostEvent, LogTypeSystemSignpostStart, LogTypeSystemSignpostEnd,
		LogTypeThreadSignpostEvent, LogTypeThreadSignpostStart, LogTypeThreadSignpostEnd:
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// Big Sur
// ---------------------------------------------------------------------------

func TestParseLogBigSurIntegration(t *testing.T) {
	logData := parseTracev3(t, bigSurArchive, "Persist/0000000000000004.tracev3")

	if got := len(logData.CatalogData[0].Firehose); got != 82 {
		t.Errorf("firehose len = %d, want 82", got)
	}
	if got := len(logData.CatalogData[0].Simpledump); got != 0 {
		t.Errorf("simpledump len = %d, want 0", got)
	}
	if got := len(logData.Header); got != 1 {
		t.Errorf("header len = %d, want 1", got)
	}
	if got := len(logData.CatalogData[0].Catalog.CatalogProcessInfoEntries); got != 45 {
		t.Errorf("catalog process info entries len = %d, want 45", got)
	}
	if got := len(logData.CatalogData[0].Statedump); got != 0 {
		t.Errorf("statedump len = %d, want 0", got)
	}
}

func TestBigSurLivedataIntegration(t *testing.T) {
	provider := logarchiveProvider(t, bigSurArchive, "logdata.LiveData.tracev3")
	cache := NewMemoryStringCache()
	timesyncData, err := CollectTimesync(provider)
	if err != nil {
		t.Fatalf("CollectTimesync: %v", err)
	}

	logData := parseTracev3(t, bigSurArchive, "logdata.LiveData.tracev3")
	results, _ := BuildLog(logData, provider, cache, timesyncData, false)
	if got := len(results); got != 101566 {
		t.Fatalf("results len = %d, want 101566", got)
	}

	found := false
	for _, r := range results {
		if r.Message == "TimeSyncTime is mach_absolute_time nanoseconds\n" {
			found = true
			if r.ActivityID != 0 {
				t.Errorf("activity_id = %d, want 0", r.ActivityID)
			}
			if r.ThreadID != 116 {
				t.Errorf("thread_id = %d, want 116", r.ThreadID)
			}
			if r.EUID != 0 {
				t.Errorf("euid = %d, want 0", r.EUID)
			}
			if r.PID != 0 {
				t.Errorf("pid = %d, want 0", r.PID)
			}
			if r.Library != "/System/Library/Extensions/IOTimeSyncFamily.kext/Contents/MacOS/IOTimeSyncFamily" {
				t.Errorf("library = %q", r.Library)
			}
			if r.Subsystem != "" {
				t.Errorf("subsystem = %q, want empty", r.Subsystem)
			}
			if r.Category != "" {
				t.Errorf("category = %q, want empty", r.Category)
			}
			if r.EventType != EventTypeLog {
				t.Errorf("event_type = %v, want Log", r.EventType)
			}
			if r.LogType != LogTypeInfo {
				t.Errorf("log_type = %v, want Info", r.LogType)
			}
			if r.Process != "/kernel" {
				t.Errorf("process = %q", r.Process)
			}
			if r.Time != 1642304801596413351.0 {
				t.Errorf("time = %v", r.Time)
			}
			if r.BootUUID != "A2A9017676CF421C84DC9BBD6263FEE7" {
				t.Errorf("boot_uuid = %q", r.BootUUID)
			}
			if r.TimezoneName != "Pacific" {
				t.Errorf("timezone_name = %q", r.TimezoneName)
			}
			break
		}
	}
	if !found {
		t.Error("did not find TimeSyncTime message")
	}
}

func TestBuildLogBigSurIntegration(t *testing.T) {
	provider := logarchiveProvider(t, bigSurArchive, "Persist/0000000000000004.tracev3")
	cache := NewMemoryStringCache()
	timesyncData, err := CollectTimesync(provider)
	if err != nil {
		t.Fatalf("CollectTimesync: %v", err)
	}

	logData := parseTracev3(t, bigSurArchive, "Persist/0000000000000004.tracev3")
	results, _ := BuildLog(logData, provider, cache, timesyncData, false)
	if len(results) != 110953 {
		t.Fatalf("results len = %d, want 110953", len(results))
	}

	r := results[0]
	if r.Process != "/usr/libexec/opendirectoryd" {
		t.Errorf("process = %q", r.Process)
	}
	if r.Subsystem != "com.apple.opendirectoryd" {
		t.Errorf("subsystem = %q", r.Subsystem)
	}
	if r.Time != 1642303933964503310.0 {
		t.Errorf("time = %v", r.Time)
	}
	if r.ActivityID != 0 {
		t.Errorf("activity_id = %d, want 0", r.ActivityID)
	}
	if r.Library != "/usr/libexec/opendirectoryd" {
		t.Errorf("library = %q", r.Library)
	}
	if r.Message != "opendirectoryd (build 796.100) launched..." {
		t.Errorf("message = %q", r.Message)
	}
	if r.PID != 105 {
		t.Errorf("pid = %d, want 105", r.PID)
	}
	if r.ThreadID != 670 {
		t.Errorf("thread_id = %d, want 670", r.ThreadID)
	}
	if r.Category != "default" {
		t.Errorf("category = %q", r.Category)
	}
	if r.LogType != LogTypeDefault {
		t.Errorf("log_type = %v, want Default", r.LogType)
	}
	if r.EventType != EventTypeLog {
		t.Errorf("event_type = %v, want Log", r.EventType)
	}
	if r.EUID != 0 {
		t.Errorf("euid = %d, want 0", r.EUID)
	}
	if r.BootUUID != "AACFB573E87545CE98B893D132766A46" {
		t.Errorf("boot_uuid = %q", r.BootUUID)
	}
	if r.TimezoneName != "Pacific" {
		t.Errorf("timezone_name = %q", r.TimezoneName)
	}
	if r.LibraryUUID != "B736DF1625F538248E9527A8CEC4991E" {
		t.Errorf("library_uuid = %q", r.LibraryUUID)
	}
	if r.ProcessUUID != "B736DF1625F538248E9527A8CEC4991E" {
		t.Errorf("process_uuid = %q", r.ProcessUUID)
	}
	if r.RawMessage != "opendirectoryd (build %{public}s) launched..." {
		t.Errorf("raw_message = %q", r.RawMessage)
	}
}

func TestParseAllLogsBigSurIntegration(t *testing.T) {
	provider := logarchiveProvider(t, bigSurArchive, "Persist/0000000000000002.tracev3")
	cache := NewMemoryStringCache()
	timesyncData, err := CollectTimesync(provider)
	if err != nil {
		t.Fatalf("CollectTimesync: %v", err)
	}
	logData := collectLogs(t, provider)

	var logDataVec []LogData
	for _, logs := range logData {
		data, _ := BuildLog(logs, provider, cache, timesyncData, false)
		logDataVec = append(logDataVec, data...)
	}
	if len(logDataVec) != 747616 {
		t.Fatalf("log_data_vec len = %d, want 747616", len(logDataVec))
	}

	var (
		unknownStrings             int
		invalidOffsets             int
		invalidSharedStringOffsets int
		statedumpCustomObjects     int
		statedumpProtocolBuffer    int
		statedumpCount             int
		signpostCount              int
		defaultType                int
		infoType                   int
		errorType                  int
		createType                 int
		debugType                  int
		useractionType             int
		faultType                  int
		lossType                   int
		stringCount                int
		emptyFormatCount           int
		sockCount                  int
		locationHarvestCount       int
		parentActivity             int
		noSuchFileOrDirectory      int
	)
	foundPrecisionString := false
	messageRe := regexp.MustCompile(`^[\s]*%s\s*$`)

	for _, logs := range logDataVec {
		if strings.Contains(logs.Message, "Failed to get string message from ") ||
			strings.Contains(logs.Message, "Unknown shared string message") {
			unknownStrings++
		} else if strings.Contains(logs.Message, "Error: Invalid offset ") {
			invalidOffsets++
		} else if strings.Contains(logs.Message, "Error: Invalid shared string offset") {
			invalidSharedStringOffsets++
		} else if strings.Contains(logs.Message, "Unsupported Statedump object") {
			statedumpCustomObjects++
		} else if strings.Contains(logs.Message, "Failed to parse StateDump protobuf") ||
			strings.Contains(logs.Message, "Failed to serialize Protobuf HashMap") {
			statedumpProtocolBuffer++
		} else if logs.Message == `#32EC4B64 [AssetCacheLocatorService.queue] sending POST [327]{"locator-tag":"#32ec4b64","local-addresses":["192.168.101.144"],"ranked-results":true,"locator-software":[{"build":"20G224","type":"system","name":"macOS","version":"11.6.1"},{"id":"com.apple.AssetCacheLocatorService","executable":"AssetCacheLocatorService","type":"bundle","name":"AssetCacheLocatorService","version":"118"}]} to https://lcdn-locator.apple.com/lcdn/locate` {
			foundPrecisionString = true
		}

		if logs.EventType == EventTypeStatedump {
			statedumpCount++
		} else if logs.EventType == EventTypeSignpost {
			signpostCount++
		} else if logs.LogType == LogTypeDefault {
			defaultType++
		} else if logs.LogType == LogTypeInfo {
			infoType++
		} else if logs.LogType == LogTypeError {
			errorType++
		} else if logs.LogType == LogTypeCreate {
			createType++
		} else if logs.LogType == LogTypeDebug {
			debugType++
		} else if logs.LogType == LogTypeUseraction {
			useractionType++
		} else if logs.LogType == LogTypeFault {
			faultType++
		} else if logs.EventType == EventTypeLoss {
			lossType++
		}

		if strings.Contains(logs.Message, `"subHarvester":"Trace"`) {
			locationHarvestCount++
		}
		if messageRe.MatchString(logs.RawMessage) {
			stringCount++
		}
		if logs.RawMessage == "" && logs.Message == "" && logs.EventType != EventTypeLoss {
			emptyFormatCount++
		}
		if strings.Contains(logs.Message, "nw_resolver_create_dns_getaddrinfo_locked_block_invoke [C1] Got DNS result type NoAddress ifindex=0 configuration.ls.apple.com configuration.ls.apple.com. ::") {
			sockCount++
		}
		if logs.ParentActivityID == 208 {
			parentActivity++
		}
		if strings.Contains(logs.Message, "No such file or directory") {
			noSuchFileOrDirectory++
		}
	}

	if unknownStrings != 0 {
		t.Errorf("unknown_strings = %d, want 0", unknownStrings)
	}
	if invalidOffsets != 54 {
		t.Errorf("invalid_offsets = %d, want 54", invalidOffsets)
	}
	if invalidSharedStringOffsets != 0 {
		t.Errorf("invalid_shared_string_offsets = %d, want 0", invalidSharedStringOffsets)
	}
	if statedumpCustomObjects != 0 {
		t.Errorf("statedump_custom_objects = %d, want 0", statedumpCustomObjects)
	}
	if statedumpProtocolBuffer != 0 {
		t.Errorf("statedump_protocol_buffer = %d, want 0", statedumpProtocolBuffer)
	}
	if !foundPrecisionString {
		t.Error("did not find precision string")
	}
	if statedumpCount != 322 {
		t.Errorf("statedump_count = %d, want 322", statedumpCount)
	}
	if signpostCount != 50665 {
		t.Errorf("signpost_count = %d, want 50665", signpostCount)
	}
	if stringCount != 11764 {
		t.Errorf("string_count = %d, want 11764", stringCount)
	}
	if emptyFormatCount != 56 {
		t.Errorf("empty_format_count = %d, want 56", emptyFormatCount)
	}
	if defaultType != 462518 {
		t.Errorf("default_type = %d, want 462518", defaultType)
	}
	if infoType != 114540 {
		t.Errorf("info_type = %d, want 114540", infoType)
	}
	if errorType != 29132 {
		t.Errorf("error_type = %d, want 29132", errorType)
	}
	if createType != 87831 {
		t.Errorf("create_type = %d, want 87831", createType)
	}
	if debugType != 1908 {
		t.Errorf("debug_type = %d, want 1908", debugType)
	}
	if useractionType != 15 {
		t.Errorf("useraction_type = %d, want 15", useractionType)
	}
	if faultType != 680 {
		t.Errorf("fault_type = %d, want 680", faultType)
	}
	if lossType != 5 {
		t.Errorf("loss_type = %d, want 5", lossType)
	}
	if sockCount != 2 {
		t.Errorf("sock_count = %d, want 2", sockCount)
	}
	if locationHarvestCount != 11 {
		t.Errorf("location_harvest_count = %d, want 11", locationHarvestCount)
	}
	if parentActivity != 5 {
		t.Errorf("parent_activity = %d, want 5", parentActivity)
	}
	if noSuchFileOrDirectory != 1728 {
		t.Errorf("no_such_file_or_directory = %d, want 1728", noSuchFileOrDirectory)
	}
}

func TestParseAllPersistLogsWithNetworkBigSurIntegration(t *testing.T) {
	provider := logarchiveProvider(t, bigSurArchive, "Persist/0000000000000002.tracev3")
	cache := NewMemoryStringCache()
	timesyncData, err := CollectTimesync(provider)
	if err != nil {
		t.Fatalf("CollectTimesync: %v", err)
	}
	logData := collectLogs(t, provider)

	var logDataVec []LogData
	for _, logs := range logData {
		data, _ := BuildLog(logs, provider, cache, timesyncData, false)
		logDataVec = append(logDataVec, data...)
	}

	var (
		messagesContainingNetwork int
		infoType                  int
		errorType                 int
		createType                int
		stateSimpledump           int
		signpost                  int
		defaultType               int
	)
	networkMessageUUID := false

	for _, logs := range logDataVec {
		if !strings.Contains(strings.ToLower(logs.Message), "network") {
			continue
		}
		if logs.LogType == LogTypeDefault {
			defaultType++
			if strings.Contains(logs.Message, "7C10C1EF-1B86-494F-800D-C769A89172C1") {
				networkMessageUUID = true
			}
		} else if logs.LogType == LogTypeInfo {
			infoType++
		} else if logs.LogType == LogTypeError {
			errorType++
		} else if logs.LogType == LogTypeCreate {
			createType++
			continue
		} else if logs.EventType == EventTypeSimpledump || logs.EventType == EventTypeStatedump {
			stateSimpledump++
			continue
		} else if isSignpost(logs.LogType) {
			signpost++
			continue
		}
		messagesContainingNetwork++
	}
	if messagesContainingNetwork != 9173 {
		t.Errorf("messages_containing_network = %d, want 9173", messagesContainingNetwork)
	}
	if defaultType != 8320 {
		t.Errorf("default_type = %d, want 8320", defaultType)
	}
	if !networkMessageUUID {
		t.Error("network_message_uuid = false, want true")
	}
	if infoType != 638 {
		t.Errorf("info_type = %d, want 638", infoType)
	}
	if errorType != 215 {
		t.Errorf("error_type = %d, want 215", errorType)
	}
	if createType != 687 {
		t.Errorf("create_type = %d, want 687", createType)
	}
	if stateSimpledump != 34 {
		t.Errorf("state_simple_dump = %d, want 34", stateSimpledump)
	}
	if signpost != 62 {
		t.Errorf("signpost = %d, want 62", signpost)
	}
}

func TestParseAllLogsPrivateBigSurIntegration(t *testing.T) {
	provider := logarchiveProvider(t, bigSurPrivateArchive, "Persist/0000000000000002.tracev3")
	cache := NewMemoryStringCache()
	timesyncData, err := CollectTimesync(provider)
	if err != nil {
		t.Fatalf("CollectTimesync: %v", err)
	}
	logData := collectLogs(t, provider)

	var logDataVec []LogData
	for _, logs := range logData {
		data, _ := BuildLog(logs, provider, cache, timesyncData, false)
		logDataVec = append(logDataVec, data...)
	}
	if len(logDataVec) != 887890 {
		t.Fatalf("log_data_vec len = %d, want 887890", len(logDataVec))
	}

	var emptyCounter, notFound, staffCount int
	for _, logs := range logDataVec {
		if logs.Message == "" {
			emptyCounter++
		}
		if strings.Contains(logs.Message, "<not found>") {
			notFound++
		}
		if strings.Contains(logs.Message, "group: staff@/Local/Default") {
			staffCount++
		}
	}
	if notFound != 0 {
		t.Errorf("not_found = %d, want 0", notFound)
	}
	if staffCount != 4 {
		t.Errorf("staff_count = %d, want 4", staffCount)
	}
	if emptyCounter != 596 {
		t.Errorf("empty_counter = %d, want 596", emptyCounter)
	}
}

func TestParseAllLogsPrivateWithPublicMixBigSurIntegration(t *testing.T) {
	provider := logarchiveProvider(t, bigSurMixArchive, "Persist/0000000000000002.tracev3")
	cache := NewMemoryStringCache()
	timesyncData, err := CollectTimesync(provider)
	if err != nil {
		t.Fatalf("CollectTimesync: %v", err)
	}
	logData := collectLogs(t, provider)

	var logDataVec []LogData
	for _, logs := range logData {
		data, _ := BuildLog(logs, provider, cache, timesyncData, false)
		logDataVec = append(logDataVec, data...)
	}
	if len(logDataVec) != 1287628 {
		t.Fatalf("log_data_vec len = %d, want 1287628", len(logDataVec))
	}

	var notFound, userNotFound, mobileNotFound, bssidCount, dnsQueryCount, bofaCount int
	for _, logs := range logDataVec {
		if strings.Contains(logs.Message, "<not found>") {
			notFound++
		}
		if strings.Contains(logs.Message, "user: -1 <not found>") {
			userNotFound++
		}
		if strings.Contains(logs.Message, "refreshing: details, reason: expired, user: mobile <not found>") {
			mobileNotFound++
		}
		if strings.Contains(logs.Message, "BSSID 00:00:00:00:00:00") {
			bssidCount++
		}
		if strings.Contains(logs.Message, "https://doh.dns.apple.com/dns-query") {
			dnsQueryCount++
		}
		if strings.Contains(logs.Message, "bankofamerica") {
			bofaCount++
		}
	}
	if notFound != 5 {
		t.Errorf("not_found = %d, want 5", notFound)
	}
	if userNotFound != 2 {
		t.Errorf("user_not_found = %d, want 2", userNotFound)
	}
	if mobileNotFound != 1 {
		t.Errorf("mobile_not_found = %d, want 1", mobileNotFound)
	}
	if bssidCount != 39 {
		t.Errorf("bssid_count = %d, want 39", bssidCount)
	}
	if dnsQueryCount != 41 {
		t.Errorf("dns_query_count = %d, want 41", dnsQueryCount)
	}
	if bofaCount != 573 {
		t.Errorf("bofa_count = %d, want 573", bofaCount)
	}
}

func TestParseAllLogsPrivateWithPublicMixBigSurSingleFileIntegration(t *testing.T) {
	provider := logarchiveProvider(t, bigSurMixArchive, "Persist/0000000000000009.tracev3")
	cache := NewMemoryStringCache()
	timesyncData, err := CollectTimesync(provider)
	if err != nil {
		t.Fatalf("CollectTimesync: %v", err)
	}

	logData := parseTracev3(t, bigSurMixArchive, "Persist/0000000000000009.tracev3")
	results, _ := BuildLog(logData, provider, cache, timesyncData, false)
	if len(results) != 91567 {
		t.Fatalf("results len = %d, want 91567", len(results))
	}

	var hexCount, dns int
	publicPrivateMixture := false
	for _, r := range results {
		if strings.Contains(r.Message, "7FAE25804F50") {
			hexCount++
		}
		if strings.Contains(r.Subsystem, ".mdns") {
			dns++
		}
		if r.Message == "os_transaction created: (7FAE25B0E420) CLLS:0x7fae23628160.LocationFine" {
			publicPrivateMixture = true
		}
	}
	if hexCount != 4 {
		t.Errorf("hex_count = %d, want 4", hexCount)
	}
	if dns != 801 {
		t.Errorf("dns = %d, want 801", dns)
	}
	if !publicPrivateMixture {
		t.Error("public_private_mixture = false, want true")
	}
}

func TestParseAllLogsPrivateWithPublicMixBigSurSpecialFileIntegration(t *testing.T) {
	provider := logarchiveProvider(t, bigSurMixArchive, "Special/0000000000000008.tracev3")
	cache := NewMemoryStringCache()
	timesyncData, err := CollectTimesync(provider)
	if err != nil {
		t.Fatalf("CollectTimesync: %v", err)
	}

	logData := parseTracev3(t, bigSurMixArchive, "Special/0000000000000008.tracev3")
	results, _ := BuildLog(logData, provider, cache, timesyncData, false)
	if len(results) != 2238 {
		t.Fatalf("results len = %d, want 2238", len(results))
	}

	var statedump, defaultType, fault, info, errorCount int
	for _, r := range results {
		if r.EventType == EventTypeStatedump {
			statedump++
		} else if r.LogType == LogTypeDefault {
			defaultType++
		} else if r.LogType == LogTypeFault {
			fault++
		} else if r.LogType == LogTypeInfo {
			info++
		} else if r.LogType == LogTypeError {
			errorCount++
		}
	}
	if statedump != 1 {
		t.Errorf("statedump = %d, want 1", statedump)
	}
	if defaultType != 1972 {
		t.Errorf("default = %d, want 1972", defaultType)
	}
	if fault != 32 {
		t.Errorf("fault = %d, want 32", fault)
	}
	if info != 41 {
		t.Errorf("info = %d, want 41", info)
	}
	if errorCount != 192 {
		t.Errorf("error = %d, want 192", errorCount)
	}
}

func TestBigSurMissingOversizeStringsIntegration(t *testing.T) {
	provider := logarchiveProvider(t, bigSurArchive, "logdata.LiveData.tracev3")
	cache := NewMemoryStringCache()
	timesyncData, err := CollectTimesync(provider)
	if err != nil {
		t.Fatalf("CollectTimesync: %v", err)
	}

	logData := parseTracev3(t, bigSurArchive, "logdata.LiveData.tracev3")
	data, _ := BuildLog(logData, provider, cache, timesyncData, false)
	if len(data) != 101566 {
		t.Fatalf("data len = %d, want 101566", len(data))
	}

	missingStrings := 0
	for _, r := range data {
		if strings.Contains(r.Message, "<Missing message data>") {
			missingStrings++
		}
	}
	if missingStrings != 52 {
		t.Errorf("missing_strings = %d, want 52", missingStrings)
	}
}

func TestBigSurOversizeStringsInAnotherFileIntegration(t *testing.T) {
	provider := logarchiveProvider(t, bigSurArchive, "logdata.LiveData.tracev3")
	cache := NewMemoryStringCache()
	timesyncData, err := CollectTimesync(provider)
	if err != nil {
		t.Fatalf("CollectTimesync: %v", err)
	}

	logData := parseTracev3(t, bigSurArchive, "Persist/0000000000000005.tracev3")
	specialData := parseTracev3(t, bigSurArchive, "Special/0000000000000005.tracev3")
	results := parseTracev3(t, bigSurArchive, "logdata.LiveData.tracev3")

	results.Oversize = append(results.Oversize, logData.Oversize...)
	results.Oversize = append(results.Oversize, specialData.Oversize...)

	data, _ := BuildLog(results, provider, cache, timesyncData, false)
	if len(data) != 101566 {
		t.Fatalf("data len = %d, want 101566", len(data))
	}

	missingStrings := 0
	for _, r := range data {
		if strings.Contains(r.Message, "<Missing message data>") {
			missingStrings++
		}
	}
	if missingStrings != 29 {
		t.Errorf("missing_strings = %d, want 29", missingStrings)
	}
}

// ---------------------------------------------------------------------------
// High Sierra
// ---------------------------------------------------------------------------

func TestParseLogHighSierraIntegration(t *testing.T) {
	logData := parseTracev3(t, highSierraArchive, "Persist/0000000000000001.tracev3")

	if got := len(logData.CatalogData[0].Firehose); got != 172 {
		t.Errorf("firehose len = %d, want 172", got)
	}
	if got := len(logData.CatalogData[0].Simpledump); got != 0 {
		t.Errorf("simpledump len = %d, want 0", got)
	}
	if got := len(logData.Header); got != 1 {
		t.Errorf("header len = %d, want 1", got)
	}
	if got := len(logData.CatalogData[0].Catalog.CatalogProcessInfoEntries); got != 30 {
		t.Errorf("catalog process info entries len = %d, want 30", got)
	}
	if got := len(logData.CatalogData[0].Statedump); got != 0 {
		t.Errorf("statedump len = %d, want 0", got)
	}
	if !strings.HasSuffix(logData.Evidence, "0000000000000001.tracev3") {
		t.Errorf("evidence = %q, want suffix 0000000000000001.tracev3", logData.Evidence)
	}
}

func TestBuildLogHighSierraIntegration(t *testing.T) {
	provider := logarchiveProvider(t, highSierraArchive, "Persist/0000000000000001.tracev3")
	cache := NewMemoryStringCache()
	timesyncData, err := CollectTimesync(provider)
	if err != nil {
		t.Fatalf("CollectTimesync: %v", err)
	}

	logData := parseTracev3(t, highSierraArchive, "Persist/0000000000000001.tracev3")
	results, _ := BuildLog(logData, provider, cache, timesyncData, false)
	if len(results) != 162402 {
		t.Fatalf("results len = %d, want 162402", len(results))
	}

	r := results[0]
	if r.Process != "/usr/libexec/opendirectoryd" {
		t.Errorf("process = %q", r.Process)
	}
	if r.Subsystem != "com.apple.opendirectoryd" {
		t.Errorf("subsystem = %q", r.Subsystem)
	}
	if r.Time != 1624134811546060433.0 {
		t.Errorf("time = %v", r.Time)
	}
	if r.ActivityID != 0 {
		t.Errorf("activity_id = %d, want 0", r.ActivityID)
	}
	if r.Library != "/usr/libexec/opendirectoryd" {
		t.Errorf("library = %q", r.Library)
	}
	if r.Message != "opendirectoryd (build 483.700) launched..." {
		t.Errorf("message = %q", r.Message)
	}
	if r.PID != 59 {
		t.Errorf("pid = %d, want 59", r.PID)
	}
	if r.ThreadID != 622 {
		t.Errorf("thread_id = %d, want 622", r.ThreadID)
	}
	if r.Category != "default" {
		t.Errorf("category = %q", r.Category)
	}
	if r.LogType != LogTypeDefault {
		t.Errorf("log_type = %v, want Default", r.LogType)
	}
	if r.EventType != EventTypeLog {
		t.Errorf("event_type = %v, want Log", r.EventType)
	}
	if r.EUID != 0 {
		t.Errorf("euid = %d, want 0", r.EUID)
	}
	if r.BootUUID != "30774817CF1549B0920E1A8E17D47AB5" {
		t.Errorf("boot_uuid = %q", r.BootUUID)
	}
	if r.TimezoneName != "Pacific" {
		t.Errorf("timezone_name = %q", r.TimezoneName)
	}
	if r.ProcessUUID != "AD43C574A9F73311A4E995237667082A" {
		t.Errorf("process_uuid = %q", r.ProcessUUID)
	}
	if r.LibraryUUID != "AD43C574A9F73311A4E995237667082A" {
		t.Errorf("library_uuid = %q", r.LibraryUUID)
	}
	if r.RawMessage != "opendirectoryd (build %{public}s) launched..." {
		t.Errorf("raw_message = %q", r.RawMessage)
	}
}

func TestBuildLogComplexFormatHighSierraIntegration(t *testing.T) {
	provider := logarchiveProvider(t, highSierraArchive, "Persist/0000000000000001.tracev3")
	cache := NewMemoryStringCache()
	timesyncData, err := CollectTimesync(provider)
	if err != nil {
		t.Fatalf("CollectTimesync: %v", err)
	}

	logData := parseTracev3(t, highSierraArchive, "Persist/0000000000000001.tracev3")
	results, _ := BuildLog(logData, provider, cache, timesyncData, false)
	if len(results) != 162402 {
		t.Fatalf("results len = %d, want 162402", len(results))
	}

	const want = "<PCPersistentTimer: 0x7f8b72c722f0> Calculated minimum fire date [2021-06-19 19:47:59 -0700] (75%) with fire date [2021-06-19 21:51:14 -0700], start date [2021-06-19 13:38:14 -0700], minimum early fire proportion 0.75, power state detection supported: no, in high power state: no, early fire constant interval 0"
	for _, r := range results {
		if r.Message == want {
			if r.Process != "/System/Library/PrivateFrameworks/CalendarNotification.framework/Versions/A/XPCServices/CalNCService.xpc/Contents/MacOS/CalNCService" {
				t.Errorf("process = %q", r.Process)
			}
			if r.Subsystem != "com.apple.PersistentConnection" {
				t.Errorf("subsystem = %q", r.Subsystem)
			}
			if r.Time != 1624135094694359040.0 {
				t.Errorf("time = %v", r.Time)
			}
			if r.ActivityID != 0 {
				t.Errorf("activity_id = %d, want 0", r.ActivityID)
			}
			if r.Library != "/System/Library/PrivateFrameworks/PersistentConnection.framework/Versions/A/PersistentConnection" {
				t.Errorf("library = %q", r.Library)
			}
			if r.PID != 580 {
				t.Errorf("pid = %d, want 580", r.PID)
			}
			if r.ThreadID != 8759 {
				t.Errorf("thread_id = %d, want 8759", r.ThreadID)
			}
			if r.Category != "persistentTimer.com.apple.CalendarNotification.EKTravelEngine.periodicRefreshTimer" {
				t.Errorf("category = %q", r.Category)
			}
			if r.LogType != LogTypeDefault {
				t.Errorf("log_type = %v, want Default", r.LogType)
			}
			if r.EventType != EventTypeLog {
				t.Errorf("event_type = %v, want Log", r.EventType)
			}
			if r.EUID != 501 {
				t.Errorf("euid = %d, want 501", r.EUID)
			}
			if r.BootUUID != "30774817CF1549B0920E1A8E17D47AB5" {
				t.Errorf("boot_uuid = %q", r.BootUUID)
			}
			if r.TimezoneName != "Pacific" {
				t.Errorf("timezone_name = %q", r.TimezoneName)
			}
			if r.ProcessUUID != "3E78A65047873F8AAFB10EA606B84B5D" {
				t.Errorf("process_uuid = %q", r.ProcessUUID)
			}
			if r.LibraryUUID != "761AF71A7FBE3374A4A48A38E0D59B6B" {
				t.Errorf("library_uuid = %q", r.LibraryUUID)
			}
			if r.RawMessage != "%{public}@ Calculated minimum fire date [%{public}@] (%g%%) with fire date [%{public}@], start date [%{public}@], minimum early fire proportion %g, power state detection supported: %{public}s, in high power state: %{public}s, early fire constant interval %f" {
				t.Errorf("raw_message = %q", r.RawMessage)
			}
			return
		}
	}
	t.Fatal("did not find message match")
}

func TestBuildLogNegativeNumberHighSierraIntegration(t *testing.T) {
	provider := logarchiveProvider(t, highSierraArchive, "Special/0000000000000003.tracev3")
	cache := NewMemoryStringCache()
	timesyncData, err := CollectTimesync(provider)
	if err != nil {
		t.Fatalf("CollectTimesync: %v", err)
	}

	logData := parseTracev3(t, highSierraArchive, "Special/0000000000000003.tracev3")
	results, _ := BuildLog(logData, provider, cache, timesyncData, false)
	if len(results) != 12058 {
		t.Fatalf("results len = %d, want 12058", len(results))
	}

	for _, r := range results {
		if r.Message == "[BTUserEventAgentController messageTracerEventDriven] PowerSource -2 -2\n" {
			if r.RawMessage != "[BTUserEventAgentController messageTracerEventDriven] PowerSource %f %f\n" {
				t.Errorf("raw_message = %q", r.RawMessage)
			}
			return
		}
	}
	t.Fatal("did not find negative message match")
}

func TestParseAllLogsHighSierraIntegration(t *testing.T) {
	provider := logarchiveProvider(t, highSierraArchive, "Persist/0000000000000001.tracev3")
	cache := NewMemoryStringCache()
	timesyncData, err := CollectTimesync(provider)
	if err != nil {
		t.Fatalf("CollectTimesync: %v", err)
	}
	logData := collectLogs(t, provider)

	var logDataVec []LogData
	for _, logs := range logData {
		data, _ := BuildLog(logs, provider, cache, timesyncData, false)
		logDataVec = append(logDataVec, data...)
	}
	if len(logDataVec) != 569796 {
		t.Fatalf("log_data_vec len = %d, want 569796", len(logDataVec))
	}

	var (
		emptyCounter           int
		emptyIdentityservicesd int
		emptyCallservicesd     int
		emptyConfigd           int
		emptyCoreduetd         int
		privateEntries         int
		kernelEntries          int
		stringCount            int
	)
	messageRe := regexp.MustCompile(`^[\s]*%s\s*$`)

	for _, logs := range logDataVec {
		if logs.Message == "" {
			emptyCounter++
			if logs.Process == "/System/Library/PrivateFrameworks/TelephonyUtilities.framework/callservicesd" {
				emptyCallservicesd++
			} else if logs.Process == "/System/Library/PrivateFrameworks/IDS.framework/identityservicesd.app/Contents/MacOS/identityservicesd" {
				emptyIdentityservicesd++
			} else if logs.Process == "/usr/libexec/configd" {
				emptyConfigd++
			} else if logs.Process == "/usr/libexec/coreduetd" {
				emptyCoreduetd++
			}
		} else if strings.Contains(logs.Message, "<private>") {
			privateEntries += strings.Count(logs.Message, "<private>")
		}
		if strings.Contains(logs.Message, "bytes in/out: 818/542, packets in/out: 2/2, rtt: 0.020s, retransmitted packets: 1, out-of-order packets: 2") {
			wantMsg := "[11 <private> stream, pid: 344] cancelled\n\t[11.1 334B42D96E654481B31C3A452BFB96B7 <private>.49154<-><private>]\n\tConnected Path: satisfied (Path is satisfied), interface: en0, ipv4, dns\n\tDuration: 0.115s, DNS @0.000s took 0.002s, TCP @0.002s took 0.014s\n\tbytes in/out: 818/542, packets in/out: 2/2, rtt: 0.020s, retransmitted packets: 1, out-of-order packets: 2"
			if logs.Message != wantMsg {
				t.Errorf("message = %q", logs.Message)
			}
			wantRaw := "[%{public}s %{private}@ %{public}@] cancelled\n\t[%s %{uuid_t}.16P %{private,network:in_addr}d.%d<->%{private,network:sockaddr}.*P]\n\tConnected Path: %@\n\tDuration: %u.%03us, DNS @%u.%03us took %u.%03us, %{public}s @%u.%03us took %u.%03us\n\tbytes in/out: %llu/%llu, packets in/out: %llu/%llu, rtt: %u.%03us, retransmitted packets: %llu, out-of-order packets: %u"
			if logs.RawMessage != wantRaw {
				t.Errorf("raw_message = %q", logs.RawMessage)
			}
		}
		if logs.Process == "/kernel" && logs.Library == "/kernel" {
			kernelEntries++
		}
		if messageRe.MatchString(logs.RawMessage) {
			stringCount++
		}
	}
	if emptyCounter != 107 {
		t.Errorf("empty_counter = %d, want 107", emptyCounter)
	}
	if emptyIdentityservicesd != 24 {
		t.Errorf("empty_identityservicesd = %d, want 24", emptyIdentityservicesd)
	}
	if emptyConfigd != 64 {
		t.Errorf("empty_configd = %d, want 64", emptyConfigd)
	}
	if emptyCoreduetd != 1 {
		t.Errorf("empty_coreduetd = %d, want 1", emptyCoreduetd)
	}
	if emptyCallservicesd != 18 {
		t.Errorf("empty_callservicesd = %d, want 18", emptyCallservicesd)
	}
	if privateEntries != 88352 {
		t.Errorf("private_entries = %d, want 88352", privateEntries)
	}
	if kernelEntries != 389 {
		t.Errorf("kernel_entries = %d, want 389", kernelEntries)
	}
	if stringCount != 23982 {
		t.Errorf("string_count = %d, want 23982", stringCount)
	}

	var (
		unknownStrings             int
		invalidOffsets             int
		invalidSharedStringOffsets int
		statedumpCustomObjects     int
		statedumpProtocolBuffer    int
	)
	for _, logs := range logDataVec {
		if strings.Contains(logs.Message, "Failed to get string message from ") ||
			strings.Contains(logs.Message, "Unknown shared string message") {
			unknownStrings++
		}
		if strings.Contains(logs.Message, "Error: Invalid offset ") {
			invalidOffsets++
		}
		if strings.Contains(logs.Message, "Error: Invalid shared string offset") {
			invalidSharedStringOffsets++
		}
		if strings.Contains(logs.Message, "Unsupported Statedump object") {
			statedumpCustomObjects++
		}
		if strings.Contains(logs.Message, "Failed to parse StateDump protobuf") ||
			strings.Contains(logs.Message, "Failed to serialize Protobuf HashMap") {
			statedumpProtocolBuffer++
		}
	}
	if unknownStrings != 0 {
		t.Errorf("unknown_strings = %d, want 0", unknownStrings)
	}
	if invalidOffsets != 3 {
		t.Errorf("invalid_offsets = %d, want 3", invalidOffsets)
	}
	if invalidSharedStringOffsets != 0 {
		t.Errorf("invalid_shared_string_offsets = %d, want 0", invalidSharedStringOffsets)
	}
	if statedumpCustomObjects != 0 {
		t.Errorf("statedump_custom_objects = %d, want 0", statedumpCustomObjects)
	}
	if statedumpProtocolBuffer != 0 {
		t.Errorf("statedump_protocol_buffer = %d, want 0", statedumpProtocolBuffer)
	}
}

// ---------------------------------------------------------------------------
// Monterey
// ---------------------------------------------------------------------------

func TestParseLogMontereyIntegration(t *testing.T) {
	logData := parseTracev3(t, montereyArchive, "Persist/000000000000000a.tracev3")

	if got := len(logData.CatalogData[0].Firehose); got != 17 {
		t.Errorf("firehose len = %d, want 17", got)
	}
	if got := len(logData.CatalogData[0].Simpledump); got != 383 {
		t.Errorf("simpledump len = %d, want 383", got)
	}
	if got := len(logData.Header); got != 1 {
		t.Errorf("header len = %d, want 1", got)
	}
	if got := len(logData.CatalogData[0].Catalog.CatalogProcessInfoEntries); got != 17 {
		t.Errorf("catalog process info entries len = %d, want 17", got)
	}
	if got := len(logData.CatalogData[0].Statedump); got != 0 {
		t.Errorf("statedump len = %d, want 0", got)
	}
}

func TestBuildLogMontereyIntegration(t *testing.T) {
	provider := logarchiveProvider(t, montereyArchive, "Persist/000000000000000a.tracev3")
	cache := NewMemoryStringCache()
	timesyncData, err := CollectTimesync(provider)
	if err != nil {
		t.Fatalf("CollectTimesync: %v", err)
	}

	logData := parseTracev3(t, montereyArchive, "Persist/000000000000000a.tracev3")
	results, _ := BuildLog(logData, provider, cache, timesyncData, false)
	if len(results) != 322859 {
		t.Fatalf("results len = %d, want 322859", len(results))
	}

	r := results[0]
	if r.Process != "/kernel" {
		t.Errorf("process = %q", r.Process)
	}
	if r.Subsystem != "" {
		t.Errorf("subsystem = %q, want empty", r.Subsystem)
	}
	if r.Time != 1651345928766719209.0 {
		t.Errorf("time = %v", r.Time)
	}
	if r.ActivityID != 0 {
		t.Errorf("activity_id = %d, want 0", r.ActivityID)
	}
	if r.Library != "/System/Library/Extensions/Sandbox.kext/Contents/MacOS/Sandbox" {
		t.Errorf("library = %q", r.Library)
	}
	if r.Message != "2 duplicate reports for Sandbox: MTLCompilerServi(187) deny(1) file-read-metadata /private" {
		t.Errorf("message = %q", r.Message)
	}
	if r.PID != 0 {
		t.Errorf("pid = %d, want 0", r.PID)
	}
	if r.ThreadID != 2241 {
		t.Errorf("thread_id = %d, want 2241", r.ThreadID)
	}
	if r.Category != "" {
		t.Errorf("category = %q, want empty", r.Category)
	}
	if r.LogType != LogTypeError {
		t.Errorf("log_type = %v, want Error", r.LogType)
	}
	if r.EventType != EventTypeLog {
		t.Errorf("event_type = %v, want Log", r.EventType)
	}
	if r.EUID != 0 {
		t.Errorf("euid = %d, want 0", r.EUID)
	}
	if r.BootUUID != "17AB576950394796B7F3CD2C157F4A2F" {
		t.Errorf("boot_uuid = %q", r.BootUUID)
	}
	if r.TimezoneName != "New_York" {
		t.Errorf("timezone_name = %q", r.TimezoneName)
	}
	if r.LibraryUUID != "7EFAFB8B6CA63090957FC68A6230BC38" {
		t.Errorf("library_uuid = %q", r.LibraryUUID)
	}
	if r.ProcessUUID != "C342869FFFB93CCEA5A3EA711C1E87F6" {
		t.Errorf("process_uuid = %q", r.ProcessUUID)
	}
	if r.RawMessage != "%s" {
		t.Errorf("raw_message = %q", r.RawMessage)
	}
}

func TestParseAllLogsMontereyIntegration(t *testing.T) {
	provider := logarchiveProvider(t, montereyArchive, "Persist/000000000000000a.tracev3")
	cache := NewMemoryStringCache()
	timesyncData, err := CollectTimesync(provider)
	if err != nil {
		t.Fatalf("CollectTimesync: %v", err)
	}
	logData := collectLogs(t, provider)

	var logDataVec []LogData
	for _, logs := range logData {
		data, _ := BuildLog(logs, provider, cache, timesyncData, false)
		logDataVec = append(logDataVec, data...)
	}
	if len(logDataVec) != 2397109 {
		t.Fatalf("log_data_vec len = %d, want 2397109", len(logDataVec))
	}

	var (
		unknownStrings             int
		invalidOffsets             int
		invalidSharedStringOffsets int
		statedumpCustomObjects     int
		statedumpProtocolBuffer    int
		stringCount                int
		simpleLogDisplay           int
		simpleLogsCount            int
		mutilitiesWorldclock       int
		mutililtiesReturn          int
		locationTracker            int
		pausesTracker              int
		dnsCounts                  int
	)
	messageRe := regexp.MustCompile(`^[\s]*%s\s*$`)

	for _, logs := range logDataVec {
		if strings.Contains(logs.Message, "Failed to get string message from ") ||
			strings.Contains(logs.Message, "Unknown shared string message") {
			unknownStrings++
		}
		if strings.Contains(logs.Message, "Error: Invalid offset ") {
			invalidOffsets++
		}
		if strings.Contains(logs.Message, "Error: Invalid shared string offset") {
			invalidSharedStringOffsets++
		}
		if strings.Contains(logs.Message, "Unsupported Statedump object") {
			statedumpCustomObjects++
		}
		if strings.Contains(logs.Message, "Failed to parse StateDump protobuf") ||
			strings.Contains(logs.Message, "Failed to serialize Protobuf HashMap") {
			statedumpProtocolBuffer++
		}
		if messageRe.MatchString(logs.RawMessage) {
			stringCount++
		}
		if strings.Contains(logs.Message, "MTUtilities: WorldClockWidget:") && logs.LogType == LogTypeDefault {
			mutilitiesWorldclock++
		}
		if strings.Contains(logs.Message, "MTUtilities: Returning widget") {
			mutililtiesReturn++
		}
		if strings.Contains(logs.Message, "allowsMapCorrection") {
			locationTracker++
		}
		if strings.Contains(logs.Message, "\"pausesLocationUpdatesAutomatically\":1,") {
			pausesTracker++
		}
		if strings.Contains(logs.Message, "Question Count: 1, Answer Record Count: 0, Authority Record Count: 0, Additional Record Count: 0") {
			dnsCounts++
		}
		if logs.LogType == LogTypeSimpledump {
			simpleLogsCount++
			if logs.Process == "/System/Library/PrivateFrameworks/MobileAccessoryUpdater.framework/XPCServices/UARPUpdaterServiceDisplay.xpc/Contents/MacOS/UARPUpdaterServiceDisplay" && logs.Subsystem == "" {
				simpleLogDisplay++
			}
		}
	}
	if simpleLogsCount != 162715 {
		t.Errorf("simple_logs len = %d, want 162715", simpleLogsCount)
	}
	if simpleLogDisplay != 34 {
		t.Errorf("simple_log_display = %d, want 34", simpleLogDisplay)
	}
	if unknownStrings != 531 {
		t.Errorf("unknown_strings = %d, want 531", unknownStrings)
	}
	if invalidOffsets != 60 {
		t.Errorf("invalid_offsets = %d, want 60", invalidOffsets)
	}
	if invalidSharedStringOffsets != 309 {
		t.Errorf("invalid_shared_string_offsets = %d, want 309", invalidSharedStringOffsets)
	}
	if statedumpCustomObjects != 0 {
		t.Errorf("statedump_custom_objects = %d, want 0", statedumpCustomObjects)
	}
	if statedumpProtocolBuffer != 0 {
		t.Errorf("statedump_protocol_buffer = %d, want 0", statedumpProtocolBuffer)
	}
	if stringCount != 28196 {
		t.Errorf("string_count = %d, want 28196", stringCount)
	}
	if mutilitiesWorldclock != 57 {
		t.Errorf("mutilities_worldclock = %d, want 57", mutilitiesWorldclock)
	}
	if mutililtiesReturn != 71 {
		t.Errorf("mutililties_return = %d, want 71", mutililtiesReturn)
	}
	if dnsCounts != 3196 {
		t.Errorf("dns_counts = %d, want 3196", dnsCounts)
	}
	if locationTracker != 298 {
		t.Errorf("location_tracker = %d, want 298", locationTracker)
	}
	if pausesTracker != 180 {
		t.Errorf("pauses_tracker = %d, want 180", pausesTracker)
	}
}

// ---------------------------------------------------------------------------
// Tahoe
// ---------------------------------------------------------------------------

func TestParseLogTahoeIntegration(t *testing.T) {
	logData := parseTracev3(t, tahoeArchive, "Persist/000000000000000a.tracev3")

	if got := len(logData.CatalogData); got != 121 {
		t.Fatalf("catalog_data len = %d, want 121", got)
	}
	if got := len(logData.CatalogData[78].Firehose); got != 112 {
		t.Errorf("catalog_data[78] firehose len = %d, want 112", got)
	}
	if got := len(logData.CatalogData[12].Simpledump); got != 78 {
		t.Errorf("catalog_data[12].simpledump len = %d, want 78", got)
	}
	if got := len(logData.Header); got != 1 {
		t.Errorf("header len = %d, want 1", got)
	}
	if got := len(logData.CatalogData[0].Catalog.CatalogProcessInfoEntries); got != 10 {
		t.Errorf("catalog process info entries len = %d, want 10", got)
	}
	if got := len(logData.CatalogData[0].Statedump); got != 0 {
		t.Errorf("statedump len = %d, want 0", got)
	}
}

func TestBuildLogTahoeIntegration(t *testing.T) {
	provider := logarchiveProvider(t, tahoeArchive, "Persist/000000000000000a.tracev3")
	cache := NewMemoryStringCache()
	timesyncData, err := CollectTimesync(provider)
	if err != nil {
		t.Fatalf("CollectTimesync: %v", err)
	}

	logData := parseTracev3(t, tahoeArchive, "Persist/000000000000000a.tracev3")
	results, _ := BuildLog(logData, provider, cache, timesyncData, false)
	if len(results) != 305785 {
		t.Fatalf("results len = %d, want 305785", len(results))
	}

	r := results[103032]
	if r.Process != "/System/Library/PrivateFrameworks/IDS.framework/identityservicesd.app/Contents/MacOS/identityservicesd" {
		t.Errorf("process = %q", r.Process)
	}
	if r.Subsystem != "" {
		t.Errorf("subsystem = %q, want empty", r.Subsystem)
	}
	if r.Time != 1.7766457650551785e18 {
		t.Errorf("time = %v", r.Time)
	}
	if r.ActivityID != 25562 {
		t.Errorf("activity_id = %d, want 25562", r.ActivityID)
	}
	if r.ParentActivityID != 0 {
		t.Errorf("parent_activity_id = %d, want 0", r.ParentActivityID)
	}
	if r.Library != "/System/Library/Frameworks/Security.framework/Versions/A/Security" {
		t.Errorf("library = %q", r.Library)
	}
	if r.Message != "SecKeyCreateWithData" {
		t.Errorf("message = %q", r.Message)
	}
	if r.PID != 412 {
		t.Errorf("pid = %d, want 412", r.PID)
	}
	if r.ThreadID != 2701 {
		t.Errorf("thread_id = %d, want 2701", r.ThreadID)
	}
	if r.Category != "" {
		t.Errorf("category = %q, want empty", r.Category)
	}
	if r.LogType != LogTypeCreate {
		t.Errorf("log_type = %v, want Create", r.LogType)
	}
	if r.EventType != EventTypeActivity {
		t.Errorf("event_type = %v, want Activity", r.EventType)
	}
	if r.EUID != 501 {
		t.Errorf("euid = %d, want 501", r.EUID)
	}
	if r.BootUUID != "78EDF02104B6458E9EFAAAC1FB21CCF7" {
		t.Errorf("boot_uuid = %q", r.BootUUID)
	}
	if r.TimezoneName != "Pacific" {
		t.Errorf("timezone_name = %q", r.TimezoneName)
	}
	if r.LibraryUUID != "22A9E9D9308633AAB1B36C0FA75D3797" {
		t.Errorf("library_uuid = %q", r.LibraryUUID)
	}
	if r.ProcessUUID != "338D916F98A033EBB68B80C74C6C41C8" {
		t.Errorf("process_uuid = %q", r.ProcessUUID)
	}
	if r.RawMessage != "SecKeyCreateWithData" {
		t.Errorf("raw_message = %q", r.RawMessage)
	}
	if len(r.MessageEntries) != 0 {
		t.Errorf("message_entries len = %d, want 0", len(r.MessageEntries))
	}
	if !strings.HasSuffix(r.Evidence, "000000000000000a.tracev3") {
		t.Errorf("evidence = %q", r.Evidence)
	}
	if r.Timestamp != "2026-04-20T00:42:45.055178496Z" {
		t.Errorf("timestamp = %q", r.Timestamp)
	}

	r45 := results[45]
	if r45.Process != "/usr/libexec/opendirectoryd" {
		t.Errorf("process = %q", r45.Process)
	}
	if r45.Subsystem != "com.apple.CFBundle" {
		t.Errorf("subsystem = %q", r45.Subsystem)
	}
	if r45.Time != 1.7766457511717076e18 {
		t.Errorf("time = %v", r45.Time)
	}
	if r45.ActivityID != 192 {
		t.Errorf("activity_id = %d, want 192", r45.ActivityID)
	}
	if r45.ParentActivityID != 0 {
		t.Errorf("parent_activity_id = %d, want 0", r45.ParentActivityID)
	}
	if r45.Library != "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation" {
		t.Errorf("library = %q", r45.Library)
	}
	if r45.Message != "dlsym cannot find symbol odm_RecordRemoveValue in CFBundle 0x102ed4970 </System/Library/OpenDirectory/Modules/SystemCache.bundle> (bundle, loaded): <private>" {
		t.Errorf("message = %q", r45.Message)
	}
	if r45.PID != 131 {
		t.Errorf("pid = %d, want 131", r45.PID)
	}
	if r45.ThreadID != 790 {
		t.Errorf("thread_id = %d, want 790", r45.ThreadID)
	}
	if r45.Category != "loading" {
		t.Errorf("category = %q", r45.Category)
	}
	if r45.LogType != LogTypeError {
		t.Errorf("log_type = %v, want Error", r45.LogType)
	}
	if r45.EventType != EventTypeLog {
		t.Errorf("event_type = %v, want Log", r45.EventType)
	}
	if r45.EUID != 0 {
		t.Errorf("euid = %d, want 0", r45.EUID)
	}
	if r45.BootUUID != "78EDF02104B6458E9EFAAAC1FB21CCF7" {
		t.Errorf("boot_uuid = %q", r45.BootUUID)
	}
	if r45.TimezoneName != "Pacific" {
		t.Errorf("timezone_name = %q", r45.TimezoneName)
	}
	if r45.LibraryUUID != "61AFC7A8FF8D3F8F8B0F42CAFB667E76" {
		t.Errorf("library_uuid = %q", r45.LibraryUUID)
	}
	if r45.ProcessUUID != "751A0472343930F7B421E36891337A30" {
		t.Errorf("process_uuid = %q", r45.ProcessUUID)
	}
	if r45.RawMessage != "dlsym cannot find symbol %{public}@ in %{public}@: %s" {
		t.Errorf("raw_message = %q", r45.RawMessage)
	}
	if len(r45.MessageEntries) == 0 || r45.MessageEntries[0].MessageStrings != "odm_RecordRemoveValue" {
		t.Errorf("message_entries[0].message_strings mismatch: %#v", r45.MessageEntries)
	}
	if !strings.HasSuffix(r45.Evidence, "000000000000000a.tracev3") {
		t.Errorf("evidence = %q", r45.Evidence)
	}
	if r45.Timestamp != "2026-04-20T00:42:31.171707648Z" {
		t.Errorf("timestamp = %q", r45.Timestamp)
	}

	var midnight, stringCount, precisionCount, numberCount, privateNumberCount int
	for _, entry := range results {
		if !strings.Contains(entry.Timestamp, "2026-04-20T") {
			t.Fatalf("timestamp = %q, want 2026-04-20T", entry.Timestamp)
		}
		if strings.Contains(entry.Timestamp, "2026-04-20T00:42") {
			midnight++
		}
		for _, value := range entry.MessageEntries {
			if value.Item == FirehoseItemUnknown {
				t.Fatalf("unexpected Unknown item in %#v", value)
			}
			switch value.Item {
			case FirehoseItemString:
				stringCount++
			case FirehoseItemNumber:
				numberCount++
			case FirehoseItemPrecision:
				precisionCount++
			case FirehoseItemPrivateNumber:
				privateNumberCount++
			}
		}
	}
	if stringCount != 369927 {
		t.Errorf("string_count = %d, want 369927", stringCount)
	}
	if numberCount != 382427 {
		t.Errorf("number_count = %d, want 382427", numberCount)
	}
	if precisionCount != 13077 {
		t.Errorf("precision_count = %d, want 13077", precisionCount)
	}
	if privateNumberCount != 711 {
		t.Errorf("private_number_count = %d, want 711", privateNumberCount)
	}
	if midnight != 209452 {
		t.Errorf("midnight = %d, want 209452", midnight)
	}
}

func TestCheckLogTahoeIntegration(t *testing.T) {
	provider := logarchiveProvider(t, tahoeArchive, "Persist/0000000000000002.tracev3")
	cache := NewMemoryStringCache()
	timesyncData, err := CollectTimesync(provider)
	if err != nil {
		t.Fatalf("CollectTimesync: %v", err)
	}

	logData := parseTracev3(t, tahoeArchive, "Persist/0000000000000002.tracev3")
	results, _ := BuildLog(logData, provider, cache, timesyncData, false)

	invalidSharedStringOffsets := 0
	for _, r := range results {
		if strings.Contains(r.Message, "Error: Invalid shared string offset") {
			invalidSharedStringOffsets++
		}
	}
	if invalidSharedStringOffsets != 97 {
		t.Errorf("invalid_shared_string_offsets = %d, want 97", invalidSharedStringOffsets)
	}
}

func TestParseAllLogsTahoeIntegration(t *testing.T) {
	provider := logarchiveProvider(t, tahoeArchive, "Persist/0000000000000002.tracev3")
	cache := NewMemoryStringCache()
	timesyncData, err := CollectTimesync(provider)
	if err != nil {
		t.Fatalf("CollectTimesync: %v", err)
	}
	logData := collectLogs(t, provider)

	var logDataVec []LogData
	for _, logs := range logData {
		data, _ := BuildLog(logs, provider, cache, timesyncData, false)
		logDataVec = append(logDataVec, data...)
	}
	if len(logDataVec) != 4288584 {
		t.Fatalf("log_data_vec len = %d, want 4288584", len(logDataVec))
	}

	var (
		unknownStrings             int
		invalidOffsets             int
		invalidSharedStringOffsets int
		statedumpCustomObjects     int
		statedumpProtocolBuffer    int
		syncthing                  int
		brew                       int
	)
	for _, logs := range logDataVec {
		if strings.Contains(logs.Message, "Failed to get string message from ") ||
			strings.Contains(logs.Message, "Unknown shared string message") {
			unknownStrings++
			if !strings.HasSuffix(logs.Evidence, "4.tracev3") && !strings.HasSuffix(logs.Evidence, "5.tracev3") {
				t.Fatalf("unexpected missing strings for evidence: %s", logs.Evidence)
			}
		}
		if strings.Contains(logs.Message, "Error: Invalid offset ") {
			invalidOffsets++
		}
		if strings.Contains(logs.Message, "Error: Invalid shared string offset") {
			invalidSharedStringOffsets++
		}
		if strings.Contains(logs.Message, "Unsupported Statedump object") {
			statedumpCustomObjects++
		}
		if strings.Contains(logs.Message, "Failed to parse StateDump protobuf") ||
			strings.Contains(logs.Message, "Failed to serialize Protobuf HashMap") {
			statedumpProtocolBuffer++
		}
		if strings.Contains(logs.Message, "syncthing") {
			syncthing++
		}
		if strings.Contains(logs.Message, "brew") {
			brew++
		}
	}
	if unknownStrings != 2 {
		t.Errorf("unknown_strings = %d, want 2", unknownStrings)
	}
	if invalidOffsets != 268 {
		t.Errorf("invalid_offsets = %d, want 268", invalidOffsets)
	}
	if invalidSharedStringOffsets != 647 {
		t.Errorf("invalid_shared_string_offsets = %d, want 647", invalidSharedStringOffsets)
	}
	if statedumpCustomObjects != 0 {
		t.Errorf("statedump_custom_objects = %d, want 0", statedumpCustomObjects)
	}
	if statedumpProtocolBuffer != 0 {
		t.Errorf("statedump_protocol_buffer = %d, want 0", statedumpProtocolBuffer)
	}
	if syncthing != 1146 {
		t.Errorf("syncthing = %d, want 1146", syncthing)
	}
	if brew != 97 {
		t.Errorf("brew = %d, want 97", brew)
	}
}
