// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

import (
	"io"
	"path/filepath"
)

// ParseLog parses a tracev3 file and returns the deconstructed log data.
func ParseLog(reader io.Reader, evidence string) (*UnifiedLogData, error) {
	buf, err := io.ReadAll(reader)
	if err != nil {
		logger.Printf("[macos-unifiedlogs] Failed to read the tracev3 file: %v", err)
		return nil, ErrRead
	}
	logger.Printf("Read %d bytes from tracev3 file", len(buf))

	_, logData, err := parseUnifiedLog(buf, evidence)
	if err != nil {
		logger.Printf("[macos-unifiedlogs] Failed to parse the tracev3 file: %v", err)
		return nil, ErrTracev3Parse
	}
	return logData, nil
}

// CollectStrings parses all UUID files provided by the provider. The files should follow the
// same layout as the live system (ex: path/to/files/<two character UUID>/<remaining UUID name>).
func CollectStrings(provider FileProvider) ([]*UUIDText, error) {
	var uuidtextVec []*UUIDText

	for _, source := range provider.UUIDTextFiles() {
		buf, err := readSource(source)
		if err != nil {
			logger.Printf("[macos-unifiedlogs] Failed to read uuidfile %s: %v", source.SourcePath(), err)
			continue
		}

		logger.Printf("Read %d bytes for file %s", len(buf), source.SourcePath())

		uuidtextData, err := parseUUIDText(buf)
		if err != nil {
			logger.Printf("[macos-unifiedlogs] Failed to parse UUID file %s: %v", source.SourcePath(), err)
			continue
		}

		uuidtextData.UUID = filepath.Base(source.SourcePath())
		uuidtextVec = append(uuidtextVec, uuidtextData)
	}

	return uuidtextVec, nil
}

// CollectSharedStrings parses all dsc uuid files provided by the provider.
func CollectSharedStrings(provider FileProvider) ([]*SharedCacheStrings, error) {
	var sharedStringsVec []*SharedCacheStrings

	for _, source := range provider.DSCFiles() {
		buf, err := readSource(source)
		if err != nil {
			logger.Printf("[macos-unifiedlogs] Failed to read dsc file: %v", err)
			continue
		}

		results, err := parseDSC(buf)
		if err != nil {
			logger.Printf("[macos-unifiedlogs] Failed to parse dsc file: %v", err)
			continue
		}

		results.DSCUUID = filepath.Base(source.SourcePath())
		sharedStringsVec = append(sharedStringsVec, results)
	}

	return sharedStringsVec, nil
}

// CollectTimesync parses all timesync files provided by the provider.
func CollectTimesync(provider FileProvider) (map[string]*TimesyncBoot, error) {
	timesyncData := make(map[string]*TimesyncBoot)

	for _, source := range provider.TimesyncFiles() {
		buffer, err := readSource(source)
		if err != nil {
			logger.Printf("[macos-unifiedlogs] Failed to read timesync file: %v", err)
			continue
		}

		timesyncMap, err := parseTimesyncData(buffer)
		if err != nil {
			logger.Printf("[macos-unifiedlogs] Failed to parse timesync file: %v", err)
			continue
		}

		// If a macOS system has been online for a long time, macOS will create a new
		// timesync file with the same boot UUID. So we check if we already have an
		// existing UUID and if we do, we just add the data to the existing data we have.
		for key, value := range timesyncMap {
			if existingBoot, ok := timesyncData[key]; ok {
				existingBoot.Timesync = append(existingBoot.Timesync, value.Timesync...)
				continue
			}
			timesyncData[key] = value
		}
	}

	return timesyncData, nil
}
