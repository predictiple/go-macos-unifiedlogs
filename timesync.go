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

// TimesyncBoot contains the timesync boot data associated with the Unified Log.
type TimesyncBoot struct {
	Signature           uint16     `json:"signature"`
	HeaderSize          uint16     `json:"header_size"`
	Unknown             uint32     `json:"unknown"`
	BootUUID            string     `json:"boot_uuid"`
	TimebaseNumerator   uint32     `json:"timebase_numerator"`
	TimebaseDenominator uint32     `json:"timebase_denominator"`
	BootTime            int64      `json:"boot_time"` // Number of nanoseconds since UNIXEPOCH
	TimezoneOffsetMins  uint32     `json:"timezone_offset_mins"`
	DaylightSavings     uint32     `json:"daylight_savings"` // 0 is no DST, 1 is DST
	Timesync            []Timesync `json:"timesync"`
}

// Timesync contains an individual timesync record. Timestamps are in UTC.
type Timesync struct {
	Signature       uint32 `json:"signature"`
	Flags           uint32 `json:"flags"`
	KernelTime      uint64 `json:"kernel_time"` // Mach continuous timestamp
	Walltime        int64  `json:"walltime"`    // Number of nanoseconds since UNIXEPOCH
	Timezone        uint32 `json:"timezone"`
	DaylightSavings uint32 `json:"daylight_savings"` // 0 is no DST, 1 is DST
}

// parseTimesyncData parses the Unified Log timesync files.
func parseTimesyncData(data []byte) (map[string]*TimesyncBoot, error) {
	timesyncData := make(map[string]*TimesyncBoot)
	c := newCursor(data)

	timesyncBoot := &TimesyncBoot{}

	for !c.isEmpty() {
		timesyncSignature, err := c.peekU32()
		if err != nil {
			return nil, err
		}

		const timesyncSig uint32 = 0x207354
		if timesyncSignature == timesyncSig {
			timesync, err := parseTimesync(c)
			if err != nil {
				return nil, err
			}
			timesyncBoot.Timesync = append(timesyncBoot.Timesync, timesync)
		} else {
			if timesyncBoot.Signature != 0 {
				if existingBoot, ok := timesyncData[timesyncBoot.BootUUID]; ok {
					existingBoot.Timesync = append(existingBoot.Timesync, timesyncBoot.Timesync...)
				} else {
					timesyncData[timesyncBoot.BootUUID] = timesyncBoot
				}
			}
			timesyncBootData, err := parseTimesyncBoot(c)
			if err != nil {
				return nil, err
			}
			timesyncBoot = timesyncBootData
		}
	}
	if existingBoot, ok := timesyncData[timesyncBoot.BootUUID]; ok {
		existingBoot.Timesync = append(existingBoot.Timesync, timesyncBoot.Timesync...)
	} else {
		timesyncData[timesyncBoot.BootUUID] = timesyncBoot
	}
	return timesyncData, nil
}

// parseTimesyncBoot parses a timesync boot header record.
func parseTimesyncBoot(c *cursor) (*TimesyncBoot, error) {
	timesyncSignature, err := c.u16()
	if err != nil {
		return nil, err
	}

	const expectedBootSignature uint16 = 0xbbb0
	if expectedBootSignature != timesyncSignature {
		logger.Printf("[macos-unifiedlogs] Incorrect Timesync boot header signature. Expected %d. Got: %d",
			expectedBootSignature, timesyncSignature)
		return nil, fmt.Errorf("incorrect timesync boot header signature: %w", ErrIncomplete)
	}

	timesyncHeaderSize, err := c.u16()
	if err != nil {
		return nil, err
	}
	timesyncUnknown, err := c.u32()
	if err != nil {
		return nil, err
	}
	timesyncBootUUID, err := c.u128be()
	if err != nil {
		return nil, err
	}
	timesyncTimebaseNumerator, err := c.u32()
	if err != nil {
		return nil, err
	}
	timesyncTimebaseDenominator, err := c.u32()
	if err != nil {
		return nil, err
	}
	timesyncBootTime, err := c.i64()
	if err != nil {
		return nil, err
	}
	timesyncTimezoneOffsetMins, err := c.u32()
	if err != nil {
		return nil, err
	}
	timesyncDaylightSavings, err := c.u32()
	if err != nil {
		return nil, err
	}

	return &TimesyncBoot{
		Signature:           timesyncSignature,
		HeaderSize:          timesyncHeaderSize,
		Unknown:             timesyncUnknown,
		BootUUID:            u128Hex(timesyncBootUUID),
		TimebaseNumerator:   timesyncTimebaseNumerator,
		TimebaseDenominator: timesyncTimebaseDenominator,
		BootTime:            timesyncBootTime,
		TimezoneOffsetMins:  timesyncTimezoneOffsetMins,
		DaylightSavings:     timesyncDaylightSavings,
	}, nil
}

// parseTimesync parses an individual timesync record.
func parseTimesync(c *cursor) (Timesync, error) {
	timesync := Timesync{}

	timesyncSignature, err := c.u32()
	if err != nil {
		return Timesync{}, err
	}

	const expectedRecordSignature uint32 = 0x207354
	if expectedRecordSignature != timesyncSignature {
		logger.Printf("[macos-unifiedlogs] Incorrect Timesync record header signature. Expected %d. Got: %d",
			expectedRecordSignature, timesyncSignature)
		return Timesync{}, fmt.Errorf("incorrect timesync record header signature: %w", ErrIncomplete)
	}

	timesyncFlags, err := c.u32()
	if err != nil {
		return Timesync{}, err
	}
	timesyncKernelTime, err := c.u64()
	if err != nil {
		return Timesync{}, err
	}
	timesyncWalltime, err := c.i64()
	if err != nil {
		return Timesync{}, err
	}
	timesyncTimezone, err := c.u32()
	if err != nil {
		return Timesync{}, err
	}
	timesyncDaylightSavings, err := c.u32()
	if err != nil {
		return Timesync{}, err
	}

	timesync.Signature = timesyncSignature
	timesync.Flags = timesyncFlags
	timesync.KernelTime = timesyncKernelTime
	timesync.Walltime = timesyncWalltime
	timesync.Timezone = timesyncTimezone
	timesync.DaylightSavings = timesyncDaylightSavings

	return timesync, nil
}

// getTimestamp calculates the timestamp for a firehose log entry.
//
// Timestamp calculation logic:
// Firehose Log entry timestamp is calculated by using firehosePreambleTime,
// firehose.continous_time_delta, and timesync timestamps.
// Firehose log header/preamble contains a base timestamp. All log entries
// following the header are continuous from that base. EXCEPT when the base time
// is zero. If the base time is zero the TimeSync boot record boot time is used.
//
// Get all timesync boot records if timesync uuid equals boot uuid in tracev3
// header data. Loop through all timesync records from matching boot uuid until
// timesync cont_time/kernel time is greater than firehosePreambleTime.
// Subtract timesync_cont_time/kernel time from firehose_log_delta_time.
// If APPLE SILICON (ARM) is the architecture, then we need to multiply
// timesync_cont_time and firehose_log_delta_time by the timebase 125.0/3.0 to
// get the nanosecond representation.
//
// Add results to timesync_walltime (unix epoch in nanoseconds).
// Final results is unix epoch timestamp in nanoseconds.
func getTimestamp(timesyncData map[string]*TimesyncBoot, bootUUID string, firehoseLogDeltaTime, firehosePreambleTime uint64) float64 {
	var timesyncContinousTime uint64
	var timesyncWalltime int64

	// Apple Intel uses 1/1 as the timebase
	timebaseAdjustment := 1.0
	if timesync, ok := timesyncData[bootUUID]; ok {
		if timesync.TimebaseNumerator == 125 && timesync.TimebaseDenominator == 3 {
			// For Apple Silicon (ARM) we need to adjust the mach time by
			// multiplying by 125.0/3.0 to get the accurate nanosecond count
			timebaseAdjustment = 125.0 / 3.0
		}

		// A preamble time of 0 means we need to use the timesync header boot
		// time as our minimum value. We also set the timesync_continous_time to zero.
		if firehosePreambleTime == 0 {
			timesyncContinousTime = 0
			timesyncWalltime = timesync.BootTime
		}
		for _, timesyncRecord := range timesync.Timesync {
			if timesyncRecord.KernelTime > firehoseLogDeltaTime {
				if timesyncContinousTime == 0 && timesyncWalltime == 0 {
					timesyncContinousTime = timesyncRecord.KernelTime
					timesyncWalltime = timesyncRecord.Walltime
				}
				break
			}

			timesyncContinousTime = timesyncRecord.KernelTime
			timesyncWalltime = timesyncRecord.Walltime
		}
	}

	// Equivalent to Rust's (firehose_log_delta_time as f64).mul_add(
	// timebase_adjustment, -(timesync_continous_time as f64) * timebase_adjustment)
	continousTime := math.FMA(float64(firehoseLogDeltaTime), timebaseAdjustment, -float64(timesyncContinousTime)*timebaseAdjustment)
	return continousTime + float64(timesyncWalltime)
}
