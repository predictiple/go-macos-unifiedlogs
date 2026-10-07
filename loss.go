// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

// FirehoseLoss holds a loss Firehose log entry.
type FirehoseLoss struct {
	StartTime uint64 `json:"start_time"`
	EndTime   uint64 `json:"end_time"`
	Count     uint64 `json:"count"`
}

// parseFirehoseLoss parses a loss Firehose log entry.
// Ex: tp 16 + 48: loss
func parseFirehoseLoss(data []byte) ([]byte, FirehoseLoss, error) {
	var firehoseLoss FirehoseLoss

	c := newCursor(data)
	firehoseStartTime, err := c.u64()
	if err != nil {
		return nil, firehoseLoss, err
	}
	firehoseEndTime, err := c.u64()
	if err != nil {
		return nil, firehoseLoss, err
	}
	firehoseCount, err := c.u64()
	if err != nil {
		return nil, firehoseLoss, err
	}

	firehoseLoss.StartTime = firehoseStartTime
	firehoseLoss.EndTime = firehoseEndTime
	firehoseLoss.Count = firehoseCount

	return c.rest(), firehoseLoss, nil
}
