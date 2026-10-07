// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

import (
	"fmt"
	"math/big"
)

// SimpleDump is a Simpledump log entry.
// Introduced in macOS Monterey (12).  Appears to be a "simpler" version of Statedump?
// So far appears to just contain a single string.
type SimpleDump struct {
	ChunkTag                    uint32 `json:"chunk_tag"`
	ChunkSubtag                 uint32 `json:"chunk_subtag"`
	ChunkDataSize               uint64 `json:"chunk_data_size"`
	FirstProcID                 uint64 `json:"first_proc_id"`
	SecondProcID                uint64 `json:"second_proc_id"`
	ContinousTime               uint64 `json:"continous_time"`
	ThreadID                    uint64 `json:"thread_id"`
	UnknownOffset               uint32 `json:"unknown_offset"`
	UnknownTTL                  uint16 `json:"unknown_ttl"`
	UnknownType                 uint16 `json:"unknown_type"`
	SenderUUID                  string `json:"sender_uuid"`
	DscUUID                     string `json:"dsc_uuid"`
	UnknownNumberMessageStrings uint32 `json:"unknown_number_message_strings"`
	UnknownSizeSubsystemString  uint32 `json:"unknown_size_subsystem_string"`
	UnknownSizeMessageString    uint32 `json:"unknown_size_message_string"`
	Subsystem                   string `json:"subsystem"`
	MessageString               string `json:"message_string"`
}

func parseSimpledump(data []byte) ([]byte, SimpleDump, error) {
	var simpledump SimpleDump

	c := newCursor(data)
	simpledumpChunkTag, err := c.u32()
	if err != nil {
		return nil, simpledump, err
	}
	simpledumpChunkSubTag, err := c.u32()
	if err != nil {
		return nil, simpledump, err
	}
	simpledumpChunkDataSize, err := c.u64()
	if err != nil {
		return nil, simpledump, err
	}
	simpledumpFirstProcID, err := c.u64()
	if err != nil {
		return nil, simpledump, err
	}
	simpledumpSecondProcID, err := c.u64()
	if err != nil {
		return nil, simpledump, err
	}
	simpledumpContinousTime, err := c.u64()
	if err != nil {
		return nil, simpledump, err
	}
	simpledumpThreadID, err := c.u64()
	if err != nil {
		return nil, simpledump, err
	}
	simpledumpUnknownOffset, err := c.u32()
	if err != nil {
		return nil, simpledump, err
	}
	simpledumpUnknownTTL, err := c.u16()
	if err != nil {
		return nil, simpledump, err
	}
	simpledumpUnknownType, err := c.u16()
	if err != nil {
		return nil, simpledump, err
	}
	senderUUID, err := c.u128be()
	if err != nil {
		return nil, simpledump, err
	}
	dscUUID, err := c.u128be()
	if err != nil {
		return nil, simpledump, err
	}
	simpledumpUnknownNumberMessageStrings, err := c.u32()
	if err != nil {
		return nil, simpledump, err
	}
	simpledumpUnknownSizeSubsystemString, err := c.u32()
	if err != nil {
		return nil, simpledump, err
	}
	simpledumpUnknownSizeMessageString, err := c.u32()
	if err != nil {
		return nil, simpledump, err
	}

	simpledump.ChunkTag = simpledumpChunkTag
	simpledump.ChunkSubtag = simpledumpChunkSubTag
	simpledump.ChunkDataSize = simpledumpChunkDataSize
	simpledump.ContinousTime = simpledumpContinousTime
	simpledump.FirstProcID = simpledumpFirstProcID
	simpledump.SecondProcID = simpledumpSecondProcID
	simpledump.ThreadID = simpledumpThreadID
	simpledump.UnknownOffset = simpledumpUnknownOffset
	simpledump.UnknownTTL = simpledumpUnknownTTL
	simpledump.UnknownType = simpledumpUnknownType

	simpledump.SenderUUID = fmt.Sprintf("%032X", new(big.Int).SetBytes(senderUUID[:]))
	simpledump.DscUUID = fmt.Sprintf("%032X", new(big.Int).SetBytes(dscUUID[:]))
	simpledump.UnknownNumberMessageStrings = simpledumpUnknownNumberMessageStrings
	simpledump.UnknownSizeSubsystemString = simpledumpUnknownSizeSubsystemString
	simpledump.UnknownSizeMessageString = simpledumpUnknownSizeMessageString

	subsystemString, err := c.take(int(simpledumpUnknownSizeSubsystemString))
	if err != nil {
		return nil, simpledump, err
	}
	messageString, err := c.take(int(simpledumpUnknownSizeMessageString))
	if err != nil {
		return nil, simpledump, err
	}

	if len(subsystemString) > 0 {
		_, subsystem, err := extractString(subsystemString)
		if err != nil {
			return nil, simpledump, err
		}
		simpledump.Subsystem = subsystem
	}
	if len(messageString) > 0 {
		_, message, err := extractString(messageString)
		if err != nil {
			return nil, simpledump, err
		}
		simpledump.MessageString = message
	}

	return c.rest(), simpledump, nil
}
