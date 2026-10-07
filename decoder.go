// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

import (
	"fmt"
	"strings"
)

// DecoderError mirrors the Rust `DecoderError::Parse` variant used by the
// custom decoder objects. Display()/Error() return the message; Debug() returns
// the detailed parser failure used by decoder.go when logging decode errors.
type DecoderError struct {
	Input      []byte
	ParserName string
	Message    string
}

// Error implements the error interface (mirrors Rust's Display).
func (e *DecoderError) Error() string {
	return e.Message
}

// String mirrors Rust's Display implementation.
func (e *DecoderError) String() string {
	return e.Message
}

// Debug mirrors Rust's Debug implementation
// ("Failed at {parser_name} parser, data {input:?}: {message}").
func (e *DecoderError) Debug() string {
	return fmt.Sprintf("Failed at %s parser, data %v: %s", e.ParserName, e.Input, e.Message)
}

// checkObjects checks if a log value contains one of the supported decoders and
// decodes it to a string.
func checkObjects(formatString string, messageValues []FirehoseItemType, itemType uint8, itemIndex int) string {
	index := itemIndex
	const precisionItem uint8 = 0x12

	// Increment index to get the actual firehose item data
	if itemType == precisionItem {
		index++
		if index >= len(messageValues) {
			return fmt.Sprintf("Index out of bounds for FirehoseItemInfo Vec. Got adjusted index %d, Vec size is %d. This should not have happened", index, len(messageValues))
		}
	}

	const maskedHashType uint8 = 0xf2
	// Check if the log value is hashed or marked private
	if (strings.Contains(formatString, "mask.hash") && messageValues[index].ItemType == maskedHashType) ||
		messageValues[index].MessageStrings == "<private>" {
		return messageValues[index].MessageStrings
	}

	// Check if log value contains one of the supported decoders
	messageString := messageValues[index].MessageStrings

	switch {
	case strings.Contains(formatString, "BOOL"):
		return uppercaseBool(messageString)
	case strings.Contains(formatString, "bool"):
		return lowercaseBool(messageString)
	case strings.Contains(formatString, "uuid_t"):
		return decodeOrLog(parseUUID(messageString))
	case strings.Contains(formatString, "darwin.errno"):
		return errnoCodes(messageString)
	case strings.Contains(formatString, "mach.errno"):
		return machCodes(messageString)
	case strings.Contains(formatString, "%{errno"):
		return errnoCodes(messageString)
	case strings.Contains(formatString, "darwin.mode"):
		return permission(messageString)
	case strings.Contains(formatString, "odtypes:ODError"):
		return openDirectoryErrors(messageString)
	case strings.Contains(formatString, "odtypes:mbridtype"):
		return memberIDType(messageString)
	case strings.Contains(formatString, "odtypes:mbr_details"):
		return decodeOrLog(memberDetails(messageString))
	case strings.Contains(formatString, "odtypes:nt_sid_t"):
		return decodeOrLog(sidDetails(messageString))
	case strings.Contains(formatString, "location:CLClientAuthorizationStatus"):
		return decodeOrLog(clientAuthorizationStatus(messageString))
	case strings.Contains(formatString, "location:CLDaemonStatus_Type::Reachability"):
		return decodeOrLog(daemonStatusType(messageString))
	case strings.Contains(formatString, "location:CLSubHarvesterIdentifier"):
		return decodeOrLog(subharvesterIdentifier(messageString))
	case strings.Contains(formatString, "location:SqliteResult"):
		return decodeOrLog(sqliteLocation(messageString))
	case strings.Contains(formatString, "location:_CLClientManagerStateTrackerState"):
		return decodeOrLog(clientManagerStateTrackerState(messageString))
	case strings.Contains(formatString, "location:_CLLocationManagerStateTrackerState"):
		return decodeOrLog(locationManagerStateTrackerState(messageString))
	case strings.Contains(formatString, "network:in6_addr"):
		return decodeIPOrLog(ipvSix(messageString))
	case strings.Contains(formatString, "network:in_addr"):
		return decodeIPOrLog(ipvFour(messageString))
	case strings.Contains(formatString, "network:sockaddr"):
		return decodeOrLog(sockaddr(messageString))
	case strings.Contains(formatString, "time_t"):
		return decodeOrLog(parseTime(messageString))
	case strings.Contains(formatString, "mdns:dnshdr"):
		return decodeOrLog(parseDnsHeader(messageString))
	case strings.Contains(formatString, "mdns:rd.svcb"):
		return decodeOrLog(getServiceBinding(messageString))
	case strings.Contains(formatString, "location:IOMessage"):
		return decodeOrLog(ioMessage(messageString))
	case strings.Contains(formatString, "mdnsresponder:domain_name"):
		return decodeOrLog(getDomainName(messageString))
	case strings.Contains(formatString, "mdnsresponder:mac_addr"):
		return decodeOrLog(getDnsMacAddr(messageString))
	case strings.Contains(formatString, "mdnsresponder:ip_addr"):
		return decodeOrLog(dnsIPAddr(messageString))
	case strings.Contains(formatString, "mdns:addrmv"):
		return dnsAddRmv(messageString)
	case strings.Contains(formatString, "mdns:rrtype"):
		return decodeOrLog(dnsRecords(messageString))
	case strings.Contains(formatString, "mdns:nreason"):
		return decodeOrLog(dnsReason(messageString))
	case strings.Contains(formatString, "mdns:protocol"):
		return decodeOrLog(dnsProtocol(messageString))
	case strings.Contains(formatString, "mdns:dns.idflags"):
		return decodeOrLog(dnsIDFlags(messageString))
	case strings.Contains(formatString, "mdns:dns.counts"):
		return decodeCountsOrLog(dnsCounts(messageString))
	case strings.Contains(formatString, "mdns:yesno"):
		return dnsYesNo(messageString)
	case strings.Contains(formatString, "mdns:acceptable"):
		return dnsAcceptable(messageString)
	case strings.Contains(formatString, "mdns:gaiopts"):
		return decodeOrLog(dnsGetaddrinfoOpts(messageString))
	}
	return ""
}

// decodeOrLog returns the decoded value, or logs the error and returns its
// message (mirrors the Rust `Err(e) => { log::error!(...); e.to_string() }`).
func decodeOrLog(value string, err error) string {
	if err != nil {
		logger.Printf("[macos-unifiedlogs] Failed to decode log object. Error: %v", err)
		return err.Error()
	}
	return value
}

// decodeIPOrLog is like decodeOrLog but formats a net.IP result.
func decodeIPOrLog(value interface{ String() string }, err error) string {
	if err != nil {
		logger.Printf("[macos-unifiedlogs] Failed to decode log object. Error: %v", err)
		return err.Error()
	}
	return value.String()
}

// decodeCountsOrLog is like decodeOrLog but formats a DnsCounts result.
func decodeCountsOrLog(value DnsCounts, err error) string {
	if err != nil {
		logger.Printf("[macos-unifiedlogs] Failed to decode log object. Error: %v", err)
		return err.Error()
	}
	return value.String()
}
