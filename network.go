// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

import (
	"encoding/binary"
	"fmt"
	"net"
)

// ipvSix parses an IPv6 address.
func ipvSix(input string) (net.IP, error) {
	decodedData, err := decodeStandard(input)
	if err != nil {
		return nil, &DecoderError{
			Input:      []byte(input),
			ParserName: "ipv vix",
			Message:    "Failed to base64 decode ipv6 data",
		}
	}

	_, result, err := getIPSix(decodedData)
	if err != nil {
		return nil, &DecoderError{
			Input:      []byte(input),
			ParserName: "ipv vix",
			Message:    "Failed to get ipv6",
		}
	}

	return result, nil
}

// ipvFour parses an IPv4 address.
func ipvFour(input string) (net.IP, error) {
	decodedData, err := decodeStandard(input)
	if err != nil {
		return nil, &DecoderError{
			Input:      []byte(input),
			ParserName: "ipv four",
			Message:    "Failed to base64 decode ipv4 data",
		}
	}

	_, result, err := getIPFour(decodedData)
	if err != nil {
		return nil, &DecoderError{
			Input:      []byte(input),
			ParserName: "ipv four",
			Message:    "Failed to get ipv4",
		}
	}

	return result, nil
}

// sockaddr parses a sockaddr structure.
func sockaddr(input string) (string, error) {
	if input == "" {
		return "<NULL>", nil
	}

	decodedData, err := decodeStandard(input)
	if err != nil {
		return "", &DecoderError{
			Input:      []byte(input),
			ParserName: "sock addr",
			Message:    "Failed to bas64 decode sockaddr data",
		}
	}

	_, result, err := getSockaddrData(decodedData)
	if err != nil {
		return "", &DecoderError{
			Input:      []byte(input),
			ParserName: "ipv four",
			Message:    "Failed to get sockaddr structure",
		}
	}

	return result, nil
}

// getSockaddrData gets the sockaddr data.
func getSockaddrData(input []byte) ([]byte, string, error) {
	if len(input) < 2 {
		return nil, "", ErrEof
	}
	family := input[1]
	rest := input[2:]

	// Family types seen so far (AF_INET should be used most often)
	switch family {
	case 2:
		// AF_INET
		if len(rest) < 2 {
			return nil, "", ErrEof
		}
		port := binary.BigEndian.Uint16(rest)
		rest = rest[2:]

		remaining, ipAddr, err := getIPFour(rest)
		if err != nil {
			return nil, "", err
		}

		if port == 0 {
			return remaining, ipAddr.String(), nil
		}
		return remaining, fmt.Sprintf("%s:%d", ipAddr.String(), port), nil
	case 30:
		if len(rest) < 22 {
			return nil, "", ErrEof
		}
		port := binary.BigEndian.Uint16(rest)
		flow := binary.BigEndian.Uint32(rest[2:6])
		ipAddr := net.IP(append([]byte{}, rest[6:22]...))
		scope := binary.BigEndian.Uint32(rest[22:26])

		if port == 0 {
			return rest[26:], fmt.Sprintf("%s, Flow ID: %d, Scope ID: %d", ipAddr.String(), flow, scope), nil
		}
		return rest[26:], fmt.Sprintf("%s:%d, Flow ID: %d, Scope ID: %d", ipAddr.String(), port, flow, scope), nil
	default:
		logger.Printf("[macos-unifiedlogs] Unknown sockaddr family: %d. From: %v", family, rest)
		return rest, fmt.Sprintf("Unknown sockaddr family: %d", family), nil
	}
}

// getIPFour gets the IPv4 data (big-endian u32).
func getIPFour(input []byte) ([]byte, net.IP, error) {
	if len(input) < 4 {
		return nil, nil, ErrEof
	}
	value := binary.BigEndian.Uint32(input)
	ip := net.IPv4(byte(value>>24), byte(value>>16), byte(value>>8), byte(value)).To4()
	return input[4:], ip, nil
}

// getIPSix gets the IPv6 data (big-endian u128).
func getIPSix(input []byte) ([]byte, net.IP, error) {
	if len(input) < 16 {
		return nil, nil, ErrEof
	}
	ip := make(net.IP, 16)
	copy(ip, input[:16])
	return input[16:], ip, nil
}
