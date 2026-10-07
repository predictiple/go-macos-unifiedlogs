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
	"strconv"
	"unicode"
)

// DnsCounts is the DNS header counts.
type DnsCounts struct {
	Question   uint16 `json:"question"`
	Answer     uint16 `json:"answer"`
	Authority  uint16 `json:"authority"`
	Additional uint16 `json:"additional"`
}

// String mirrors the Rust Display implementation for DnsCounts.
func (d DnsCounts) String() string {
	return fmt.Sprintf("Question Count: %d, Answer Record Count: %d, Authority Record Count: %d, Additional Record Count: %d",
		d.Question, d.Answer, d.Authority, d.Additional)
}

// parseDnsHeader parses the DNS header.
func parseDnsHeader(data string) (string, error) {
	decodedData, err := decodeStandard(data)
	if err != nil {
		return "", &DecoderError{
			Input:      []byte(data),
			ParserName: "dns header",
			Message:    "Failed to base64 decode DNS header details",
		}
	}

	_, message, err := getDnsHeader(decodedData)
	if err != nil {
		return "", &DecoderError{
			Input:      []byte(data),
			ParserName: "dns header",
			Message:    "Failed to parse DNS header details",
		}
	}
	return message, nil
}

// getDnsHeader gets the DNS header data.
func getDnsHeader(data []byte) ([]byte, string, error) {
	c := newCursor(data)

	idData, err := c.take(2)
	if err != nil {
		return nil, "", err
	}
	id := binary.BigEndian.Uint16(idData)

	flagData, err := c.take(2)
	if err != nil {
		return nil, "", err
	}
	message := getDnsFlags(flagData)
	flags := binary.BigEndian.Uint16(flagData)

	_, countMessage, err := parseCounts(c.rest())
	if err != nil {
		return nil, "", err
	}
	c.skip(8)

	headerMessage := fmt.Sprintf("Query ID: 0x%X, Flags: 0x%X %s, %s", id, flags, message, countMessage)
	return c.rest(), headerMessage, nil
}

// getDnsFlags parses the DNS bit flags. The input must be two bytes.
func getDnsFlags(data []byte) string {
	const QR = 1
	const OPCODE = 4
	const AA = 1
	const TC = 1
	const RD = 1
	const RA = 1
	const Z = 3
	const RCODE = 4
	_ = QR
	_ = Z

	value := binary.BigEndian.Uint16(data)
	query := (value >> 15) & 0x1
	opcode := (value >> 11) & 0xF
	authoritativeFlag := (value >> 10) & 0x1
	truncationFlag := (value >> 9) & 0x1
	recursionDesired := (value >> 8) & 0x1
	recursionAvailable := (value >> 7) & 0x1
	responseCode := value & 0xF

	opcodeMessage := ""
	switch opcode {
	case 0:
		opcodeMessage = "QUERY"
	case 1:
		opcodeMessage = "IQUERY"
	case 2:
		opcodeMessage = "STATUS"
	case 3:
		opcodeMessage = "RESERVED"
	case 4:
		opcodeMessage = "NOTIFY"
	case 5:
		opcodeMessage = "UPDATE"
	default:
		opcodeMessage = "UNKNOWN OPCODE"
	}

	responseMessage := ""
	switch responseCode {
	case 0:
		responseMessage = "No Error"
	case 1:
		responseMessage = "Format Error"
	case 2:
		responseMessage = "Server Failure"
	case 3:
		responseMessage = "NX Domain"
	case 4:
		responseMessage = "Not Implemented"
	case 5:
		responseMessage = "Refused"
	case 6:
		responseMessage = "YX Domain"
	case 7:
		responseMessage = "YX RR Set"
	case 8:
		responseMessage = "NX RR Set"
	case 9:
		responseMessage = "Not Auth"
	case 10:
		responseMessage = "Not Zone"
	default:
		responseMessage = "Unknown Response Code"
	}

	return fmt.Sprintf("Opcode: %s, \n    Query Type: %d,\n    Authoritative Answer Flag: %d, \n    Truncation Flag: %d, \n    Recursion Desired: %d, \n    Recursion Available: %d, \n    Response Code: %s",
		opcodeMessage, query, authoritativeFlag, truncationFlag, recursionDesired, recursionAvailable, responseMessage)
}

// getDomainName base64 decodes the domain name associated with a log entry.
func getDomainName(data string) (string, error) {
	decodedData, err := decodeStandard(data)
	if err != nil {
		return "", &DecoderError{
			Input:      []byte(data),
			ParserName: "dns domain name",
			Message:    "Failed to base64 decode DNS name details",
		}
	}

	_, results, err := extractString(decodedData)
	if err != nil {
		return "", &DecoderError{
			Input:      []byte(data),
			ParserName: "dns domain name",
			Message:    "Failed to extract domain name from logs",
		}
	}

	cleanDomain := ""
	for _, char := range results {
		if char == '\n' || char == '\t' || char == '\r' || !unicode.IsPrint(char) {
			cleanDomain += "."
			continue
		}
		cleanDomain += string(char)
	}
	return cleanDomain, nil
}

// getServiceBinding parses a DNS Service Binding record type.
func getServiceBinding(data string) (string, error) {
	decodedData, err := decodeStandard(data)
	if err != nil {
		return "", &DecoderError{
			Input:      []byte(data),
			ParserName: "dns service binding",
			Message:    "Failed to base64 decode DNS svcb details",
		}
	}

	_, result, err := parseSvcb(decodedData)
	if err != nil {
		return "", &DecoderError{
			Input:      []byte(data),
			ParserName: "dns service binding",
			Message:    "Failed to parse DNS Service Binding data",
		}
	}
	return result, nil
}

// parseSvcb parses a DNS SVC Binding record.
// Format: https://datatracker.ietf.org/doc/draft-ietf-dnsop-svcb-https/00/
func parseSvcb(data []byte) ([]byte, string, error) {
	c := newCursor(data)

	idData, err := c.take(2)
	if err != nil {
		return nil, "", err
	}
	id := binary.BigEndian.Uint16(idData)

	unknownTypeData, err := c.take(4)
	if err != nil {
		return nil, "", err
	}
	unknownType := binary.BigEndian.Uint32(unknownTypeData)

	const dnsOverHTTPS = 0x800000
	if unknownType == dnsOverHTTPS {
		urlSize, err := c.u8()
		if err != nil {
			return nil, "", err
		}
		return extractStringSize(c.rest(), uint64(urlSize))
	}

	alpnSize, err := c.u8()
	if err != nil {
		return nil, "", err
	}
	alpnData, err := c.take(int(alpnSize))
	if err != nil {
		return nil, "", err
	}
	_, alpnMessage, err := parseSvcbAlpn(alpnData)
	if err != nil {
		return nil, "", err
	}

	_, ipMessage, err := parseSvcbIp(c.rest())
	if err != nil {
		return nil, "", err
	}

	message := fmt.Sprintf("rdata: %d . %s %s", id, alpnMessage, ipMessage)
	return c.rest(), message, nil
}

// parseSvcbAlpn parses the Application Layer Protocol Negotiation.
func parseSvcbAlpn(data []byte) ([]byte, string, error) {
	c := newCursor(data)
	message := "alpn="
	for !c.isEmpty() {
		alpnEntrySize, err := c.u8()
		if err != nil {
			return nil, "", err
		}
		alpnEntry, err := c.take(int(alpnEntrySize))
		if err != nil {
			return nil, "", err
		}
		_, alpnName, err := extractString(alpnEntry)
		if err != nil {
			return nil, "", err
		}
		message += alpnName
		message += ","
	}
	return c.rest(), message, nil
}

// parseSvcbIp parses the IPs.
func parseSvcbIp(data []byte) ([]byte, string, error) {
	const ipv4 uint16 = 4
	const ipv6 uint16 = 6

	c := newCursor(data)
	ipv4s := ""
	ipv6s := ""

	// IPs can either be IPv4 or/and IPv6
	for !c.isEmpty() {
		versionData, err := c.take(2)
		if err != nil {
			return nil, "", err
		}
		ipVersion := binary.BigEndian.Uint16(versionData)
		if ipVersion != ipv4 && ipVersion != ipv6 {
			return nil, "", fmt.Errorf("invalid ip version: %w", ErrFail)
		}

		sizeData, err := c.take(2)
		if err != nil {
			return nil, "", err
		}
		ipSize := binary.BigEndian.Uint16(sizeData)

		ipData, err := c.take(int(ipSize))
		if err != nil {
			return nil, "", err
		}

		ipCursor := newCursor(ipData)
		if ipVersion == ipv4 {
			for !ipCursor.isEmpty() {
				raw, err := ipCursor.take(4)
				if err != nil {
					return nil, "", err
				}
				if ipv4s != "" {
					ipv4s += ","
				}
				ipv4s += net.IP(raw).String()
			}
		} else {
			for !ipCursor.isEmpty() {
				raw, err := ipCursor.take(16)
				if err != nil {
					return nil, "", err
				}
				if ipv6s != "" {
					ipv6s += ","
				}
				ipv6s += net.IP(raw).String()
			}
		}
	}

	message := fmt.Sprintf("ipv4 hint:%s, ipv6 hint:%s", ipv4s, ipv6s)
	return c.rest(), message, nil
}

// getDnsMacAddr gets the MAC Address from the log data.
func getDnsMacAddr(data string) (string, error) {
	decodedData, err := decodeStandard(data)
	if err != nil {
		return "", &DecoderError{
			Input:      []byte(data),
			ParserName: "dns mac address",
			Message:    "Failed to base64 decode DNS mac address details",
		}
	}

	_, messageResults, err := parseMacAddr(decodedData)
	if err != nil {
		return "", &DecoderError{
			Input:      []byte(data),
			ParserName: "dns mac address",
			Message:    "Failed to parse DNS mac address data",
		}
	}
	return messageResults, nil
}

// parseMacAddr parses the MAC Address.
func parseMacAddr(data []byte) ([]byte, string, error) {
	c := newCursor(data)
	message := ""
	for !c.isEmpty() {
		item, err := c.u8()
		if err != nil {
			return nil, "", err
		}
		if message != "" {
			message += ":"
		}
		message += fmt.Sprintf("%02X", item)
	}
	return c.rest(), message, nil
}

// dnsIPAddr gets IP Address info from log data.
func dnsIPAddr(data string) (string, error) {
	decodedData, err := decodeStandard(data)
	if err != nil {
		return "", &DecoderError{
			Input:      []byte(data),
			ParserName: "dns ip address",
			Message:    "Failed to base64 decode DNS ip address details",
		}
	}

	_, results, err := parseDnsIPAddr(decodedData)
	if err != nil {
		return "", &DecoderError{
			Input:      []byte(data),
			ParserName: "dns ip address",
			Message:    "Failed to parse DNS ip address data",
		}
	}
	return results, nil
}

// parseDnsIPAddr parses an IP Address object.
func parseDnsIPAddr(data []byte) ([]byte, string, error) {
	c := newCursor(data)
	ipVersion, err := c.u32()
	if err != nil {
		return nil, "", err
	}
	const ipv4 uint32 = 4
	const ipv6 uint32 = 6
	if ipVersion == ipv4 {
		remaining, result, err := getIPFour(c.rest())
		if err != nil {
			return nil, "", err
		}
		return remaining, result.String(), nil
	}
	if ipVersion == ipv6 {
		remaining, result, err := getIPSix(c.rest())
		if err != nil {
			return nil, "", err
		}
		return remaining, result.String(), nil
	}
	return nil, "", ErrFail
}

// dnsAddRmv translates DNS add/rmv log values.
func dnsAddRmv(data string) string {
	if data == "1" {
		return "add"
	}
	return "rmv"
}

// dnsRecords translates DNS records to a string.
func dnsRecords(data string) (string, error) {
	records := map[string]string{
		"1":     "A",
		"2":     "NS",
		"5":     "CNAME",
		"6":     "SOA",
		"10":    "NULL",
		"12":    "PTR",
		"13":    "HINFO",
		"15":    "MX",
		"16":    "TXT",
		"17":    "RP",
		"18":    "AFSDB",
		"24":    "SIG",
		"25":    "KEY",
		"28":    "AAAA",
		"29":    "LOC",
		"33":    "SRV",
		"35":    "NAPTR",
		"36":    "KX",
		"37":    "CERT",
		"39":    "DNAME",
		"42":    "APL",
		"43":    "DS",
		"44":    "SSHFP",
		"45":    "IPSECKEY",
		"46":    "RRSIG",
		"47":    "NSEC",
		"48":    "DNSKEY",
		"49":    "DHCID",
		"50":    "NSEC3",
		"51":    "NSEC3PARAM",
		"52":    "TLSA",
		"53":    "SMIMEA",
		"55":    "HIP",
		"59":    "CDS",
		"60":    "CDNSKEY",
		"61":    "OPENPGPKEY",
		"62":    "CSYNC",
		"63":    "ZONEMD",
		"64":    "SVCB",
		"65":    "HTTPS",
		"108":   "EUI48",
		"109":   "EUI64",
		"249":   "TKEY",
		"250":   "TSIG",
		"255":   "ANY",
		"256":   "URI",
		"257":   "CAA",
		"32768": "TA",
		"32769": "DLV",
	}

	message, ok := records[data]
	if !ok {
		return "", &DecoderError{
			Input:      []byte(data),
			ParserName: "dns records",
			Message:    "Unknown DNS Resource Record Type",
		}
	}
	return message, nil
}

// dnsReason translates a DNS reason to a string.
func dnsReason(data string) (string, error) {
	reasons := map[string]string{
		"1": "no-data",
		"4": "query-suppressed",
		"3": "no-dns-service",
		"2": "nxdomain",
		"5": "server error",
	}

	message, ok := reasons[data]
	if !ok {
		return "", &DecoderError{
			Input:      []byte(data),
			ParserName: "dns reason",
			Message:    "Unknown DNS Reason",
		}
	}
	return message, nil
}

// dnsProtocol translates the DNS protocol used to a string.
func dnsProtocol(data string) (string, error) {
	protocols := map[string]string{
		"1": "UDP",
		"2": "TCP",
		"4": "HTTPS",
	}

	message, ok := protocols[data]
	if !ok {
		return "", &DecoderError{
			Input:      []byte(data),
			ParserName: "dns protocol",
			Message:    "Unknown DNS Protocol",
		}
	}
	return message, nil
}

// dnsIDFlags gets just the DNS flags associated with the DNS header.
func dnsIDFlags(data string) (string, error) {
	flags, err := strconv.ParseUint(data, 10, 32)
	if err != nil {
		return "", &DecoderError{
			Input:      []byte(data),
			ParserName: "dns id flags",
			Message:    "Failed to convert ID Flags to int",
		}
	}

	bytes := make([]byte, 4)
	binary.BigEndian.PutUint32(bytes, uint32(flags))

	_, result, err := parseIDFlags(bytes)
	if err != nil {
		return "", &DecoderError{
			Input:      []byte(data),
			ParserName: "dns id flags",
			Message:    "Failed to get ID Flags",
		}
	}
	return result, nil
}

// parseIDFlags parses just the DNS flags associated with the DNS header.
func parseIDFlags(data []byte) ([]byte, string, error) {
	c := newCursor(data)
	idData, err := c.take(2)
	if err != nil {
		return nil, "", err
	}
	id := binary.BigEndian.Uint16(idData)

	flagData, err := c.take(2)
	if err != nil {
		return nil, "", err
	}
	flags := binary.BigEndian.Uint16(flagData)
	message := getDnsFlags(flagData)

	return c.rest(), fmt.Sprintf("id: 0x%X, flags: 0x%X %s", id, flags, message), nil
}

// dnsCounts gets just the DNS count data associated with the DNS header.
func dnsCounts(data string) (DnsCounts, error) {
	countsInt, err := strconv.ParseUint(data, 10, 64)
	if err != nil {
		return DnsCounts{}, &DecoderError{
			Input:      []byte(data),
			ParserName: "dns counts",
			Message:    "Failed to convert counts to int",
		}
	}

	bytes := make([]byte, 8)
	binary.BigEndian.PutUint64(bytes, countsInt)

	_, counts, err := parseCounts(bytes)
	if err != nil {
		return DnsCounts{}, &DecoderError{
			Input:      []byte(data),
			ParserName: "dns counts",
			Message:    "Failed to get counts",
		}
	}
	return counts, nil
}

// parseCounts parses the DNS count data associated with the DNS header.
func parseCounts(data []byte) ([]byte, DnsCounts, error) {
	c := newCursor(data)

	questionData, err := c.take(2)
	if err != nil {
		return nil, DnsCounts{}, err
	}
	answerData, err := c.take(2)
	if err != nil {
		return nil, DnsCounts{}, err
	}
	authorityData, err := c.take(2)
	if err != nil {
		return nil, DnsCounts{}, err
	}
	additionalData, err := c.take(2)
	if err != nil {
		return nil, DnsCounts{}, err
	}
	question := binary.BigEndian.Uint16(questionData)
	answer := binary.BigEndian.Uint16(answerData)
	authority := binary.BigEndian.Uint16(authorityData)
	additional := binary.BigEndian.Uint16(additionalData)

	return c.rest(), DnsCounts{Question: question, Answer: answer, Authority: authority, Additional: additional}, nil
}

// dnsYesNo translates DNS yes/no log values.
func dnsYesNo(data string) string {
	if data == "0" {
		return "no"
	}
	return "yes"
}

// dnsAcceptable translates DNS acceptable log values.
func dnsAcceptable(data string) string {
	if data == "0" {
		return "unacceptable"
	}
	return "acceptable"
}

// dnsGetaddrinfoOpts translates DNS getaddrinfo log values.
func dnsGetaddrinfoOpts(data string) (string, error) {
	options := map[string]string{
		"0":  "0x0 {}",
		"4":  "0x4 {in-app-browser}",
		"8":  "0x8 {use-failover}",
		"12": "0xC {in-app-browser, use-failover}",
		"24": "0x18 {use-failover, prohibit-encrypted-dns}",
		"32": "0x20 {use-cache-only}",
	}

	message, ok := options[data]
	if !ok {
		return "", &DecoderError{
			Input:      []byte(data),
			ParserName: "dns getaddrinfo opts",
			Message:    "Unknown DNS getaddrinfo options",
		}
	}
	return message, nil
}
