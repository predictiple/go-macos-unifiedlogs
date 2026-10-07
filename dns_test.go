// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package unifiedlogs

import "testing"

const dnsHeaderExpected = "Query ID: 0xB973, Flags: 0x100 Opcode: QUERY, \n    Query Type: 0,\n    Authoritative Answer Flag: 0, \n    Truncation Flag: 0, \n    Recursion Desired: 1, \n    Recursion Available: 0, \n    Response Code: No Error, Question Count: 1, Answer Record Count: 0, Authority Record Count: 0, Additional Record Count: 0"

const dnsFlagsExpected = "Opcode: QUERY, \n    Query Type: 0,\n    Authoritative Answer Flag: 0, \n    Truncation Flag: 0, \n    Recursion Desired: 1, \n    Recursion Available: 0, \n    Response Code: No Error"

func TestParseDnsHeader(t *testing.T) {
	testData := "uXMBAAABAAAAAAAA"
	result, err := parseDnsHeader(testData)
	if err != nil {
		t.Fatalf("parseDnsHeader failed: %v", err)
	}
	if result != "Query ID: 0xB973, Flags: 0x100 Opcode: QUERY, \n    Query Type: 0,\n    Authoritative Answer Flag: 0, \n    Truncation Flag: 0, \n    Recursion Desired: 1, \n    Recursion Available: 0, \n    Response Code: No Error, Question Count: 1, Answer Record Count: 0, Authority Record Count: 0, Additional Record Count: 0" {
		t.Errorf("parseDnsHeader = %q", result)
	}
}

func TestGetDnsFlags(t *testing.T) {
	testData := []byte{185, 115, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	_, result, err := getDnsHeader(testData)
	if err != nil {
		t.Fatalf("getDnsHeader failed: %v", err)
	}
	if result != "Query ID: 0xB973, Flags: 0x100 Opcode: QUERY, \n    Query Type: 0,\n    Authoritative Answer Flag: 0, \n    Truncation Flag: 0, \n    Recursion Desired: 1, \n    Recursion Available: 0, \n    Response Code: No Error, Question Count: 1, Answer Record Count: 0, Authority Record Count: 0, Additional Record Count: 0" {
		t.Errorf("getDnsHeader = %q", result)
	}
}

func TestGetDnsHeader(t *testing.T) {
	testData := []byte{1, 0}
	result := getDnsFlags(testData)
	if result != "Opcode: QUERY, \n    Query Type: 0,\n    Authoritative Answer Flag: 0, \n    Truncation Flag: 0, \n    Recursion Desired: 1, \n    Recursion Available: 0, \n    Response Code: No Error" {
		t.Errorf("getDnsFlags = %q", result)
	}
}

func TestGetDomainName(t *testing.T) {
	testData := "AzE0NAMxMDEDMTY4AzE5Mgdpbi1hZGRyBGFycGEA"
	result, err := getDomainName(testData)
	if err != nil {
		t.Fatalf("getDomainName failed: %v", err)
	}
	if result != ".144.101.168.192.in-addr.arpa" {
		t.Errorf("getDomainName = %q", result)
	}
}

func TestGetServiceBinding(t *testing.T) {
	testData := "AAEAAAEAAwJoMgAEAAhoEJRAaBCVQAAGACAmBkcAAAAAAAAAAABoEJRAJgZHAAAAAAAAAAAAaBCVQA=="
	result, err := getServiceBinding(testData)
	if err != nil {
		t.Fatalf("getServiceBinding failed: %v", err)
	}
	expected := "rdata: 1 . alpn=h2, ipv4 hint:104.16.148.64,104.16.149.64, ipv6 hint:2606:4700::6810:9440,2606:4700::6810:9540"
	if result != expected {
		t.Errorf("getServiceBinding = %q, want %q", result, expected)
	}
}

func TestParseSvcb(t *testing.T) {
	testData := "AAEAAAEAAwJoMgAEAAhoEJRAaBCVQAAGACAmBkcAAAAAAAAAAABoEJRAJgZHAAAAAAAAAAAAaBCVQA=="
	decodedData, err := decodeStandard(testData)
	if err != nil {
		t.Fatalf("decodeStandard failed: %v", err)
	}

	_, result, err := parseSvcb(decodedData)
	if err != nil {
		t.Fatalf("parseSvcb failed: %v", err)
	}
	expected := "rdata: 1 . alpn=h2, ipv4 hint:104.16.148.64,104.16.149.64, ipv6 hint:2606:4700::6810:9440,2606:4700::6810:9540"
	if result != expected {
		t.Errorf("parseSvcb = %q, want %q", result, expected)
	}
}

func TestParseSvcbAlpn(t *testing.T) {
	testData := []byte{2, 104, 50}
	_, result, err := parseSvcbAlpn(testData)
	if err != nil {
		t.Fatalf("parseSvcbAlpn failed: %v", err)
	}
	if result != "alpn=h2," {
		t.Errorf("parseSvcbAlpn = %q, want alpn=h2,", result)
	}
}

func TestParseSvcbIp(t *testing.T) {
	testData := []byte{
		0, 4, 0, 8, 104, 16, 148, 64, 104, 16, 149, 64, 0, 6, 0, 32, 38, 6, 71, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 104, 16, 148, 64, 38, 6, 71, 0, 0, 0, 0, 0, 0, 0, 0, 0, 104, 16, 149, 64,
	}
	_, result, err := parseSvcbIp(testData)
	if err != nil {
		t.Fatalf("parseSvcbIp failed: %v", err)
	}
	expected := "ipv4 hint:104.16.148.64,104.16.149.64, ipv6 hint:2606:4700::6810:9440,2606:4700::6810:9540"
	if result != expected {
		t.Errorf("parseSvcbIp = %q, want %q", result, expected)
	}
}

func TestParseSvcbIpShouldNotInfiniteLoop(t *testing.T) {
	testData := []byte{
		0, 4, 0, 4, 104, 16, 148, 64,
		0, 6, 0, 16, 38, 6, 71, 0, 0, 0, 0, 0, 0, 0, 0, 0, 104, 16, 148, 64,
		0, 42, 0, 0,
	}
	_, _, err := parseSvcbIp(testData)
	if err == nil {
		t.Fatal("expected parseSvcbIp to return an error")
	}
}

func TestGetDnsMacAddr(t *testing.T) {
	testData := "AAAAAAAA"
	result, err := getDnsMacAddr(testData)
	if err != nil {
		t.Fatalf("getDnsMacAddr failed: %v", err)
	}
	if result != "00:00:00:00:00:00" {
		t.Errorf("getDnsMacAddr = %q", result)
	}
}

func TestParseMacAddr(t *testing.T) {
	testData := []byte{0, 0, 0, 0, 0, 0}
	_, result, err := parseMacAddr(testData)
	if err != nil {
		t.Fatalf("parseMacAddr failed: %v", err)
	}
	if result != "00:00:00:00:00:00" {
		t.Errorf("parseMacAddr = %q", result)
	}
}

func TestDnsIpAddr(t *testing.T) {
	testData := "BAAAAMCoZZAAAAAAAAAAAAAAAAA="
	result, err := dnsIPAddr(testData)
	if err != nil {
		t.Fatalf("dnsIPAddr failed: %v", err)
	}
	if result != "192.168.101.144" {
		t.Errorf("dnsIPAddr = %q", result)
	}
}

func TestParseDnsIpAddr(t *testing.T) {
	testData := []byte{
		4, 0, 0, 0, 192, 168, 101, 144, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	}
	_, result, err := parseDnsIPAddr(testData)
	if err != nil {
		t.Fatalf("parseDnsIPAddr failed: %v", err)
	}
	if result != "192.168.101.144" {
		t.Errorf("parseDnsIPAddr = %q", result)
	}
}

func TestDnsAddrmv(t *testing.T) {
	testData := "1"
	result := dnsAddRmv(testData)
	if result != "add" {
		t.Errorf("dnsAddRmv = %q", result)
	}
}

func TestDnsRecords(t *testing.T) {
	testData := "65"
	result, err := dnsRecords(testData)
	if err != nil {
		t.Fatalf("dnsRecords failed: %v", err)
	}
	if result != "HTTPS" {
		t.Errorf("dnsRecords = %q", result)
	}
}

func TestDnsReason(t *testing.T) {
	testData := "1"
	result, err := dnsReason(testData)
	if err != nil {
		t.Fatalf("dnsReason failed: %v", err)
	}
	if result != "no-data" {
		t.Errorf("dnsReason = %q", result)
	}
}

func TestDnsProtocol(t *testing.T) {
	testData := "1"
	result, err := dnsProtocol(testData)
	if err != nil {
		t.Fatalf("dnsProtocol failed: %v", err)
	}
	if result != "UDP" {
		t.Errorf("dnsProtocol = %q", result)
	}
}

func TestDnsIdflags(t *testing.T) {
	testData := "2126119168"
	result, err := dnsIDFlags(testData)
	if err != nil {
		t.Fatalf("dnsIDFlags failed: %v", err)
	}
	expected := "id: 0x7EBA, flags: 0x100 Opcode: QUERY, \n    Query Type: 0,\n    Authoritative Answer Flag: 0, \n    Truncation Flag: 0, \n    Recursion Desired: 1, \n    Recursion Available: 0, \n    Response Code: No Error"
	if result != expected {
		t.Errorf("dnsIDFlags = %q, want %q", result, expected)
	}
}

func TestParseIdflags(t *testing.T) {
	testData := []byte{0x7e, 0xba, 0x1, 0}
	_, result, err := parseIDFlags(testData)
	if err != nil {
		t.Fatalf("parseIDFlags failed: %v", err)
	}
	expected := "id: 0x7EBA, flags: 0x100 Opcode: QUERY, \n    Query Type: 0,\n    Authoritative Answer Flag: 0, \n    Truncation Flag: 0, \n    Recursion Desired: 1, \n    Recursion Available: 0, \n    Response Code: No Error"
	if result != expected {
		t.Errorf("parseIDFlags = %q, want %q", result, expected)
	}
}

func TestDnsCounts(t *testing.T) {
	testData := "281474976710656"
	result, err := dnsCounts(testData)
	if err != nil {
		t.Fatalf("dnsCounts failed: %v", err)
	}
	expected := DnsCounts{Question: 1, Answer: 0, Authority: 0, Additional: 0}
	if result != expected {
		t.Errorf("dnsCounts = %+v, want %+v", result, expected)
	}
}

func TestParseCounts(t *testing.T) {
	testData := []byte{0, 1, 0, 0, 0, 0, 0, 0}
	_, result, err := parseCounts(testData)
	if err != nil {
		t.Fatalf("parseCounts failed: %v", err)
	}
	expected := DnsCounts{Question: 1, Answer: 0, Authority: 0, Additional: 0}
	if result != expected {
		t.Errorf("parseCounts = %+v, want %+v", result, expected)
	}
}

func TestDnsYesNo(t *testing.T) {
	testData := "0"
	result := dnsYesNo(testData)
	if result != "no" {
		t.Errorf("dnsYesNo = %q", result)
	}
}

func TestDnsAcceptable(t *testing.T) {
	testData := "0"
	result := dnsAcceptable(testData)
	if result != "unacceptable" {
		t.Errorf("dnsAcceptable = %q", result)
	}
}

func TestDnsGetaddrinfoOpts(t *testing.T) {
	testData := "8"
	result, err := dnsGetaddrinfoOpts(testData)
	if err != nil {
		t.Fatalf("dnsGetaddrinfoOpts failed: %v", err)
	}
	if result != "0x8 {use-failover}" {
		t.Errorf("dnsGetaddrinfoOpts = %q", result)
	}
}
