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

// DnsConfig mirrors the Rust `DnsConfig` struct.
type DnsConfig struct {
	Nameservers    []string `json:"nameservers"`
	SearchDomains  []string `json:"search_domains"`
	Timeout        uint32   `json:"timeout"`
	Order          uint32   `json:"order"`
	IfIndex        uint32   `json:"if_index"`
	IfIndexValue   string   `json:"if_index_value"`
	DnsFlags       uint32   `json:"dns_flags"`
	DnsFlagsString string   `json:"dns_flags_string"`
	Reach          uint32   `json:"reach"`
	ReachString    string   `json:"reach_string"`
	ConfigID       string   `json:"config_id"`
	Options        string   `json:"options"`
	Domain         string   `json:"domain"`
	Unknown        string   `json:"unknown"`
}

// getDNSConfig parses DNS configuration. Can view live data with macOS command
// `scutil --dns`. This info is also logged to the Unified Log.
func getDNSConfig(data []byte) ([]byte, string, error) {
	c := newCursor(data)
	resolverCount, err := c.u32be()
	if err != nil {
		return data, "", err
	}
	if err := c.skip(8); err != nil {
		return data, "", err
	}
	scopeCount, err := c.u32be()
	if err != nil {
		return data, "", err
	}
	if err := c.skip(8); err != nil {
		return data, "", err
	}
	// Seen 0x5D8D7152
	if err := c.skip(4); err != nil {
		return data, "", err
	}
	// Seen 0x0
	if err := c.skip(16); err != nil {
		return data, "", err
	}
	// Seen 0x85C73301
	if err := c.skip(4); err != nil {
		return data, "", err
	}
	// Seen 0x000005EC. Maybe a size?
	if err := c.skip(4); err != nil {
		return data, "", err
	}
	// Seen 0x00000070. Maybe a size?
	if err := c.skip(4); err != nil {
		return data, "", err
	}

	// The input after the fixed headers. This pre-parse value is what the
	// original Rust implementation returns.
	input := c.rest()
	totalCount := resolverCount + scopeCount
	_, message, err := parseDNSConfig(input, totalCount)
	if err != nil {
		return data, "", err
	}

	return input, message, nil
}

// parseDNSConfig parses the DNS config data and assembles the message.
func parseDNSConfig(data []byte, resolverScopeCount uint32) ([]byte, string, error) {
	count := uint32(0)
	remaining := data
	var resolvers []DnsConfig
	var scopes []DnsConfig
	for count < resolverScopeCount {
		// 1 = DNS Resolver. 2 = DNS Scope. Both appear to have same format
		c := newCursor(remaining)
		resolverOrScope, err := c.u32be()
		if err != nil {
			return remaining, "", err
		}
		size, err := c.u32be()
		if err != nil {
			return remaining, "", err
		}

		adjust := uint32(8)
		if adjust > size {
			break
		}
		// Size includes `resolver_or_scope` and `size` value
		configData, err := c.take(int(size - adjust))
		if err != nil {
			return remaining, "", err
		}
		remaining = c.rest()

		switch resolverOrScope {
		case 1:
			_, config, err := parseDNSResolver(configData)
			if err != nil {
				return remaining, "", err
			}
			resolvers = append(resolvers, config)
		case 2:
			_, config, err := parseDNSResolver(configData)
			if err != nil {
				return remaining, "", err
			}
			scopes = append(scopes, config)
		default:
			logger.Printf("[macos-unifiedlogs] Unknown DNS config type. Neither resolver or scope: %d\n", resolverOrScope)
			return remaining, fmt.Sprintf(
				"Unknown DNS config type. Neither resolver or scope: %d: %s",
				resolverOrScope, encodeStandard(data),
			), nil
		}
		count++
	}

	// Now assemble our message!
	message := "DNS Configuration\n"
	message += assembleMessage(message, resolvers)

	message += "DNS configuration (for scoped queries)\n\n"
	message += assembleMessage(message, scopes)

	return remaining, message, nil
}

// assembleMessage combines our `DnsConfig`s into a single message.
func assembleMessage(logMessage string, configs []DnsConfig) string {
	message := logMessage
	for key, entry := range configs {
		resolverMessage := fmt.Sprintf("resolver #%d\n", key)
		for index, value := range entry.SearchDomains {
			resolverMessage += fmt.Sprintf("  search domain[%d] : %s\n", index, value)
		}
		for index, value := range entry.Nameservers {
			resolverMessage += fmt.Sprintf("  nameserver[%d] : %s\n", index, value)
		}

		if entry.IfIndex != 0 && entry.IfIndexValue != "" {
			resolverMessage += fmt.Sprintf("  if_index : %d (%s)\n", entry.IfIndex, entry.IfIndexValue)
		}

		if entry.Domain != "" {
			resolverMessage += fmt.Sprintf("  domain   : %s\n", entry.Domain)
		}
		if entry.Options != "" {
			resolverMessage += fmt.Sprintf("  options  : %s\n", entry.Options)
		}
		if entry.Timeout != 0 {
			resolverMessage += fmt.Sprintf("  timeout  : %d\n", entry.Timeout)
		}

		resolverMessage += fmt.Sprintf("  flags    : 0x%08x %s\n", entry.DnsFlags, entry.DnsFlagsString)
		resolverMessage += fmt.Sprintf("  reach    : 0x%08x %s\n", entry.Reach, entry.ReachString)
		if entry.Order != 0 {
			resolverMessage += fmt.Sprintf("  order    : %d\n", entry.Order)
		}
		resolverMessage += fmt.Sprintf("  config id: %s\n\n", entry.ConfigID)

		message += resolverMessage
	}

	return message
}

// parseDNSResolver parses DNS resolver data.
func parseDNSResolver(data []byte) ([]byte, DnsConfig, error) {
	c := newCursor(data)
	// Seen 0x0
	if err := c.skip(8); err != nil {
		return data, DnsConfig{}, err
	}
	if _, err := c.u32be(); err != nil { // nameserver_count
		return data, DnsConfig{}, err
	}
	// Seen 0x0. 3 flags? (each 4 bytes?)
	if err := c.skip(12); err != nil {
		return data, DnsConfig{}, err
	}
	if _, err := c.u32be(); err != nil { // search_domain_count
		return data, DnsConfig{}, err
	}
	// Seen 0x0. More flags?
	if err := c.skip(28); err != nil {
		return data, DnsConfig{}, err
	}

	timeout, err := c.u32be()
	if err != nil {
		return data, DnsConfig{}, err
	}
	order, err := c.u32be()
	if err != nil {
		return data, DnsConfig{}, err
	}
	ifIndex, err := c.u32be()
	if err != nil {
		return data, DnsConfig{}, err
	}
	dnsFlags, err := c.u32be()
	if err != nil {
		return data, DnsConfig{}, err
	}
	reach, err := c.u32be()
	if err != nil {
		return data, DnsConfig{}, err
	}

	// Seen 0x0. More flags?
	if err := c.skip(20); err != nil {
		return data, DnsConfig{}, err
	}
	// Size for remaining bytes
	if _, err := c.u32be(); err != nil {
		return data, DnsConfig{}, err
	}

	// The input after the fixed headers. Pre-loop value is returned, mirroring
	// the original Rust implementation.
	input := c.rest()

	// remaining bytes is variety of config options
	minSize := 10
	remaining := input
	config := DnsConfig{
		Timeout:  timeout,
		Order:    order,
		IfIndex:  ifIndex,
		DnsFlags: dnsFlags,
		Reach:    reach,
	}
	if dnsFlags == 6 {
		config.DnsFlagsString = "(Request A records, Request AAAA records)"
	}
	if reach == 0 {
		config.ReachString = "(Not Reachable)"
	} else if reach == 0x00020002 {
		config.ReachString = "(Reachable, Directly Reachable Address)"
	}

	for len(remaining) > minSize {
		// Option types:
		// 0xc - search domain
		// 0xb - nameserver
		// 0x10 - if_index value
		// 0xa - domain
		// 0xe - options
		// 0xf - config id
		oc := newCursor(remaining)
		optionType, err := oc.u32be()
		if err != nil {
			return remaining, config, err
		}
		optionSize, err := oc.u32be()
		if err != nil {
			return remaining, config, err
		}
		adjust := uint32(8)
		if adjust > optionSize {
			break
		}
		// `option_size` includes `option_type` and `option_size`
		optionData, err := oc.take(int(optionSize - adjust))
		if err != nil {
			return remaining, config, err
		}
		remaining = oc.rest()
		switch optionType {
		case 0xc:
			_, v, err := extractString(optionData)
			if err != nil {
				return remaining, config, err
			}
			config.SearchDomains = append(config.SearchDomains, v)
		case 0x10:
			_, v, err := extractString(optionData)
			if err != nil {
				return remaining, config, err
			}
			config.IfIndexValue = v
		case 0xb:
			_, v, err := parseNameserver(optionData)
			if err != nil {
				return remaining, config, err
			}
			config.Nameservers = append(config.Nameservers, v)
		case 0xf:
			_, v, err := extractString(optionData)
			if err != nil {
				return remaining, config, err
			}
			config.ConfigID = v
		case 0xa:
			_, v, err := extractString(optionData)
			if err != nil {
				return remaining, config, err
			}
			config.Domain = v
		case 0xe:
			_, v, err := extractString(optionData)
			if err != nil {
				return remaining, config, err
			}
			config.Options = v
		default:
			logger.Printf("[macos-unifiedlogs] Unknown DNS option type: %d\n", optionType)
			config.Unknown = fmt.Sprintf(
				"Unknown DNS option type: %d: %s",
				optionType, encodeStandard(data),
			)
			return remaining, config, nil
		}
	}

	return input, config, nil
}

// parseNameserver parses a nameserver IPv4 or IPv6.
func parseNameserver(data []byte) ([]byte, string, error) {
	ipv4 := 16
	ipv6 := 28
	var input []byte
	var value string
	if len(data) == ipv4 {
		c := newCursor(data)
		// Flags?
		if _, err := c.u32be(); err != nil {
			return data, "", err
		}
		remaining, ip, err := getIPFour(c.rest())
		if err != nil {
			return data, "", err
		}
		input = remaining
		value = ip.String()
	} else if len(data) == ipv6 {
		c := newCursor(data)
		// Flags?
		if _, err := c.u64be(); err != nil {
			return data, "", err
		}
		_, ip, err := getIPSix(c.rest())
		if err != nil {
			return data, "", err
		}
		input = data
		value = ip.String()
	} else {
		logger.Printf("[macos-unifiedlogs] Unknown nameserver data type\n")
		return data, fmt.Sprintf("Unknown nameserver data type: %s", encodeStandard(data)), nil
	}

	return input, value, nil
}

// NetworkInterface mirrors the Rust `NetworkInterface` struct.
type NetworkInterface struct {
	Name         string       `json:"name"`
	IP           string       `json:"ip"`
	Rank         uint32       `json:"rank"`
	RankFlag     RankFlag     `json:"rank_flag"`
	RankPosition uint32       `json:"rank_position"`
	Reach        uint32       `json:"reach"`
	ReachFlags   []ReachFlags `json:"reach_flags"`
	Signature    string       `json:"signature"`
	Generation   uint64       `json:"generation"`
	Flag         uint64       `json:"flag"`
	AliasOffset  int32        `json:"alias_offset"`
}

// getNetworkInterface parses `Network Interface` structures. The format is open
// source at
// <https://github.com/apple-oss-distributions/configd/blob/main/nwi/network_state_information_priv.h>
func getNetworkInterface(data []byte) ([]byte, string, error) {
	c := newCursor(data)
	if _, err := c.u32(); err != nil { // version
		return data, "", err
	}

	// Max number of IPv4 and IPv6 that can be in the interface list
	maxProtocolCount, err := c.u32()
	if err != nil {
		return data, "", err
	}
	ipv4Count, err := c.u32()
	if err != nil {
		return data, "", err
	}
	ipv6Count, err := c.u32()
	if err != nil {
		return data, "", err
	}
	if _, err := c.u32(); err != nil { // list_count
		return data, "", err
	}

	if _, err := c.u32(); err != nil { // ref_count
		return data, "", err
	}
	if _, err := c.u32(); err != nil { // reach_flags_v4
		return data, "", err
	}
	if _, err := c.u32(); err != nil { // reach_flags_v6
		return data, "", err
	}

	generationCount, err := c.u64()
	if err != nil {
		return data, "", err
	}

	// Each interface size seems to be 112 bytes
	interfaceSize := uint32(112)
	ip4InterfaceData, err := c.take(int(interfaceSize * maxProtocolCount))
	if err != nil {
		return data, "", err
	}
	_, ip4Interfaces, err := parseInterface(ip4InterfaceData, ipv4Count)
	if err != nil {
		return data, "", err
	}

	ip6InterfaceData, err := c.take(int(interfaceSize * maxProtocolCount))
	if err != nil {
		return data, "", err
	}
	input := c.rest()
	_, ip6Interfaces, err := parseInterface(ip6InterfaceData, ipv6Count)
	if err != nil {
		return data, "", err
	}

	message := assembleNetworkInterface(ip4Interfaces, ip6Interfaces, generationCount, uint64(len(data)))

	return input, message, nil
}

// parseInterface parses interface data.
func parseInterface(data []byte, interfaceCount uint32) ([]byte, []NetworkInterface, error) {
	remaining := data
	count := uint32(0)

	minSize := 112
	var interfaces []NetworkInterface
	for count < interfaceCount && len(remaining) >= minSize {
		c := newCursor(remaining)
		interfaceName, err := c.take(16)
		if err != nil {
			return remaining, interfaces, err
		}
		_, name, err := extractString(interfaceName)
		if err != nil {
			return remaining, interfaces, err
		}

		flag, err := c.u64()
		if err != nil {
			return remaining, interfaces, err
		}
		aliasOffset, err := c.i32()
		if err != nil {
			return remaining, interfaces, err
		}
		rank, err := c.u32()
		if err != nil {
			return remaining, interfaces, err
		}

		// Either IPv4 or IPv6. 2 = IPv4, 0x1E = IPv6
		interfaceFamily, err := c.u32()
		if err != nil {
			return remaining, interfaces, err
		}
		ipData, err := c.take(16)
		if err != nil {
			return remaining, interfaces, err
		}
		var ip string
		switch interfaceFamily {
		case 0x2:
			_, v, err := getIPFour(ipData)
			if err != nil {
				return remaining, interfaces, err
			}
			ip = v.String()
		case 0x1E:
			_, v, err := getIPSix(ipData)
			if err != nil {
				return remaining, interfaces, err
			}
			ip = v.String()
		default:
			logger.Printf("[macos-unifiedlogs] Unknown interface family: %d\n", interfaceFamily)
			ip = fmt.Sprintf("Unknown interface family: %d", interfaceFamily)
		}

		generation, err := c.u64()
		if err != nil {
			return remaining, interfaces, err
		}
		reach, err := c.u32()
		if err != nil {
			return remaining, interfaces, err
		}
		if _, err := c.take(28); err != nil { // vpn_ip_data
			return remaining, interfaces, err
		}

		sig, err := c.take(20)
		if err != nil {
			return remaining, interfaces, err
		}

		rankFlag, rankPosition := getRank(rank)
		interfaces = append(interfaces, NetworkInterface{
			Name:         name,
			IP:           ip,
			Rank:         rank,
			Reach:        reach,
			Signature:    formatSignature(sig),
			Generation:   generation,
			Flag:         flag,
			ReachFlags:   getReach(reach),
			RankFlag:     rankFlag,
			RankPosition: rankPosition,
			AliasOffset:  aliasOffset,
		})

		remaining = c.rest()
		count++
	}

	return remaining, interfaces, nil
}

// ReachFlags mirrors the Rust `ReachFlags` enum.
type ReachFlags string

// ReachFlags values.
const (
	ReachFlagReachable            ReachFlags = "Reachable"
	ReachFlagConnectionRequired   ReachFlags = "ConnectionRequired"
	ReachFlagConnectionOnTraffic  ReachFlags = "ConnectionOnTraffic"
	ReachFlagInterventionRequired ReachFlags = "InterventionRequired"
	ReachFlagConnectionOnDemand   ReachFlags = "ConnectionOnDemand"
	ReachFlagIsLocalAddress       ReachFlags = "IsLocalAddress"
	ReachFlagIsDirect             ReachFlags = "IsDirect"
	ReachFlagIsWwan               ReachFlags = "IsWwan"
)

// getReach determines reach flags. Does the opposite bitwise operation defined
// here:
// <https://github.com/orta/tickets/blob/master/SystemConfiguration.framework/Versions/A/Headers/SCNetworkReachability.h>
func getReach(reach uint32) []ReachFlags {
	var flags []ReachFlags
	if reach>>1 != 0 {
		flags = append(flags, ReachFlagReachable)
	}
	if reach>>2 != 0 {
		flags = append(flags, ReachFlagConnectionRequired)
	}
	if reach>>3 != 0 {
		flags = append(flags, ReachFlagConnectionOnTraffic)
	}
	if reach>>4 != 0 {
		flags = append(flags, ReachFlagInterventionRequired)
	}
	if reach>>5 != 0 {
		flags = append(flags, ReachFlagConnectionOnDemand)
	}
	if reach>>16 != 0 {
		flags = append(flags, ReachFlagIsLocalAddress)
	}
	if reach>>17 != 0 {
		flags = append(flags, ReachFlagIsDirect)
	}
	if reach>>18 != 0 {
		flags = append(flags, ReachFlagIsWwan)
	}

	return flags
}

// RankFlag mirrors the Rust `RankFlag` enum.
type RankFlag string

// RankFlag values.
const (
	RankFlagFirst   RankFlag = "First"
	RankFlagDefault RankFlag = "Default"
	RankFlagLast    RankFlag = "Last"
	RankFlagNever   RankFlag = "Never"
	RankFlagScoped  RankFlag = "Scoped"
	RankFlagMask    RankFlag = "Mask"
	RankFlagUnknown RankFlag = "Unknown"
)

// getRank checks the rank flags. See:
// <https://github.com/apple-oss-distributions/configd/blob/main/nwi/network_state_information_priv.h#L62>
func getRank(rank uint32) (RankFlag, uint32) {
	top8Bits := uint32(24)
	rankValue := rank >> top8Bits
	var value RankFlag
	switch rankValue {
	case 0x0:
		value = RankFlagFirst
	case 0x1:
		value = RankFlagDefault
	case 0x2:
		value = RankFlagLast
	case 0x3:
		value = RankFlagNever
	case 0x4:
		value = RankFlagScoped
	case 0xff:
		value = RankFlagMask
	default:
		value = RankFlagUnknown
	}

	bottom8Bits := uint32(0xffffff)
	return value, rank & bottom8Bits
}

// formatSignature renders a 20-byte signature the same way as the Rust
// `format!("0x{sig:02x?}")` with the separators and brackets stripped.
func formatSignature(sig []byte) string {
	var b strings.Builder
	b.WriteString("0x")
	for _, x := range sig {
		fmt.Fprintf(&b, "%02x", x)
	}
	return b.String()
}

// debugReachFlags mirrors Rust's Debug rendering of a `Vec<ReachFlags>`.
func debugReachFlags(flags []ReachFlags) string {
	parts := make([]string, len(flags))
	for i, f := range flags {
		parts[i] = string(f)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// assembleNetworkInterface assembles our log message.
func assembleNetworkInterface(ip4 []NetworkInterface, ip6 []NetworkInterface, generationCount uint64, size uint64) string {
	message := fmt.Sprintf(
		"Network information (generation %d size=%d)\nIPv4 network interface information\n", generationCount, size,
	)

	ip4Count := int32(len(ip4))
	ip6Count := int32(len(ip6))

	// ipv4 first
	message = combineData(message, ip4, ip4Count, ip6Count, true)
	message += "IPv6 network interface information\n"
	message = combineData(message, ip6, ip4Count, ip6Count, false)

	names := newNameSet()
	for _, entry := range ip4 {
		if entry.RankFlag == RankFlagNever {
			continue
		}
		names.add(entry.Name)
	}
	for _, entry := range ip6 {
		if entry.RankFlag == RankFlagNever {
			continue
		}
		names.add(entry.Name)
	}

	message += fmt.Sprintf("Network interfaces: %s\n", strings.Join(names.list(), ", "))

	return message
}

// nameSet preserves insertion order while de-duplicating names.
type nameSet struct {
	seen  map[string]bool
	order []string
}

func newNameSet() *nameSet {
	return &nameSet{seen: map[string]bool{}}
}

func (n *nameSet) add(name string) {
	if !n.seen[name] {
		n.seen[name] = true
		n.order = append(n.order, name)
	}
}

func (n *nameSet) list() []string {
	return n.order
}

// combineData combines interface log data.
func combineData(logMessage string, interfaces []NetworkInterface, ip4Count int32, ip6Count int32, isIP4 bool) string {
	message := logMessage
	for _, entry := range interfaces {
		flag, values := getFlags(entry.Flag, ip4Count, ip6Count, entry.AliasOffset, isIP4)
		ip4Message := fmt.Sprintf(
			"     %s : flags      : 0x%x (%s)\n",
			entry.Name,
			flag,
			strings.Join(values, ","),
		)
		ip4Message += fmt.Sprintf("           address    : %s\n", entry.IP)
		ip4Message += fmt.Sprintf("           reach      : 0x%08x %s\n", entry.Reach, debugReachFlags(entry.ReachFlags))
		ip4Message += fmt.Sprintf(
			"           rank       : 0x%08x (%s, 0x%x)\n",
			entry.Rank, entry.RankFlag, entry.RankPosition,
		)
		if entry.Signature != "0x0000000000000000000000000000000000000000" {
			ip4Message += fmt.Sprintf("           signature  : {length = 20, bytes = %s}\n", entry.Signature)
		}

		ip4Message += fmt.Sprintf("           generation : %d\n", entry.Generation)
		ip4Message += fmt.Sprintf("   REACH : flags 0x%010x %s\n", entry.Reach, debugReachFlags(entry.ReachFlags))

		message += ip4Message
	}
	return message
}

// getFlags gets interface flags.
func getFlags(flags uint64, ip4Count int32, ip6Count int32, alias int32, isIP4 bool) (uint64, []string) {
	// Combine both because interface flags may reference another interface in our list
	listSize := ip4Count + ip6Count
	// <https://github.com/apple-oss-distributions/configd/blob/main/nwi/network_information.h#L132>
	dns := uint64(0x4)
	cat46 := uint64(0x40)
	notInList := uint64(0x8)
	notInIfList := uint64(0x20)

	flag := uint64(0x1)
	if !isIP4 {
		flag = 0x2
	}
	values := []string{"IPv4"}
	if !isIP4 {
		values = []string{"IPv6"}
	}
	if flags&dns != 0 {
		flag |= dns
		values = append(values, "DNS")
	}
	if flags&cat46 != 0 {
		flag |= cat46
		// Client address translation. Converts IPv4 to IPv6
		values = append(values, "CAT46")
	}
	if flags&notInList != 0 {
		flag |= notInList
		values = append(values, "NOT-IN-LIST")
	}
	if flags&notInIfList != 0 {
		flag |= notInIfList
		values = append(values, "NOT-IN-IFLIST")
	}
	if alias != 0 {
		if alias > ip4Count && alias < listSize {
			flag |= 0x2
			values = append(values, "IPv6")
		} else if alias < 0 && (alias+ip6Count) == 0 {
			// Go back to top of list to ip4
			flag |= 0x1
			values = append(values, "IPv4")
		}
	}

	return flag, values
}
