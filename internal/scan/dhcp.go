package scan

import (
	"bufio"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type leases struct {
	byIP  map[netip.Addr]string
	byMAC map[string]string
}

// readDHCPLeases gathers hostnames from common DHCP server/client lease files.
// It never returns an error: unreadable or missing files are simply skipped.
func readDHCPLeases() leases {
	out := leases{byIP: map[netip.Addr]string{}, byMAC: map[string]string{}}
	patterns := []string{
		"/var/lib/misc/dnsmasq.leases",
		"/var/lib/dnsmasq/dnsmasq.leases",
		"/run/dnsmasq/dnsmasq.leases",
		"/tmp/dhcp.leases",
		"/var/lib/dhcp/dhclient.leases",
		"/var/lib/dhcp/dhclient-*.lease",
		"/var/lib/dhcpcd/*.lease",
		"/var/lib/NetworkManager/*.lease",
	}
	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		for _, path := range matches {
			data, err := os.ReadFile(path)
			if err != nil || len(data) > 4<<20 {
				continue
			}
			text := string(data)
			base := filepath.Base(path)
			switch {
			case strings.Contains(text, "lease {") || base == "dhclient.leases":
				parseISCLeases(text, &out)
			case strings.Contains(base, ".lease") && strings.Contains(text, "="):
				parseKeyValueLeases(text, &out)
			default:
				parseDnsmasqLeases(text, &out)
			}
		}
	}
	return out
}

func parseDnsmasqLeases(text string, out *leases) {
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 4 {
			ip, err := netip.ParseAddr(fields[2])
			if err != nil {
				continue
			}
			mac := normMAC(fields[1])
			name := fields[3]
			if name == "*" || strings.Contains(name, "?") {
				name = ""
			}
			addLease(out, ip, mac, name)
			continue
		}
		// Some routers use "mac ip hostname".
		if len(fields) == 3 {
			ip, err := netip.ParseAddr(fields[1])
			if err != nil {
				continue
			}
			addLease(out, ip, normMAC(fields[0]), fields[2])
		}
	}
}

var (
	iscAddressRe = regexp.MustCompile(`(?m)^\s*fixed-address\s+([0-9.]+)\s*;`)
	iscNameRe    = regexp.MustCompile(`(?m)^\s*(?:option\s+host-name|client-hostname)\s+"([^"]*)"\s*;`)
	iscMACRe     = regexp.MustCompile(`(?mi)^\s*hardware\s+ethernet\s+([0-9a-f:.-]+)\s*;`)
)

func parseISCLeases(text string, out *leases) {
	// Lease blocks end with a closing brace at column zero.
	for _, block := range strings.Split(text, "}") {
		addr := iscAddressRe.FindStringSubmatch(block)
		if len(addr) < 2 {
			continue
		}
		ip, err := netip.ParseAddr(addr[1])
		if err != nil {
			continue
		}
		name := ""
		if m := iscNameRe.FindStringSubmatch(block); len(m) > 1 {
			name = m[1]
		}
		mac := ""
		if m := iscMACRe.FindStringSubmatch(block); len(m) > 1 {
			mac = normMAC(m[1])
		}
		addLease(out, ip, mac, name)
	}
}

func parseKeyValueLeases(text string, out *leases) {
	// dhcpcd and NetworkManager leases are INI-like key=value blocks.
	addrKeys := map[string]bool{
		"ip_address": true, "ipaddress": true, "address": true, "ip4_address_0": true,
	}
	macKeys := map[string]bool{
		"hwaddr": true, "mac_address": true, "dhcp4_client_id": true, "client_id": true,
	}
	nameKeys := map[string]bool{
		"hostname": true, "host_name": true, "dhcp4_host_name": true, "client_hostname": true,
	}
	var ip netip.Addr
	var mac, name string
	flush := func() {
		if ip.IsValid() {
			addLease(out, ip, mac, name)
		}
		ip, mac, name = netip.Addr{}, "", ""
	}
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			flush()
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.Trim(strings.TrimSpace(value), `"`)
		switch {
		case addrKeys[key]:
			if addr, err := netip.ParseAddr(value); err == nil {
				ip = addr
			}
		case macKeys[key]:
			mac = normMAC(strings.TrimPrefix(value, "01:"))
		case nameKeys[key]:
			if value != "" && value != "*" {
				name = value
			}
		}
	}
	flush()
}

func addLease(out *leases, ip netip.Addr, mac, name string) {
	if !ip.IsValid() {
		return
	}
	if name = cleanHostname(name); name != "" && isReasonableName(name) {
		out.byIP[ip] = name
		if mac != "" {
			out.byMAC[mac] = name
		}
	}
}

func normMAC(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.NewReplacer("-", ":", ".", ":", " ", "").Replace(s)
	if len(s) != 17 && len(s) == 12 {
		var b strings.Builder
		for i := 0; i < 12; i += 2 {
			if i > 0 {
				b.WriteByte(':')
			}
			b.WriteString(s[i : i+2])
		}
		s = b.String()
	}
	if len(s) != 17 || isZeroMAC(s) {
		return ""
	}
	return s
}
