package scan

import (
	"fmt"
	"strconv"
	"strings"
)

var serviceNames = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
	67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http", 88: "kerberos",
	110: "pop3", 111: "rpcbind", 123: "ntp", 135: "msrpc", 137: "netbios-ns",
	138: "netbios-dgm", 139: "netbios-ssn", 143: "imap", 161: "snmp",
	389: "ldap", 443: "https", 445: "smb", 465: "smtps", 500: "isakmp",
	514: "syslog", 515: "lpd", 548: "afp", 554: "rtsp", 587: "submission",
	631: "ipp", 636: "ldaps", 993: "imaps", 995: "pop3s", 1080: "socks",
	1883: "mqtt", 1900: "upnp", 2049: "nfs", 2222: "ssh-alt", 2375: "docker",
	2376: "docker-tls", 3000: "dev-http", 3128: "squid", 3306: "mysql",
	3389: "rdp", 3478: "stun", 5000: "http-alt", 5060: "sip",
	5353: "mdns", 5432: "postgres", 5555: "adb", 5900: "vnc", 5985: "winrm",
	5986: "winrm-tls", 6379: "redis", 6443: "k8s-api", 8000: "http-alt",
	8008: "http-alt", 8069: "odoo", 8080: "http-proxy", 8081: "http-alt",
	8443: "https-alt", 8888: "http-alt", 9000: "http-alt", 9090: "prometheus",
	9100: "jetdirect", 9222: "chrome-debug", 9418: "git", 11211: "memcached",
	27017: "mongodb", 32400: "plex", 50000: "sap", 51413: "transmission",
	62078: "iphone-sync", 25565: "minecraft", 19132: "minecraft-be",
}

// ServiceName returns a friendly name for a port.
func ServiceName(port int) string {
	if s, ok := serviceNames[port]; ok {
		return s
	}
	return "tcp"
}

// PortLabel returns e.g. "443/https".
func PortLabel(port int) string {
	if s, ok := serviceNames[port]; ok {
		return fmt.Sprintf("%d/%s", port, s)
	}
	return strconv.Itoa(port)
}

// ParsePorts parses a comma-separated port list with optional ranges,
// for example "22,80,443,8000-8100". An empty string returns defaults.
func ParsePorts(spec string) ([]int, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return append([]int(nil), DefaultPorts...), nil
	}
	seen := map[int]bool{}
	var ports []int
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if lo, hi, ok := strings.Cut(part, "-"); ok {
			start, err1 := strconv.Atoi(strings.TrimSpace(lo))
			end, err2 := strconv.Atoi(strings.TrimSpace(hi))
			if err1 != nil || err2 != nil || start < 1 || end > 65535 || start > end {
				return nil, fmt.Errorf("invalid port range %q", part)
			}
			if end-start > 4096 {
				return nil, fmt.Errorf("port range %q is too large (max 4096 ports)", part)
			}
			for p := start; p <= end; p++ {
				if !seen[p] {
					seen[p] = true
					ports = append(ports, p)
				}
			}
			continue
		}
		p, err := strconv.Atoi(part)
		if err != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("invalid port %q", part)
		}
		if !seen[p] {
			seen[p] = true
			ports = append(ports, p)
		}
	}
	if len(ports) == 0 {
		return nil, fmt.Errorf("no valid ports specified")
	}
	if len(ports) > 4096 {
		return nil, fmt.Errorf("too many ports specified (max 4096)")
	}
	return ports, nil
}
