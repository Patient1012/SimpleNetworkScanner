// Package scan discovers devices on the local network and enriches them
// with names, vendors, open ports and latency.
package scan

import (
	"net"
	"net/netip"
	"time"
)

// Options controls how a scan is performed.
type Options struct {
	// Interface is the network interface to scan. Empty means auto-detect.
	Interface string
	// Subnet overrides the detected subnet, e.g. "192.168.1.0/24".
	Subnet string
	// Ports is the list of TCP ports to probe.
	Ports []int
	// PortTimeout is the timeout for a single TCP connection attempt.
	PortTimeout time.Duration
	// PingTimeout is the timeout for a single ICMP echo request.
	PingTimeout time.Duration
	// MaxHosts caps the number of addresses scanned in large subnets.
	MaxHosts int
	// DisableMDNS and DisableNBNS turn off the respective name lookups.
	DisableMDNS bool
	DisableNBNS bool
}

// DefaultPorts is the TCP port list probed during a scan.
var DefaultPorts = []int{
	22, 80, 443, 445, 139, 3389, 8080, 8443,
	53, 631, 9100, 5000, 3000, 5432, 3306, 6379,
	27017, 21, 23, 25, 110, 143, 993, 995,
	1883, 5900, 5985, 5986, 62078, 8000, 8008, 8081,
	8888, 9000, 9090, 32400, 50000, 51413,
}

// DefaultOptions returns sensible defaults for a home/office LAN.
func DefaultOptions() Options {
	return Options{
		Ports:       append([]int(nil), DefaultPorts...),
		PortTimeout: 400 * time.Millisecond,
		PingTimeout: 800 * time.Millisecond,
		MaxHosts:    1024,
	}
}

// Network describes the local network being scanned.
type Network struct {
	InterfaceName string
	Interface     *net.Interface
	LocalIP       netip.Addr
	LocalMAC      net.HardwareAddr
	Prefix        netip.Prefix
	Gateway       netip.Addr
}

// Device is a single host discovered on the network.
type Device struct {
	IP       netip.Addr
	MAC      string
	Hostname string
	Vendor   string
	Model    string
	Ports    []int
	RTT      time.Duration

	Online  bool
	Self    bool
	Gateway bool

	// FirstSeen and LastSeen are maintained across scans by the UI/store.
	FirstSeen time.Time
	LastSeen  time.Time

	// NameSource records where Hostname came from (e.g. "mdns", "dns").
	NameSource string
}

// Key returns a stable identity for merging scan results. IPs are used while
// scanning; the history store keys devices by MAC when available.
func (d Device) Key() string {
	if d.MAC != "" {
		return d.MAC
	}
	return "ip:" + d.IP.String()
}

// Progress reports scan progress to the UI.
type Progress struct {
	Phase string
	Done  int
	Total int
}

// Summary describes a completed scan.
type Summary struct {
	Started   time.Time
	Finished  time.Time
	Hosts     int
	Up        int
	OpenPorts int
	Truncated bool
	// PingAvailable is false when unprivileged ICMP could not be used.
	PingAvailable bool
}

// Elapsed returns how long the scan took.
func (s Summary) Elapsed() time.Duration {
	if s.Started.IsZero() || s.Finished.IsZero() {
		return 0
	}
	return s.Finished.Sub(s.Started)
}
