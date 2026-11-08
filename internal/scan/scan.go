package scan

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"sync/atomic"
	"time"

	"netscan/internal/oui"
)

// Scanner performs repeated scans of a single local network.
type Scanner struct {
	opts Options
	net  *Network
}

// New creates a scanner and detects the network to scan.
func New(opts Options) (*Scanner, error) {
	defaults := DefaultOptions()
	if opts.Ports == nil {
		opts.Ports = defaults.Ports
	}
	if opts.PortTimeout <= 0 {
		opts.PortTimeout = defaults.PortTimeout
	}
	if opts.PingTimeout <= 0 {
		opts.PingTimeout = defaults.PingTimeout
	}
	if opts.MaxHosts <= 0 {
		opts.MaxHosts = defaults.MaxHosts
	}
	netw, err := Detect(opts)
	if err != nil {
		return nil, err
	}
	return &Scanner{opts: opts, net: netw}, nil
}

// Network returns the detected network configuration.
func (s *Scanner) Network() *Network { return s.net }

// Options returns a copy of the scanner options.
func (s *Scanner) Options() Options { return s.opts }

// Scan discovers hosts and enriches them. progress may be nil. found is called
// with partial results as soon as hosts are discovered, and may be nil.
func (s *Scanner) Scan(ctx context.Context, progress func(Progress), found func(Device)) ([]Device, Summary, error) {
	summary := Summary{Started: time.Now()}
	if progress == nil {
		progress = func(Progress) {}
	}
	if found == nil {
		found = func(Device) {}
	}

	hosts, truncated := s.net.Hosts(s.opts.MaxHosts)
	summary.Hosts = len(hosts)
	summary.Truncated = truncated
	if len(hosts) == 0 {
		return nil, summary, fmt.Errorf("no host addresses in subnet %s", s.net.Prefix)
	}

	// Phase 1: ICMP and a cheap TCP probe run concurrently. The TCP probe also
	// primes the kernel's ARP table for hosts that ignore ICMP.
	var pingDone, aliveDone atomic.Int64
	totalDiscover := len(hosts) * 2
	reportDiscover := func() {
		d := int(pingDone.Load() + aliveDone.Load())
		progress(Progress{Phase: "Discovering hosts", Done: d, Total: totalDiscover})
	}
	progress(Progress{Phase: "Discovering hosts", Done: 0, Total: totalDiscover})

	type pingResult struct {
		rtt map[netip.Addr]time.Duration
		ok  bool
	}
	pingCh := make(chan pingResult, 1)
	go func() {
		rtts, ok := pingSweep(ctx, hosts, s.opts.PingTimeout, 96, func(done, total int) {
			pingDone.Store(int64(done))
			reportDiscover()
		})
		pingCh <- pingResult{rtt: rtts, ok: ok}
	}()

	aliveCh := make(chan map[netip.Addr]time.Duration, 1)
	go func() {
		aliveCh <- tcpAlive(ctx, hosts, s.opts.PortTimeout, 128, func(done, total int) {
			aliveDone.Store(int64(done))
			reportDiscover()
		})
	}()

	ping := <-pingCh
	alive := <-aliveCh
	summary.PingAvailable = ping.ok

	if err := ctx.Err(); err != nil {
		return nil, summary, err
	}

	up := make(map[netip.Addr]hostInfo, len(ping.rtt)+len(alive))
	for ip, rtt := range ping.rtt {
		up[ip] = hostInfo{rtt: rtt, source: "icmp"}
	}
	for ip, rtt := range alive {
		if prev, ok := up[ip]; !ok || prev.rtt == 0 {
			up[ip] = hostInfo{rtt: rtt, source: "tcp"}
		}
	}

	// Phase 2: read the kernel neighbor table. Any valid ARP entry proves a
	// host is present, even if it blocks ICMP and all probed TCP ports.
	macByIP := map[netip.Addr]string{}
	if neighbors, err := neighborTable(s.net.Interface.Index); err == nil {
		for _, n := range neighbors {
			if !s.net.Prefix.Contains(n.IP) {
				continue
			}
			if n.Iface != "" && n.Iface != s.net.InterfaceName {
				continue
			}
			if n.MAC != "" {
				if prev, ok := macByIP[n.IP]; !ok || prev == "" {
					macByIP[n.IP] = n.MAC
				}
			}
			if _, ok := up[n.IP]; !ok {
				up[n.IP] = hostInfo{source: "arp"}
			}
		}
	}

	// The scanning host is always present.
	if s.net.Prefix.Contains(s.net.LocalIP) {
		if _, ok := up[s.net.LocalIP]; !ok {
			up[s.net.LocalIP] = hostInfo{source: "local"}
		}
		if mac := s.net.LocalMAC.String(); mac != "" {
			if _, ok := macByIP[s.net.LocalIP]; !ok {
				macByIP[s.net.LocalIP] = mac
			}
		}
	}
	// A default gateway on this subnet is reachable by definition.
	if s.net.Gateway.IsValid() && s.net.Prefix.Contains(s.net.Gateway) {
		if _, ok := up[s.net.Gateway]; !ok {
			up[s.net.Gateway] = hostInfo{source: "route"}
		}
	}

	now := time.Now()
	devices := make([]Device, 0, len(up))
	for ip, info := range up {
		mac := macByIP[ip]
		if mac == "" && ip == s.net.LocalIP {
			mac = s.net.LocalMAC.String()
		}
		devices = append(devices, Device{
			IP:         ip,
			MAC:        mac,
			Vendor:     oui.Lookup(mac),
			RTT:        info.rtt,
			Online:     true,
			Self:       ip == s.net.LocalIP,
			Gateway:    ip == s.net.Gateway && s.net.Gateway.IsValid(),
			LastSeen:   now,
			NameSource: "",
		})
	}
	sort.Slice(devices, func(i, j int) bool { return devices[i].IP.Less(devices[j].IP) })
	for _, d := range devices {
		found(d)
	}

	// Phase 3: full TCP port scan of the hosts that responded.
	upIPs := make([]netip.Addr, 0, len(devices))
	for _, d := range devices {
		upIPs = append(upIPs, d.IP)
	}
	portTotal := len(upIPs) * len(s.opts.Ports)
	progress(Progress{Phase: "Scanning ports", Done: 0, Total: portTotal})
	openPorts, portRTT := portScan(ctx, upIPs, s.opts.Ports, s.opts.PortTimeout, 384, func(done, total int) {
		progress(Progress{Phase: "Scanning ports", Done: done, Total: total})
	})
	for i := range devices {
		ports := openPorts[devices[i].IP]
		devices[i].Ports = ports
		summary.OpenPorts += len(ports)
		if devices[i].RTT == 0 {
			if rtt, ok := portRTT[devices[i].IP]; ok {
				devices[i].RTT = rtt
			}
		}
	}

	if err := ctx.Err(); err != nil {
		return devices, summary, err
	}

	// Phase 4: names and models.
	progress(Progress{Phase: "Resolving names and models", Done: 0, Total: 1})
	names, models := resolveNames(ctx, s.net.Interface, s.net.Gateway, devices, 1500*time.Millisecond, s.opts.DisableMDNS, s.opts.DisableNBNS)
	for i := range devices {
		if c, ok := names[devices[i].IP]; ok {
			devices[i].Hostname = c.name
			devices[i].NameSource = c.source
		}
		if model := models[devices[i].IP]; model != "" {
			devices[i].Model = model
		}
	}
	progress(Progress{Phase: "Resolving names and models", Done: 1, Total: 1})

	if host, err := os.Hostname(); err == nil && devices != nil {
		for i := range devices {
			if devices[i].Self && devices[i].Hostname == "" {
				devices[i].Hostname = cleanHostname(host)
				devices[i].NameSource = "local"
			}
		}
	}

	summary.Up = len(devices)
	summary.Finished = time.Now()
	return devices, summary, nil
}
