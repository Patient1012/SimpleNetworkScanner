package scan

import (
	"context"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"
)

// resolveNames combines DHCP leases, mDNS, NetBIOS and reverse DNS into the
// best available name for each host.
func resolveNames(ctx context.Context, iface *net.Interface, gateway netip.Addr, devices []Device, timeout time.Duration, disableMDNS, disableNBNS bool) map[netip.Addr]nameCandidate {
	if len(devices) == 0 {
		return nil
	}
	ips := make([]netip.Addr, 0, len(devices))
	for _, d := range devices {
		ips = append(ips, d.IP)
	}

	candidates := map[netip.Addr]nameCandidate{}
	merge := func(extra map[netip.Addr]nameCandidate) {
		for ip, c := range extra {
			if prev, ok := candidates[ip]; !ok || c.score > prev.score {
				candidates[ip] = c
			}
		}
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	wg.Add(1)
	go func() {
		defer wg.Done()
		lease := readDHCPLeases()
		mu.Lock()
		defer mu.Unlock()
		for _, d := range devices {
			name := ""
			if n, ok := lease.byIP[d.IP]; ok {
				name = n
			} else if n, ok := lease.byMAC[d.MAC]; ok {
				name = n
			}
			if name != "" {
				mergeOne(candidates, d.IP, nameCandidate{name: name, source: "dhcp", score: 85})
			}
		}
	}()

	if !disableMDNS {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result := mdnsNames(ctx, iface, ips, timeout)
			mu.Lock()
			defer mu.Unlock()
			merge(result)
		}()
	}

	if !disableNBNS {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result := nbnsNames(ctx, ips, 500*time.Millisecond, 24)
			mu.Lock()
			defer mu.Unlock()
			merge(result)
		}()
	}

	// Direct PTR queries to the local DNS servers (gateway first). This is more
	// reliable than the system resolver when /etc/resolv.conf lists a stale
	// nameserver ahead of the router.
	wg.Add(1)
	go func() {
		defer wg.Done()
		result := reverseDNSNames(ctx, gateway, ips, timeout)
		mu.Lock()
		defer mu.Unlock()
		merge(result)
	}()

	// Reverse DNS runs concurrently and is capped so a slow resolver does not
	// stall the scan.
	resolverDone := make(chan map[netip.Addr]nameCandidate, 1)
	go func() {
		result := map[netip.Addr]nameCandidate{}
		sem := make(chan struct{}, 16)
		var wgDNS sync.WaitGroup
		var dnsMu sync.Mutex
		for _, ip := range ips {
			wgDNS.Add(1)
			sem <- struct{}{}
			go func(ip netip.Addr) {
				defer wgDNS.Done()
				defer func() { <-sem }()
				lookupCtx, cancel := context.WithTimeout(ctx, time.Second)
				defer cancel()
				names, err := net.DefaultResolver.LookupAddr(lookupCtx, ip.String())
				if err != nil || len(names) == 0 {
					return
				}
				for _, n := range names {
					n = cleanHostname(n)
					if isReasonableName(n) {
						dnsMu.Lock()
						if prev, ok := result[ip]; !ok || len(n) < len(prev.name) {
							result[ip] = nameCandidate{name: n, source: "dns", score: 45}
						}
						dnsMu.Unlock()
						return
					}
				}
			}(ip)
		}
		wgDNS.Wait()
		resolverDone <- result
	}()

	wg.Wait()
	select {
	case result := <-resolverDone:
		mu.Lock()
		merge(result)
		mu.Unlock()
	case <-time.After(timeout + 500*time.Millisecond):
	case <-ctx.Done():
	}

	if host, err := os.Hostname(); err == nil {
		if n := cleanHostname(host); isReasonableName(n) {
			for _, d := range devices {
				if d.Self {
					mergeOne(candidates, d.IP, nameCandidate{name: n, source: "local", score: 95})
				}
			}
		}
	}
	return candidates
}

func mergeOne(m map[netip.Addr]nameCandidate, ip netip.Addr, c nameCandidate) {
	if prev, ok := m[ip]; !ok || c.score > prev.score {
		m[ip] = c
	}
}
