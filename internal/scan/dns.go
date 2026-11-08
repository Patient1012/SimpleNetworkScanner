package scan

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const dnsQueryTimeout = 500 * time.Millisecond

// reverseDNSNames asks the local DNS servers (the gateway first) for PTR
// records. The system resolver is not always usable on home networks: a stale
// nameserver in /etc/resolv.conf can make LookupAddr time out even though the
// router knows every device name.
func reverseDNSNames(ctx context.Context, gateway netip.Addr, ips []netip.Addr, timeout time.Duration) map[netip.Addr]nameCandidate {
	servers := dnsServers(gateway)
	if len(servers) == 0 || len(ips) == 0 {
		return nil
	}

	deadline := time.Now().Add(timeout)
	out := map[netip.Addr]nameCandidate{}
	var mu sync.Mutex
	sem := make(chan struct{}, 24)
	var done = make(chan struct{}, len(ips))

	for _, ip := range ips {
		go func(ip netip.Addr) {
			defer func() { done <- struct{}{} }()
			sem <- struct{}{}
			defer func() { <-sem }()

			remaining := time.Until(deadline)
			if remaining <= 0 {
				return
			}
			perQuery := dnsQueryTimeout
			if remaining < perQuery {
				perQuery = remaining
			}
			for _, server := range servers {
				if ctx.Err() != nil {
					return
				}
				name, authoritative := lookupPTR(ctx, server, ip, perQuery)
				if name != "" {
					mu.Lock()
					out[ip] = nameCandidate{name: name, source: "dns", score: 65}
					mu.Unlock()
					return
				}
				// A definitive answer from the first server (usually the
				// gateway) means another server is unlikely to know more.
				if authoritative {
					return
				}
			}
		}(ip)
	}
	// Wait for every goroutine: returning early would race with writers.
	for range ips {
		<-done
	}
	return out
}

// dnsServers returns candidate DNS servers with the gateway first. Only
// addresses that can plausibly serve the local subnet are considered.
func dnsServers(gateway netip.Addr) []netip.Addr {
	var servers []netip.Addr
	seen := map[netip.Addr]bool{}
	add := func(addr netip.Addr) {
		if !addr.IsValid() || addr.IsUnspecified() || seen[addr] {
			return
		}
		seen[addr] = true
		servers = append(servers, addr)
	}
	if gateway.IsValid() && gateway.Is4() {
		add(gateway)
	}
	for _, addr := range resolvConfServers() {
		add(addr)
	}
	return servers
}

func resolvConfServers() []netip.Addr {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "nameserver") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		addr, err := netip.ParseAddr(fields[1])
		if err != nil {
			continue
		}
		out = append(out, addr.Unmap())
	}
	return out
}

// lookupPTR queries one server for a reverse record. The second return value
// reports whether the server gave a definitive answer (even an empty one).
func lookupPTR(ctx context.Context, server, ip netip.Addr, timeout time.Duration) (string, bool) {
	id := dnsID()
	wire, err := buildDNSQuery(id, reverseARPA(ip), dnsmessage.TypePTR)
	if err != nil {
		return "", false
	}

	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "udp", net.JoinHostPort(server.String(), "53"))
	if err != nil {
		return "", false
	}
	defer conn.Close()

	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)

	if _, err := conn.Write(wire); err != nil {
		return "", false
	}
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		return "", false
	}
	name, definitive := parsePTRResponse(buf[:n], id)
	if name != "" {
		name = cleanHostname(name)
		if !isReasonableName(name) {
			return "", definitive
		}
	}
	return name, definitive
}

func buildDNSQuery(id uint16, name string, qtype dnsmessage.Type) ([]byte, error) {
	n, err := dnsmessage.NewName(name)
	if err != nil {
		return nil, err
	}
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name:  n,
			Type:  qtype,
			Class: dnsmessage.ClassINET,
		}},
	}
	return msg.Pack()
}

func parsePTRResponse(pkt []byte, id uint16) (string, bool) {
	var p dnsmessage.Parser
	hdr, err := p.Start(pkt)
	if err != nil || !hdr.Response || hdr.ID != id {
		return "", false
	}
	definitive := hdr.RCode == dnsmessage.RCodeSuccess || hdr.RCode == dnsmessage.RCodeNameError
	if err := p.SkipAllQuestions(); err != nil {
		return "", false
	}
	for {
		r, err := p.Answer()
		if err != nil {
			if errors.Is(err, dnsmessage.ErrSectionDone) {
				break
			}
			return "", definitive
		}
		if ptr, ok := r.Body.(*dnsmessage.PTRResource); ok {
			target := strings.TrimSuffix(ptr.PTR.String(), ".")
			if isReasonableName(target) {
				return target, true
			}
		}
	}
	return "", definitive
}

func dnsID() uint16 {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return uint16(time.Now().UnixNano())
	}
	return binary.BigEndian.Uint16(b[:])
}
