package scan

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type hostInfo struct {
	rtt    time.Duration
	source string
}

// pingSweep probes hosts with ICMP echo requests. Each worker owns a socket so
// reads can happen concurrently. It returns nil, false when unprivileged ICMP
// is unavailable.
func pingSweep(ctx context.Context, hosts []netip.Addr, timeout time.Duration, workers int, onProgress func(done, total int)) (map[netip.Addr]time.Duration, bool) {
	if len(hosts) == 0 {
		return map[netip.Addr]time.Duration{}, true
	}
	probe, err := icmp.ListenPacket("udp4", "0.0.0.0")
	if err != nil {
		return nil, false
	}
	probe.Close()

	if workers < 1 {
		workers = 1
	}
	if workers > len(hosts) {
		workers = len(hosts)
	}
	if workers > 128 {
		workers = 128
	}

	type result struct {
		ip  netip.Addr
		rtt time.Duration
		ok  bool
	}
	results := make(chan result, len(hosts))

	var conns []*icmp.PacketConn
	for i := 0; i < workers; i++ {
		conn, err := icmp.ListenPacket("udp4", "0.0.0.0")
		if err != nil {
			continue
		}
		conns = append(conns, conn)
	}
	if len(conns) == 0 {
		return nil, false
	}
	workers = len(conns)

	jobs := make(chan netip.Addr)
	var wg sync.WaitGroup
	for i, c := range conns {
		wg.Add(1)
		go func(c *icmp.PacketConn, id int) {
			defer wg.Done()
			defer c.Close()
			seq := 0
			for ip := range jobs {
				if ctx.Err() != nil {
					results <- result{ip: ip}
					continue
				}
				seq++
				rtt, ok := pingOne(c, ip, id, seq, timeout)
				results <- result{ip: ip, rtt: rtt, ok: ok}
			}
		}(c, 1000+i)
	}

	go func() {
		defer close(jobs)
		for _, ip := range hosts {
			select {
			case jobs <- ip:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	up := make(map[netip.Addr]time.Duration, len(hosts))
	done := 0
	for r := range results {
		done++
		if r.ok {
			up[r.ip] = r.rtt
		}
		if onProgress != nil && (done == len(hosts) || done%8 == 0) {
			onProgress(done, len(hosts))
		}
	}
	return up, true
}

func pingOne(c *icmp.PacketConn, ip netip.Addr, id, seq int, timeout time.Duration) (time.Duration, bool) {
	dst := &net.UDPAddr{IP: net.IP(ip.AsSlice())}
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{ID: id, Seq: seq, Data: []byte("netscan")},
	}
	wire, err := msg.Marshal(nil)
	if err != nil {
		return 0, false
	}
	start := time.Now()
	if _, err := c.WriteTo(wire, dst); err != nil {
		return 0, false
	}
	if err := c.SetReadDeadline(start.Add(timeout)); err != nil {
		return 0, false
	}
	buf := make([]byte, 1500)
	for {
		n, peer, err := c.ReadFrom(buf)
		if err != nil {
			return 0, false
		}
		udpPeer, ok := peer.(*net.UDPAddr)
		if !ok || !udpPeer.IP.Equal(dst.IP) {
			continue
		}
		reply, err := icmp.ParseMessage(1, buf[:n])
		if err != nil {
			continue
		}
		if reply.Type == ipv4.ICMPTypeEchoReply {
			return time.Since(start), true
		}
	}
}

// tcpAlive sends a few cheap connection attempts to determine whether a host
// responds at all. Connection refused still proves the host is alive.
func tcpAlive(ctx context.Context, hosts []netip.Addr, timeout time.Duration, workers int, onProgress func(done, total int)) map[netip.Addr]time.Duration {
	ports := []int{80, 443, 445}
	up := make(map[netip.Addr]time.Duration)
	var mu sync.Mutex
	var done int64

	if workers < 1 {
		workers = 32
	}
	if workers > len(hosts) && len(hosts) > 0 {
		workers = len(hosts)
	}

	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for _, ip := range hosts {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(ip netip.Addr) {
			defer wg.Done()
			defer func() { <-sem }()
			for _, port := range ports {
				if ctx.Err() != nil {
					break
				}
				rtt, alive := dialProbe(ip, port, timeout)
				if alive {
					mu.Lock()
					up[ip] = rtt
					mu.Unlock()
					break
				}
			}
			n := atomic.AddInt64(&done, 1)
			if onProgress != nil && (int(n) == len(hosts) || n%8 == 0) {
				onProgress(int(n), len(hosts))
			}
		}(ip)
	}
	wg.Wait()
	return up
}

// dialProbe returns the round-trip time and whether the host is alive.
func dialProbe(ip netip.Addr, port int, timeout time.Duration) (time.Duration, bool) {
	start := time.Now()
	conn, err := net.DialTimeout("tcp4", net.JoinHostPort(ip.String(), itoa(port)), timeout)
	if err == nil {
		conn.Close()
		return time.Since(start), true
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case syscall.ECONNREFUSED, syscall.ECONNRESET, syscall.EHOSTUNREACH, syscall.ENETUNREACH:
			// Refused/reset means the host responded. Unreachable means it
			// did not, but this still triggers ARP resolution.
			return time.Since(start), errno == syscall.ECONNREFUSED || errno == syscall.ECONNRESET
		}
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Timeout() {
		return 0, false
	}
	return 0, false
}

// portScan probes every configured TCP port on the given hosts and returns
// open ports per host plus the best observed RTT.
func portScan(ctx context.Context, hosts []netip.Addr, ports []int, timeout time.Duration, workers int, onProgress func(done, total int)) (map[netip.Addr][]int, map[netip.Addr]time.Duration) {
	open := make(map[netip.Addr][]int)
	rtts := make(map[netip.Addr]time.Duration)
	if len(hosts) == 0 || len(ports) == 0 {
		return open, rtts
	}

	type job struct {
		ip   netip.Addr
		port int
	}
	type result struct {
		ip   netip.Addr
		port int
		rtt  time.Duration
		open bool
	}

	total := len(hosts) * len(ports)
	if workers < 1 {
		workers = 256
	}
	if workers > total {
		workers = total
	}
	jobs := make(chan job)
	results := make(chan result, workers*2)

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if ctx.Err() != nil {
					continue
				}
				rtt, ok := scanPort(j.ip, j.port, timeout)
				results <- result{ip: j.ip, port: j.port, rtt: rtt, open: ok}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, ip := range hosts {
			for _, port := range ports {
				select {
				case jobs <- job{ip: ip, port: port}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	go func() {
		wg.Wait()
		close(results)
	}()

	done := 0
	for r := range results {
		done++
		if r.open {
			open[r.ip] = append(open[r.ip], r.port)
			if prev, ok := rtts[r.ip]; !ok || r.rtt < prev {
				rtts[r.ip] = r.rtt
			}
		}
		if onProgress != nil && (done == total || done%32 == 0) {
			onProgress(done, total)
		}
	}
	for ip := range open {
		sort.Ints(open[ip])
	}
	return open, rtts
}

func scanPort(ip netip.Addr, port int, timeout time.Duration) (time.Duration, bool) {
	start := time.Now()
	conn, err := net.DialTimeout("tcp4", net.JoinHostPort(ip.String(), itoa(port)), timeout)
	if err != nil {
		return 0, false
	}
	conn.Close()
	return time.Since(start), true
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [6]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
