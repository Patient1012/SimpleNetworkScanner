package scan

import (
	"bytes"
	"context"
	"encoding/xml"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

const ssdpTarget = "239.255.255.250:1900"

type modelCandidate struct {
	model string
	score int
}

// discoverSSDPModels sends an SSDP M-SEARCH and reads the UPnP device
// descriptions of the responders to extract model names. It only considers
// hosts that were already discovered during the scan.
func discoverSSDPModels(ctx context.Context, ips []netip.Addr, timeout time.Duration) map[netip.Addr]modelCandidate {
	if len(ips) == 0 {
		return nil
	}
	allowed := make(map[netip.Addr]bool, len(ips))
	for _, ip := range ips {
		if ip.Is4() {
			allowed[ip] = true
		}
	}

	started := time.Now()
	listenTimeout := minDuration(timeout, 800*time.Millisecond)
	locations := ssdpLocations(ctx, listenTimeout)
	if len(locations) == 0 {
		return nil
	}
	fetchTimeout := timeout - time.Since(started)
	if fetchTimeout < 300*time.Millisecond {
		fetchTimeout = 300 * time.Millisecond
	}

	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		results = map[netip.Addr]modelCandidate{}
		sem     = make(chan struct{}, 12)
	)
	for ip, location := range locations {
		if !allowed[ip] {
			continue
		}
		wg.Add(1)
		go func(ip netip.Addr, location string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			model := fetchUPnPModel(ctx, location, minDuration(fetchTimeout, 2*time.Second))
			if model == "" {
				return
			}
			mu.Lock()
			if prev, ok := results[ip]; !ok || prev.model == "" {
				results[ip] = modelCandidate{model: model, score: 80}
			}
			mu.Unlock()
		}(ip, location)
	}
	wg.Wait()
	return results
}

// ssdpLocations returns a map of responder IP to UPnP description URL.
func ssdpLocations(ctx context.Context, timeout time.Duration) map[netip.Addr]string {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		return nil
	}
	defer conn.Close()

	group := &net.UDPAddr{IP: net.IPv4(239, 255, 255, 250), Port: 1900}
	request := []byte("M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 1\r\n" +
		"ST: ssdp:all\r\n" +
		"USER-AGENT: netscan/1.0 UPnP/1.1\r\n\r\n")
	send := func() {
		_, _ = conn.WriteToUDP(request, group)
	}
	send()

	deadline := time.Now().Add(timeout)
	retryAt := time.Now().Add(300 * time.Millisecond)
	out := map[netip.Addr]string{}
	buf := make([]byte, 8192)

	for {
		now := time.Now()
		if now.After(deadline) || ctx.Err() != nil {
			break
		}
		if now.After(retryAt) {
			send()
			retryAt = deadline.Add(time.Second) // retransmit only once
		}

		wait := 100 * time.Millisecond
		if left := time.Until(deadline); left < wait {
			wait = left
		}
		if wait <= 0 {
			break
		}
		_ = conn.SetReadDeadline(time.Now().Add(wait))
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		ip, ok := netip.AddrFromSlice(addr.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		if !ip.Is4() {
			continue
		}
		location := parseSSDPHeaders(buf[:n])
		if location == "" {
			continue
		}
		if _, exists := out[ip]; !exists {
			out[ip] = location
		}
	}
	return out
}

// parseSSDPHeaders extracts the LOCATION header from an SSDP response.
func parseSSDPHeaders(pkt []byte) string {
	text := string(pkt)
	first, _, _ := strings.Cut(text, "\r\n")
	if !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(first)), "HTTP/") {
		return ""
	}
	for _, line := range strings.Split(text, "\r\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok || !strings.EqualFold(strings.TrimSpace(key), "location") {
			continue
		}
		location := strings.TrimSpace(value)
		u, err := url.Parse(location)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return ""
		}
		return location
	}
	return ""
}

var upnpHTTPClient = &http.Client{
	Timeout: 3 * time.Second,
	Transport: &http.Transport{
		Proxy:               nil,
		DialContext:         (&net.Dialer{Timeout: time.Second}).DialContext,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     5 * time.Second,
	},
}

func fetchUPnPModel(ctx context.Context, location string, timeout time.Duration) string {
	lookupCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(lookupCtx, http.MethodGet, location, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "netscan/1.0 UPnP/1.1")
	resp, err := upnpHTTPClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ""
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return ""
	}
	return parseUPnPModel(data)
}

type upnpDescription struct {
	XMLName xml.Name   `xml:"root"`
	Device  upnpDevice `xml:"device"`
}

type upnpDevice struct {
	FriendlyName     string       `xml:"friendlyName"`
	Manufacturer     string       `xml:"manufacturer"`
	ModelName        string       `xml:"modelName"`
	ModelNumber      string       `xml:"modelNumber"`
	ModelDescription string       `xml:"modelDescription"`
	Devices          []upnpDevice `xml:"deviceList>device"`
}

// parseUPnPModel extracts the most useful model string from a UPnP device
// description document.
func parseUPnPModel(data []byte) string {
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
	var root upnpDescription
	if err := xml.Unmarshal(data, &root); err != nil {
		return ""
	}
	return firstUPnPModel(root.Device)
}

func firstUPnPModel(d upnpDevice) string {
	for _, candidate := range []string{
		d.ModelName,
		d.ModelNumber,
		d.ModelDescription,
	} {
		if model := cleanModel(candidate); model != "" {
			return model
		}
	}
	for _, child := range d.Devices {
		if model := firstUPnPModel(child); model != "" {
			return model
		}
	}
	return ""
}

func cleanModel(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	s = strings.TrimSpace(s)
	if len(s) > 64 {
		runes := []rune(s)
		if len(runes) > 64 {
			s = strings.TrimSpace(string(runes[:63])) + "…"
		}
	}
	switch strings.ToLower(s) {
	case "", "unknown", "none", "n/a", "na", "generic", "default", "device":
		return ""
	}
	return s
}

func minDuration(a, b time.Duration) time.Duration {
	if a <= 0 {
		return b
	}
	if b <= 0 {
		return a
	}
	if a < b {
		return a
	}
	return b
}
