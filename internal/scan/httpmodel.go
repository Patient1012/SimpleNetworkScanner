package scan

import (
	"context"
	"crypto/tls"
	"html"
	"io"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

var localHTTPClient = &http.Client{
	Timeout: 3 * time.Second,
	Transport: &http.Transport{
		Proxy: nil,
		DialContext: (&net.Dialer{
			Timeout: time.Second,
		}).DialContext,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, // local devices often use self-signed certificates
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     5 * time.Second,
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return http.ErrUseLastResponse
		}
		if len(via) > 0 && !strings.EqualFold(req.URL.Hostname(), via[0].URL.Hostname()) {
			return http.ErrUseLastResponse
		}
		return nil
	},
}

// discoverHTTPModels falls back to the web interface of devices with open HTTP
// ports. Many appliances expose their product name in the page title or in the
// Server header even when UPnP is disabled.
func discoverHTTPModels(ctx context.Context, devices []Device, timeout time.Duration) map[netip.Addr]modelCandidate {
	if len(devices) == 0 {
		return nil
	}
	deadline := time.Now().Add(timeout)
	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		results = map[netip.Addr]modelCandidate{}
		sem     = make(chan struct{}, 12)
	)
	for _, d := range devices {
		targets := httpModelTargets(d)
		if len(targets) == 0 {
			continue
		}
		wg.Add(1)
		go func(d Device, targets []string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			for _, target := range targets {
				remaining := time.Until(deadline)
				if remaining <= 0 || ctx.Err() != nil {
					return
				}
				candidate := fetchHTTPModel(ctx, target, d, remaining)
				if candidate.model == "" {
					continue
				}
				mu.Lock()
				if prev, ok := results[d.IP]; !ok || candidate.score > prev.score {
					results[d.IP] = candidate
				}
				mu.Unlock()
				return
			}
		}(d, targets)
	}
	wg.Wait()
	return results
}

func httpModelTargets(d Device) []string {
	open := make(map[int]bool, len(d.Ports))
	for _, p := range d.Ports {
		open[p] = true
	}
	if d.Self || !d.IP.IsValid() {
		return nil
	}
	ip := d.IP.String()
	var targets []string
	for _, port := range []int{80, 443, 5000, 8080, 8443, 8000, 8008, 8081, 9000} {
		if !open[port] {
			continue
		}
		scheme := "http"
		if port == 443 || port == 8443 {
			scheme = "https"
		}
		host := ip
		if port != 80 && port != 443 {
			host = net.JoinHostPort(ip, strconv.Itoa(port))
		}
		targets = append(targets, scheme+"://"+host+"/")
		if len(targets) == 3 {
			break
		}
	}
	return targets
}

func fetchHTTPModel(ctx context.Context, target string, d Device, timeout time.Duration) modelCandidate {
	lookupCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(lookupCtx, http.MethodGet, target, nil)
	if err != nil {
		return modelCandidate{}
	}
	req.Header.Set("User-Agent", "netscan/1.0")
	resp, err := localHTTPClient.Do(req)
	if err != nil {
		return modelCandidate{}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 512<<10))
	if err != nil {
		return modelCandidate{}
	}
	if match := titleRe.FindSubmatch(body); len(match) > 1 {
		title := html.UnescapeString(string(match[1]))
		if model := modelFromTitle(title, d); model != "" {
			return modelCandidate{model: model, score: 65}
		}
	}

	// Some appliances expose the model only in the Server header.
	if model := modelFromServerHeader(resp.Header.Get("Server"), d); model != "" {
		return modelCandidate{model: model, score: 55}
	}
	return modelCandidate{}
}

func modelFromTitle(title string, d Device) string {
	title = cleanModel(title)
	if title == "" {
		return ""
	}
	title = stripPageSuffix(title)
	parts := splitTitle(title)
	if len(parts) > 1 && looksLikeHostLabel(parts[0], d) {
		parts = parts[1:]
	}
	if len(parts) > 1 && looksLikeHostLabel(parts[len(parts)-1], d) {
		parts = parts[:len(parts)-1]
	}
	title = cleanModel(strings.Join(parts, " - "))
	if title == "" || isGenericModel(title) {
		return ""
	}
	return title
}

func modelFromServerHeader(server string, d Device) string {
	server = strings.TrimSpace(server)
	if server == "" {
		return ""
	}
	for _, part := range strings.Split(server, ";") {
		part = strings.TrimSpace(part)
		if part == "" || isGenericServer(part) {
			continue
		}
		if i := strings.Index(part, " - "); i > 0 {
			suffix := strings.TrimSpace(part[i+3:])
			if looksLikeSerial(suffix) {
				part = strings.TrimSpace(part[:i])
			}
		}
		model := cleanModel(part)
		if model == "" || isGenericModel(model) {
			continue
		}
		return model
	}
	return ""
}

func stripPageSuffix(title string) string {
	for _, suffix := range []string{" - login", " | login", " login", " - sign in", " - log in", " - web interface", " - web ui"} {
		if strings.HasSuffix(strings.ToLower(title), suffix) {
			title = strings.TrimSpace(title[:len(title)-len(suffix)])
			break
		}
	}
	return title
}

func splitTitle(title string) []string {
	for _, sep := range []string{" - ", " | ", " — ", " · "} {
		if strings.Contains(title, sep) {
			parts := strings.Split(title, sep)
			for i := range parts {
				parts[i] = strings.TrimSpace(parts[i])
			}
			return parts
		}
	}
	return []string{title}
}

func looksLikeHostLabel(s string, d Device) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	if strings.EqualFold(s, d.IP.String()) || strings.EqualFold(s, d.Hostname) {
		return true
	}
	if d.Hostname != "" && strings.HasPrefix(strings.ToLower(s), strings.ToLower(d.Hostname)+".") {
		return true
	}
	// Unresolved names such as "NAS-1" still look like host labels, unlike
	// product words such as "UniFi" or "Synology".
	hasDigit := strings.IndexFunc(s, func(r rune) bool { return r >= '0' && r <= '9' }) >= 0
	return hasDigit && !strings.Contains(s, " ") && len(s) <= 32
}

func looksLikeSerial(s string) bool {
	if s == "" || len(s) > 16 || strings.Contains(s, " ") {
		return false
	}
	hasDigit := false
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			hasDigit = true
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '-', r == '_':
		default:
			return false
		}
	}
	return hasDigit
}

func isGenericServer(s string) bool {
	lower := strings.ToLower(strings.TrimSpace(s))
	for _, generic := range []string{
		"nginx", "apache", "httpd", "lighttpd", "caddy", "openresty", "envoy",
		"cloudflare", "microsoft-iis", "gunicorn", "uvicorn", "werkzeug",
		"jetty", "tomcat", "python", "go-http-client", "http server", "upnp",
		"linux", "windows", "unix", "server",
	} {
		if strings.Contains(lower, generic) {
			return true
		}
	}
	return false
}

func isGenericModel(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "home", "login", "log in", "sign in", "welcome", "index",
		"document", "untitled document", "dashboard", "web interface", "web ui",
		"router", "server", "device", "default", "admin", "status", "overview",
		"main page", "page not found", "404 not found", "not found":
		return true
	}
	return false
}
