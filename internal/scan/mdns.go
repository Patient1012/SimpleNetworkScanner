package scan

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

var mdnsServices = []string{
	"_services._dns-sd._udp.local.",
	"_device-info._tcp.local.",
	"_workstation._tcp.local.",
	"_http._tcp.local.",
	"_https._tcp.local.",
	"_smb._tcp.local.",
	"_ssh._tcp.local.",
	"_ipp._tcp.local.",
	"_printer._tcp.local.",
	"_airplay._tcp.local.",
	"_raop._tcp.local.",
	"_googlecast._tcp.local.",
	"_homekit._tcp.local.",
	"_companion-link._tcp.local.",
	"_spotify-connect._tcp.local.",
}

type nameCandidate struct {
	name   string
	source string
	score  int
}

type mdnsRecords struct {
	a        map[string]netip.Addr        // hostname -> IPv4
	srv      map[string]string            // instance -> target
	instance map[string]string            // instance -> friendly name
	reverse  map[netip.Addr]string        // IP -> PTR hostname
	txt      map[string]map[string]string // record owner -> TXT keys
}

// mdnsNames performs a short mDNS/Bonjour discovery using reverse PTR queries
// for the discovered hosts and PTR queries for common service types. It
// returns names and any model information advertised in TXT records.
func mdnsNames(ctx context.Context, iface *net.Interface, hosts []netip.Addr, timeout time.Duration) (map[netip.Addr]nameCandidate, map[netip.Addr]modelCandidate) {
	if len(hosts) == 0 {
		return nil, nil
	}
	group := &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}

	// Multicast listener receives the usual mDNS replies.
	mc, _ := net.ListenMulticastUDP("udp4", iface, group)
	if mc != nil {
		defer mc.Close()
		_ = mc.SetReadBuffer(1 << 20)
	}

	// Unicast socket sends queries and also catches unicast (QU) replies.
	uc, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return nil, nil
	}
	defer uc.Close()
	_ = uc.SetReadBuffer(1 << 20)

	packets := make(chan []byte, 512)
	stop := make(chan struct{})
	defer close(stop)

	read := func(conn *net.UDPConn) {
		buf := make([]byte, 9000)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			n, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				select {
				case <-stop:
					return
				default:
					continue
				}
			}
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			select {
			case packets <- pkt:
			case <-stop:
				return
			}
		}
	}
	if mc != nil {
		go read(mc)
	}
	go read(uc)

	query := func(name string, qtype dnsmessage.Type, unicast bool) {
		wire, err := buildMDNSQuery(name, qtype, unicast)
		if err != nil {
			return
		}
		_, _ = uc.WriteToUDP(wire, group)
	}

	for _, ip := range hosts {
		query(reverseARPA(ip), dnsmessage.TypePTR, true)
	}
	for _, svc := range mdnsServices {
		query(svc, dnsmessage.TypePTR, false)
	}

	records := mdnsRecords{
		a:        map[string]netip.Addr{},
		srv:      map[string]string{},
		instance: map[string]string{},
		reverse:  map[netip.Addr]string{},
		txt:      map[string]map[string]string{},
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return mdnsResults(records), mdnsModels(records)
		case pkt := <-packets:
			parseMDNS(pkt, &records)
		case <-time.After(100 * time.Millisecond):
		}
	}
	return mdnsResults(records), mdnsModels(records)
}

func buildMDNSQuery(name string, qtype dnsmessage.Type, unicast bool) ([]byte, error) {
	n, err := dnsmessage.NewName(name)
	if err != nil {
		return nil, err
	}
	class := dnsmessage.ClassINET
	if unicast {
		class |= 0x8000 // QU bit: request a unicast response
	}
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 0, RecursionDesired: false},
		Questions: []dnsmessage.Question{{Name: n, Type: qtype, Class: class}},
	}
	return msg.Pack()
}

func parseMDNS(pkt []byte, rec *mdnsRecords) {
	var p dnsmessage.Parser
	if _, err := p.Start(pkt); err != nil {
		return
	}
	if err := p.SkipAllQuestions(); err != nil {
		return
	}
	parseSection := func(section int) {
		for {
			var (
				r   dnsmessage.Resource
				err error
			)
			switch section {
			case 0:
				r, err = p.Answer()
			case 1:
				r, err = p.Additional()
			default:
				r, err = p.Authority()
			}
			if err != nil {
				return
			}
			name := normalizeDNSName(r.Header.Name.String())
			switch b := r.Body.(type) {
			case *dnsmessage.AResource:
				rec.a[name] = netip.AddrFrom4(b.A)
			case *dnsmessage.PTRResource:
				rawTarget := strings.TrimSuffix(b.PTR.String(), ".")
				target := normalizeDNSName(rawTarget)
				if ip, ok := parseReverseARPA(name); ok {
					if isReasonableName(target) {
						rec.reverse[ip] = target
					}
				}
				if strings.HasPrefix(name, "_") || strings.Contains(name, "._") {
					if instance := ptrInstance(rawTarget); instance != "" {
						rec.instance[target] = instance
					}
				}
			case *dnsmessage.SRVResource:
				rec.srv[name] = normalizeDNSName(b.Target.String())
			case *dnsmessage.TXTResource:
				fields := map[string]string{}
				for _, entry := range b.TXT {
					key, value, ok := strings.Cut(entry, "=")
					if !ok || strings.TrimSpace(key) == "" {
						continue
					}
					fields[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
				}
				if len(fields) > 0 {
					if rec.txt == nil {
						rec.txt = map[string]map[string]string{}
					}
					rec.txt[name] = fields
				}
			}
		}
	}
	parseSection(0)
	parseSection(2)
	parseSection(1)
}

func mdnsResults(rec mdnsRecords) map[netip.Addr]nameCandidate {
	out := map[netip.Addr]nameCandidate{}
	add := func(ip netip.Addr, name, source string, score int) {
		name = cleanHostname(name)
		if !ip.IsValid() || !isReasonableName(name) {
			return
		}
		if prev, ok := out[ip]; ok && prev.score >= score {
			return
		}
		out[ip] = nameCandidate{name: name, source: source, score: score}
	}

	for ip, host := range rec.reverse {
		add(ip, host, "mdns", 70)
	}
	for instance, friendly := range rec.instance {
		ip, ok := rec.a[rec.srv[instance]]
		if !ok {
			// Some responders put the A record under the instance name.
			ip, ok = rec.a[instance]
		}
		if ok {
			add(ip, friendly, "bonjour", 75)
		}
	}
	for host, ip := range rec.a {
		add(ip, host, "mdns", 55)
	}
	return out
}

// mdnsModels extracts model names from TXT records such as those advertised by
// _device-info._tcp and printer services.
func mdnsModels(rec mdnsRecords) map[netip.Addr]modelCandidate {
	out := map[netip.Addr]modelCandidate{}
	add := func(ip netip.Addr, owner string, score int) {
		model := mdnsTXTModel(rec.txt[owner])
		if !ip.IsValid() || model == "" {
			return
		}
		if prev, ok := out[ip]; ok && prev.score >= score {
			return
		}
		out[ip] = modelCandidate{model: model, score: score}
	}

	for host, ip := range rec.a {
		add(ip, host, 70)
	}
	for instance, target := range rec.srv {
		if ip, ok := rec.a[target]; ok {
			add(ip, instance, 72)
		}
	}
	return out
}

func mdnsTXTModel(txt map[string]string) string {
	for _, key := range []string{"model", "modelname", "product", "productname", "md", "mdl", "ty"} {
		if model := cleanModel(txt[key]); model != "" {
			return model
		}
	}
	return ""
}

func reverseARPA(ip netip.Addr) string {
	b := ip.As4()
	return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", b[3], b[2], b[1], b[0])
}

func parseReverseARPA(name string) (netip.Addr, bool) {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if !strings.HasSuffix(name, ".in-addr.arpa") {
		return netip.Addr{}, false
	}
	parts := strings.Split(strings.TrimSuffix(name, ".in-addr.arpa"), ".")
	if len(parts) != 4 {
		return netip.Addr{}, false
	}
	var b [4]byte
	for i := 0; i < 4; i++ {
		v, err := strconv.Atoi(parts[3-i])
		if err != nil || v < 0 || v > 255 {
			return netip.Addr{}, false
		}
		b[i] = byte(v)
	}
	return netip.AddrFrom4(b), true
}

func normalizeDNSName(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

func cleanHostname(name string) string {
	name = strings.TrimSpace(strings.TrimSuffix(name, "."))
	lower := strings.ToLower(name)
	for _, suffix := range []string{".localdomain", ".local"} {
		if strings.HasSuffix(lower, suffix) && len(name) > len(suffix) {
			name = name[:len(name)-len(suffix)]
			break
		}
	}
	return strings.TrimSpace(name)
}

func isReasonableName(name string) bool {
	if len(name) < 1 || len(name) > 63 {
		return false
	}
	lower := strings.ToLower(name)
	if lower == "" || lower == "local" || lower == "*" || strings.HasPrefix(lower, "_") {
		return false
	}
	if strings.ContainsAny(name, "\\\x00/") {
		return false
	}
	hasAlnum := false
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			hasAlnum = true
			break
		}
	}
	if !hasAlnum {
		return false
	}
	// Ignore service-instance labels that are just a service type.
	if strings.HasPrefix(name, "_") || strings.Contains(name, "._") {
		return false
	}
	return true
}

// ptrInstance extracts the human-friendly instance label from a Bonjour
// service instance such as "Living Room TV._airplay._tcp.local".
func ptrInstance(name string) string {
	if i := strings.Index(name, "._"); i > 0 {
		return unescapeDNSService(name[:i])
	}
	return ""
}

func unescapeDNSService(s string) string {
	if !strings.Contains(s, "\\") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		i++
		if i+2 < len(s) && isDigit(s[i]) && isDigit(s[i+1]) && isDigit(s[i+2]) {
			v, _ := strconv.Atoi(s[i : i+3])
			b.WriteByte(byte(v))
			i += 2
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }
