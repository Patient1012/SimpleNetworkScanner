package scan

import (
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func mustName(t *testing.T, s string) dnsmessage.Name {
	t.Helper()
	n, err := dnsmessage.NewName(s)
	if err != nil {
		t.Fatalf("name %q: %v", s, err)
	}
	return n
}

func TestReverseARPA(t *testing.T) {
	ip := netip.MustParseAddr("192.168.1.50")
	if got := reverseARPA(ip); got != "50.1.168.192.in-addr.arpa." {
		t.Fatalf("reverseARPA=%q", got)
	}
	got, ok := parseReverseARPA("50.1.168.192.in-addr.arpa.")
	if !ok || got != ip {
		t.Fatalf("parseReverseARPA=%v %v", got, ok)
	}
	if _, ok := parseReverseARPA("example.com."); ok {
		t.Fatal("expected false for non-arpa name")
	}
	if _, ok := parseReverseARPA("999.1.168.192.in-addr.arpa."); ok {
		t.Fatal("expected false for invalid octet")
	}
}

func TestMDNSParsing(t *testing.T) {
	instance := mustName(t, "LivingRoomTV._airplay._tcp.local.")
	target := mustName(t, "lrtv.local.")
	service := mustName(t, "_airplay._tcp.local.")
	reverse := mustName(t, "50.1.168.192.in-addr.arpa.")
	host := mustName(t, "lrtv.local.")

	msg := dnsmessage.Message{
		Header: dnsmessage.Header{Response: true, Authoritative: true},
		Answers: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{Name: service, Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET},
				Body:   &dnsmessage.PTRResource{PTR: instance},
			},
			{
				Header: dnsmessage.ResourceHeader{Name: instance, Type: dnsmessage.TypeSRV, Class: dnsmessage.ClassINET},
				Body:   &dnsmessage.SRVResource{Priority: 0, Weight: 0, Port: 7000, Target: target},
			},
			{
				Header: dnsmessage.ResourceHeader{Name: instance, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET},
				Body:   &dnsmessage.TXTResource{TXT: []string{"model=AppleTV6,2", "srcvers=1.0"}},
			},
		},
		Additionals: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{Name: host, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
				Body:   &dnsmessage.AResource{A: [4]byte{192, 168, 1, 50}},
			},
			{
				Header: dnsmessage.ResourceHeader{Name: reverse, Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET},
				Body:   &dnsmessage.PTRResource{PTR: host},
			},
		},
	}
	pkt, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}

	rec := mdnsRecords{
		a:        map[string]netip.Addr{},
		srv:      map[string]string{},
		instance: map[string]string{},
		reverse:  map[netip.Addr]string{},
		txt:      map[string]map[string]string{},
	}
	parseMDNS(pkt, &rec)
	if len(rec.a) != 1 || rec.a["lrtv.local"] != netip.MustParseAddr("192.168.1.50") {
		t.Fatalf("A records: %#v", rec.a)
	}
	if rec.srv["livingroomtv._airplay._tcp.local"] != "lrtv.local" {
		t.Fatalf("SRV: %#v", rec.srv)
	}
	if rec.instance["livingroomtv._airplay._tcp.local"] != "LivingRoomTV" {
		t.Fatalf("instance: %#v", rec.instance)
	}

	results := mdnsResults(rec)
	c, ok := results[netip.MustParseAddr("192.168.1.50")]
	if !ok || c.name != "LivingRoomTV" || c.source != "bonjour" {
		t.Fatalf("results: %#v", results)
	}

	models := mdnsModels(rec)
	if got := models[netip.MustParseAddr("192.168.1.50")].model; got != "AppleTV6,2" {
		t.Fatalf("model = %q, want AppleTV6,2", got)
	}
}

func TestMDNSNameEscaping(t *testing.T) {
	if got := ptrInstance("Noah\\032s iPhone._airplay._tcp.local"); got != "Noah s iPhone" && got != "Noah  iPhone" {
		t.Fatalf("unescaped=%q", got)
	}
	if got := cleanHostname("NAS-1.localdomain."); got != "NAS-1" {
		t.Fatalf("cleanHostname=%q", got)
	}
	if got := cleanHostname("foo.local"); got != "foo" {
		t.Fatalf("cleanHostname=%q", got)
	}
}

func TestBuildMDNSQuery(t *testing.T) {
	wire, err := buildMDNSQuery("_http._tcp.local.", dnsmessage.TypePTR, true)
	if err != nil {
		t.Fatal(err)
	}
	var p dnsmessage.Parser
	if _, err := p.Start(wire); err != nil {
		t.Fatal(err)
	}
	q, err := p.Question()
	if err != nil {
		t.Fatal(err)
	}
	if q.Class&0x8000 == 0 {
		t.Fatal("expected unicast-response bit")
	}
	if q.Type != dnsmessage.TypePTR {
		t.Fatal("unexpected question type")
	}
}
