package scan

import (
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestParsePTRResponse(t *testing.T) {
	id := uint16(0x1234)
	name, err := dnsmessage.NewName("20.99.168.192.in-addr.arpa.")
	if err != nil {
		t.Fatal(err)
	}
	target, err := dnsmessage.NewName("nas-1.localdomain.")
	if err != nil {
		t.Fatal(err)
	}
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{ID: id, Response: true, RCode: dnsmessage.RCodeSuccess},
		Questions: []dnsmessage.Question{{
			Name: name, Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET,
		}},
		Answers: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET, TTL: 60},
			Body:   &dnsmessage.PTRResource{PTR: target},
		}},
	}
	wire, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	got, definitive := parsePTRResponse(wire, id)
	if got != "nas-1.localdomain" {
		t.Fatalf("name = %q, want nas-1.localdomain", got)
	}
	if !definitive {
		t.Fatal("response should be definitive")
	}
}

func TestParsePTRResponseRejectsWrongID(t *testing.T) {
	wire, err := buildDNSQuery(7, "1.1.168.192.in-addr.arpa.", dnsmessage.TypePTR)
	if err != nil {
		t.Fatal(err)
	}
	if _, definitive := parsePTRResponse(wire, 8); definitive {
		t.Fatal("query response with mismatched ID should be ignored")
	}
}

func TestParsePTRResponseNameError(t *testing.T) {
	id := uint16(42)
	wire, err := buildDNSQuery(id, "1.1.168.192.in-addr.arpa.", dnsmessage.TypePTR)
	if err != nil {
		t.Fatal(err)
	}
	var p dnsmessage.Parser
	hdr, err := p.Start(wire)
	if err != nil {
		t.Fatal(err)
	}
	hdr.Response = true
	hdr.RCode = dnsmessage.RCodeNameError
	msg := dnsmessage.Message{Header: hdr}
	wire, err = msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if _, definitive := parsePTRResponse(wire, id); !definitive {
		t.Fatal("NXDOMAIN should count as a definitive answer")
	}
}

func TestDNSServersGatewayFirst(t *testing.T) {
	gateway := netip.MustParseAddr("192.168.99.1")
	servers := dnsServers(gateway)
	if len(servers) == 0 {
		t.Skip("no resolv.conf nameservers available")
	}
	if servers[0] != gateway {
		t.Fatalf("first server = %s, want gateway %s", servers[0], gateway)
	}
	seen := map[netip.Addr]bool{}
	for _, s := range servers {
		if seen[s] {
			t.Fatalf("duplicate server %s", s)
		}
		seen[s] = true
	}
}
