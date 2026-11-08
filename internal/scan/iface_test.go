package scan

import (
	"net/netip"
	"testing"
)

func TestParsePorts(t *testing.T) {
	defaults, err := ParsePorts("")
	if err != nil || len(defaults) != len(DefaultPorts) {
		t.Fatalf("defaults: %v %d", err, len(defaults))
	}

	got, err := ParsePorts("22, 80,443, 8000-8003,22")
	if err != nil {
		t.Fatal(err)
	}
	want := []int{22, 80, 443, 8000, 8001, 8002, 8003}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}

	for _, bad := range []string{"abc", "0", "65536", "80-70", "1-99999", "1-5000", ","} {
		if _, err := ParsePorts(bad); err == nil {
			t.Errorf("ParsePorts(%q) unexpectedly succeeded", bad)
		}
	}
}

func TestServiceNames(t *testing.T) {
	if ServiceName(22) != "ssh" || ServiceName(54321) != "tcp" {
		t.Fatal("unexpected service names")
	}
	if PortLabel(443) != "443/https" || PortLabel(12345) != "12345" {
		t.Fatal("unexpected port labels")
	}
}

func TestHostsEnumeration(t *testing.T) {
	n := &Network{Prefix: netip.MustParsePrefix("192.168.1.0/30")}
	hosts, truncated := n.Hosts(0)
	if truncated || len(hosts) != 2 || hosts[0].String() != "192.168.1.1" || hosts[1].String() != "192.168.1.2" {
		t.Fatalf("got %v truncated=%v", hosts, truncated)
	}

	n.Prefix = netip.MustParsePrefix("192.168.1.0/31")
	hosts, _ = n.Hosts(0)
	if len(hosts) != 2 || hosts[0].String() != "192.168.1.0" || hosts[1].String() != "192.168.1.1" {
		t.Fatalf("/31 got %v", hosts)
	}

	n.Prefix = netip.MustParsePrefix("192.168.1.0/24")
	hosts, truncated = n.Hosts(10)
	if !truncated || len(hosts) != 10 || hosts[0].String() != "192.168.1.1" {
		t.Fatalf("cap got %d truncated=%v", len(hosts), truncated)
	}

	n.Prefix = netip.MustParsePrefix("10.0.0.7/32")
	hosts, _ = n.Hosts(0)
	if len(hosts) != 1 || hosts[0].String() != "10.0.0.7" {
		t.Fatalf("/32 got %v", hosts)
	}

	n.Prefix = netip.MustParsePrefix("172.16.0.0/16")
	hosts, truncated = n.Hosts(1024)
	if !truncated || len(hosts) != 1024 || hosts[0].String() != "172.16.0.1" {
		t.Fatalf("large prefix got %d", len(hosts))
	}
}

func TestParseSubnet(t *testing.T) {
	p, err := parseSubnet("192.168.5.0/24")
	if err != nil || p.String() != "192.168.5.0/24" {
		t.Fatalf("%v %v", p, err)
	}
	p, err = parseSubnet("192.168.5.9")
	if err != nil || p.String() != "192.168.5.0/24" {
		t.Fatalf("%v %v", p, err)
	}
	if _, err := parseSubnet("::1/64"); err == nil {
		t.Fatal("expected IPv6 subnet to be rejected")
	}
	if _, err := parseSubnet("nope"); err == nil {
		t.Fatal("expected invalid subnet to be rejected")
	}
}

func TestParseRouteHex(t *testing.T) {
	addr, err := parseRouteHex("0163A8C0")
	if err != nil || addr.String() != "192.168.99.1" {
		t.Fatalf("got %v %v", addr, err)
	}
	if _, err := parseRouteHex("zz"); err == nil {
		t.Fatal("expected error")
	}
}
