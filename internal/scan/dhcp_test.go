package scan

import (
	"net/netip"
	"testing"
)

func TestParseDnsmasqLeases(t *testing.T) {
	out := leases{byIP: map[netip.Addr]string{}, byMAC: map[string]string{}}
	parseDnsmasqLeases("1700000000 aa:bb:cc:dd:ee:ff 192.168.1.5 foo 01:aa:bb:cc:dd:ee:ff\n1700000000 * 192.168.1.6 * *\n", &out)
	if out.byIP[netip.MustParseAddr("192.168.1.5")] != "foo" {
		t.Fatalf("missing ip name: %#v", out.byIP)
	}
	if out.byMAC["aa:bb:cc:dd:ee:ff"] != "foo" {
		t.Fatalf("missing mac name: %#v", out.byMAC)
	}
	if _, ok := out.byIP[netip.MustParseAddr("192.168.1.6")]; ok {
		t.Fatal("wildcard hostname should be ignored")
	}
}

func TestParseISCLeases(t *testing.T) {
	text := `
lease {
  interface "eth0";
  fixed-address 192.168.1.7;
  option host-name "laptop";
  hardware ethernet 11:22:33:44:55:66;
}
lease {
  fixed-address 192.168.1.8;
  client-hostname "phone";
}
`
	out := leases{byIP: map[netip.Addr]string{}, byMAC: map[string]string{}}
	parseISCLeases(text, &out)
	if out.byIP[netip.MustParseAddr("192.168.1.7")] != "laptop" {
		t.Fatalf("missing laptop: %#v", out)
	}
	if out.byMAC["11:22:33:44:55:66"] != "laptop" {
		t.Fatalf("missing mac: %#v", out.byMAC)
	}
	if out.byIP[netip.MustParseAddr("192.168.1.8")] != "phone" {
		t.Fatalf("missing phone: %#v", out)
	}
}

func TestParseKeyValueLeases(t *testing.T) {
	text := `# dhcpcd lease
ip_address=192.168.1.9
hostname=desktop
hwaddr=AA-BB-CC-00-11-22

ADDRESS=192.168.1.10
DHCP4_HOST_NAME=printer
DHCP4_CLIENT_ID=01:aa:bb:cc:dd:ee:ff
`
	out := leases{byIP: map[netip.Addr]string{}, byMAC: map[string]string{}}
	parseKeyValueLeases(text, &out)
	if out.byIP[netip.MustParseAddr("192.168.1.9")] != "desktop" {
		t.Fatalf("missing desktop: %#v", out.byIP)
	}
	if out.byMAC["aa:bb:cc:00:11:22"] != "desktop" {
		t.Fatalf("missing desktop mac: %#v", out.byMAC)
	}
	if out.byIP[netip.MustParseAddr("192.168.1.10")] != "printer" {
		t.Fatalf("missing printer: %#v", out.byIP)
	}
	if out.byMAC["aa:bb:cc:dd:ee:ff"] != "printer" {
		t.Fatalf("missing printer mac: %#v", out.byMAC)
	}
}

func TestNormMAC(t *testing.T) {
	cases := map[string]string{
		"AA:BB:CC:DD:EE:FF": "aa:bb:cc:dd:ee:ff",
		"aa-bb-cc-dd-ee-ff": "aa:bb:cc:dd:ee:ff",
		"aabbccddeeff":      "aa:bb:cc:dd:ee:ff",
		"00:00:00:00:00:00": "",
		"nope":              "",
	}
	for in, want := range cases {
		if got := normMAC(in); got != want {
			t.Errorf("normMAC(%q)=%q want %q", in, got, want)
		}
	}
}
