package scan

import (
	"net/netip"
	"testing"
)

func TestModelFromTitle(t *testing.T) {
	d := Device{IP: netip.MustParseAddr("192.168.1.20"), Hostname: "NAS-1"}
	cases := map[string]string{
		"NAS-1 - Synology DiskStation": "Synology DiskStation",
		"UniFi Security Gateway":       "UniFi Security Gateway",
		"Synology DiskStation - NAS-1": "Synology DiskStation",
		"Login":                        "",
		"HP OfficeJet Pro 6970":        "HP OfficeJet Pro 6970",
	}
	for in, want := range cases {
		if got := modelFromTitle(in, d); got != want {
			t.Errorf("modelFromTitle(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestModelFromServerHeader(t *testing.T) {
	d := Device{IP: netip.MustParseAddr("192.168.1.129")}
	cases := map[string]string{
		"HP HTTP Server; HP OfficeJet Pro 6970 - T0F33A; Serial Number: TH8751R0HF": "HP OfficeJet Pro 6970",
		"nginx":           "",
		"MiniUPnPd/2.1":   "",
		"Synology_DS920+": "Synology_DS920+",
	}
	for in, want := range cases {
		if got := modelFromServerHeader(in, d); got != want {
			t.Errorf("modelFromServerHeader(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHTTPModelTargets(t *testing.T) {
	d := Device{
		IP:    netip.MustParseAddr("192.168.1.129"),
		Ports: []int{80, 443, 8080},
	}
	got := httpModelTargets(d)
	want := []string{"http://192.168.1.129/", "https://192.168.1.129/", "http://192.168.1.129:8080/"}
	if len(got) != len(want) {
		t.Fatalf("targets = %#v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("targets[%d] = %q, want %q", i, got[i], want[i])
		}
	}

	if targets := httpModelTargets(Device{IP: d.IP, Self: true, Ports: []int{80}}); len(targets) != 0 {
		t.Fatalf("self targets = %#v", targets)
	}
}
