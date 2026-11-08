package oui

import "testing"

func TestLookup(t *testing.T) {
	if Count() < 10000 {
		t.Fatalf("OUI database too small: %d", Count())
	}
	cases := map[string]string{
		"00:11:32:98:9f:65": "Synology Incorporated",
		"00-28-F8-6D-1A-9B": "Intel Corporate",
		"bc:24:11:ee:65:78": "Proxmox Server Solutions GmbH",
	}
	for mac, want := range cases {
		if got := Lookup(mac); got != want {
			t.Errorf("Lookup(%q)=%q want %q", mac, got, want)
		}
	}
	if got := Lookup("zz:zz:zz"); got != "" {
		t.Errorf("invalid MAC gave %q", got)
	}
	if got := Lookup(""); got != "" {
		t.Errorf("empty MAC gave %q", got)
	}
}
