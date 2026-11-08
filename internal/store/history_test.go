package store

import (
	"os"
	"testing"
	"time"

	"net/netip"
	"netscan/internal/scan"
)

func TestHistoryRoundTrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_STATE_HOME", dir)

	h := Load()
	if len(h.Records) != 0 {
		t.Fatal("expected empty history")
	}
	first := time.Now().Add(-24 * time.Hour).Truncate(time.Second)
	device := scan.Device{
		IP:        netip.MustParseAddr("192.168.1.10"),
		MAC:       "aa:bb:cc:dd:ee:ff",
		Hostname:  "laptop",
		Vendor:    "Example Corp",
		Model:     "ExampleBook 14",
		FirstSeen: first,
		LastSeen:  first,
		Online:    true,
	}
	h.Update([]scan.Device{device})
	if err := h.Save(); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(h.Path); err != nil {
		t.Fatalf("history file missing: %v", err)
	}

	loaded := Load()
	if len(loaded.Records) != 1 {
		t.Fatalf("records=%d", len(loaded.Records))
	}
	rec, ok := loaded.Lookup("192.168.1.10", "aa:bb:cc:dd:ee:ff")
	if !ok || rec.Name != "laptop" || rec.Model != "ExampleBook 14" || !rec.FirstSeen.Equal(first) {
		t.Fatalf("record=%#v ok=%v", rec, ok)
	}

	// A later scan without a name or model should keep the remembered values.
	applied := scan.Device{IP: netip.MustParseAddr("192.168.1.10"), MAC: "aa:bb:cc:dd:ee:ff"}
	loaded.Apply(&applied)
	if applied.Hostname != "laptop" || applied.NameSource != "remembered" {
		t.Fatalf("applied=%#v", applied)
	}
	if applied.Model != "ExampleBook 14" {
		t.Fatalf("model not applied: %#v", applied)
	}
}

func TestHistoryMACMigration(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_STATE_HOME", dir)

	h := Load()
	first := time.Now().Add(-time.Hour).Truncate(time.Second)
	// First observation has no MAC, so it is keyed by IP.
	h.Update([]scan.Device{{
		IP:        netip.MustParseAddr("192.168.1.20"),
		Hostname:  "printer",
		FirstSeen: first,
	}})
	// The MAC later becomes visible at the same address; the record should be
	// re-keyed by MAC while keeping its history.
	h.Update([]scan.Device{{
		IP:       netip.MustParseAddr("192.168.1.20"),
		MAC:      "11:22:33:44:55:66",
		LastSeen: time.Now(),
	}})
	// DHCP moves the device; the MAC key keeps its identity.
	h.Update([]scan.Device{{
		IP:       netip.MustParseAddr("192.168.1.21"),
		MAC:      "11:22:33:44:55:66",
		LastSeen: time.Now(),
	}})

	rec, ok := h.Lookup("192.168.1.21", "11:22:33:44:55:66")
	if !ok {
		t.Fatal("missing migrated record")
	}
	if !rec.FirstSeen.Equal(first) {
		t.Fatalf("first seen changed: %v", rec.FirstSeen)
	}
	if rec.Name != "printer" {
		t.Fatalf("name not retained: %q", rec.Name)
	}
	if _, ok := h.Records["ip:192.168.1.20"]; ok {
		t.Fatal("old IP-keyed record was not removed")
	}
}

func TestSnapshotSorted(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_STATE_HOME", dir)
	h := Load()
	h.Update([]scan.Device{
		{IP: netip.MustParseAddr("10.0.0.2")},
		{IP: netip.MustParseAddr("10.0.0.1")},
	})
	recs := h.Snapshot()
	if len(recs) != 2 || recs[0].IP != "10.0.0.1" || recs[1].IP != "10.0.0.2" {
		t.Fatalf("snapshot=%#v", recs)
	}
}
