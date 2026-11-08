package scan

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestIntegrationScan performs a real scan of the local network. It is opt-in
// because it depends on the machine's network configuration.
//
//	NETSCAN_INTEGRATION=1 go test ./internal/scan -run TestIntegrationScan -v
func TestIntegrationScan(t *testing.T) {
	if os.Getenv("NETSCAN_INTEGRATION") == "" {
		t.Skip("set NETSCAN_INTEGRATION=1 to run a live scan")
	}
	opts := DefaultOptions()
	opts.PortTimeout = 300 * time.Millisecond
	opts.PingTimeout = 1 * time.Second
	scanner, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	devices, summary, err := scanner.Scan(ctx, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) == 0 {
		t.Fatal("no devices found")
	}

	selfFound := false
	for _, d := range devices {
		if d.Self {
			selfFound = true
			if d.IP != scanner.Network().LocalIP {
				t.Fatalf("self IP mismatch: %s", d.IP)
			}
		}
		if !d.IP.Is4() {
			t.Fatalf("non-IPv4 device: %s", d.IP)
		}
		if !scanner.Network().Prefix.Contains(d.IP) {
			t.Fatalf("device outside subnet: %s", d.IP)
		}
	}
	if !selfFound {
		t.Fatal("scanning host was not included")
	}
	if summary.Up != len(devices) {
		t.Fatalf("summary up=%d devices=%d", summary.Up, len(devices))
	}
	if summary.Finished.Before(summary.Started) {
		t.Fatal("bad summary timestamps")
	}
	t.Logf("%s: %d devices in %s", scanner.Network().Prefix, len(devices), summary.Elapsed())
	for _, d := range devices {
		name := d.Hostname
		if name == "" {
			name = "—"
		}
		t.Logf("  %-15s %-28s %-17s %v", d.IP, name, d.MAC, d.Ports)
	}
}
