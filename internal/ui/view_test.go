package ui

import (
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/lipgloss"
	"net/netip"

	"netscan/internal/scan"
)

func testModel() *Model {
	m := &Model{
		styles:      newStyles(),
		devices:     map[string]*scan.Device{},
		sortKey:     SortIP,
		showOffline: true,
		filter:      textinput.New(),
		spinner:     spinner.New(),
		width:       140,
		height:      32,
		interval:    60 * time.Second,
	}
	add := func(d *scan.Device) { m.devices[d.IP.String()] = d }
	add(&scan.Device{
		IP: netip.MustParseAddr("192.168.1.1"), MAC: "aa:bb:cc:dd:ee:01",
		Hostname: "router", Vendor: "Ubiquiti Inc", Ports: []int{22, 53, 80, 443},
		RTT: 2 * time.Millisecond, Online: true, Gateway: true,
		FirstSeen: time.Now().Add(-48 * time.Hour), LastSeen: time.Now(),
	})
	add(&scan.Device{
		IP: netip.MustParseAddr("192.168.1.2"), MAC: "aa:bb:cc:dd:ee:02",
		Hostname: "this-is-a-very-long-hostname-for-truncation.localdomain",
		Vendor:   "A Very Long Vendor Name Incorporated Limited",
		Ports:    []int{80, 139, 443, 445, 5000, 8000, 8008, 8080, 8443, 9000, 32400},
		RTT:      120 * time.Millisecond, Online: true,
		FirstSeen: time.Now().Add(-24 * time.Hour), LastSeen: time.Now(),
	})
	add(&scan.Device{
		IP: netip.MustParseAddr("192.168.1.3"), MAC: "aa:bb:cc:dd:ee:03",
		Hostname: "printer", Vendor: "Hewlett Packard", Ports: []int{80, 631, 9100},
		RTT: time.Millisecond, Online: true,
	})
	add(&scan.Device{
		IP: netip.MustParseAddr("192.168.1.4"), MAC: "aa:bb:cc:dd:ee:04",
		Hostname: "old-laptop", Vendor: "Intel Corporate",
		Online: false, FirstSeen: time.Now().Add(-72 * time.Hour), LastSeen: time.Now().Add(-2 * time.Hour),
	})
	m.recomputeRows(false)
	return m
}

func TestLayoutColumnsExactWidth(t *testing.T) {
	for w := 20; w <= 220; w++ {
		cols := layoutColumns(w)
		sum := 0
		for _, c := range cols {
			if c.width <= 0 {
				t.Fatalf("w=%d column %v has width %d", w, c.key, c.width)
			}
			sum += c.width
		}
		total := sum + 2*(len(cols)-1) + 2 // leading bar + separator spaces
		if total != w {
			t.Errorf("w=%d total=%d cols=%d widths=%v", w, total, len(cols), cols)
		}
	}
}

func TestViewFitsTerminal(t *testing.T) {
	m := testModel()
	for _, size := range []struct{ w, h int }{
		{40, 12}, {60, 20}, {80, 24}, {100, 30}, {120, 32}, {150, 40}, {200, 50},
	} {
		m.width, m.height = size.w, size.h
		view := m.View()
		lines := strings.Split(view, "\n")
		if len(lines) != size.h {
			t.Errorf("%dx%d: got %d lines", size.w, size.h, len(lines))
		}
		for i, line := range lines {
			if got := lipgloss.Width(line); got > size.w {
				t.Errorf("%dx%d: line %d width %d: %q", size.w, size.h, i, got, line)
			}
		}
	}
}

func TestEmptyAndScanningViews(t *testing.T) {
	m := testModel()
	m.devices = map[string]*scan.Device{}
	m.rows = nil
	m.width, m.height = 100, 30
	view := m.View()
	if !strings.Contains(view, "No devices found") {
		t.Fatal("empty state missing")
	}

	m.scanning = true
	m.phase = "Discovering hosts"
	m.progressDone = 42
	m.progressFull = 254
	view = m.View()
	if !strings.Contains(view, "Discovering hosts") {
		t.Fatal("scanning state missing")
	}

	m.scanning = false
	m.lastErr = errTest("boom")
	view = m.View()
	if !strings.Contains(view, "Scan failed") {
		t.Fatal("error state missing")
	}
}

type errTest string

func (e errTest) Error() string { return string(e) }

func TestFilteringAndSorting(t *testing.T) {
	m := testModel()
	if len(m.rows) != 4 {
		t.Fatalf("rows=%d", len(m.rows))
	}

	m.filterValue = "printer"
	m.recomputeRows(false)
	if len(m.rows) != 1 || m.rows[0].Hostname != "printer" {
		t.Fatalf("filter rows=%v", m.rows)
	}

	m.filterValue = ""
	m.showOffline = false
	m.recomputeRows(false)
	if len(m.rows) != 3 {
		t.Fatalf("offline filter rows=%d", len(m.rows))
	}
	if m.rows[0].IP.String() != "192.168.1.1" {
		t.Fatal("unexpected first row")
	}

	m.sortKey = SortName
	m.sortDesc = false
	m.recomputeRows(false)
	if m.rows[0].Hostname != "printer" || !strings.HasPrefix(m.rows[len(m.rows)-1].Hostname, "this-is-a-very-long") {
		t.Fatalf("name sort: %v", hostnames(m.rows))
	}

	m.sortKey = SortRTT
	m.recomputeRows(false)
	if m.rows[0].Hostname == "" || m.rows[len(m.rows)-1].RTT != 120*time.Millisecond {
		t.Fatalf("rtt sort: %v", m.rows)
	}
}

func hostnames(rows []*scan.Device) []string {
	out := make([]string, len(rows))
	for i, d := range rows {
		out[i] = d.Hostname
	}
	return out
}

func TestDetailAndHelpFit(t *testing.T) {
	m := testModel()
	m.width, m.height = 120, 40
	m.detailIP = "192.168.1.2"
	m.showDetail = true
	view := m.View()
	if !strings.Contains(view, "Device details") || !strings.Contains(view, "Ports (11)") {
		t.Fatalf("detail view incomplete:\n%s", view)
	}
	for _, line := range strings.Split(view, "\n") {
		if lipgloss.Width(line) > m.width {
			t.Errorf("detail line too wide: %q", line)
		}
	}

	m.showDetail = false
	m.showHelp = true
	view = m.View()
	if !strings.Contains(view, "Keyboard shortcuts") {
		t.Fatal("help view missing")
	}
	for _, line := range strings.Split(view, "\n") {
		if lipgloss.Width(line) > m.width {
			t.Errorf("help line too wide: %q", line)
		}
	}
}

func TestSmallHelpFits(t *testing.T) {
	m := testModel()
	m.width, m.height = 80, 24
	m.showHelp = true
	view := m.View()
	lines := strings.Split(view, "\n")
	if len(lines) > 24 {
		t.Fatalf("help is %d lines for a 24-line terminal", len(lines))
	}
}

func TestFormatHelpers(t *testing.T) {
	if got := formatRTT(0); got != "—" {
		t.Errorf("rtt 0 = %q", got)
	}
	if got := formatRTT(500 * time.Microsecond); got != "<1ms" {
		t.Errorf("rtt sub-ms = %q", got)
	}
	if got := formatRTT(2500 * time.Microsecond); got != "2.5ms" {
		t.Errorf("rtt ms = %q", got)
	}
	if got := formatPortsCompact([]int{22, 80, 443}); got != "22,80,443" {
		t.Errorf("ports = %q", got)
	}
	if got := truncatePlain("abcdefgh", 5); got != "abcd…" {
		t.Errorf("truncate = %q", got)
	}
	if got := wrapItems([]string{"aa/bb", "cc/dd", "ee/ff"}, ", ", 10); len(got) != 3 {
		t.Errorf("wrap = %#v", got)
	}
}
