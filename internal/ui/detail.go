package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/mattn/go-runewidth"

	"netscan/internal/scan"
)

func (m *Model) detailView(w, h int) string {
	d := m.detailDevice()
	if d == nil {
		m.showDetail = false
		return m.View()
	}
	contentW := min(76, w-10)
	if contentW < 32 {
		contentW = max(20, w-4)
	}

	var lines []string
	lines = append(lines, m.styles.boxTitle.Render("Device details"))
	lines = append(lines, "")

	name := d.Hostname
	if name == "" {
		name = scan.DescribeRole(*d)
	}
	if name == "" {
		name = "Unknown device"
	}
	dot, _ := statusCell(d)
	dotStyle := m.styles.muted
	if d.Online {
		dotStyle = m.styles.green
	}
	lines = append(lines, dotStyle.Render(dot)+" "+m.styles.text.Bold(true).Render(name))
	lines = append(lines, "")

	add := func(label, value string) {
		lines = append(lines, m.styles.muted.Render(padCell(label, 14, false))+value)
	}

	add("IP address", d.IP.String())

	hostname := d.Hostname
	if hostname == "" {
		hostname = "—"
	}
	add("Hostname", hostname)
	add("MAC address", valueOr(d.MAC, "—"))
	add("Vendor", valueOr(d.Vendor, "Unknown"))
	add("Model", valueOr(d.Model, "Unknown"))
	add("Type", valueOr(scan.DescribeRole(*d), "Unknown"))

	status := statusText(d)
	if d.Self {
		status += " · this device"
	}
	if d.Gateway {
		status += " · gateway"
	}
	statusStyle := m.styles.green
	if !d.Online {
		statusStyle = m.styles.muted
	}
	lines = append(lines, m.styles.muted.Render(padCell("Status", 14, false))+statusStyle.Render(status))
	add("Latency", formatRTT(d.RTT))

	ports := "none detected"
	if len(d.Ports) > 0 {
		labels := make([]string, len(d.Ports))
		for i, p := range d.Ports {
			labels[i] = scan.PortLabel(p)
		}
		wrapped := wrapItems(labels, ", ", max(12, contentW-15))
		ports = strings.Join(wrapped, "\n")
	}
	portLines := strings.Split(ports, "\n")
	for i, line := range portLines {
		label := ""
		if i == 0 {
			label = fmt.Sprintf("Ports (%d)", len(d.Ports))
		}
		add(label, line)
	}

	add("Name source", valueOr(d.NameSource, "—"))
	add("First seen", formatFirstSeen(d.FirstSeen))
	add("Last seen", formatLastSeen(d.LastSeen))
	lines = append(lines, "")
	lines = append(lines, m.styles.muted.Render("esc back  ·  r rescan  ·  q quit"))

	box := m.styles.box.Width(contentW).Render(strings.Join(lines, "\n"))
	return lipgloss.Place(w, h, lipgloss.Center, lipgloss.Center, box)
}

func (m *Model) helpView(w, h int) string {
	contentW := min(70, w-10)
	if contentW < 34 {
		contentW = max(24, w-4)
	}

	var lines []string
	lines = append(lines, m.styles.boxTitle.Render("Keyboard shortcuts"))
	lines = append(lines, "")

	section := func(title string) {
		lines = append(lines, m.styles.accent.Render(title))
	}
	keyLine := func(key, desc string) {
		lines = append(lines, "  "+m.styles.key.Render(padCell(key, 14, false))+m.styles.text.Render(desc))
	}

	section("Navigation")
	keyLine("↑ / k", "move up")
	keyLine("↓ / j", "move down")
	keyLine("PgUp / PgDn", "page up / down")
	keyLine("g / G", "jump to top / bottom")
	keyLine("enter / d", "device details")
	keyLine("esc", "back / clear filter")
	lines = append(lines, "")
	section("Scanning")
	keyLine("r", "rescan now")
	keyLine("p", "pause auto-refresh")
	keyLine("o", "show / hide offline")
	keyLine("s / S", "next column / reverse")
	keyLine("/", "filter devices")
	keyLine("?", "this help")
	keyLine("q", "quit")
	lines = append(lines, "")
	lines = append(lines, m.styles.muted.Render("esc or ? to close"))

	box := m.styles.box.Width(contentW).Render(strings.Join(lines, "\n"))
	return lipgloss.Place(w, h, lipgloss.Center, lipgloss.Center, box)
}

func valueOr(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func formatFirstSeen(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	now := time.Now()
	if sameDay(t, now) {
		return "today " + t.Format("15:04")
	}
	if sameDay(t, now.AddDate(0, 0, -1)) {
		return "yesterday " + t.Format("15:04")
	}
	return t.Format("2006-01-02 15:04")
}

func formatLastSeen(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return relativeTime(t) + "  (" + t.Format("15:04:05") + ")"
}

func sameDay(a, b time.Time) bool {
	ay, am, ad := a.Date()
	by, bm, bd := b.Date()
	return ay == by && am == bm && ad == bd
}

func relativeTime(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < 10*time.Second:
		return "just now"
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	case d < 30*24*time.Hour:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	default:
		return t.Format("Jan 2")
	}
}

// wrapItems packs comma-separated items into lines no wider than width.
func wrapItems(items []string, sep string, width int) []string {
	if len(items) == 0 {
		return nil
	}
	if width < 4 {
		width = 4
	}
	var lines []string
	cur := ""
	for _, item := range items {
		candidate := item
		if cur != "" {
			candidate = cur + sep + item
		}
		if cur != "" && runewidth.StringWidth(candidate) > width {
			lines = append(lines, cur)
			cur = item
			continue
		}
		cur = candidate
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
}
