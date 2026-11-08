package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/mattn/go-runewidth"

	"netscan/internal/scan"
)

type column struct {
	key   SortKey
	title string
	width int
	flex  bool
	min   int
	right bool
}

var allColumns = []column{
	{key: SortIP, title: "IP ADDRESS", width: 15},
	{key: SortName, title: "HOSTNAME", flex: true, min: 10},
	{key: SortVendor, title: "VENDOR", flex: true, min: 8},
	{key: SortModel, title: "MODEL", flex: true, min: 8},
	{key: SortMAC, title: "MAC", width: 17},
	{key: SortPorts, title: "OPEN PORTS", flex: true, min: 7},
	{key: SortRTT, title: "RTT", width: 7, right: true},
	{key: SortStatus, title: "STATUS", width: 8},
}

// layoutColumns selects and sizes the table columns for a terminal width.
func layoutColumns(w int) []column {
	if w <= 0 {
		w = 100
	}
	if w < 34 {
		return []column{{key: SortName, title: "HOSTNAME", width: max(4, w-2), flex: true}}
	}
	if w < 44 {
		// IP and a name is all that fits.
		return []column{
			{key: SortIP, title: "IP", width: 15},
			{key: SortName, title: "HOSTNAME", width: max(4, w-2-2-15), flex: true},
		}
	}

	cols := append([]column(nil), allColumns...)
	drop := func(key SortKey) {
		out := cols[:0]
		for _, c := range cols {
			if c.key != key {
				out = append(out, c)
			}
		}
		cols = out
	}
	if w < 112 {
		drop(SortVendor)
	}
	if w < 92 {
		drop(SortMAC)
	}
	if w < 76 {
		drop(SortPorts)
	}
	if w < 62 {
		drop(SortRTT)
	}

	for {
		fixed, seps, flexCount, mins := measure(cols, w)
		if w-2-seps-fixed >= mins || flexCount <= 1 {
			break
		}
		// Drop optional columns until the flexible columns fit.
		switch {
		case containsCol(cols, SortVendor):
			drop(SortVendor)
		case containsCol(cols, SortModel):
			drop(SortModel)
		case containsCol(cols, SortPorts):
			drop(SortPorts)
		case containsCol(cols, SortMAC):
			drop(SortMAC)
		case containsCol(cols, SortRTT):
			drop(SortRTT)
		default:
			goto allocate
		}
	}

allocate:
	_, seps, _, _ := measure(cols, w)
	fixed := 0
	flexSum := 0
	for _, c := range cols {
		if c.flex {
			flexSum += c.min
		} else {
			fixed += c.width
		}
	}
	rem := w - 2 - seps - fixed
	if rem < 0 {
		rem = 0
	}

	var flex []int
	weightTotal := 0
	for i, c := range cols {
		if c.flex {
			flex = append(flex, i)
			switch c.key {
			case SortName:
				weightTotal += 5
			case SortModel:
				weightTotal += 4
			case SortPorts:
				weightTotal += 3
			default:
				weightTotal += 2
			}
		}
	}
	left := rem
	extra := rem - flexSum
	if extra < 0 {
		extra = 0
	}
	for n, idx := range flex {
		c := &cols[idx]
		weight := 2
		switch c.key {
		case SortName:
			weight = 5
		case SortModel:
			weight = 4
		case SortPorts:
			weight = 3
		}
		if n == len(flex)-1 {
			c.width = max(c.min, left)
			break
		}
		share := c.min
		if weightTotal > 0 {
			share += extra * weight / weightTotal
		}
		share = max(c.min, share)
		c.width = share
		left -= share
		extra -= share - c.min
		if extra < 0 {
			extra = 0
		}
		weightTotal -= weight
	}
	return cols
}

func measure(cols []column, w int) (fixed, seps, flexCount, mins int) {
	for _, c := range cols {
		if c.flex {
			flexCount++
			mins += c.min
		} else {
			fixed += c.width
		}
	}
	seps = 2 * (len(cols) - 1)
	return
}

func containsCol(cols []column, key SortKey) bool {
	for _, c := range cols {
		if c.key == key {
			return true
		}
	}
	return false
}

func tableColumnsForWidth(w int) []column {
	return layoutColumns(w)
}

// View renders the whole application.
func (m *Model) View() string {
	w, h := m.width, m.height
	if w <= 0 {
		w = 100
	}
	if h <= 0 {
		h = 24
	}
	if m.showHelp {
		return m.helpView(w, h)
	}
	if m.showDetail {
		return m.detailView(w, h)
	}

	cols := layoutColumns(w)
	lines := make([]string, 0, h)
	lines = append(lines, m.headerView(w))
	lines = append(lines, renderHeaderRow(m.styles, cols, m.sortKey, m.sortDesc, w))
	body := m.tableView(cols, w)
	for _, line := range body {
		lines = append(lines, line)
	}
	lines = append(lines, m.statusLine(w))
	lines = append(lines, m.hintLine(w))
	for len(lines) < h {
		lines = append(lines, "")
	}
	if len(lines) > h {
		lines = lines[:h]
	}
	return strings.Join(lines, "\n")
}

func (m *Model) headerView(w int) string {
	version := ""
	if m.cfg.Version != "" {
		version = " v" + strings.TrimPrefix(m.cfg.Version, "v")
	}
	iface := ""
	prefix := ""
	if m.cfg.Scanner != nil {
		if n := m.cfg.Scanner.Network(); n != nil {
			iface = n.InterfaceName
			prefix = n.Prefix.String()
		}
	}
	left := m.styles.title.Render("netscan") +
		m.styles.muted.Render(version+"  ") +
		m.styles.text.Render(iface) +
		m.styles.muted.Render("  ·  ") +
		m.styles.accent.Render(prefix)

	online, known := 0, len(m.devices)
	for _, d := range m.devices {
		if d.Online {
			online++
		}
	}
	right := m.styles.green.Render("●") + " " + m.styles.text.Render(fmt.Sprintf("%d online", online)) +
		m.styles.muted.Render("  ·  ") + m.styles.text.Render(fmt.Sprintf("%d known", known))
	if m.filterValue != "" {
		right += m.styles.muted.Render("  ·  ") +
			m.styles.accent.Render(fmt.Sprintf("%d shown", len(m.rows)))
	}
	if m.lastSummary.Truncated {
		right += m.styles.yellow.Render("  ·  capped")
	}
	return padBetween(left, right, w)
}

func renderHeaderRow(st styles, cols []column, sortKey SortKey, desc bool, w int) string {
	var b strings.Builder
	b.WriteString("  ")
	for i, c := range cols {
		if i > 0 {
			b.WriteString("  ")
		}
		title := c.title
		if c.key == sortKey {
			if desc {
				title += "▼"
			} else {
				title += "▲"
			}
		}
		style := st.header
		if c.key == sortKey {
			style = st.headerActive
		}
		b.WriteString(style.Render(padCell(title, c.width, c.right)))
	}
	line := b.String()
	if gap := w - lipgloss.Width(line); gap > 0 {
		line += strings.Repeat(" ", gap)
	}
	return line
}

func (m *Model) tableView(cols []column, w int) []string {
	vis := m.bodyHeight()
	lines := make([]string, 0, vis)
	if len(m.rows) == 0 {
		return m.emptyBody(vis, w)
	}

	start := m.offset
	if start >= len(m.rows) {
		start = max(0, len(m.rows)-1)
	}
	for i := start; i < len(m.rows) && len(lines) < vis; i++ {
		selected := i == m.cursor
		lines = append(lines, m.renderRow(m.rows[i], cols, w, selected))
	}
	for len(lines) < vis {
		lines = append(lines, "")
	}
	return lines
}

func (m *Model) renderRow(d *scan.Device, cols []column, w int, selected bool) string {
	sepStyle := m.styles.text
	if selected {
		sepStyle = sepStyle.Background(m.styles.selectedBG)
	}

	var b strings.Builder
	if selected {
		b.WriteString(m.styles.selBar.Render("▌"))
	} else {
		b.WriteString(" ")
	}
	b.WriteString(sepStyle.Render(" "))
	for i, c := range cols {
		if i > 0 {
			b.WriteString(sepStyle.Render("  "))
		}
		b.WriteString(m.renderCell(d, c, selected))
	}
	if gap := w - lipgloss.Width(b.String()); gap > 0 {
		b.WriteString(sepStyle.Render(strings.Repeat(" ", gap)))
	}
	return b.String()
}

func (m *Model) renderCell(d *scan.Device, c column, selected bool) string {
	value := ""
	style := m.styles.text

	switch c.key {
	case SortIP:
		value = d.IP.String()
		if d.Self {
			style = m.styles.cyan
		}
	case SortName:
		value = d.Hostname
		if value == "" {
			value = scan.DescribeRole(*d)
		}
		if value == "" {
			value = "—"
			style = m.styles.muted
		}
	case SortVendor:
		value = d.Vendor
		style = m.styles.muted
		if value == "" {
			value = "—"
		}
	case SortModel:
		value = d.Model
		style = m.styles.muted
		if value == "" {
			value = "—"
		}
	case SortMAC:
		value = d.MAC
		style = m.styles.muted
		if value == "" {
			value = "—"
		}
	case SortPorts:
		value = formatPortsCompact(d.Ports)
		if value == "" {
			value = "—"
			style = m.styles.muted
		}
	case SortRTT:
		value = formatRTT(d.RTT)
		if d.RTT == 0 {
			style = m.styles.muted
		} else if d.RTT > 100*time.Millisecond {
			style = m.styles.yellow
		}
	case SortStatus:
		dot, label := statusCell(d)
		value = dot + " " + label
		switch {
		case d.Self:
			style = m.styles.cyan
		case d.Gateway:
			style = m.styles.yellow
		case d.Online:
			style = m.styles.green
		default:
			style = m.styles.muted
		}
	}

	if !d.Online && !selected {
		style = m.styles.muted
		if c.key == SortStatus {
			style = m.styles.muted
		}
	}
	if selected {
		style = style.Bold(true).Background(m.styles.selectedBG)
	}
	return style.Render(padCell(value, c.width, c.right))
}

func (m *Model) emptyBody(vis, w int) []string {
	lines := make([]string, vis)
	for i := range lines {
		lines[i] = ""
	}

	var msg []string
	switch {
	case m.scanning:
		bar := progressBar(30, progressFraction(m.progressDone, m.progressFull), m.styles)
		msg = []string{
			m.spinner.View() + "  " + m.styles.text.Render("Scanning "+m.networkLabel()),
			"",
			m.styles.muted.Render(m.phase),
			"",
			bar + "  " + m.styles.muted.Render(progressPercent(m.progressDone, m.progressFull)),
		}
	case m.lastErr != nil:
		msg = []string{
			m.styles.red.Render("Scan failed"),
			"",
			m.styles.muted.Render(truncatePlain(m.lastErr.Error(), max(20, w-2))),
			"",
			m.styles.muted.Render("Press r to try again"),
		}
	case m.filterValue != "":
		msg = []string{
			m.styles.text.Render("No devices match " + m.styles.accent.Render("/"+m.filterValue)),
			"",
			m.styles.muted.Render("Press esc to clear the filter"),
		}
	default:
		msg = []string{
			m.styles.text.Render("No devices found yet"),
			"",
			m.styles.muted.Render("Press r to scan again"),
		}
	}

	start := max(0, (vis-len(msg))/2)
	for i, line := range msg {
		idx := start + i
		if idx >= vis {
			break
		}
		lines[idx] = centerLine(line, w)
	}
	return lines
}

func (m *Model) networkLabel() string {
	if m.cfg.Scanner != nil {
		if n := m.cfg.Scanner.Network(); n != nil {
			return n.Prefix.String()
		}
	}
	return "network"
}

func (m *Model) statusLine(w int) string {
	if m.toast != "" {
		return padBetween(m.styles.accent.Render(m.toast), "", w)
	}

	var left string
	switch {
	case m.scanning:
		barW := 22
		if w > 110 {
			barW = 32
		}
		bar := progressBar(barW, progressFraction(m.progressDone, m.progressFull), m.styles)
		left = m.spinner.View() + " " +
			m.styles.text.Render(m.phase) + "  " +
			bar + "  " +
			m.styles.muted.Render(progressPercent(m.progressDone, m.progressFull)) + "  " +
			m.styles.muted.Render(fmt.Sprintf("%d/%d", m.progressDone, m.progressFull))
		if m.progressFull == 0 {
			left = m.spinner.View() + " " + m.styles.text.Render(m.phase)
		}
	case m.lastErr != nil && !m.scanning:
		left = m.styles.red.Render("scan error: " + truncatePlain(m.lastErr.Error(), max(20, w-30)))
	default:
		online, known := 0, 0
		for _, d := range m.devices {
			known++
			if d.Online {
				online++
			}
		}
		elapsed := m.lastSummary.Elapsed()
		timing := m.timeUntilNextScan()
		left = m.styles.green.Render("●") + " " + m.styles.text.Render(fmt.Sprintf("%d online", online)) +
			m.styles.muted.Render("  ·  ") + m.styles.text.Render(fmt.Sprintf("%d known", known))
		if len(m.rows) != known {
			left += m.styles.muted.Render("  ·  ") + m.styles.accent.Render(fmt.Sprintf("%d shown", len(m.rows)))
		}
		if elapsed > 0 {
			left += m.styles.muted.Render("  ·  scan " + formatElapsed(elapsed))
		}
		if timing != "" {
			left += m.styles.muted.Render("  ·  " + timing)
		}
	}

	right := ""
	if m.scanning {
		right = m.styles.muted.Render("r rescan  ·  q quit")
	} else if !m.lastScan.IsZero() {
		right = m.styles.muted.Render("scanned " + m.lastScan.Format("15:04:05"))
	}
	return padBetween(left, right, w)
}

func (m *Model) hintLine(w int) string {
	if m.filterFocus {
		line := m.filter.View() + "  " + m.styles.muted.Render("enter apply  ·  esc clear")
		return padRight(truncateStyled(line, w), w)
	}
	type hint struct {
		key  string
		desc string
	}
	hints := []hint{
		{"↑↓", "move"},
		{"enter", "details"},
		{"r", "rescan"},
		{"s", "sort"},
		{"/", "filter"},
		{"o", "offline"},
		{"p", "pause"},
		{"?", "help"},
		{"q", "quit"},
	}
	var b strings.Builder
	for i, h := range hints {
		if i > 0 {
			b.WriteString(m.styles.muted.Render("  ·  "))
		}
		b.WriteString(m.styles.key.Render(h.key))
		b.WriteString(" ")
		b.WriteString(m.styles.muted.Render(h.desc))
	}
	line := " " + b.String()
	return padRight(truncateStyled(line, w), w)
}

func progressFraction(done, total int) float64 {
	if total <= 0 {
		return 0
	}
	f := float64(done) / float64(total)
	if f > 1 {
		return 1
	}
	if f < 0 {
		return 0
	}
	return f
}

func progressPercent(done, total int) string {
	if total <= 0 {
		return ""
	}
	return fmt.Sprintf("%d%%", int(progressFraction(done, total)*100))
}

func progressBar(width int, frac float64, st styles) string {
	if width < 4 {
		width = 4
	}
	filled := int(float64(width) * frac)
	if filled > width {
		filled = width
	}
	if filled < 0 {
		filled = 0
	}
	return st.accent.Render(strings.Repeat("█", filled)) +
		st.muted.Render(strings.Repeat("░", width-filled))
}

func statusCell(d *scan.Device) (string, string) {
	switch {
	case !d.Online:
		return "○", "off"
	case d.Self:
		return "●", "self"
	case d.Gateway:
		return "●", "gw"
	default:
		return "●", "online"
	}
}

func statusText(d *scan.Device) string {
	switch {
	case d.Self:
		return "self"
	case d.Gateway:
		return "gateway"
	case d.Online:
		return "online"
	default:
		return "offline"
	}
}

func formatPortsCompact(ports []int) string {
	if len(ports) == 0 {
		return ""
	}
	var b strings.Builder
	for i, p := range ports {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%d", p)
	}
	return b.String()
}

func formatRTT(d time.Duration) string {
	if d <= 0 {
		return "—"
	}
	if d < time.Millisecond {
		return "<1ms"
	}
	if d < 10*time.Millisecond {
		return fmt.Sprintf("%.1fms", float64(d)/float64(time.Millisecond))
	}
	if d < time.Second {
		return fmt.Sprintf("%dms", int(d.Round(time.Millisecond)/time.Millisecond))
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}

func formatElapsed(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}

func padCell(s string, width int, right bool) string {
	s = truncatePlain(s, width)
	gap := width - runewidth.StringWidth(s)
	if gap < 0 {
		gap = 0
	}
	if right {
		return strings.Repeat(" ", gap) + s
	}
	return s + strings.Repeat(" ", gap)
}

func truncatePlain(s string, width int) string {
	if width <= 0 {
		return ""
	}
	if runewidth.StringWidth(s) <= width {
		return s
	}
	return runewidth.Truncate(s, width, "…")
}

func truncateStyled(s string, width int) string {
	if width <= 0 {
		return ""
	}
	return ansi.Truncate(s, width, "…")
}

func centerLine(s string, width int) string {
	w := lipgloss.Width(s)
	if w >= width {
		return truncateStyled(s, width)
	}
	left := (width - w) / 2
	return strings.Repeat(" ", left) + s
}

func padRight(s string, width int) string {
	if gap := width - lipgloss.Width(s); gap > 0 {
		return s + strings.Repeat(" ", gap)
	}
	return truncateStyled(s, width)
}

func padBetween(left, right string, width int) string {
	lw, rw := lipgloss.Width(left), lipgloss.Width(right)
	if lw+rw+1 > width {
		avail := max(0, width-rw-1)
		left = truncateStyled(left, avail)
		lw = lipgloss.Width(left)
	}
	gap := width - lw - rw
	if gap < 0 {
		gap = 0
	}
	return left + strings.Repeat(" ", gap) + right
}
