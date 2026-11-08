package ui

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"netscan/internal/scan"
	"netscan/internal/store"
)

// Config configures the TUI.
type Config struct {
	Scanner  *scan.Scanner
	History  *store.History
	Interval time.Duration
	Version  string
}

// Model is the Bubble Tea application model.
type Model struct {
	cfg      Config
	styles   styles
	spinner  spinner.Model
	filter   textinput.Model
	interval time.Duration

	width  int
	height int

	devices map[string]*scan.Device
	rows    []*scan.Device
	cursor  int
	offset  int

	sortKey  SortKey
	sortDesc bool

	showOffline bool
	paused      bool
	filterValue string
	filterFocus bool

	showHelp   bool
	showDetail bool
	detailIP   string

	scanning     bool
	scanID       int
	scanCh       chan tea.Msg
	scanCancel   context.CancelFunc
	phase        string
	progressDone int
	progressFull int
	lastSummary  scan.Summary
	lastScan     time.Time
	nextScan     time.Time
	lastErr      error
	hasScanned   bool

	toast      string
	toastUntil time.Time

	quit bool
}

// SortKey identifies the sortable table column.
type SortKey int

const (
	SortIP SortKey = iota
	SortName
	SortVendor
	SortMAC
	SortPorts
	SortRTT
	SortStatus
)

func (k SortKey) String() string {
	switch k {
	case SortIP:
		return "IP"
	case SortName:
		return "hostname"
	case SortVendor:
		return "vendor"
	case SortMAC:
		return "MAC"
	case SortPorts:
		return "open ports"
	case SortRTT:
		return "latency"
	case SortStatus:
		return "status"
	}
	return "IP"
}

type tickMsg time.Time
type progressMsg struct {
	id int
	p  scan.Progress
}
type deviceFoundMsg struct {
	id int
	d  scan.Device
}
type scanDoneMsg struct {
	id      int
	devices []scan.Device
	summary scan.Summary
	err     error
}
type scanClosedMsg struct{ id int }
type savedMsg struct{ err error }

// New creates the TUI model.
func New(cfg Config) *Model {
	if cfg.History == nil {
		cfg.History = store.Load()
	}
	m := &Model{
		cfg:         cfg,
		styles:      newStyles(),
		devices:     map[string]*scan.Device{},
		sortKey:     SortIP,
		showOffline: true,
		interval:    cfg.Interval,
	}

	m.spinner = spinner.New(
		spinner.WithSpinner(spinner.Dot),
		spinner.WithStyle(m.styles.accent),
	)

	m.filter = textinput.New()
	m.filter.Placeholder = "IP, hostname, MAC or vendor"
	m.filter.Prompt = "/ "
	m.filter.CharLimit = 80
	m.filter.Width = 44

	for _, rec := range cfg.History.Snapshot() {
		addr, err := netip.ParseAddr(rec.IP)
		if err != nil || !addr.Is4() {
			continue
		}
		source := ""
		if rec.Name != "" {
			source = "remembered"
		}
		m.devices[rec.IP] = &scan.Device{
			IP:         addr,
			MAC:        rec.MAC,
			Hostname:   rec.Name,
			Vendor:     rec.Vendor,
			Online:     false,
			FirstSeen:  rec.FirstSeen,
			LastSeen:   rec.LastSeen,
			NameSource: source,
		}
	}
	m.recomputeRows(false)
	return m
}

// Init starts the first scan, the clock, and the spinner.
func (m *Model) Init() tea.Cmd {
	return tea.Batch(m.startScan(), tickCmd())
}

func tickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func (m *Model) startScan() tea.Cmd {
	if m.scanCancel != nil {
		m.scanCancel()
	}
	m.scanID++
	id := m.scanID
	ctx, cancel := context.WithCancel(context.Background())
	m.scanCancel = cancel
	m.scanning = true
	m.phase = "Starting scan"
	m.progressDone = 0
	m.progressFull = 0
	m.lastErr = nil
	m.nextScan = time.Time{}

	ch := make(chan tea.Msg, 512)
	m.scanCh = ch
	scanner := m.cfg.Scanner

	go func() {
		devices, summary, err := scanner.Scan(
			ctx,
			func(p scan.Progress) {
				select {
				case ch <- progressMsg{id: id, p: p}:
				case <-ctx.Done():
				}
			},
			func(d scan.Device) {
				select {
				case ch <- deviceFoundMsg{id: id, d: d}:
				case <-ctx.Done():
				}
			},
		)
		select {
		case ch <- scanDoneMsg{id: id, devices: devices, summary: summary, err: err}:
		case <-ctx.Done():
		}
		close(ch)
	}()

	return tea.Batch(m.spinner.Tick, waitForScan(ch, id))
}

func waitForScan(ch chan tea.Msg, id int) tea.Cmd {
	return func() tea.Msg {
		msg, ok := <-ch
		if !ok {
			return scanClosedMsg{id: id}
		}
		return msg
	}
}

// Update handles Bubble Tea messages.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		if m.filterFocus {
			m.filter.Width = max(20, min(60, msg.Width-20))
		}
		m.ensureVisible()
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)

	case tickMsg:
		if m.toast != "" && time.Now().After(m.toastUntil) {
			m.toast = ""
		}
		return m, tea.Batch(tickCmd(), m.maybeAutoScan())

	case spinner.TickMsg:
		if !m.scanning {
			return m, nil
		}
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	case progressMsg:
		if msg.id != m.scanID {
			return m, nil
		}
		m.phase = msg.p.Phase
		m.progressDone = msg.p.Done
		m.progressFull = msg.p.Total
		return m, waitForScan(m.scanCh, msg.id)

	case deviceFoundMsg:
		if msg.id != m.scanID {
			return m, nil
		}
		m.mergeDevice(msg.d)
		m.recomputeRows(true)
		return m, waitForScan(m.scanCh, msg.id)

	case scanDoneMsg:
		if msg.id != m.scanID {
			return m, nil
		}
		return m, m.finishScan(msg)

	case scanClosedMsg:
		if msg.id == m.scanID && m.scanning {
			m.scanning = false
			if m.lastErr == nil {
				m.lastErr = errors.New("scan ended unexpectedly")
			}
		}
		return m, nil

	case savedMsg:
		if msg.err != nil {
			m.setToast("Could not save history: " + msg.err.Error())
		}
		return m, nil
	}
	return m, nil
}

func (m *Model) maybeAutoScan() tea.Cmd {
	if m.interval <= 0 || m.paused || m.scanning || m.nextScan.IsZero() {
		return nil
	}
	if time.Now().Before(m.nextScan) {
		return nil
	}
	return m.startScan()
}

func (m *Model) finishScan(msg scanDoneMsg) tea.Cmd {
	m.scanning = false
	now := time.Now()
	m.hasScanned = true
	if msg.err != nil && !errors.Is(msg.err, context.Canceled) {
		m.lastErr = msg.err
	} else {
		m.lastErr = nil
	}

	success := msg.err == nil
	seen := make(map[string]bool, len(msg.devices))
	for i := range msg.devices {
		d := msg.devices[i]
		if d.Ports == nil {
			d.Ports = []int{}
		}
		if d.FirstSeen.IsZero() {
			m.cfg.History.Apply(&d)
		}
		d.Online = true
		d.LastSeen = now
		m.mergeDevice(d)
		seen[d.IP.String()] = true
	}
	if success {
		for ip, d := range m.devices {
			if !seen[ip] {
				d.Online = false
			}
		}
	}

	if msg.summary.Finished.IsZero() {
		msg.summary.Finished = now
	}
	m.lastSummary = msg.summary
	m.lastScan = now
	if m.interval > 0 {
		m.nextScan = now.Add(m.interval)
	}
	m.recomputeRows(true)

	if len(seen) > 0 {
		batch := make([]scan.Device, 0, len(seen))
		for ip := range seen {
			if d, ok := m.devices[ip]; ok {
				batch = append(batch, *d)
			}
		}
		m.cfg.History.Update(batch)
		return saveHistoryCmd(m.cfg.History)
	}
	return nil
}

func saveHistoryCmd(h *store.History) tea.Cmd {
	return func() tea.Msg { return savedMsg{err: h.Save()} }
}

func (m *Model) mergeDevice(d scan.Device) {
	ip := d.IP.String()
	cur, ok := m.devices[ip]
	if !ok {
		m.cfg.History.Apply(&d)
		if d.FirstSeen.IsZero() {
			d.FirstSeen = time.Now()
		}
		if d.LastSeen.IsZero() {
			d.LastSeen = time.Now()
		}
		m.devices[ip] = &d
		return
	}
	if d.MAC != "" {
		cur.MAC = d.MAC
	}
	if d.Vendor != "" {
		cur.Vendor = d.Vendor
	}
	if d.Hostname != "" {
		cur.Hostname = d.Hostname
		cur.NameSource = d.NameSource
	}
	if d.Ports != nil {
		cur.Ports = append([]int(nil), d.Ports...)
	}
	if d.RTT > 0 {
		cur.RTT = d.RTT
	}
	if d.Online {
		cur.Online = true
	}
	if d.Self {
		cur.Self = true
	}
	if d.Gateway {
		cur.Gateway = true
	}
	if !d.LastSeen.IsZero() {
		cur.LastSeen = d.LastSeen
	}
	if cur.FirstSeen.IsZero() {
		cur.FirstSeen = d.FirstSeen
	}
}

func (m *Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	if m.filterFocus {
		switch key {
		case "ctrl+c":
			return m.quitNow()
		case "esc":
			m.filterFocus = false
			m.filter.Blur()
			m.filter.SetValue("")
			m.filterValue = ""
			m.recomputeRows(false)
			return m, nil
		case "enter":
			m.filterFocus = false
			m.filter.Blur()
			m.filterValue = m.filter.Value()
			m.recomputeRows(false)
			return m, nil
		default:
			var cmd tea.Cmd
			m.filter, cmd = m.filter.Update(msg)
			m.filterValue = m.filter.Value()
			m.recomputeRows(false)
			return m, cmd
		}
	}

	if m.showHelp {
		switch key {
		case "q", "ctrl+c":
			return m.quitNow()
		case "esc", "?", "h":
			m.showHelp = false
			return m, nil
		}
		return m, nil
	}
	if m.showDetail {
		switch key {
		case "q", "ctrl+c":
			return m.quitNow()
		case "esc", "enter", "d":
			m.showDetail = false
			return m, nil
		case "r":
			m.showDetail = false
			return m, m.startScan()
		}
		return m, nil
	}

	switch key {
	case "q", "ctrl+c":
		return m.quitNow()
	case "r":
		m.setToast("Rescanning…")
		return m, m.startScan()
	case "p":
		m.paused = !m.paused
		if m.paused {
			m.setToast("Auto-refresh paused")
		} else {
			m.setToast("Auto-refresh resumed")
			if m.interval > 0 && !m.lastScan.IsZero() {
				m.nextScan = time.Now()
			}
		}
	case "o":
		m.showOffline = !m.showOffline
		if m.showOffline {
			m.setToast("Showing offline devices")
		} else {
			m.setToast("Hiding offline devices")
		}
		m.recomputeRows(false)
	case "/":
		m.filterFocus = true
		m.showHelp = false
		m.showDetail = false
		m.filter.SetValue(m.filterValue)
		m.filter.CursorEnd()
		m.filter.Focus()
		if m.width > 0 {
			m.filter.Width = max(20, min(60, m.width-20))
		}
		return m, textinput.Blink
	case "esc":
		if m.filterValue != "" {
			m.filterValue = ""
			m.filter.SetValue("")
			m.recomputeRows(false)
			m.setToast("Filter cleared")
		}
	case "s":
		m.nextSort()
		m.recomputeRows(true)
	case "S":
		m.sortDesc = !m.sortDesc
		m.recomputeRows(true)
	case "g", "home":
		m.cursor = 0
		m.ensureVisible()
	case "G", "end":
		m.cursor = max(0, len(m.rows)-1)
		m.ensureVisible()
	case "up", "k":
		m.moveCursor(-1)
	case "down", "j":
		m.moveCursor(1)
	case "pgup", "ctrl+b":
		m.moveCursor(-m.pageSize())
	case "pgdown", "ctrl+f":
		m.moveCursor(m.pageSize())
	case "enter", "d":
		if d := m.selectedDevice(); d != nil {
			m.detailIP = d.IP.String()
			m.showDetail = true
		}
	case "?", "h":
		m.showHelp = true
	}
	return m, nil
}

func (m *Model) quitNow() (tea.Model, tea.Cmd) {
	m.quit = true
	if m.scanCancel != nil {
		m.scanCancel()
	}
	// Persist anything not yet saved before leaving.
	if m.cfg.History != nil {
		_ = m.cfg.History.Save()
	}
	return m, tea.Quit
}

func (m *Model) setToast(s string) {
	m.toast = s
	m.toastUntil = time.Now().Add(3 * time.Second)
}

func (m *Model) selectedDevice() *scan.Device {
	if m.cursor < 0 || m.cursor >= len(m.rows) {
		return nil
	}
	return m.rows[m.cursor]
}

func (m *Model) selectedIP() string {
	if d := m.selectedDevice(); d != nil {
		return d.IP.String()
	}
	return ""
}

func (m *Model) detailDevice() *scan.Device {
	return m.devices[m.detailIP]
}

func (m *Model) moveCursor(delta int) {
	if len(m.rows) == 0 {
		m.cursor = 0
		return
	}
	m.cursor += delta
	if m.cursor < 0 {
		m.cursor = 0
	}
	if m.cursor >= len(m.rows) {
		m.cursor = len(m.rows) - 1
	}
	m.ensureVisible()
}

func (m *Model) pageSize() int {
	return max(1, m.bodyHeight())
}

func (m *Model) bodyHeight() int {
	h := m.height
	if h <= 0 {
		h = 24
	}
	return max(1, h-4)
}

func (m *Model) ensureVisible() {
	vis := m.bodyHeight()
	if vis <= 0 {
		return
	}
	if m.cursor < m.offset {
		m.offset = m.cursor
	}
	if m.cursor >= m.offset+vis {
		m.offset = m.cursor - vis + 1
	}
	maxOffset := max(0, len(m.rows)-vis)
	if m.offset > maxOffset {
		m.offset = maxOffset
	}
	if m.offset < 0 {
		m.offset = 0
	}
}

func (m *Model) recomputeRows(keepSelection bool) {
	selected := ""
	if keepSelection {
		selected = m.selectedIP()
	}
	term := strings.ToLower(strings.TrimSpace(m.filterValue))

	rows := make([]*scan.Device, 0, len(m.devices))
	for _, d := range m.devices {
		if !m.showOffline && !d.Online {
			continue
		}
		if term != "" && !deviceMatches(d, term) {
			continue
		}
		rows = append(rows, d)
	}

	key := m.sortKey
	desc := m.sortDesc
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if key == SortName || key == SortVendor {
			af, bf := fieldValue(a, key) != "", fieldValue(b, key) != ""
			if af != bf {
				return af // empty values always last
			}
		}
		if key == SortRTT {
			az, bz := a.RTT == 0, b.RTT == 0
			if az != bz {
				return !az
			}
		}
		cmp := compareDevices(a, b, key)
		if cmp == 0 {
			return a.IP.Less(b.IP)
		}
		if desc {
			return cmp > 0
		}
		return cmp < 0
	})
	m.rows = rows

	if selected != "" {
		for i, d := range rows {
			if d.IP.String() == selected {
				m.cursor = i
				m.ensureVisible()
				return
			}
		}
	}
	if len(rows) == 0 {
		m.cursor = 0
		m.offset = 0
		return
	}
	if m.cursor >= len(rows) {
		m.cursor = len(rows) - 1
	}
	if m.cursor < 0 {
		m.cursor = 0
	}
	m.ensureVisible()
}

func (m *Model) nextSort() {
	visible := tableColumnsForWidth(m.width)
	if len(visible) == 0 {
		return
	}
	idx := 0
	for i, c := range visible {
		if c.key == m.sortKey {
			idx = (i + 1) % len(visible)
			break
		}
	}
	m.sortKey = visible[idx].key
}

func fieldValue(d *scan.Device, key SortKey) string {
	switch key {
	case SortName:
		return d.Hostname
	case SortVendor:
		return d.Vendor
	case SortMAC:
		return d.MAC
	}
	return ""
}

func compareDevices(a, b *scan.Device, key SortKey) int {
	switch key {
	case SortIP:
		if a.IP.Less(b.IP) {
			return -1
		}
		if a.IP == b.IP {
			return 0
		}
		return 1
	case SortName:
		return strings.Compare(strings.ToLower(a.Hostname), strings.ToLower(b.Hostname))
	case SortVendor:
		return strings.Compare(strings.ToLower(a.Vendor), strings.ToLower(b.Vendor))
	case SortMAC:
		return strings.Compare(a.MAC, b.MAC)
	case SortPorts:
		if len(a.Ports) != len(b.Ports) {
			if len(a.Ports) < len(b.Ports) {
				return -1
			}
			return 1
		}
		return 0
	case SortRTT:
		if a.RTT < b.RTT {
			return -1
		}
		if a.RTT > b.RTT {
			return 1
		}
		return 0
	case SortStatus:
		ra, rb := statusRank(a), statusRank(b)
		if ra < rb {
			return -1
		}
		if ra > rb {
			return 1
		}
		return 0
	}
	return 0
}

func statusRank(d *scan.Device) int {
	switch {
	case d.Self:
		return 0
	case d.Gateway:
		return 1
	case d.Online:
		return 2
	default:
		return 3
	}
}

func deviceMatches(d *scan.Device, term string) bool {
	parts := []string{
		d.IP.String(), d.Hostname, d.MAC, d.Vendor,
		d.NameSource, statusText(d), scan.DescribeRole(*d),
		formatPortsCompact(d.Ports),
	}
	for _, p := range parts {
		if p != "" && strings.Contains(strings.ToLower(p), term) {
			return true
		}
	}
	return false
}

func (m *Model) timeUntilNextScan() string {
	if m.interval <= 0 {
		return "auto-refresh off"
	}
	if m.paused {
		return "paused"
	}
	if m.scanning || m.nextScan.IsZero() {
		return "scanning"
	}
	left := time.Until(m.nextScan)
	if left < 0 {
		return "scanning"
	}
	secs := int(left.Round(time.Second).Seconds())
	if secs <= 0 {
		return "next scan now"
	}
	if secs >= 60 {
		return fmt.Sprintf("next scan %dm%02ds", secs/60, secs%60)
	}
	return fmt.Sprintf("next scan %ds", secs)
}
