// Command netscan is a terminal network scanner for the local subnet.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"

	"netscan/internal/scan"
	"netscan/internal/store"
	"netscan/internal/ui"
)

var version = "1.0.0"

func main() {
	if err := run(); err != nil {
		clearTerminal(os.Stderr)
		fmt.Fprintln(os.Stderr, "netscan:", err)
		os.Exit(1)
	}
}

// clearTerminal wipes the screen before an error is printed after the TUI has
// stopped, so a partial or restored interface does not obscure the message.
func clearTerminal(f *os.File) {
	if f == nil || !isTTY(f) || os.Getenv("TERM") == "dumb" {
		return
	}
	fmt.Fprint(f, "\x1b[2J\x1b[H")
}

func run() error {
	var (
		iface     = flag.String("iface", "", "network interface to scan (default: interface of the default route)")
		subnet    = flag.String("subnet", "", "subnet in CIDR form, e.g. 192.168.1.0/24 (default: detected)")
		portsSpec = flag.String("ports", "", "comma-separated TCP ports or ranges (default: a curated set)")
		interval  = flag.Duration("interval", 60*time.Second, "auto-refresh interval in the TUI; 0 disables it")
		portTO    = flag.Duration("timeout", 400*time.Millisecond, "TCP connection timeout per port")
		pingTO    = flag.Duration("ping-timeout", 800*time.Millisecond, "ICMP echo timeout per host")
		maxHosts  = flag.Int("max-hosts", 1024, "maximum number of addresses to scan")
		once      = flag.Bool("once", false, "scan once, print a table, and exit")
		jsonOut   = flag.Bool("json", false, "scan once and print JSON (implies --once)")
		noColor   = flag.Bool("no-color", false, "disable color output")
		noMDNS    = flag.Bool("no-mdns", false, "disable mDNS/Bonjour name discovery")
		noNBNS    = flag.Bool("no-nbns", false, "disable NetBIOS name discovery")
		printVer  = flag.Bool("version", false, "print version and exit")
	)
	flag.Usage = usage
	flag.Parse()

	if *printVer {
		fmt.Printf("netscan %s\n", version)
		return nil
	}
	if *interval < 0 {
		return fmt.Errorf("--interval cannot be negative")
	}
	if *maxHosts <= 0 {
		return fmt.Errorf("--max-hosts must be positive")
	}
	ports, err := scan.ParsePorts(*portsSpec)
	if err != nil {
		return err
	}

	opts := scan.Options{
		Interface:   *iface,
		Subnet:      *subnet,
		Ports:       ports,
		PortTimeout: *portTO,
		PingTimeout: *pingTO,
		MaxHosts:    *maxHosts,
		DisableMDNS: *noMDNS,
		DisableNBNS: *noNBNS,
	}
	scanner, err := scan.New(opts)
	if err != nil {
		return err
	}

	if *noColor || os.Getenv("NO_COLOR") != "" {
		lipgloss.SetColorProfile(termenv.Ascii)
	}

	if *jsonOut || *once {
		return runOnce(scanner, *jsonOut)
	}

	history := store.Load()
	model := ui.New(ui.Config{
		Scanner:  scanner,
		History:  history,
		Interval: *interval,
		Version:  version,
	})
	p := tea.NewProgram(model, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		return fmt.Errorf("TUI: %w", err)
	}
	return nil
}

func runOnce(scanner *scan.Scanner, asJSON bool) error {
	history := store.Load()
	start := time.Now()
	progress := func(p scan.Progress) {
		if !isTTY(os.Stderr) {
			return
		}
		line := fmt.Sprintf("%s  %d/%d", p.Phase, p.Done, p.Total)
		if p.Total == 0 {
			line = p.Phase
		}
		fmt.Fprintf(os.Stderr, "\r\033[K%-70s", line)
	}
	devices, summary, err := scanner.Scan(context.Background(), progress, nil)
	if isTTY(os.Stderr) {
		fmt.Fprint(os.Stderr, "\r\033[K")
	}
	if err != nil {
		return err
	}
	for i := range devices {
		history.Apply(&devices[i])
	}
	history.Update(devices)
	_ = history.Save()

	if asJSON {
		return printJSON(scanner, devices, summary, start)
	}
	printTable(scanner, devices, summary)
	return nil
}

func printTable(scanner *scan.Scanner, devices []scan.Device, summary scan.Summary) {
	netw := scanner.Network()
	fmt.Printf("Network  %s  %s  (local %s", netw.InterfaceName, netw.Prefix, netw.LocalIP)
	if netw.Gateway.IsValid() {
		fmt.Printf(", gateway %s", netw.Gateway)
	}
	fmt.Println(")")

	sort.Slice(devices, func(i, j int) bool { return devices[i].IP.Less(devices[j].IP) })
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "IP\tHOSTNAME\tMAC\tVENDOR\tMODEL\tOPEN PORTS\tRTT\tTYPE\tSTATUS")
	online := 0
	for _, d := range devices {
		if d.Online {
			online++
		}
		hostname := d.Hostname
		if hostname == "" {
			hostname = "—"
		}
		mac := d.MAC
		if mac == "" {
			mac = "—"
		}
		vendor := d.Vendor
		if vendor == "" {
			vendor = "—"
		}
		model := d.Model
		if model == "" {
			model = "—"
		}
		ports := formatPorts(d.Ports)
		if ports == "" {
			ports = "—"
		}
		role := scan.DescribeRole(d)
		if role == "" {
			role = "—"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			d.IP, hostname, mac, vendor, model, ports, rttString(d.RTT), role, statusString(d))
	}
	tw.Flush()

	fmt.Println()
	fmt.Printf("%d online · %d known · scan %.1fs", online, len(devices), summary.Elapsed().Seconds())
	if summary.Truncated {
		fmt.Printf(" · subnet capped at %d hosts", summary.Hosts)
	}
	if !summary.PingAvailable {
		fmt.Print(" · ICMP unavailable (TCP/ARP only)")
	}
	fmt.Println()
}

func formatPorts(ports []int) string {
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = fmt.Sprintf("%d", p)
	}
	return strings.Join(parts, ",")
}

func rttString(d time.Duration) string {
	if d <= 0 {
		return "—"
	}
	if d < time.Millisecond {
		return "<1ms"
	}
	if d < 10*time.Millisecond {
		return fmt.Sprintf("%.1fms", float64(d)/float64(time.Millisecond))
	}
	return fmt.Sprintf("%dms", d.Milliseconds())
}

func statusString(d scan.Device) string {
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

func printJSON(scanner *scan.Scanner, devices []scan.Device, summary scan.Summary, started time.Time) error {
	type jsonDevice struct {
		IP        string    `json:"ip"`
		Hostname  string    `json:"hostname,omitempty"`
		MAC       string    `json:"mac,omitempty"`
		Vendor    string    `json:"vendor,omitempty"`
		Model     string    `json:"model,omitempty"`
		Ports     []int     `json:"ports"`
		LatencyMS *float64  `json:"latency_ms,omitempty"`
		Online    bool      `json:"online"`
		Self      bool      `json:"self"`
		Gateway   bool      `json:"gateway"`
		Role      string    `json:"role,omitempty"`
		NameFrom  string    `json:"name_source,omitempty"`
		FirstSeen time.Time `json:"first_seen,omitempty"`
		LastSeen  time.Time `json:"last_seen,omitempty"`
	}
	netw := scanner.Network()
	out := struct {
		Version     string       `json:"version"`
		Interface   string       `json:"interface"`
		Subnet      string       `json:"subnet"`
		LocalIP     string       `json:"local_ip"`
		Gateway     string       `json:"gateway,omitempty"`
		ScannedAt   time.Time    `json:"scanned_at"`
		DurationMS  int64        `json:"duration_ms"`
		Hosts       int          `json:"hosts_scanned"`
		DeviceCount int          `json:"device_count"`
		Ping        bool         `json:"icmp_available"`
		Devices     []jsonDevice `json:"devices"`
	}{
		Version:     version,
		Interface:   netw.InterfaceName,
		Subnet:      netw.Prefix.String(),
		LocalIP:     netw.LocalIP.String(),
		ScannedAt:   started,
		DurationMS:  summary.Elapsed().Milliseconds(),
		Hosts:       summary.Hosts,
		DeviceCount: len(devices),
		Ping:        summary.PingAvailable,
		Devices:     make([]jsonDevice, 0, len(devices)),
	}
	if netw.Gateway.IsValid() {
		out.Gateway = netw.Gateway.String()
	}
	for _, d := range devices {
		jd := jsonDevice{
			IP:        d.IP.String(),
			Hostname:  d.Hostname,
			MAC:       d.MAC,
			Vendor:    d.Vendor,
			Model:     d.Model,
			Ports:     d.Ports,
			Online:    d.Online,
			Self:      d.Self,
			Gateway:   d.Gateway,
			Role:      scan.DescribeRole(d),
			NameFrom:  d.NameSource,
			FirstSeen: d.FirstSeen,
			LastSeen:  d.LastSeen,
		}
		if d.Ports == nil {
			jd.Ports = []int{}
		}
		if d.RTT > 0 {
			ms := float64(d.RTT) / float64(time.Millisecond)
			jd.LatencyMS = &ms
		}
		out.Devices = append(out.Devices, jd)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func isTTY(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func usage() {
	out := flag.CommandLine.Output()
	fmt.Fprintf(out, `netscan %s - discover devices on your local network

Usage:
  netscan [flags]

The default mode is an interactive table. It rescans automatically and keeps
track of first/last seen times and device names between runs.

Flags:
`, version)
	flag.PrintDefaults()
	fmt.Fprint(out, `
Examples:
  netscan
  netscan --iface wlan0 --interval 30s
  netscan --subnet 10.0.0.0/24 --ports 22,80,443
  netscan --once
  netscan --json

Notes:
  Host discovery combines ICMP echo, TCP probes and the kernel ARP table.
  Names come from mDNS/Bonjour, NetBIOS, DHCP leases and reverse DNS.
  Models come from UPnP/SSDP descriptions and mDNS TXT records.
  MAC vendors are resolved offline from the IEEE OUI registry.
  No root privileges are required on Linux with unprivileged ICMP enabled.
`)
}
