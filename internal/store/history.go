// Package store persists device history between runs.
package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"netscan/internal/scan"
)

const version = 1

// Record is a persisted device observation.
type Record struct {
	IP        string    `json:"ip"`
	MAC       string    `json:"mac,omitempty"`
	Name      string    `json:"name,omitempty"`
	Vendor    string    `json:"vendor,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

type fileFormat struct {
	Version int               `json:"version"`
	Devices map[string]Record `json:"devices"`
}

// History is an in-memory view of the persisted device database.
type History struct {
	Path    string
	Records map[string]Record

	mu sync.Mutex
}

// Load reads the history file. A missing or corrupt file yields an empty
// history rather than an error.
func Load() *History {
	h := &History{Path: defaultPath(), Records: map[string]Record{}}
	data, err := os.ReadFile(h.Path)
	if err != nil {
		return h
	}
	var f fileFormat
	if err := json.Unmarshal(data, &f); err != nil || f.Devices == nil {
		return h
	}
	for key, rec := range f.Devices {
		if rec.IP == "" {
			continue
		}
		h.Records[key] = rec
	}
	return h
}

func defaultPath() string {
	if dir := os.Getenv("XDG_STATE_HOME"); dir != "" {
		return filepath.Join(dir, "netscan", "history.json")
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.Join(os.TempDir(), "netscan-history.json")
	}
	return filepath.Join(home, ".local", "state", "netscan", "history.json")
}

// Lookup finds a record by MAC first, then by IP.
func (h *History) Lookup(ip, mac string) (Record, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if mac != "" {
		if rec, ok := h.Records[mac]; ok {
			return rec, true
		}
	}
	for _, rec := range h.Records {
		if rec.IP == ip {
			return rec, true
		}
	}
	return Record{}, false
}

// Apply fills FirstSeen and LastSeen on a device from persisted history.
func (h *History) Apply(d *scan.Device) {
	rec, ok := h.Lookup(d.IP.String(), d.MAC)
	if !ok {
		if d.FirstSeen.IsZero() {
			d.FirstSeen = time.Now()
		}
		return
	}
	d.FirstSeen = rec.FirstSeen
	if d.NameSource == "" && rec.Name != "" && d.Hostname == "" {
		d.Hostname = rec.Name
		d.NameSource = "remembered"
	}
	if d.Vendor == "" {
		d.Vendor = rec.Vendor
	}
	if !d.LastSeen.After(rec.LastSeen) {
		d.LastSeen = rec.LastSeen
	}
}

// Update merges a completed scan into the history and returns it. Records are
// keyed by MAC when available so DHCP address changes keep their identity.
func (h *History) Update(devices []scan.Device) {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()

	for _, d := range devices {
		key := d.Key()
		old, oldKey := h.findLocked(d.IP.String(), d.MAC)

		first := d.FirstSeen
		if first.IsZero() {
			first = old.FirstSeen
		}
		if first.IsZero() {
			first = now
		}
		last := d.LastSeen
		if last.IsZero() {
			last = now
		}
		name := d.Hostname
		if name == "" {
			name = old.Name
		}
		vendor := d.Vendor
		if vendor == "" {
			vendor = old.Vendor
		}
		rec := Record{
			IP:        d.IP.String(),
			MAC:       d.MAC,
			Name:      name,
			Vendor:    vendor,
			FirstSeen: first,
			LastSeen:  last,
		}
		if oldKey != "" && oldKey != key {
			delete(h.Records, oldKey)
		}
		h.Records[key] = rec
	}
}

func (h *History) findLocked(ip, mac string) (Record, string) {
	if mac != "" {
		if rec, ok := h.Records[mac]; ok {
			return rec, mac
		}
	}
	for key, rec := range h.Records {
		if rec.IP == ip {
			return rec, key
		}
	}
	return Record{}, ""
}

// Snapshot returns records sorted by IP.
func (h *History) Snapshot() []Record {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]Record, 0, len(h.Records))
	for _, rec := range h.Records {
		out = append(out, rec)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}

// Save writes the history atomically.
func (h *History) Save() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(h.Path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(fileFormat{Version: version, Devices: h.Records}, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(h.Path), ".history-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, h.Path)
}
