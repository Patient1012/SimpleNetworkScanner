// Package oui provides offline MAC address vendor lookup using the IEEE
// Organizationally Unique Identifier registry.
package oui

import (
	_ "embed"
	"encoding/csv"
	"io"
	"sort"
	"strings"
	"sync"
)

//go:embed oui.csv
var csvData string

var (
	once  sync.Once
	table map[string]string
	long  []string
)

func load() {
	table = make(map[string]string, 42000)
	r := csv.NewReader(strings.NewReader(csvData))
	r.FieldsPerRecord = -1
	// Skip the header row.
	if _, err := r.Read(); err != nil {
		return
	}
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil || len(rec) < 3 {
			continue
		}
		prefix := strings.ToUpper(strings.TrimSpace(rec[1]))
		org := strings.TrimSpace(rec[2])
		if len(prefix) != 6 || org == "" {
			continue
		}
		table[prefix] = org
		long = append(long, org)
	}
	// Prefer shorter, more specific company names when the registry contains
	// several variants of the same organization.
	sort.SliceStable(long, func(i, j int) bool { return len(long[i]) < len(long[j]) })
}

// Lookup returns the organization registered for a MAC address, or "".
// It accepts "aa:bb:cc:dd:ee:ff", "aa-bb-cc-dd-ee-ff" and "aabbccddeeff".
func Lookup(mac string) string {
	once.Do(load)
	clean := strings.Map(func(r rune) rune {
		switch r {
		case ':', '-', '.', ' ':
			return -1
		}
		return r
	}, strings.ToUpper(mac))
	if len(clean) < 6 {
		return ""
	}
	return table[clean[:6]]
}

// Count returns the number of OUI entries loaded.
func Count() int {
	once.Do(load)
	return len(table)
}
