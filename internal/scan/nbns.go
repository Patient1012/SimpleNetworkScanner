package scan

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// nbnsNames queries the NetBIOS name service (UDP 137) for workstation names.
// Windows and Samba hosts usually answer a node status request.
func nbnsNames(ctx context.Context, hosts []netip.Addr, timeout time.Duration, workers int) map[netip.Addr]nameCandidate {
	if len(hosts) == 0 {
		return nil
	}
	if workers < 1 {
		workers = 24
	}
	if workers > len(hosts) {
		workers = len(hosts)
	}
	out := map[netip.Addr]nameCandidate{}
	var mu sync.Mutex

	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for i, ip := range hosts {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(ip netip.Addr, txID uint16) {
			defer wg.Done()
			defer func() { <-sem }()
			if name := queryNBNS(ip, txID, timeout); name != "" {
				mu.Lock()
				out[ip] = nameCandidate{name: name, source: "netbios", score: 65}
				mu.Unlock()
			}
		}(ip, uint16(i+1))
	}
	wg.Wait()
	return out
}

func queryNBNS(ip netip.Addr, txID uint16, timeout time.Duration) string {
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IP(ip.AsSlice()), Port: 137})
	if err != nil {
		return ""
	}
	defer conn.Close()

	req := nbnsStatusRequest(txID)
	if _, err := conn.Write(req); err != nil {
		return ""
	}
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil || n < 12 {
		return ""
	}
	return parseNBNSResponse(buf[:n])
}

// nbnsStatusRequest builds a NetBIOS node status request for the wildcard
// name "*", encoded with the standard first-level encoding.
func nbnsStatusRequest(txID uint16) []byte {
	b := make([]byte, 0, 50)
	var hdr [12]byte
	binary.BigEndian.PutUint16(hdr[0:2], txID)
	// Flags 0x0000 (query), QDCOUNT 1.
	binary.BigEndian.PutUint16(hdr[4:6], 1)
	b = append(b, hdr[:]...)

	// Encoded "*" padded to 16 bytes.
	b = append(b, 0x20)
	b = append(b, 'C', 'K')
	for i := 0; i < 30; i++ {
		b = append(b, 'A')
	}
	b = append(b, 0x00)
	b = append(b, 0x00, 0x21) // NBSTAT
	b = append(b, 0x00, 0x01) // IN
	return b
}

// parseNBNSResponse extracts the workstation name from a node status response.
func parseNBNSResponse(pkt []byte) string {
	if len(pkt) < 12 {
		return ""
	}
	ancount := int(binary.BigEndian.Uint16(pkt[6:8]))
	if ancount == 0 {
		return ""
	}
	pos := 12
	// Skip question name and fixed question fields.
	skip, ok := skipDNSName(pkt, pos)
	if !ok {
		return ""
	}
	pos = skip + 4
	var fallback string
	for i := 0; i < ancount && pos < len(pkt); i++ {
		nameEnd, ok := skipDNSName(pkt, pos)
		if !ok || nameEnd+10 > len(pkt) {
			return fallback
		}
		rtype := binary.BigEndian.Uint16(pkt[nameEnd : nameEnd+2])
		rdlen := int(binary.BigEndian.Uint16(pkt[nameEnd+8 : nameEnd+10]))
		dataStart := nameEnd + 10
		dataEnd := dataStart + rdlen
		if dataEnd > len(pkt) {
			return fallback
		}
		if rtype == 0x0021 && rdlen >= 1 {
			name := parseNBSTATNames(pkt[dataStart:dataEnd])
			if name != "" {
				return name
			}
			fallback = name
		}
		pos = dataEnd
	}
	return fallback
}

func parseNBSTATNames(data []byte) string {
	if len(data) < 1 {
		return ""
	}
	count := int(data[0])
	var fileServer string
	for i := 0; i < count; i++ {
		off := 1 + i*18
		if off+18 > len(data) {
			break
		}
		raw := data[off : off+15]
		suffix := data[off+15]
		flags := binary.BigEndian.Uint16(data[off+16 : off+18])
		if flags&0x8000 != 0 {
			continue // group name
		}
		name := strings.TrimRight(strings.TrimSpace(string(raw)), "\x00")
		name = strings.TrimSpace(name)
		if name == "" || !isReasonableName(name) {
			continue
		}
		switch suffix {
		case 0x00:
			return name
		case 0x20:
			if fileServer == "" {
				fileServer = name
			}
		}
	}
	return fileServer
}

// skipDNSName returns the offset just past a (possibly compressed) DNS name.
func skipDNSName(pkt []byte, pos int) (int, bool) {
	for pos < len(pkt) {
		l := int(pkt[pos])
		if l == 0 {
			return pos + 1, true
		}
		if l&0xC0 == 0xC0 {
			if pos+1 >= len(pkt) {
				return 0, false
			}
			return pos + 2, true
		}
		if l&0xC0 != 0 {
			return 0, false
		}
		pos += 1 + l
	}
	return 0, false
}
