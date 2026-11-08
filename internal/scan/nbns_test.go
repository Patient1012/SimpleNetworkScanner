package scan

import (
	"encoding/binary"
	"fmt"
	"testing"
)

func TestNBNSStatusRequest(t *testing.T) {
	req := nbnsStatusRequest(0x1234)
	if len(req) != 50 {
		t.Fatalf("request length %d", len(req))
	}
	if binary.BigEndian.Uint16(req[0:2]) != 0x1234 {
		t.Fatal("bad transaction id")
	}
	if binary.BigEndian.Uint16(req[4:6]) != 1 {
		t.Fatal("expected one question")
	}
	if req[12] != 0x20 || req[13] != 'C' || req[14] != 'K' {
		t.Fatalf("bad encoded wildcard: % x", req[12:16])
	}
}

func TestParseNBNSResponse(t *testing.T) {
	pkt := nbnsStatusRequest(1)
	binary.BigEndian.PutUint16(pkt[2:4], 0x8400) // response
	binary.BigEndian.PutUint16(pkt[6:8], 1)      // one answer

	data := []byte{2}
	data = append(data, []byte(fmt.Sprintf("%-15s", "WORKSTATION"))...)
	data = append(data, 0x00, 0x00, 0x00)
	group := []byte(fmt.Sprintf("%-15s", "WORKGROUP"))
	group[14] = 'P'
	data = append(data, group...)
	data = append(data, 0x00, 0x80, 0x00)

	var rr []byte
	rr = append(rr, 0xC0, 0x0C) // compressed name pointer to offset 12
	rr = append(rr, 0x00, 0x21)
	rr = append(rr, 0x00, 0x01)
	rr = append(rr, 0x00, 0x00, 0x00, 0x3C)
	var rdlen [2]byte
	binary.BigEndian.PutUint16(rdlen[:], uint16(len(data)))
	rr = append(rr, rdlen[:]...)
	rr = append(rr, data...)
	pkt = append(pkt, rr...)

	if got := parseNBNSResponse(pkt); got != "WORKSTATION" {
		t.Fatalf("got %q", got)
	}

	if got := parseNBNSResponse([]byte{1, 2, 3}); got != "" {
		t.Fatalf("malformed gave %q", got)
	}
}

func TestSkipDNSName(t *testing.T) {
	// A label "ab" followed by a pointer.
	pkt := []byte{2, 'a', 'b', 0xC0, 0x0C}
	end, ok := skipDNSName(pkt, 0)
	if !ok || end != 5 {
		t.Fatalf("end=%d ok=%v", end, ok)
	}
	if _, ok := skipDNSName([]byte{2, 'a'}, 0); ok {
		t.Fatal("truncated name should fail")
	}
}
