package scan

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// Neighbor is an entry from the kernel's ARP/neighbor table.
type Neighbor struct {
	IP    netip.Addr
	MAC   string
	State string
	Iface string
}

const (
	nudIncomplete = 0x01
	nudReachable  = 0x02
	nudStale      = 0x04
	nudDelay      = 0x08
	nudProbe      = 0x10
	nudFailed     = 0x20
	nudNoARP      = 0x40
	nudPermanent  = 0x80

	ndaDst    = 1
	ndaLLAddr = 2
)

// neighborTable reads IPv4 ARP entries from the kernel using netlink, then
// enriches them with the interface name. It falls back to /proc/net/arp.
func neighborTable(ifIndex int) ([]Neighbor, error) {
	neighbors, err := netlinkNeighbors(ifIndex)
	if err == nil {
		return neighbors, nil
	}
	return procARP(ifIndex)
}

func netlinkNeighbors(ifIndex int) ([]Neighbor, error) {
	rib, err := syscall.NetlinkRIB(syscall.RTM_GETNEIGH, syscall.AF_INET)
	if err != nil {
		return nil, err
	}
	msgs, err := syscall.ParseNetlinkMessage(rib)
	if err != nil {
		return nil, err
	}

	var out []Neighbor
	for _, msg := range msgs {
		if msg.Header.Type != syscall.RTM_NEWNEIGH || len(msg.Data) < 12 {
			continue
		}
		if msg.Data[0] != syscall.AF_INET {
			continue
		}
		idx := int(int32(binary.NativeEndian.Uint32(msg.Data[4:8])))
		if ifIndex > 0 && idx != ifIndex {
			continue
		}
		state := binary.NativeEndian.Uint16(msg.Data[8:10])
		if state&(nudIncomplete|nudFailed) != 0 {
			continue
		}

		var dst []byte
		var lladdr []byte
		attrs := msg.Data[12:]
		for len(attrs) >= 4 {
			alen := int(binary.NativeEndian.Uint16(attrs[0:2]))
			atype := binary.NativeEndian.Uint16(attrs[2:4])
			if alen < 4 || alen > len(attrs) {
				break
			}
			val := attrs[4:alen]
			switch atype {
			case ndaDst:
				dst = val
			case ndaLLAddr:
				lladdr = val
			}
			step := (alen + 3) &^ 3
			if step > len(attrs) {
				break
			}
			attrs = attrs[step:]
		}
		if len(dst) != 4 || len(lladdr) < 6 {
			continue
		}
		ip := netip.AddrFrom4([4]byte(dst[:4]))
		mac := net.HardwareAddr(lladdr[:6]).String()
		if isZeroMAC(mac) {
			continue
		}
		out = append(out, Neighbor{
			IP:    ip,
			MAC:   mac,
			State: nudName(state),
			Iface: interfaceName(idx),
		})
	}
	return out, nil
}

func nudName(state uint16) string {
	switch {
	case state&nudReachable != 0:
		return "reachable"
	case state&nudPermanent != 0:
		return "permanent"
	case state&nudDelay != 0:
		return "delay"
	case state&nudProbe != 0:
		return "probe"
	case state&nudStale != 0:
		return "stale"
	case state&nudNoARP != 0:
		return "noarp"
	default:
		return "unknown"
	}
}

func interfaceName(index int) string {
	if iface, err := net.InterfaceByIndex(index); err == nil {
		return iface.Name
	}
	return strconv.Itoa(index)
}

func isZeroMAC(mac string) bool {
	return mac == "" || mac == "00:00:00:00:00:00"
}

// procARP is a fallback for systems where netlink is unavailable.
func procARP(ifIndex int) ([]Neighbor, error) {
	data, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return nil, err
	}
	ifaceName := ""
	if ifIndex > 0 {
		ifaceName = interfaceName(ifIndex)
	}
	var out []Neighbor
	for i, line := range strings.Split(string(data), "\n") {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		if ifaceName != "" && fields[5] != ifaceName {
			continue
		}
		if fields[3] == "00:00:00:00:00:00" {
			continue
		}
		ip, err := netip.ParseAddr(fields[0])
		if err != nil {
			continue
		}
		out = append(out, Neighbor{
			IP:    ip,
			MAC:   strings.ToLower(fields[3]),
			State: "reachable",
			Iface: fields[5],
		})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no ARP entries")
	}
	return out, nil
}
