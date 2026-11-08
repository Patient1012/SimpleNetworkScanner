package scan

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// Detect resolves the network interface, local address, subnet and gateway to
// scan. If opts.Interface or opts.Subnet are set they take precedence.
func Detect(opts Options) (*Network, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}

	defaultIface, defaultGateway := defaultRoute()

	var candidates []net.Interface
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		candidates = append(candidates, iface)
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no active network interface found")
	}

	var chosen *net.Interface
	if opts.Interface != "" {
		for i := range ifaces {
			if ifaces[i].Name == opts.Interface {
				if ifaces[i].Flags&net.FlagUp == 0 {
					return nil, fmt.Errorf("interface %s is down", opts.Interface)
				}
				chosen = &ifaces[i]
				break
			}
		}
		if chosen == nil {
			return nil, fmt.Errorf("interface %q not found", opts.Interface)
		}
	} else if defaultIface != "" {
		for i := range candidates {
			if candidates[i].Name == defaultIface {
				chosen = &candidates[i]
				break
			}
		}
	}
	if chosen == nil {
		for i := range candidates {
			if hasIPv4(&candidates[i]) {
				chosen = &candidates[i]
				break
			}
		}
	}
	if chosen == nil {
		return nil, fmt.Errorf("no active network interface with an IPv4 address found")
	}

	localIP, mask, err := interfaceIPv4(chosen)
	if err != nil {
		return nil, err
	}

	var prefix netip.Prefix
	if opts.Subnet != "" {
		prefix, err = parseSubnet(opts.Subnet)
		if err != nil {
			return nil, err
		}
		// If the user supplied an address instead of a network, mask it.
		prefix = prefix.Masked()
	} else {
		bits := maskSize(mask)
		addr := netip.AddrFrom4([4]byte(localIP.To4()))
		prefix, err = addr.Prefix(bits)
		if err != nil {
			return nil, fmt.Errorf("build subnet: %w", err)
		}
	}

	gateway := netip.Addr{}
	if chosen.Name == defaultIface && defaultGateway.IsValid() {
		gateway = defaultGateway
	}

	return &Network{
		InterfaceName: chosen.Name,
		Interface:     chosen,
		LocalIP:       netip.AddrFrom4([4]byte(localIP.To4())),
		LocalMAC:      chosen.HardwareAddr,
		Prefix:        prefix.Masked(),
		Gateway:       gateway,
	}, nil
}

func parseSubnet(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "/") {
		addr, err := netip.ParseAddr(s)
		if err != nil || !addr.Is4() {
			return netip.Prefix{}, fmt.Errorf("invalid subnet %q: expected CIDR such as 192.168.1.0/24", s)
		}
		p, err := addr.Prefix(24)
		if err != nil {
			return netip.Prefix{}, err
		}
		return p.Masked(), nil
	}
	p, err := netip.ParsePrefix(s)
	if err != nil || !p.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("invalid subnet %q: expected IPv4 CIDR such as 192.168.1.0/24", s)
	}
	return p.Masked(), nil
}

func hasIPv4(iface *net.Interface) bool {
	_, _, err := interfaceIPv4(iface)
	return err == nil
}

func interfaceIPv4(iface *net.Interface) (net.IP, net.IPMask, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, nil, fmt.Errorf("addresses for %s: %w", iface.Name, err)
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip4 := ipnet.IP.To4()
		if ip4 == nil {
			continue
		}
		return ip4, ipnet.Mask, nil
	}
	return nil, nil, fmt.Errorf("interface %s has no IPv4 address", iface.Name)
}

func maskSize(mask net.IPMask) int {
	ones, bits := mask.Size()
	if bits != 32 || ones < 0 {
		return 24
	}
	return ones
}

// defaultRoute reads the IPv4 default route from /proc/net/route.
func defaultRoute() (iface string, gateway netip.Addr) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return "", netip.Addr{}
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 {
			continue
		}
		if fields[1] != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(fields[3], 16, 32)
		if err != nil || flags&0x1 == 0 {
			continue
		}
		iface = fields[0]
		if gw, err := parseRouteHex(fields[2]); err == nil {
			gateway = gw
		}
		return iface, gateway
	}
	return iface, gateway
}

// parseRouteHex converts the little-endian hex form used by /proc/net/route.
func parseRouteHex(s string) (netip.Addr, error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 4 {
		return netip.Addr{}, fmt.Errorf("bad route address %q", s)
	}
	var v [4]byte
	v[0] = b[3]
	v[1] = b[2]
	v[2] = b[1]
	v[3] = b[0]
	return netip.AddrFrom4(v), nil
}

// Hosts enumerates the usable host addresses in the network. It returns the
// addresses plus whether the list was truncated to max.
func (n *Network) Hosts(max int) ([]netip.Addr, bool) {
	prefix := n.Prefix.Masked()
	bits := prefix.Bits()
	base := prefix.Addr().As4()
	baseVal := binary.BigEndian.Uint32(base[:])
	size := uint64(1) << uint(32-bits)

	var first, last uint64
	switch {
	case bits >= 31:
		first, last = 0, size-1
	case size <= 2:
		first, last = 0, size-1
	default:
		// Exclude network and broadcast addresses.
		first, last = 1, size-2
	}
	count := int(last - first + 1)

	truncated := false
	if max > 0 && count > max {
		count = max
		truncated = true
	}

	hosts := make([]netip.Addr, 0, count)
	for i := 0; i < count; i++ {
		v := baseVal + uint32(first) + uint32(i)
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], v)
		hosts = append(hosts, netip.AddrFrom4(b))
	}
	return hosts, truncated
}

// IsLocal reports whether addr is assigned to the scanning interface.
func (n *Network) IsLocal(addr netip.Addr) bool {
	return n.LocalIP == addr
}
