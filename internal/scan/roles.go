package scan

import (
	"strings"
)

// DescribeRole produces a short, human-friendly guess at what a device is,
// based on its open ports, vendor and hostname.
func DescribeRole(d Device) string {
	if d.Self {
		return "This device"
	}
	if d.Gateway {
		return "Gateway / router"
	}

	has := func(port int) bool {
		for _, p := range d.Ports {
			if p == port {
				return true
			}
		}
		return false
	}
	hasAny := func(ports ...int) bool {
		for _, p := range ports {
			if has(p) {
				return true
			}
		}
		return false
	}

	var tags []string
	add := func(tag string) {
		for _, t := range tags {
			if t == tag {
				return
			}
		}
		tags = append(tags, tag)
	}

	// Strong signals from the services exposed by the device.
	if has(62078) {
		add("iPhone / iPad")
	}
	if hasAny(631, 515, 9100) {
		add("Printer")
	}
	if hasAny(3389, 5985, 5986) {
		add("Windows PC")
	}
	if hasAny(8008, 8009) {
		add("Chromecast")
	}
	if has(548) {
		add("Mac file sharing")
	}
	if hasAny(2375, 2376) {
		add("Docker host")
	}
	if has(5060) {
		add("VoIP phone")
	}
	if has(5900) {
		add("VNC")
	}
	if has(53) {
		add("DNS server")
	}

	// Vendor signatures.
	v := strings.ToLower(d.Vendor)
	addVendor := func(needle, tag string) {
		if strings.Contains(v, needle) {
			add(tag)
		}
	}
	addVendor("synology", "NAS")
	addVendor("proxmox", "Proxmox host")
	addVendor("ubiquiti", "UniFi device")
	addVendor("apple", "Apple device")
	addVendor("sonos", "Sonos speaker")
	addVendor("raspberry", "Raspberry Pi")
	addVendor("nintendo", "Nintendo console")
	addVendor("hive", "Smart home hub")
	addVendor("amazon", "Amazon device")
	addVendor("sony", "Sony device")
	addVendor("espressif", "IoT device")

	// Generic file/media/database services.
	if hasAny(5000, 5001) && has(445) {
		add("NAS")
	}
	if has(445) || has(139) {
		add("SMB file server")
	}
	if has(32400) {
		add("Plex media server")
	}
	if has(1883) {
		add("MQTT device")
	}
	if hasAny(3306, 5432, 6379, 27017) {
		add("Database server")
	}
	if has(22) && hasAny(80, 443, 8080, 8443) {
		add("Linux server")
	} else if has(22) {
		add("SSH server")
	} else if hasAny(80, 443, 8080, 8443) {
		add("Web server")
	}

	if len(tags) == 0 {
		h := strings.ToLower(d.Hostname)
		switch {
		case strings.Contains(h, "homeassistant") || strings.Contains(h, "hass"):
			add("Home Assistant")
		case strings.Contains(h, "jellyfin"):
			add("Jellyfin server")
		case strings.Contains(h, "plex"):
			add("Plex media server")
		case strings.Contains(h, "iphone") || strings.Contains(h, "ipad"):
			add("iPhone / iPad")
		case strings.Contains(h, "macbook") || strings.Contains(h, "imac"):
			add("Mac")
		case strings.Contains(h, "nas"):
			add("NAS")
		case strings.Contains(h, "printer"):
			add("Printer")
		case strings.Contains(h, "camera") || strings.Contains(h, "cam"):
			add("Camera")
		case strings.Contains(h, "tv"):
			add("TV")
		case strings.Contains(h, "router"):
			add("Router")
		}
	}

	if len(tags) > 2 {
		tags = tags[:2]
	}
	return strings.Join(tags, " · ")
}
