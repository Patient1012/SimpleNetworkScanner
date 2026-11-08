package scan

import "testing"

func TestParseSSDPHeaders(t *testing.T) {
	pkt := []byte("HTTP/1.1 200 OK\r\n" +
		"CACHE-CONTROL: max-age=120\r\n" +
		"LOCATION: http://192.168.1.20:5000/rootDesc.xml\r\n" +
		"SERVER: Linux UPnP/1.0\r\n\r\n")
	if got := parseSSDPHeaders(pkt); got != "http://192.168.1.20:5000/rootDesc.xml" {
		t.Fatalf("location = %q", got)
	}
}

func TestParseSSDPHeadersRejectsBadLocation(t *testing.T) {
	pkt := []byte("HTTP/1.1 200 OK\r\nLOCATION: file:///etc/passwd\r\n\r\n")
	if got := parseSSDPHeaders(pkt); got != "" {
		t.Fatalf("location = %q, want empty", got)
	}
}

func TestParseUPnPModel(t *testing.T) {
	data := []byte(`<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion><major>1</major><minor>0</minor></specVersion>
  <device>
    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
    <friendlyName>Router</friendlyName>
    <manufacturer>Ubiquiti Inc.</manufacturer>
    <modelName>UniFi Dream Router</modelName>
    <modelNumber>UDR</modelNumber>
  </device>
</root>`)
	if got := parseUPnPModel(data); got != "UniFi Dream Router" {
		t.Fatalf("model = %q", got)
	}
}

func TestParseUPnPNestedModel(t *testing.T) {
	data := []byte(`<root>
  <device>
    <friendlyName>Gateway</friendlyName>
    <modelName>Generic</modelName>
    <deviceList>
      <device>
        <friendlyName>Access Point</friendlyName>
        <modelName>U6 Pro</modelName>
      </device>
    </deviceList>
  </device>
</root>`)
	if got := parseUPnPModel(data); got != "U6 Pro" {
		t.Fatalf("model = %q", got)
	}
}

func TestCleanModel(t *testing.T) {
	cases := map[string]string{
		"  HP   OfficeJet\nPro 9010 ": "HP OfficeJet Pro 9010",
		"Unknown":                     "",
		"":                            "",
		"U6 Pro":                      "U6 Pro",
	}
	for in, want := range cases {
		if got := cleanModel(in); got != want {
			t.Errorf("cleanModel(%q) = %q, want %q", in, got, want)
		}
	}
}
