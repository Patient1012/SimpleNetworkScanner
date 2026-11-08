# netscan

`netscan` is a terminal network scanner for Linux. It discovers every device on
the local subnet and shows a live, sortable table with addresses, names,
vendors, models, open ports, latency and inferred device roles.


## Features

- ICMP sweep plus TCP liveness probes, with the kernel ARP/neighbour table as a
  third source, so hosts that ignore ping still show up.
- Device names from DHCP leases, router/local reverse DNS, mDNS/Bonjour,
  NetBIOS and the local hostname, merged by confidence.
- Device models from UPnP/SSDP, mDNS TXT records and web-interface titles or
  server headers.
- Offline MAC vendor lookup from a bundled IEEE OUI database.
- Open-port scan of a curated set of common ports.
- Inferred roles such as gateway, NAS, printer, smart-home hub, Proxmox host,
  console or SSH server.
- Live TUI with sorting, filtering, a detail view and rescanning.
- Persistent history keyed by MAC, so names and first-seen times survive
  address changes and restarts.
- `--once` table and `--json` output for scripts and quick checks.
- No root required on Linux when unprivileged ICMP is enabled (the default on
  most distributions). If ICMP is unavailable it falls back to TCP and ARP.

## Requirements

- Linux (the neighbour-table reader uses netlink).
- Go 1.26 or newer to build. The repository vendors all dependencies, so builds
  work offline.

## Build

```sh
make            # builds ./netscan
make install    # installs to $GOBIN or ~/go/bin
make test       # unit tests
make integration# opt-in real scan of the current network
```

Or directly:

```sh
go build -trimpath -o netscan .
./netscan
```

## Usage

```sh
netscan                       # interactive TUI, auto-refresh every 60s
netscan --interval 30s        # refresh more often (0 disables auto-refresh)
netscan --once                # print one scan as a table and exit
netscan --json | jq           # machine-readable output
netscan --iface eth0          # scan a specific interface
netscan --subnet 10.0.0.0/24  # override the detected subnet
netscan --ports 22,80,443,8000-8100
```

### Keys

| Key | Action |
| --- | --- |
| `↑` / `k`, `↓` / `j` | Move selection |
| `PgUp` / `PgDn` | Page up / down |
| `g` / `G` | Jump to top / bottom |
| `enter` / `d` | Device details |
| `esc` | Back / clear filter |
| `r` | Rescan now |
| `p` | Pause or resume auto-refresh |
| `o` | Show or hide offline devices |
| `s` / `S` | Sort by next column / reverse order |
| `/` | Filter by IP, hostname, MAC, vendor or model |
| `?` / `h` | Help |
| `q` / `ctrl+c` | Quit |

### Flags

| Flag | Default | Description |
| --- | --- | --- |
| `--iface` | auto | Interface to scan |
| `--subnet` | auto | Subnet in CIDR form |
| `--ports` | curated set | Comma-separated ports and ranges |
| `--interval` | `60s` | TUI auto-refresh interval (`0` disables) |
| `--timeout` | `400ms` | Per-port TCP timeout |
| `--ping-timeout` | `800ms` | Per-host ICMP timeout |
| `--max-hosts` | `1024` | Cap on scanned addresses in large subnets |
| `--once` | off | Scan once, print a table, exit |
| `--json` | off | Scan once, print JSON, exit (implies `--once`) |
| `--no-color` | off | Disable color (also honours `NO_COLOR`) |
| `--no-mdns` | off | Disable mDNS/Bonjour discovery |
| `--no-nbns` | off | Disable NetBIOS discovery |
| `--version` | | Print version |

## How it works

1. **Discovery** runs an ICMP sweep and a cheap TCP probe concurrently. Any
   valid ARP/neighbour entry also counts as a live host. The local host and
   default gateway are always included when they are in the subnet.
2. **Port scan** probes the configured ports on every live host.
3. **Name resolution** combines DHCP lease files, reverse DNS queried directly
   from the gateway and `/etc/resolv.conf` nameservers, mDNS/Bonjour, NetBIOS
   node-status queries and the local hostname. Higher-confidence sources win.
4. **Enrichment** maps MAC prefixes to vendors from the embedded OUI database,
   asks UPnP/SSDP and mDNS for model details, falls back to web-interface
   titles and server headers, and infers a role from ports, vendor and
   hostname.

History is stored at `$XDG_STATE_HOME/netscan/history.json`, falling back to
`~/.local/state/netscan/history.json`. Delete that file to forget all devices.

## Notes

- Reverse DNS is sent to the gateway first because a stale first nameserver in
  `/etc/resolv.conf` is a common cause of missing names on home networks.
- mDNS discovery requires UDP 5353 to be reachable. If Avahi is running it may
  already own the socket; the scanner still tries unicast and multicast and
  simply skips mDNS when it gets no replies.
- Model discovery is best effort. Devices that expose UPnP, mDNS TXT records or
  a web interface usually report a model; devices with none of those show `—`.
- The relay/proxy and VPN interfaces can make "the local subnet" ambiguous; use
  `--iface` or `--subnet` to be explicit.
