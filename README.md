# Go OT Security

OT/ICS security assessment and monitoring platform.
Single Go binary with embedded web dashboard for field deployment.

Implements controls mapped to NIST CSF 2.0, IEC 62443, ISO 27001:2022,
NIST SP 800-82, MITRE ATT&CK for ICS, and SEMI E187.

AI-assisted development with Claude Code.

![Dashboard](https://img.shields.io/badge/dashboard-embedded-blue)
![Go](https://img.shields.io/badge/Go-1.26-00ADD8)
![License](https://img.shields.io/badge/license-MIT-green)

## What It Does

Plug a Raspberry Pi (or any device running this binary) into a factory network.
Open a browser. Scan the subnet. Get a complete security assessment in minutes.

- Discovers all IT and OT devices on the network
- Identifies industrial protocols (Modbus, S7comm, EtherNet/IP, HSMS, OPC UA, MQTT)
- Detects IT services (RDP, SMB, SQL, DNS, FTP, Telnet)
- Checks IT/OT network separation
- Matches known CVEs against discovered devices
- Flags default credentials and insecure protocols
- Maps findings to 4 compliance frameworks (29 controls)
- Monitors for changes and new devices in real-time
- Tracks PLC register configurations over time

## Quick Start

```bash
# Build
go build -o ot-security ./cmd/server/

# Run
./ot-security

# Open browser
open http://localhost:8443
```

## Field Deployment

```bash
# Raspberry Pi (ARM64)
GOOS=linux GOARCH=arm64 go build -o ot-security-arm64 ./cmd/server/
scp ot-security-arm64 pi@factory-network:~/

# Industrial PC (x86)
GOOS=linux GOARCH=amd64 go build -o ot-security-amd64 ./cmd/server/
```

Single binary, no dependencies. No runtime, no database server, no npm.

## Dashboard

Dark-themed technical dashboard with two tabs:

**Discover** -- scan networks, view assets, check compliance

```
+--------------------------------------------------+
| OT SECURITY    [discover] [monitor]    * Online   |
+--------------------------------------------------+
|  15 DEVICES  |  1 OT  |  9 IT  |  0 HIGH RISK   |
+--------------------------------------------------+
| ! IT/OT NOT SEPARATED - 9 IT and 1 OT devices    |
+--------------------------------------------------+
| NETWORK SCAN  | ASSETS                            |
| [192.168.1.0] | IP       Vendor  Type  Proto Risk |
| [Scan]        | .1       -       web   ftp.. 3.0  |
|               | .200     Siemens plc   s7    4.5  |
| COMPLIANCE    | .201     Weintek hmi   http  2.0  |
| IEC 62443 40% | .50      -       it_db mssql 1.5  |
| NIST CSF  43% |                                   |
| ISO 27001 57% |                                   |
+--------------------------------------------------+
```

**Monitor** -- real-time alerts and change detection

## Features

### Phase 1: Asset Discovery

- TCP port scan (IT + OT ports, configurable concurrency)
- 8 industrial protocol probes: Modbus FC17, S7comm COTP, EtherNet/IP
  List Identity, HSMS Select.req, OPC UA Hello, MQTT CONNECT, BACnet, DNP3
- 11 IT protocol detection: RDP, SMB, DNS, LDAP, MSSQL, MySQL, PostgreSQL,
  VNC, SMTP, FTP, Telnet
- Multi-probe fallback for non-standard ports
- MAC address resolution via ARP table (macOS + Linux)
- MAC OUI vendor identification (30+ industrial vendors: Siemens, Rockwell,
  Schneider, ABB, Omron, Mitsubishi, MOXA, Advantech, Beckhoff, etc.)
- Device type classification: PLC, HMI, RTU, semiconductor equipment,
  IoT gateway, OPC UA server, IT workstation, database server, file server, etc.
- Risk scoring (0-10 CVSS-style) based on exposed services
- IT/OT separation analysis (same-subnet detection)
- SQLite persistence

### Phase 2: Vulnerability + Compliance

- Embedded ICS CVE database (20+ high-impact entries from ICS-CERT/NVD)
- Default credential pattern matching (15+ vendor-specific entries)
- Insecure protocol flagging (Telnet, FTP, plain Modbus, S7comm, HSMS)
- Compliance mapping engine with 4 frameworks:

| Framework | Controls | What It Checks |
|-----------|----------|----------------|
| IEC 62443-3-3 | 10 | Auth, access control, integrity, confidentiality, segmentation |
| NIST CSF 2.0 | 7 | Asset management, risk assessment, access control, monitoring |
| ISO 27001:2022 Annex A | 7 | Inventory, endpoint protection, network security, config mgmt |
| SEMI E187 | 5 | OS security, network, access control, anti-malware, logging |

### Phase 3: Network Monitoring

- Periodic subnet re-scan with configurable interval
- New device detection (MITRE ATT&CK T0842)
- Port change tracking (new services opened/closed)
- Critical CVE alerting on each scan cycle
- Default credential pattern alerting
- Insecure protocol alerting
- Alert engine with severity levels (critical/high/medium/low/info)
- MITRE ATT&CK for ICS technique mapping
- Alert acknowledge support

### Phase 4: Configuration Management

- Modbus holding register snapshot capture
- Golden image creation and comparison
- Snapshot diff engine (register-level change detection)
- Config drift alerts (MITRE ATT&CK T0821 - Modify Controller Tasking)
- Per-device snapshot history (last 50)

## API Reference

### Discovery

| Path | Method | Description |
|------|--------|-------------|
| `/api/scan` | POST | Start subnet scan `{"subnet":"192.168.1.0/24","ports":[502,102,80]}` |
| `/api/scan/status` | GET | Scan progress |
| `/api/assets` | GET | List all discovered assets |
| `/api/assets/{id}` | GET | Asset detail |
| `/api/topology` | GET | Network topology nodes |
| `/api/stats` | GET | Summary (device counts, IT/OT separation status) |

### Vulnerability + Compliance

| Path | Method | Description |
|------|--------|-------------|
| `/api/vuln/{id}` | GET | CVEs, credentials, insecure services for one asset |
| `/api/compliance` | GET | Full compliance report (all 4 frameworks) |

### Monitoring

| Path | Method | Description |
|------|--------|-------------|
| `/api/monitor/start` | POST | Start monitoring `{"subnet":"192.168.1.0/24","interval_ms":60000}` |
| `/api/monitor/stop` | POST | Stop monitoring |
| `/api/monitor/status` | GET | Monitor state |
| `/api/alerts` | GET | Alert list `?limit=50` |
| `/api/alerts/stats` | GET | Alert counts by severity |
| `/api/alerts/{id}/ack` | POST | Acknowledge alert |

### Config Management

| Path | Method | Description |
|------|--------|-------------|
| `/api/config/snapshot` | POST | Take register snapshot `{"host":"192.168.1.200","count":100}` |
| `/api/config/golden` | POST | Set golden image `{"device_ip":"192.168.1.200"}` |
| `/api/config/snapshots/{ip}` | GET | List snapshots for device |
| `/api/config/diff/{ip}` | GET | Diff latest vs golden |
| `/api/config/devices` | GET | List devices with snapshots |

## Protocol Probes

| Protocol | Default Port | Probe Method | Risk Factor |
|----------|-------------|-------------|-------------|
| Modbus TCP | 502 | FC17 Report Slave ID | No auth/encryption |
| S7comm | 102 | COTP Connection Request | No auth (older FW) |
| EtherNet/IP | 44818 | List Identity | Limited auth |
| HSMS (SECS/GEM) | 5000+ | Select.req | No auth/encryption |
| OPC UA | 4840 | Hello message | - |
| MQTT | 1883 | CONNECT packet | No auth (if open) |
| RDP | 3389 | Port detection | Remote desktop exposed |
| SMB | 445 | Port detection | File sharing |
| Telnet | 23 | Banner grab | Plaintext credentials |
| FTP | 21 | Banner grab | Plaintext data |
| SSH | 22 | Banner grab | - |
| HTTP/S | 80/443 | Server header | Unencrypted mgmt |
| MSSQL/MySQL/PG | 1433/3306/5432 | Port detection | DB exposed |
| DNS | 53 | Port detection | - |
| VNC | 5900 | Banner grab | Remote desktop |

## Architecture

```
go-ot-security/
├── cmd/server/main.go              # Entry point
├── internal/
│   ├── discovery/                  # Phase 1: Asset Discovery
│   │   ├── portscan.go             # TCP port scanner (IT + OT)
│   │   ├── protocol.go             # Protocol probes + multi-probe
│   │   ├── fingerprint.go          # MAC OUI, device classification, risk
│   │   └── asset.go                # Full scan pipeline
│   ├── vuln/                       # Phase 2: Vulnerability
│   │   ├── cve.go                  # ICS CVE database
│   │   └── credential.go           # Default credentials + insecure services
│   ├── compliance/                 # Phase 2: Compliance
│   │   ├── engine.go               # Framework check engine
│   │   ├── iec62443.go             # IEC 62443-3-3 (10 controls)
│   │   ├── nistcsf.go              # NIST CSF 2.0 (7 controls)
│   │   ├── iso27001.go             # ISO 27001 Annex A (7 controls)
│   │   └── semi187.go              # SEMI E187 (5 controls)
│   ├── monitor/                    # Phase 3: Monitoring
│   │   ├── monitor.go              # Active monitor + change detection
│   │   └── alert.go                # Alert engine + MITRE mapping
│   ├── config/                     # Phase 4: Config Management
│   │   ├── snapshot.go             # Modbus register snapshot
│   │   ├── diff.go                 # Snapshot diff engine
│   │   └── store.go                # Snapshot storage
│   ├── server/                     # HTTP API + embedded UI
│   │   ├── router.go               # chi router (all endpoints)
│   │   ├── response.go             # JSON envelope
│   │   └── embed.go                # //go:embed React dashboard
│   └── store/                      # SQLite persistence
│       └── db.go                   # Asset, scan, alert tables
├── web/dashboard/                  # React source (dev only)
│   └── src/
│       ├── App.tsx                 # Discover + Monitor tabs
│       └── components/             # ScanForm, AssetTable, CompliancePanel, etc.
├── openspec/                       # Spec-driven development docs
├── go.mod
└── LICENSE
```

## Framework Mapping

This tool implements automated checks that map to controls in major security frameworks.
It does not claim certification or compliance -- it provides assessment data to support
your compliance program.

```
NIST CSF 2.0          IEC 62443-3-3       ISO 27001:2022      SEMI E187
+---------------+     +---------------+   +---------------+   +-----------+
| ID.AM Assets  |     | FR1 Auth      |   | A.5.9 Invent  |   | OS Sec    |
| ID.RA Risk    |     | FR2 Use Ctrl  |   | A.8.1 Endpt   |   | Network   |
| PR.AC Access  |     | FR3 Integrity |   | A.8.7 Malware |   | Access    |
| PR.DS Data    |     | FR4 Confid    |   | A.8.20 NetSec |   | Anti-Mal  |
| PR.PS Platform|     | FR5 Segment   |   | A.8.21 SvcSec |   | Logging   |
| DE.CM Monitor |     | FR6 Audit     |   | ...           |   +-----------+
| DE.AE Analysis|     | FR7 Avail     |   +---------------+
+---------------+     +---------------+
```

## Safety

- **Read-only**: No write operations to any device (Modbus FC01-04 only)
- **Rate controlled**: Configurable concurrency (default 50), inter-probe delay
- **Timeout**: All probes have 500ms timeout (configurable)
- **No exploitation**: Discovery and assessment only
- **Physical access**: Requires network connectivity to target subnet

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8443` | HTTP server port |
| `DB_PATH` | `ot-security.db` | SQLite database path |

## Tech Stack

| Component | Choice |
|-----------|--------|
| Language | Go 1.26 |
| HTTP | chi v5 |
| Database | SQLite (modernc.org, pure Go) |
| Modbus | goburrow/modbus |
| Frontend | React + Tailwind + shadcn/ui |
| Embedding | Go `embed` package |

## Related Projects

| Project | Description |
|---------|-------------|
| [go-modbus-scanner](https://github.com/seikaikyo/go-modbus-scanner) | PLC register map discovery tool |
| [go-edge-gateway](https://github.com/seikaikyo/go-edge-gateway) | Industrial protocol edge gateway |
| [go-factory-io](https://github.com/seikaikyo/go-factory-io) | SECS/GEM protocol library |
