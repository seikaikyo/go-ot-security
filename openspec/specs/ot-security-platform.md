---
title: OT Security Platform
status: active
created: 2026-04-01
---

# OT Security Platform

## Overview

Go-based OT/ICS security assessment and monitoring platform.
Single binary with embedded web dashboard, designed for field deployment
(Raspberry Pi / industrial PC on factory network).

Implements controls from NIST CSF 2.0, IEC 62443, ISO 27001:2022,
NIST SP 800-82 r3, MITRE ATT&CK for ICS, and SEMI E187.

AI-assisted development with Claude Code.

## Architecture

```
go-ot-security/
├── cmd/server/main.go
├── internal/
│   ├── discovery/          # Phase 1: Asset Discovery
│   │   ├── portscan.go     # TCP/UDP port scanning
│   │   ├── protocol.go     # Industrial protocol detection
│   │   ├── fingerprint.go  # Device fingerprinting
│   │   ├── topology.go     # Network topology mapping
│   │   └── asset.go        # Asset inventory management
│   ├── vuln/               # Phase 2: Vulnerability Assessment
│   │   ├── cve.go          # CVE lookup (NVD/ICS-CERT)
│   │   ├── credential.go   # Default credential detection
│   │   ├── protocol.go     # Insecure protocol detection
│   │   └── risk.go         # Risk scoring (CVSS-based)
│   ├── compliance/         # Phase 2: Compliance Mapping
│   │   ├── engine.go       # Compliance check engine
│   │   ├── iec62443.go     # IEC 62443 SL assessment
│   │   ├── nistcsf.go      # NIST CSF 2.0 mapping
│   │   ├── iso27001.go     # ISO 27001 Annex A checks
│   │   ├── semi187.go      # SEMI E187 equipment checks
│   │   └── report.go       # Report generation (JSON/HTML)
│   ├── monitor/            # Phase 3: Network Monitoring
│   │   ├── capture.go      # Packet capture (gopacket)
│   │   ├── dpi.go          # Industrial protocol DPI
│   │   ├── baseline.go     # Traffic baseline + anomaly
│   │   ├── alert.go        # Alert engine (webhook/syslog)
│   │   └── rules.go        # Detection rules (MITRE ATT&CK)
│   ├── config/             # Phase 4: Config Management
│   │   ├── snapshot.go     # PLC register snapshot
│   │   ├── diff.go         # Configuration diff
│   │   ├── golden.go       # Golden image comparison
│   │   └── history.go      # Change history tracking
│   ├── server/             # HTTP server + API
│   │   ├── router.go
│   │   ├── response.go
│   │   └── embed.go
│   └── store/              # Local data persistence
│       └── db.go           # SQLite for asset/scan/alert storage
├── web/dashboard/          # React frontend source
├── Dockerfile
└── go.mod
```

## Framework Mapping

### NIST CSF 2.0 Functions → Tool Features

| Function | Category | Tool Feature |
|----------|----------|-------------|
| **GV** Govern | GV.OC Organization Context | Asset inventory + risk scoring |
| **ID** Identify | ID.AM Asset Management | Network scan + device fingerprint |
| | ID.RA Risk Assessment | CVE lookup + CVSS scoring |
| **PR** Protect | PR.AC Access Control | Default credential detection |
| | PR.DS Data Security | Encryption check (TLS/SSH vs Telnet/FTP) |
| | PR.PS Platform Security | Firmware version audit |
| **DE** Detect | DE.CM Continuous Monitoring | Traffic capture + protocol DPI |
| | DE.AE Adverse Event Analysis | Anomaly detection + MITRE rules |
| **RS** Respond | RS.MA Incident Management | Alert + event timeline |
| | RS.AN Analysis | Forensic data collection |
| **RC** Recover | RC.RP Recovery Planning | Config backup + rollback |

### IEC 62443 Zones → Tool Checks

| Zone | Assessment | Tool Check |
|------|-----------|------------|
| Zone 0 (Safety) | SL-4 controls | Isolation verification |
| Zone 1 (Control) | SL-3 controls | Protocol audit + access control |
| Zone 2 (Supervisory) | SL-2 controls | Network segmentation check |
| Zone 3 (Enterprise) | SL-1 controls | IT/OT boundary validation |
| Conduits | Data flow control | Port + protocol inventory |

### MITRE ATT&CK for ICS → Detection Rules

| Tactic | Technique | Detection |
|--------|-----------|-----------|
| Initial Access | Internet Accessible Device | Open port on public subnet |
| Execution | Change Program State | Modbus FC05/06/15/16 write |
| Persistence | Module Firmware | Firmware version change |
| Evasion | Rootkit | Unexpected open ports |
| Discovery | Network Sniffing | Promiscuous mode detection |
| Lateral Movement | Default Credentials | Known credential match |
| Collection | Point & Tag Identification | Unauthorized register read burst |
| Impact | Manipulation of Control | Unexpected setpoint change |

## Industrial Protocol Support

| Protocol | Port | Detection | DPI | Write Alert |
|----------|------|-----------|-----|------------|
| Modbus TCP | 502 | Phase 1 | Phase 3 | FC05/06/15/16 |
| EtherNet/IP | 44818 | Phase 1 | Phase 3 | Implicit msg |
| OPC UA | 4840 | Phase 1 | - | - |
| SECS/GEM (HSMS) | 5000+ | Phase 1 | Phase 3 | S2F41 remote cmd |
| BACnet | 47808 | Phase 1 | - | - |
| DNP3 | 20000 | Phase 1 | Phase 3 | Write ops |
| S7comm (Siemens) | 102 | Phase 1 | Phase 3 | Write variable |
| MQTT | 1883 | Phase 1 | - | - |
| HTTP/HTTPS | 80/443 | Phase 1 | - | - |
| Telnet | 23 | Phase 1 | - | Flag insecure |
| FTP | 21 | Phase 1 | - | Flag insecure |
| SSH | 22 | Phase 1 | - | - |

## Data Model

### Asset

```go
type Asset struct {
    ID          string
    IP          string
    MAC         string
    Hostname    string
    Vendor      string    // from OUI + protocol fingerprint
    Model       string
    Firmware    string
    Protocols   []string  // modbus, ethernetip, opcua, ...
    OpenPorts   []Port
    RiskScore   float64   // 0-10 CVSS-based
    Zone        string    // IEC 62443 zone assignment
    FirstSeen   time.Time
    LastSeen    time.Time
    CVEs        []CVE
    Compliance  map[string]ComplianceResult // framework → result
}
```

### Alert

```go
type Alert struct {
    ID        string
    Severity  string    // critical, high, medium, low, info
    Source    string    // IP or device
    Rule      string    // MITRE technique ID or custom
    Message   string
    Details   map[string]any
    Timestamp time.Time
    Acked     bool
}
```

## Deployment

| Target | Method |
|--------|--------|
| Raspberry Pi | `GOOS=linux GOARCH=arm64 go build` |
| Industrial PC (x86) | `GOOS=linux GOARCH=amd64 go build` |
| Docker | Multi-stage Dockerfile |
| Factory network | Single binary, port 8443 (HTTPS) |

## Implementation Phases

### Phase 1: Asset Discovery (MVP)
Network scan + industrial protocol detection + device fingerprint +
asset inventory + topology map + embedded dashboard.

### Phase 2: Vulnerability + Compliance
CVE lookup + default credentials + insecure protocol detection +
risk scoring + compliance mapping (IEC 62443/NIST CSF/ISO 27001/SEMI E187) +
report generation.

### Phase 3: Network Monitoring
Packet capture + industrial protocol DPI + traffic baseline +
anomaly detection + MITRE ATT&CK rules + real-time alerts.

### Phase 4: Config Management
PLC register snapshot + diff + golden image + change tracking +
timeline view.

## Related Changes

- [[phase1-asset-discovery]]
