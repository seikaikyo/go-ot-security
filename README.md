# Go OT Security

OT/ICS security assessment and monitoring platform.
Single Go binary for field deployment on factory networks.

Implements controls mapped to NIST CSF 2.0, IEC 62443,
ISO 27001:2022, NIST SP 800-82, MITRE ATT&CK for ICS, and SEMI E187.

AI-assisted development with Claude Code.

## Quick Start

```bash
go build -o ot-security ./cmd/server/
./ot-security
# Open http://localhost:8443
```

## Raspberry Pi / Industrial PC

```bash
GOOS=linux GOARCH=arm64 go build -o ot-security-arm64 ./cmd/server/
scp ot-security-arm64 pi@factory-network:~/
```

## Scan a Subnet

```bash
curl -X POST http://localhost:8443/api/scan \
  -H "Content-Type: application/json" \
  -d '{"subnet":"192.168.1.0/24"}'

# Check progress
curl http://localhost:8443/api/scan/status

# View discovered assets
curl http://localhost:8443/api/assets
```

## Features

### Phase 1: Asset Discovery (implemented)
- TCP port scan with configurable concurrency
- Industrial protocol detection (Modbus, S7comm, EtherNet/IP, HSMS, OPC UA, MQTT, BACnet, DNP3)
- MAC OUI vendor identification (30+ industrial vendors)
- Device type classification (PLC, HMI, RTU, IoT gateway, etc.)
- Risk scoring (0-10 CVSS-style) based on exposed services
- SQLite persistence for asset inventory

### Phase 2: Vulnerability + Compliance (planned)
- CVE lookup against NVD/ICS-CERT
- Default credential detection
- Compliance mapping (IEC 62443 / NIST CSF / ISO 27001 / SEMI E187)
- Report generation

### Phase 3: Network Monitoring (planned)
- Industrial protocol DPI (deep packet inspection)
- Traffic baseline + anomaly detection
- MITRE ATT&CK for ICS detection rules
- Real-time alerts

### Phase 4: Config Management (planned)
- PLC register snapshot + diff
- Golden image comparison
- Change tracking

## API

| Path | Method | Description |
|------|--------|-------------|
| `/health` | GET | Health check |
| `/api/scan` | POST | Start subnet scan |
| `/api/scan/status` | GET | Scan progress |
| `/api/assets` | GET | List discovered assets |
| `/api/assets/{id}` | GET | Asset detail |
| `/api/topology` | GET | Network topology |
| `/api/stats` | GET | Dashboard stats |

## Protocol Probes

| Protocol | Port | Probe Method |
|----------|------|-------------|
| Modbus TCP | 502 | FC17 Report Slave ID |
| S7comm | 102 | COTP Connection Request |
| EtherNet/IP | 44818 | List Identity |
| HSMS (SECS/GEM) | 5000+ | Select.req |
| OPC UA | 4840 | Hello message |
| MQTT | 1883 | CONNECT packet |
| HTTP/S | 80/443 | Server header grab |
| SSH/Telnet/FTP | 22/23/21 | Banner grab |

## Architecture

```
go-ot-security/
├── cmd/server/main.go           # Entry point
├── internal/
│   ├── discovery/               # Asset discovery engine
│   │   ├── portscan.go          # TCP port scanner
│   │   ├── protocol.go          # Protocol probes
│   │   ├── fingerprint.go       # Vendor/device identification
│   │   └── asset.go             # Full scan pipeline
│   ├── server/                  # HTTP API
│   │   ├── router.go
│   │   ├── response.go
│   │   └── embed.go
│   └── store/                   # SQLite persistence
│       └── db.go
└── openspec/                    # Spec-driven development docs
```

## Safety

- Read-only network operations (no writes to any device)
- Configurable scan concurrency (default 50)
- Configurable timeout per probe (default 500ms)
- No vulnerability exploitation
- Requires physical network access
