---
title: "Phase 1: Asset Discovery"
type: feature
status: in-progress
spec: ot-security-platform
created: 2026-04-01
---

# Phase 1: Asset Discovery

## Goal

MVP — scan a factory network subnet, discover all devices,
identify industrial protocols, fingerprint vendors, build asset
inventory, display in embedded web dashboard.

## Architecture

```
go-ot-security/
├── cmd/server/main.go              # Entry point
├── internal/
│   ├── discovery/
│   │   ├── portscan.go             # SYN/connect scan
│   │   ├── protocol.go             # Industrial protocol probes
│   │   ├── fingerprint.go          # Vendor/model identification
│   │   └── asset.go                # Asset data model + store
│   ├── server/
│   │   ├── router.go               # chi router + API
│   │   ├── response.go             # JSON response helpers
│   │   └── embed.go                # //go:embed dashboard
│   └── store/
│       └── db.go                   # SQLite persistence
├── web/dashboard/                  # React frontend
│   └── src/
│       ├── App.tsx
│       ├── components/
│       │   ├── ScanForm.tsx        # Subnet input + scan trigger
│       │   ├── AssetTable.tsx      # Device inventory table
│       │   ├── AssetDetail.tsx     # Single device detail
│       │   ├── TopologyMap.tsx     # Network topology (simple)
│       │   ├── RiskBadge.tsx       # Risk score visualization
│       │   └── ProtocolBadge.tsx   # Protocol type badges
│       └── lib/
│           └── api.ts
├── go.mod
├── Dockerfile
└── README.md
```

## Scan Flow

```
POST /api/scan {subnet: "192.168.1.0/24"}
  │
  ├─ Phase A: Host Discovery
  │   └─ ICMP ping sweep + TCP SYN to common ports
  │   └─ Result: list of live IPs
  │
  ├─ Phase B: Port Scan
  │   └─ TCP connect scan on each live host
  │   └─ Common ports: 21,22,23,80,102,443,502,1883,4840,
  │      5000-5010,20000,44818,47808
  │   └─ Result: open ports per host
  │
  ├─ Phase C: Protocol Identification
  │   └─ Per open port, send protocol-specific probe:
  │      502 → Modbus FC17 (Report Slave ID)
  │      102 → S7comm COTP connection
  │      44818 → EtherNet/IP List Identity
  │      4840 → OPC UA GetEndpoints
  │      5000+ → HSMS Select.req
  │      1883 → MQTT CONNECT
  │      80/443 → HTTP GET / (grab server header)
  │      22 → SSH banner grab
  │      23 → Telnet banner grab
  │   └─ Result: protocol name + version + response data
  │
  ├─ Phase D: Fingerprinting
  │   └─ MAC OUI lookup (vendor from MAC prefix)
  │   └─ Protocol response parsing (model, firmware)
  │   └─ HTTP server header parsing
  │   └─ Banner string matching
  │   └─ Result: vendor, model, firmware per device
  │
  └─ Phase E: Risk Scoring
      └─ Base score from:
         - Insecure protocols (Telnet=+3, FTP=+2, plain Modbus=+1)
         - Open management ports (HTTP=+1, SSH=0)
         - Default credentials detected (+4)
         - Internet-exposed industrial protocol (+5)
         - No encryption available (+2)
      └─ Scale: 0-10 (CVSS-style)
```

## API Endpoints

| Path | Method | Description |
|------|--------|-------------|
| `/api/scan` | POST | Start subnet scan |
| `/api/scan/status` | GET | Current scan progress |
| `/api/assets` | GET | List all discovered assets |
| `/api/assets/{id}` | GET | Asset detail |
| `/api/assets/{id}/ports` | GET | Open ports for asset |
| `/api/topology` | GET | Network topology data |
| `/api/stats` | GET | Dashboard summary stats |
| `/health` | GET | Health check |
| `/` | GET | Web dashboard |

### POST /api/scan

```json
{
  "subnet": "192.168.1.0/24",
  "ports": "common",
  "timeout_ms": 500,
  "concurrency": 50
}
```

ports options: "common" (preset), "full" (1-65535), or custom "21,22,80,502"

### GET /api/assets response

```json
{
  "success": true,
  "data": [
    {
      "id": "asset-001",
      "ip": "192.168.1.200",
      "mac": "00:1B:1B:XX:XX:XX",
      "vendor": "Siemens",
      "model": "S7-1200",
      "firmware": "V4.5",
      "protocols": ["s7comm", "http"],
      "open_ports": [102, 80],
      "risk_score": 4.5,
      "risk_factors": ["plain industrial protocol", "http management"],
      "zone": "",
      "first_seen": "2026-04-01T10:00:00Z",
      "last_seen": "2026-04-01T10:05:00Z"
    }
  ]
}
```

### GET /api/topology response

```json
{
  "success": true,
  "data": {
    "scanner": "192.168.1.100",
    "subnet": "192.168.1.0/24",
    "nodes": [
      {"id": "asset-001", "ip": "192.168.1.200", "type": "plc", "vendor": "Siemens"},
      {"id": "asset-002", "ip": "192.168.1.201", "type": "hmi", "vendor": "Weintek"}
    ],
    "connections": [
      {"from": "asset-001", "to": "asset-002", "protocol": "modbus"}
    ]
  }
}
```

## Protocol Probes

### Modbus (port 502)
```
→ FC17 (Report Slave ID): 00 01 00 00 00 02 01 11
← Device ID string, Run Status
```

### S7comm (port 102)
```
→ COTP Connection Request + S7 Setup Communication
← S7 response with CPU model info
```

### EtherNet/IP (port 44818)
```
→ List Identity (0x0063)
← Vendor ID, Device Type, Product Name, Serial, Product Code
```

### HSMS/SECS (port 5000+)
```
→ Select.req
← Select.rsp (confirms SECS/GEM equipment)
```

### OPC UA (port 4840)
```
→ GetEndpoints request
← Server application name, endpoint URLs, security policies
```

## Device Type Classification

| Indicators | Classification |
|-----------|---------------|
| Port 502 + Modbus response | PLC / RTU |
| Port 102 + S7comm response | Siemens PLC |
| Port 44818 + EtherNet/IP | Allen-Bradley PLC |
| Port 5000+ + HSMS response | Semiconductor Equipment |
| Port 80 + HMI vendor header | HMI Panel |
| Port 4840 + OPC UA | OPC UA Server |
| Port 1883 + MQTT | IoT Gateway |
| Port 47808 + BACnet | Building Automation |
| Port 22 only | Network Device / Server |
| Port 80/443 only | IT Device / Web Server |

## MAC OUI Database

Embedded lookup table for industrial vendor identification:

| OUI Prefix | Vendor |
|-----------|--------|
| 00:1B:1B | Siemens |
| 00:00:BC | Allen-Bradley |
| 00:80:F4 | Telemecanique (Schneider) |
| 00:60:35 | Dallas Semiconductor |
| 00:0A:E4 | Advantech |
| 00:D0:C9 | Advantech |
| 00:1C:06 | Siemens |
| 00:0E:8C | Siemens |
| 00:30:DE | Wago |
| 00:01:05 | Beckhoff |
| 00:04:A3 | Weintek |

(Full list: ~200 entries from IEEE OUI database for industrial vendors)

## Dashboard UI

```
┌────────────────────────────────────────────────────┐
│  OT SECURITY                          [Scan] [Export] │
├────────────────────────────────────────────────────┤
│                                                    │
│  ┌─ Summary ─────────────────────────────────┐    │
│  │ 12 devices  │ 3 PLC │ 2 HMI │ 4 high risk│    │
│  └───────────────────────────────────────────┘    │
│                                                    │
│  ┌─ Assets ──────────────────────────────────┐    │
│  │ IP          Vendor    Type  Proto  Risk   │    │
│  │ .200        Siemens   PLC   S7     ████ 7 │    │
│  │ .201        Weintek   HMI   HTTP   ██── 4 │    │
│  │ .202        Advantech GW    MQTT   █─── 2 │    │
│  │ .203        Unknown   ???   Telnet ████ 8 │    │
│  └───────────────────────────────────────────┘    │
│                                                    │
│  ┌─ Topology ────────────────────────────────┐    │
│  │     [PLC .200]──modbus──[HMI .201]        │    │
│  │         │                                  │    │
│  │     [GW .202]──mqtt──[Broker .50]         │    │
│  └───────────────────────────────────────────┘    │
│                                                    │
└────────────────────────────────────────────────────┘
```

## Tech Stack

| Component | Choice | Reason |
|-----------|--------|--------|
| Port scan | `net.DialTimeout` | No pcap dependency, works on Pi |
| Protocol probes | Custom Go | Lightweight, no heavy libs |
| MAC OUI | Embedded map | Offline, no internet needed |
| Storage | SQLite (modernc.org) | Pure Go, no CGO |
| HTTP | chi v5 | Consistent with other Go projects |
| Frontend | React + Tailwind + shadcn/ui | Consistent with go-modbus-scanner |
| Embed | Go embed | Single binary deployment |

## Implementation Steps

### Step 1: Project skeleton
- go.mod, main.go, router, response, embed
- Health endpoint, SQLite init

### Step 2: Port scanner
- TCP connect scan with configurable concurrency
- Common industrial ports preset
- Async job with progress tracking

### Step 3: Protocol probes
- Modbus FC17 probe
- S7comm COTP probe
- EtherNet/IP List Identity probe
- HSMS Select.req probe
- Banner grab (SSH/Telnet/HTTP)

### Step 4: Fingerprinting + Asset model
- MAC OUI lookup
- Protocol response parsing
- Device type classification
- Risk scoring
- SQLite persistence

### Step 5: Dashboard
- React app with dark theme
- Scan form + progress
- Asset table (sortable/filterable)
- Asset detail panel
- Simple topology view
- Risk score visualization
- Export (CSV/JSON)

### Step 6: Packaging
- Dockerfile, README, LICENSE
- Cross-compile script (arm64/amd64)

## Safety

- **Read-only**: No write operations to any device
- **Rate controlled**: Configurable concurrency, prevents network flooding
- **Timeout**: All probes have configurable timeout (default 500ms)
- **No exploitation**: Discovery only, no vulnerability exploitation
- **Authorization**: Tool requires physical network access (field deployment)

## Test Plan

| Step | Test |
|------|------|
| Port scan | Scan localhost, verify known open ports |
| Modbus probe | Against go-modbus-scanner or diagslave |
| Fingerprint | Mock responses, verify vendor/model parsing |
| Risk scoring | Unit tests with known port/protocol combinations |
| API | curl all endpoints, verify JSON format |
| Dashboard | Browser test with embedded UI |
| Cross-compile | `GOOS=linux GOARCH=arm64 go build` |

## Checklist

- [ ] Step 1: Project skeleton
- [ ] Step 2: Port scanner
- [ ] Step 3: Protocol probes
- [ ] Step 4: Fingerprinting + asset model
- [ ] Step 5: Dashboard
- [ ] Step 6: Packaging
