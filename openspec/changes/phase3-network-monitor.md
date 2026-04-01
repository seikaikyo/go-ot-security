---
title: "Phase 3: Network Monitoring"
type: feature
status: pending
spec: ot-security-platform
created: 2026-04-01
---

# Phase 3: Network Monitoring

## Scope

- Packet capture (gopacket/pcap or AF_PACKET)
- Industrial protocol DPI:
  - Modbus function code decode + write alert
  - S7comm read/write variable decode
  - EtherNet/IP implicit messaging decode
  - HSMS SECS-II message decode
  - DNP3 operation decode
- Traffic baseline establishment (per device, per protocol)
- Anomaly detection (deviation from baseline)
- MITRE ATT&CK for ICS detection rules
- Real-time alert engine (webhook, syslog, email)
- Unauthorized device detection (new MAC on network)
- IT/OT boundary monitoring

## Dependencies

- Phase 1 (asset discovery) completed
- Phase 2 (vulnerability) recommended but not required

## Checklist

- [ ] Packet capture engine
- [ ] Modbus DPI
- [ ] S7comm DPI
- [ ] EtherNet/IP DPI
- [ ] HSMS DPI
- [ ] Traffic baseline engine
- [ ] Anomaly detection
- [ ] MITRE ATT&CK rules
- [ ] Alert engine (webhook/syslog)
- [ ] Dashboard: live monitoring tab + alert feed
