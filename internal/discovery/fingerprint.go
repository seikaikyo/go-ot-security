package discovery

import (
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

// OUI database for industrial vendors (MAC address prefix → vendor)
var ouiDB = map[string]string{
	"00:1b:1b": "Siemens",
	"00:1c:06": "Siemens",
	"00:0e:8c": "Siemens",
	"00:1f:f8": "Siemens",
	"a8:49:4d": "Siemens",
	"00:00:bc": "Rockwell/Allen-Bradley",
	"00:01:fa": "Rockwell/Allen-Bradley",
	"00:0a:f3": "Rockwell/Allen-Bradley",
	"00:80:f4": "Schneider Electric",
	"00:80:f7": "Schneider Electric",
	"00:0d:54": "Schneider Electric",
	"00:60:35": "ABB",
	"00:20:d0": "ABB",
	"00:0a:e4": "Advantech",
	"00:d0:c9": "Advantech",
	"00:01:05": "Beckhoff",
	"00:30:de": "WAGO",
	"00:04:a3": "Weintek",
	"00:26:74": "Weintek",
	"00:c0:c7": "Omron",
	"00:11:fa": "Omron",
	"00:40:9d": "Mitsubishi Electric",
	"00:03:19": "Mitsubishi Electric",
	"00:01:c0": "Keyence",
	"00:0b:ab": "Yokogawa",
	"00:a0:69": "Yokogawa",
	"00:1a:e8": "Delta Electronics",
	"00:14:7a": "Delta Electronics",
	"00:e0:4c": "Realtek",
	"00:13:3b": "MOXA",
	"00:90:e8": "MOXA",
	"70:b3:d5": "Generic Industrial",
	"b8:27:eb": "Raspberry Pi",
	"dc:a6:32": "Raspberry Pi",
	"e4:5f:01": "Raspberry Pi",
}

// VendorFromMAC looks up the vendor from MAC address.
func VendorFromMAC(mac string) string {
	mac = strings.ToLower(strings.ReplaceAll(mac, "-", ":"))
	if len(mac) >= 8 {
		prefix := mac[:8]
		if vendor, ok := ouiDB[prefix]; ok {
			return vendor
		}
	}
	return ""
}

// LookupMAC resolves MAC address from IP via ARP table.
// Works on macOS (arp -a) and Linux (/proc/net/arp).
func LookupMAC(ip string) string {
	// First: check if it's our own IP
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.String() == ip {
				return iface.HardwareAddr.String()
			}
		}
	}

	// Trigger ARP entry by connecting (TCP SYN populates ARP cache)
	conn, err := net.DialTimeout("tcp", ip+":80", 100*time.Millisecond)
	if err == nil {
		conn.Close()
	}
	// Also try common port
	conn, err = net.DialTimeout("tcp", ip+":22", 100*time.Millisecond)
	if err == nil {
		conn.Close()
	}

	// Read ARP table
	return readARPTable(ip)
}

func readARPTable(ip string) string {
	// Try Linux /proc/net/arp first
	data, err := os.ReadFile("/proc/net/arp")
	if err == nil {
		return parseLinuxARP(string(data), ip)
	}

	// macOS: run arp -n <ip>
	out, err := exec.Command("arp", "-n", ip).Output()
	if err == nil {
		return parseMacARP(string(out), ip)
	}

	return ""
}

func parseLinuxARP(data, targetIP string) string {
	lines := strings.Split(data, "\n")
	for _, line := range lines[1:] { // skip header
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[0] == targetIP {
			mac := fields[3]
			if mac != "00:00:00:00:00:00" {
				return mac
			}
		}
	}
	return ""
}

func parseMacARP(data, targetIP string) string {
	// macOS arp output: "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ..."
	lines := strings.Split(data, "\n")
	for _, line := range lines {
		if strings.Contains(line, targetIP) && strings.Contains(line, " at ") {
			parts := strings.Split(line, " at ")
			if len(parts) >= 2 {
				macPart := strings.Fields(parts[1])
				if len(macPart) > 0 {
					mac := macPart[0]
					if mac != "(incomplete)" {
						return normalizeMac(mac)
					}
				}
			}
		}
	}
	return ""
}

// normalizeMac pads single-digit hex octets: "0:1b:1b" → "00:1b:1b"
func normalizeMac(mac string) string {
	parts := strings.Split(mac, ":")
	for i, p := range parts {
		if len(p) == 1 {
			parts[i] = "0" + p
		}
	}
	return strings.Join(parts, ":")
}

// ClassifyDevice determines device type from protocols and ports.
func ClassifyDevice(protocols []string, ports []int) string {
	protoSet := make(map[string]bool)
	for _, p := range protocols {
		protoSet[p] = true
	}

	portSet := make(map[int]bool)
	for _, p := range ports {
		portSet[p] = true
	}

	// Classification rules (order matters: more specific first)
	switch {
	case protoSet["s7comm"]:
		return "plc"
	case protoSet["modbus"] && !protoSet["http"]:
		return "plc"
	case protoSet["ethernet_ip"]:
		return "plc"
	case protoSet["hsms"]:
		return "semiconductor_equipment"
	case protoSet["opcua"] && protoSet["modbus"]:
		return "plc"
	case protoSet["opcua"]:
		return "opcua_server"
	case protoSet["mqtt"]:
		return "iot_gateway"
	case protoSet["http"] && protoSet["modbus"]:
		return "hmi"
	case protoSet["http"] && (portSet[80] || portSet[8080]):
		if portSet[502] || portSet[102] || portSet[44818] {
			return "hmi"
		}
		return "web_server"
	case portSet[47808]:
		return "bac_controller"
	case portSet[20000]:
		return "rtu"

	// IT devices
	case protoSet["rdp"] || portSet[3389]:
		return "it_workstation"
	case protoSet["smb"] && protoSet["ldap"]:
		return "it_domain_controller"
	case protoSet["smb"] && (protoSet["mssql"] || protoSet["mysql"] || protoSet["postgresql"]):
		return "it_database_server"
	case protoSet["mssql"] || protoSet["mysql"] || protoSet["postgresql"]:
		return "it_database_server"
	case protoSet["smb"]:
		return "it_file_server"
	case protoSet["ldap"]:
		return "it_directory_server"
	case protoSet["smtp"]:
		return "it_mail_server"
	case protoSet["dns"]:
		return "it_dns_server"
	case protoSet["vnc"]:
		return "it_workstation"
	case portSet[9100]:
		return "it_printer"

	case portSet[22] && len(ports) == 1:
		return "network_device"
	case portSet[23]:
		return "legacy_device"
	default:
		return "unknown"
	}
}

// IsITDevice returns true if the device type is an IT asset.
func IsITDevice(deviceType string) bool {
	switch deviceType {
	case "it_workstation", "it_domain_controller", "it_database_server",
		"it_file_server", "it_directory_server", "it_mail_server",
		"it_dns_server", "it_printer", "web_server":
		return true
	}
	return false
}

// IsOTDevice returns true if the device type is an OT asset.
func IsOTDevice(deviceType string) bool {
	switch deviceType {
	case "plc", "hmi", "rtu", "semiconductor_equipment", "opcua_server",
		"iot_gateway", "bac_controller", "legacy_device":
		return true
	}
	return false
}

// RiskScore calculates a 0-10 risk score based on findings.
func RiskScore(protocols []string, ports []int) (float64, []string) {
	score := 0.0
	var factors []string

	portSet := make(map[int]bool)
	for _, p := range ports {
		portSet[p] = true
	}

	protoSet := make(map[string]bool)
	for _, p := range protocols {
		protoSet[p] = true
	}

	// Insecure protocols
	if portSet[23] || protoSet["telnet"] {
		score += 3.0
		factors = append(factors, "Telnet enabled (plaintext)")
	}
	if portSet[21] || protoSet["ftp"] {
		score += 2.0
		factors = append(factors, "FTP enabled (plaintext)")
	}

	// Industrial protocols without encryption
	if protoSet["modbus"] {
		score += 1.0
		factors = append(factors, "Modbus TCP (no auth/encryption)")
	}
	if protoSet["s7comm"] {
		score += 1.5
		factors = append(factors, "S7comm (no auth in older firmware)")
	}
	if protoSet["ethernet_ip"] {
		score += 1.0
		factors = append(factors, "EtherNet/IP (limited auth)")
	}

	// Open management interfaces
	if protoSet["http"] && (portSet[80] || portSet[8080]) {
		score += 1.0
		factors = append(factors, "HTTP management (unencrypted)")
	}

	// IT services exposed (risk if on OT network)
	if protoSet["rdp"] || portSet[3389] {
		score += 2.0
		factors = append(factors, "RDP exposed (remote desktop)")
	}
	if protoSet["vnc"] || portSet[5900] {
		score += 2.0
		factors = append(factors, "VNC exposed (remote desktop)")
	}
	if protoSet["smb"] || portSet[445] {
		score += 1.5
		factors = append(factors, "SMB file sharing enabled")
	}
	if protoSet["mssql"] || protoSet["mysql"] || protoSet["postgresql"] {
		score += 1.5
		factors = append(factors, "Database port exposed")
	}

	// Too many open ports
	if len(ports) > 5 {
		score += 1.0
		factors = append(factors, "Many open ports (attack surface)")
	}

	// Cap at 10
	if score > 10 {
		score = 10
	}

	return score, factors
}
