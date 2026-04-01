package discovery

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// ProbeResult holds protocol identification results.
type ProbeResult struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Banner   string `json:"banner"`
	Version  string `json:"version"`
	Extra    map[string]string `json:"extra,omitempty"`
}

// ProbePort identifies the protocol running on a specific port.
func ProbePort(ip string, port int, timeout time.Duration) *ProbeResult {
	// Try well-known port mapping first
	switch port {
	case 502:
		return probeModbus(ip, port, timeout)
	case 102:
		return probeS7comm(ip, port, timeout)
	case 44818:
		return probeEtherNetIP(ip, port, timeout)
	case 5000, 5001, 5002:
		return probeHSMS(ip, port, timeout)
	case 4840, 4843:
		return probeOPCUA(ip, port, timeout)
	case 1883:
		return probeMQTT(ip, port, timeout)
	case 22:
		return probeBanner(ip, port, timeout, "ssh")
	case 23:
		return probeBanner(ip, port, timeout, "telnet")
	case 21:
		return probeBanner(ip, port, timeout, "ftp")
	case 80, 8080:
		return probeHTTP(ip, port, timeout, false)
	case 443, 8443:
		return probeHTTP(ip, port, timeout, true)
	}

	// Unknown port: try banner grab first (fast, non-destructive)
	banner := probeBanner(ip, port, timeout, "unknown")
	if banner != nil && banner.Banner != "" {
		// SSH/Telnet detected from banner
		if banner.Protocol != "unknown" {
			return banner
		}
		// Check if banner looks like HTTP
		if len(banner.Banner) > 4 && banner.Banner[:4] == "HTTP" {
			return probeHTTP(ip, port, timeout, false)
		}
	}

	// Try industrial protocol probes (one at a time, stop on first match)
	if r := probeModbus(ip, port, timeout); r != nil {
		return r
	}
	if r := probeHSMS(ip, port, timeout); r != nil {
		return r
	}
	if r := probeMQTT(ip, port, timeout); r != nil {
		return r
	}

	return banner
}

// probeModbus sends Modbus FC17 (Report Slave ID)
func probeModbus(ip string, port int, timeout time.Duration) *ProbeResult {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// Modbus TCP: Transaction ID(2) + Protocol(2) + Length(2) + Unit(1) + FC17(1)
	req := []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x01, 0x11}
	conn.Write(req)

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 9 {
		// Only assume Modbus on well-known port 502
		if port == 502 {
			return &ProbeResult{Port: port, Protocol: "modbus", Banner: "Modbus TCP (no slave ID)"}
		}
		return nil
	}

	// Verify Modbus TCP response: protocol ID must be 0x0000, FC must match
	if n >= 8 && (buf[2] != 0x00 || buf[3] != 0x00) {
		return nil // Not a Modbus response
	}

	// Parse response: FC17 response contains device ID string
	result := &ProbeResult{
		Port:     port,
		Protocol: "modbus",
		Extra:    make(map[string]string),
	}

	if n > 9 {
		// Response data after MBAP header (7 bytes) + FC (1 byte) + byte count (1 byte)
		dataStart := 9
		if dataStart < n {
			slaveID := strings.TrimSpace(string(buf[dataStart:n]))
			slaveID = strings.Map(func(r rune) rune {
				if r >= 32 && r < 127 {
					return r
				}
				return -1
			}, slaveID)
			result.Banner = slaveID
		}
	}

	return result
}

// probeS7comm sends COTP Connection Request to identify Siemens PLCs
func probeS7comm(ip string, port int, timeout time.Duration) *ProbeResult {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// TPKT + COTP Connection Request
	cotpCR := []byte{
		0x03, 0x00, 0x00, 0x16, // TPKT: version=3, length=22
		0x11, 0xe0, 0x00, 0x00, 0x00, 0x01, 0x00, // COTP CR
		0xc0, 0x01, 0x0a, // TPDU size
		0xc1, 0x02, 0x01, 0x00, // Source TSAP
		0xc2, 0x02, 0x01, 0x02, // Destination TSAP (rack 0, slot 2)
	}
	conn.Write(cotpCR)

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 4 {
		return nil
	}

	// Check TPKT header
	if buf[0] == 0x03 && buf[1] == 0x00 {
		result := &ProbeResult{
			Port:     port,
			Protocol: "s7comm",
			Banner:   "Siemens S7 PLC",
			Extra:    make(map[string]string),
		}

		// If COTP CC (Connection Confirm) received
		if n > 5 && buf[5] == 0xd0 {
			result.Banner = "Siemens S7 PLC (connected)"
		}

		return result
	}

	return nil
}

// probeEtherNetIP sends List Identity request
func probeEtherNetIP(ip string, port int, timeout time.Duration) *ProbeResult {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// EtherNet/IP List Identity: command=0x0063, length=0
	listIdentity := []byte{
		0x63, 0x00, // Command: List Identity
		0x00, 0x00, // Length: 0
		0x00, 0x00, 0x00, 0x00, // Session handle
		0x00, 0x00, 0x00, 0x00, // Status
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Sender context
		0x00, 0x00, 0x00, 0x00, // Options
	}
	conn.Write(listIdentity)

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n < 26 {
		return nil
	}

	// Verify List Identity response (command 0x0063)
	if binary.LittleEndian.Uint16(buf[0:2]) != 0x0063 {
		return nil
	}

	result := &ProbeResult{
		Port:     port,
		Protocol: "ethernet_ip",
		Banner:   "EtherNet/IP Device",
		Extra:    make(map[string]string),
	}

	// Try to extract product name from response
	// CIP Identity object starts after encapsulation header (24 bytes)
	// + item count (2) + item type/length headers
	if n > 50 {
		// Product name is a short string in the identity response
		// Simplified extraction: look for readable ASCII strings
		for i := 30; i < n-2; i++ {
			nameLen := int(buf[i])
			if nameLen > 0 && nameLen < 64 && i+1+nameLen <= n {
				candidate := string(buf[i+1 : i+1+nameLen])
				if isPrintable(candidate) && len(candidate) > 3 {
					result.Banner = candidate
					break
				}
			}
		}
	}

	return result
}

// probeHSMS sends HSMS Select.req to identify SECS/GEM equipment
func probeHSMS(ip string, port int, timeout time.Duration) *ProbeResult {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// HSMS Select.req: length(4) + header(10)
	selectReq := []byte{
		0x00, 0x00, 0x00, 0x0A, // Length: 10
		0xFF, 0xFF, // Session ID (not yet assigned)
		0x00, 0x00, // Header byte 2-3
		0x00, 0x00, // PType=0, SType=1 (Select.req)
		0x00, 0x01, // System bytes
		0x00, 0x00, // System bytes
	}
	// Fix SType
	selectReq[9] = 0x01

	conn.Write(selectReq)

	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil || n < 14 {
		return nil
	}

	// Check for Select.rsp (SType=2)
	if n >= 14 && buf[9] == 0x02 {
		return &ProbeResult{
			Port:     port,
			Protocol: "hsms",
			Banner:   "SECS/GEM Equipment (HSMS)",
			Extra:    map[string]string{"stype": "select.rsp"},
		}
	}

	return nil
}

// probeOPCUA basic OPC UA detection
func probeOPCUA(ip string, port int, timeout time.Duration) *ProbeResult {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// OPC UA Hello message
	hello := []byte{
		'H', 'E', 'L', 'F', // Message type: HEL + Final
		0x1c, 0x00, 0x00, 0x00, // Message size: 28
		0x00, 0x00, 0x00, 0x00, // Protocol version
		0x00, 0x00, 0x01, 0x00, // Receive buffer size: 65536
		0x00, 0x00, 0x01, 0x00, // Send buffer size: 65536
		0x00, 0x00, 0x00, 0x00, // Max message size: 0
		0x00, 0x00, 0x00, 0x00, // Max chunk count: 0
	}
	conn.Write(hello)

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 8 {
		return nil
	}

	// Check for ACK response
	if buf[0] == 'A' && buf[1] == 'C' && buf[2] == 'K' {
		return &ProbeResult{
			Port:     port,
			Protocol: "opcua",
			Banner:   "OPC UA Server",
		}
	}

	return nil
}

// probeMQTT sends MQTT CONNECT to detect MQTT brokers
func probeMQTT(ip string, port int, timeout time.Duration) *ProbeResult {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// Minimal MQTT CONNECT packet
	connect := []byte{
		0x10, 0x10, // CONNECT, remaining length=16
		0x00, 0x04, 'M', 'Q', 'T', 'T', // Protocol name
		0x04,       // Protocol level (3.1.1)
		0x00,       // Connect flags (clean session=0)
		0x00, 0x0A, // Keep alive: 10s
		0x00, 0x04, 's', 'c', 'a', 'n', // Client ID
	}
	conn.Write(connect)

	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil || n < 2 {
		return nil
	}

	// CONNACK = 0x20
	if buf[0] == 0x20 {
		return &ProbeResult{
			Port:     port,
			Protocol: "mqtt",
			Banner:   "MQTT Broker",
		}
	}

	return nil
}

// probeHTTP sends HTTP GET to grab server header
func probeHTTP(ip string, port int, timeout time.Duration, _ bool) *ProbeResult {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	req := fmt.Sprintf("GET / HTTP/1.0\r\nHost: %s\r\n\r\n", ip)
	conn.Write([]byte(req))

	buf := make([]byte, 1024)
	n, _ := io.ReadAtLeast(conn, buf, 12)
	if n < 12 {
		return nil
	}

	resp := string(buf[:n])
	result := &ProbeResult{
		Port:     port,
		Protocol: "http",
		Extra:    make(map[string]string),
	}

	if port == 443 || port == 8443 {
		result.Protocol = "https"
	}

	// Extract Server header
	for _, line := range strings.Split(resp, "\r\n") {
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "server:") {
			result.Banner = strings.TrimSpace(line[7:])
			break
		}
	}

	if result.Banner == "" {
		// Grab first line
		if idx := strings.Index(resp, "\r\n"); idx > 0 {
			result.Banner = resp[:idx]
		}
	}

	return result
}

// probeBanner does a simple banner grab
func probeBanner(ip string, port int, timeout time.Duration, proto string) *ProbeResult {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if n == 0 {
		return &ProbeResult{Port: port, Protocol: proto}
	}

	banner := strings.TrimSpace(string(buf[:n]))
	banner = strings.Map(func(r rune) rune {
		if r >= 32 && r < 127 {
			return r
		}
		return -1
	}, banner)

	result := &ProbeResult{
		Port:     port,
		Protocol: proto,
		Banner:   banner,
	}

	// Detect SSH version
	if strings.HasPrefix(banner, "SSH-") {
		result.Protocol = "ssh"
		result.Version = banner
	}

	return result
}

func isPrintable(s string) bool {
	for _, r := range s {
		if r < 32 || r > 126 {
			return false
		}
	}
	return true
}
