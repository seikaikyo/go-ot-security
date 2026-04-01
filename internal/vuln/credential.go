package vuln

import "strings"

// DefaultCredential represents a known default login.
type DefaultCredential struct {
	Vendor   string `json:"vendor"`
	Product  string `json:"product"`
	Protocol string `json:"protocol"` // ssh, telnet, http, ftp
	Username string `json:"username"`
	Password string `json:"password"`
	Port     int    `json:"port"`
}

// Known default credentials for industrial devices.
// Sources: vendor documentation, ICS-CERT advisories (public info).
var defaultCredentials = []DefaultCredential{
	// Siemens
	{Vendor: "siemens", Product: "s7", Protocol: "http", Username: "admin", Password: "admin", Port: 80},
	{Vendor: "siemens", Product: "scalance", Protocol: "ssh", Username: "admin", Password: "admin", Port: 22},
	{Vendor: "siemens", Product: "simatic", Protocol: "http", Username: "admin", Password: "", Port: 80},

	// Schneider Electric
	{Vendor: "schneider", Product: "modicon", Protocol: "ftp", Username: "USER", Password: "USER", Port: 21},
	{Vendor: "schneider", Product: "modicon", Protocol: "http", Username: "USER", Password: "USER", Port: 80},

	// Rockwell/Allen-Bradley
	{Vendor: "rockwell", Product: "logix", Protocol: "http", Username: "admin", Password: "", Port: 80},

	// MOXA
	{Vendor: "moxa", Product: "nport", Protocol: "http", Username: "admin", Password: "", Port: 80},
	{Vendor: "moxa", Product: "nport", Protocol: "telnet", Username: "admin", Password: "", Port: 23},

	// Advantech
	{Vendor: "advantech", Product: "adam", Protocol: "http", Username: "admin", Password: "admin", Port: 80},
	{Vendor: "advantech", Product: "webaccess", Protocol: "http", Username: "admin", Password: "admin", Port: 80},

	// Weintek
	{Vendor: "weintek", Product: "cmt", Protocol: "http", Username: "admin", Password: "111111", Port: 80},

	// Omron
	{Vendor: "omron", Product: "nj", Protocol: "http", Username: "admin", Password: "admin", Port: 80},

	// Delta
	{Vendor: "delta", Product: "dvp", Protocol: "http", Username: "admin", Password: "admin", Port: 80},

	// Generic network devices
	{Vendor: "", Product: "", Protocol: "telnet", Username: "admin", Password: "admin", Port: 23},
	{Vendor: "", Product: "", Protocol: "telnet", Username: "root", Password: "root", Port: 23},
	{Vendor: "", Product: "", Protocol: "ssh", Username: "admin", Password: "admin", Port: 22},
	{Vendor: "", Product: "", Protocol: "ftp", Username: "anonymous", Password: "", Port: 21},
	{Vendor: "", Product: "", Protocol: "http", Username: "admin", Password: "admin", Port: 80},
	{Vendor: "", Product: "", Protocol: "http", Username: "admin", Password: "1234", Port: 80},
}

// CredentialWarning is a finding about potential default credentials.
type CredentialWarning struct {
	Credential DefaultCredential `json:"credential"`
	Reason     string            `json:"reason"`
}

// CheckDefaultCredentials finds potential default credential risks for a device.
// This does NOT attempt login — it matches vendor/product/port to known defaults.
func CheckDefaultCredentials(vendor, model string, ports []int, protocols []string) []CredentialWarning {
	vendor = strings.ToLower(vendor)
	model = strings.ToLower(model)

	portSet := make(map[int]bool)
	for _, p := range ports {
		portSet[p] = true
	}

	protoSet := make(map[string]bool)
	for _, p := range protocols {
		protoSet[strings.ToLower(p)] = true
	}

	var warnings []CredentialWarning

	for _, cred := range defaultCredentials {
		// Must have the port open
		if !portSet[cred.Port] {
			continue
		}

		matched := false

		// Vendor-specific match
		if cred.Vendor != "" {
			if strings.Contains(vendor, cred.Vendor) {
				matched = true
			}
			if !matched {
				for _, p := range []string{cred.Product} {
					if p != "" && strings.Contains(model, p) {
						matched = true
						break
					}
				}
			}
		} else {
			// Generic credential: match by protocol/port
			if protoSet[cred.Protocol] || portSet[cred.Port] {
				matched = true
			}
		}

		if matched {
			reason := "device matches known default credential pattern"
			if cred.Vendor != "" {
				reason = cred.Vendor + " " + cred.Product + " ships with default " + cred.Protocol + " credentials"
			}
			warnings = append(warnings, CredentialWarning{
				Credential: cred,
				Reason:     reason,
			})
		}
	}

	return warnings
}

// InsecureService represents an insecure protocol finding.
type InsecureService struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

// CheckInsecureServices flags insecure protocols.
func CheckInsecureServices(ports []int, protocols []string) []InsecureService {
	var findings []InsecureService

	portSet := make(map[int]bool)
	for _, p := range ports {
		portSet[p] = true
	}

	protoSet := make(map[string]bool)
	for _, p := range protocols {
		protoSet[p] = true
	}

	if portSet[23] || protoSet["telnet"] {
		findings = append(findings, InsecureService{
			Port: 23, Protocol: "telnet", Severity: "critical",
			Message: "Telnet transmits all data including credentials in plaintext",
		})
	}
	if portSet[21] || protoSet["ftp"] {
		findings = append(findings, InsecureService{
			Port: 21, Protocol: "ftp", Severity: "high",
			Message: "FTP transmits credentials and data in plaintext",
		})
	}
	if protoSet["modbus"] {
		findings = append(findings, InsecureService{
			Port: 502, Protocol: "modbus", Severity: "medium",
			Message: "Modbus TCP has no built-in authentication or encryption",
		})
	}
	if protoSet["s7comm"] {
		findings = append(findings, InsecureService{
			Port: 102, Protocol: "s7comm", Severity: "medium",
			Message: "S7comm lacks authentication in older firmware versions",
		})
	}
	if protoSet["hsms"] {
		findings = append(findings, InsecureService{
			Port: 5000, Protocol: "hsms", Severity: "medium",
			Message: "HSMS/SECS-II protocol has no encryption or authentication",
		})
	}
	if (portSet[80] || portSet[8080]) && protoSet["http"] {
		findings = append(findings, InsecureService{
			Port: 80, Protocol: "http", Severity: "low",
			Message: "HTTP management interface without TLS encryption",
		})
	}

	return findings
}
