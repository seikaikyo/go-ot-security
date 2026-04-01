package vuln

import (
	"strings"
)

// CVE represents a known vulnerability relevant to ICS/OT.
type CVE struct {
	ID          string   `json:"id"`
	Description string   `json:"description"`
	CVSS        float64  `json:"cvss"`
	Severity    string   `json:"severity"` // critical, high, medium, low
	Vendors     []string `json:"vendors"`
	Products    []string `json:"products"`
	Protocols   []string `json:"protocols"`
	References  []string `json:"references"`
}

// Embedded ICS CVE database — curated list of high-impact ICS vulnerabilities.
// Data sourced from public ICS-CERT advisories and NVD.
var icsDatabase = []CVE{
	// Siemens S7
	{ID: "CVE-2019-13945", Description: "Siemens S7-1200/1500 PLC allows remote code execution via crafted packets on port 102", CVSS: 9.8, Severity: "critical", Vendors: []string{"siemens"}, Products: []string{"s7-1200", "s7-1500", "s7"}, Protocols: []string{"s7comm"}},
	{ID: "CVE-2019-10929", Description: "Siemens S7 Communication Processor susceptible to replay attack", CVSS: 5.9, Severity: "medium", Vendors: []string{"siemens"}, Products: []string{"s7"}, Protocols: []string{"s7comm"}},
	{ID: "CVE-2022-38465", Description: "Siemens S7-1500/1200 private key extraction allows PLC impersonation", CVSS: 9.8, Severity: "critical", Vendors: []string{"siemens"}, Products: []string{"s7-1200", "s7-1500", "s7"}, Protocols: []string{"s7comm"}},

	// Modbus general
	{ID: "CVE-2017-16744", Description: "Modbus TCP protocol lacks authentication, allowing unauthorized read/write", CVSS: 9.1, Severity: "critical", Vendors: []string{}, Products: []string{}, Protocols: []string{"modbus"}, References: []string{"ICS-CERT"}},
	{ID: "CVE-2020-25159", Description: "Rockwell Automation MicroLogix Modbus denial of service via malformed packets", CVSS: 7.5, Severity: "high", Vendors: []string{"rockwell", "allen-bradley"}, Products: []string{"micrologix"}, Protocols: []string{"modbus"}},

	// Schneider Electric
	{ID: "CVE-2019-6857", Description: "Schneider Electric Modicon M340 allows unauthorized firmware upload", CVSS: 8.6, Severity: "high", Vendors: []string{"schneider"}, Products: []string{"modicon", "m340"}, Protocols: []string{"modbus"}},
	{ID: "CVE-2021-22779", Description: "Schneider Electric EcoStruxure allows unauthorized access to controller memory", CVSS: 9.8, Severity: "critical", Vendors: []string{"schneider"}, Products: []string{"ecostruxure", "modicon"}, Protocols: []string{"modbus"}},

	// EtherNet/IP
	{ID: "CVE-2021-22681", Description: "Rockwell Automation EtherNet/IP CIP authentication bypass", CVSS: 9.8, Severity: "critical", Vendors: []string{"rockwell", "allen-bradley"}, Products: []string{"logix", "1756", "compactlogix"}, Protocols: []string{"ethernet_ip"}},
	{ID: "CVE-2022-1159", Description: "Rockwell Automation Studio 5000 allows unauthorized PLC code modification", CVSS: 7.7, Severity: "high", Vendors: []string{"rockwell", "allen-bradley"}, Products: []string{"logix", "studio5000"}, Protocols: []string{"ethernet_ip"}},

	// SECS/GEM
	{ID: "ICS-ALERT-HSMS", Description: "HSMS protocol transmits SECS-II messages without encryption or authentication", CVSS: 7.5, Severity: "high", Vendors: []string{}, Products: []string{}, Protocols: []string{"hsms"}, References: []string{"SEMI E37"}},

	// OPC UA
	{ID: "CVE-2022-29862", Description: "OPC UA .NET stack denial of service via infinite loop", CVSS: 7.5, Severity: "high", Vendors: []string{}, Products: []string{}, Protocols: []string{"opcua"}},

	// Omron
	{ID: "CVE-2022-34151", Description: "Omron NJ/NX-series PLC hardcoded credentials allowing remote access", CVSS: 9.8, Severity: "critical", Vendors: []string{"omron"}, Products: []string{"nj", "nx"}, Protocols: []string{}},

	// Mitsubishi
	{ID: "CVE-2021-20594", Description: "Mitsubishi MELSEC iQ-R series authentication bypass via brute force", CVSS: 9.1, Severity: "critical", Vendors: []string{"mitsubishi"}, Products: []string{"melsec", "iq-r"}, Protocols: []string{}},

	// Telnet/FTP general
	{ID: "ICS-ALERT-TELNET", Description: "Telnet transmits credentials in plaintext, enabling credential theft on OT networks", CVSS: 8.0, Severity: "high", Vendors: []string{}, Products: []string{}, Protocols: []string{"telnet"}},
	{ID: "ICS-ALERT-FTP", Description: "FTP transmits data and credentials in plaintext", CVSS: 6.5, Severity: "medium", Vendors: []string{}, Products: []string{}, Protocols: []string{"ftp"}},

	// MQTT
	{ID: "ICS-ALERT-MQTT", Description: "MQTT broker without authentication allows unauthorized message injection", CVSS: 7.5, Severity: "high", Vendors: []string{}, Products: []string{}, Protocols: []string{"mqtt"}},

	// BACnet
	{ID: "CVE-2019-12480", Description: "BACnet protocol implementations vulnerable to denial of service", CVSS: 7.5, Severity: "high", Vendors: []string{}, Products: []string{}, Protocols: []string{"bacnet"}},

	// DNP3
	{ID: "CVE-2013-2828", Description: "DNP3 protocol susceptible to man-in-the-middle due to lack of authentication", CVSS: 7.5, Severity: "high", Vendors: []string{}, Products: []string{}, Protocols: []string{"dnp3"}},

	// MOXA
	{ID: "CVE-2021-39279", Description: "MOXA NPort device servers allow command injection via web interface", CVSS: 8.8, Severity: "high", Vendors: []string{"moxa"}, Products: []string{"nport"}, Protocols: []string{"http"}},

	// Advantech
	{ID: "CVE-2021-21805", Description: "Advantech R-SeeNet stack-based buffer overflow allowing remote code execution", CVSS: 9.8, Severity: "critical", Vendors: []string{"advantech"}, Products: []string{"r-seenet", "adam"}, Protocols: []string{"http"}},
}

// LookupCVEs finds relevant CVEs for a device based on vendor, model, and protocols.
func LookupCVEs(vendor string, model string, protocols []string) []CVE {
	vendor = strings.ToLower(vendor)
	model = strings.ToLower(model)

	protoSet := make(map[string]bool)
	for _, p := range protocols {
		protoSet[strings.ToLower(p)] = true
	}

	var matches []CVE
	seen := make(map[string]bool)

	for _, cve := range icsDatabase {
		if seen[cve.ID] {
			continue
		}

		matched := false

		// Match by vendor
		for _, v := range cve.Vendors {
			if vendor != "" && strings.Contains(vendor, v) {
				matched = true
				break
			}
		}

		// Match by product/model
		if !matched {
			for _, p := range cve.Products {
				if model != "" && strings.Contains(model, p) {
					matched = true
					break
				}
			}
		}

		// Match by protocol
		if !matched {
			for _, p := range cve.Protocols {
				if protoSet[p] {
					matched = true
					break
				}
			}
		}

		if matched {
			matches = append(matches, cve)
			seen[cve.ID] = true
		}
	}

	return matches
}
