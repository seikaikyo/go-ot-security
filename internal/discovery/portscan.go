package discovery

import (
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

// CommonPorts for industrial networks
var CommonPorts = []int{
	21,    // FTP
	22,    // SSH
	23,    // Telnet
	80,    // HTTP
	102,   // S7comm (Siemens)
	443,   // HTTPS
	502,   // Modbus TCP
	1883,  // MQTT
	4840,  // OPC UA
	4843,  // OPC UA (secure)
	5000,  // HSMS (SECS/GEM)
	5001,  // HSMS
	5002,  // HSMS
	8080,  // HTTP alt
	8443,  // HTTPS alt
	20000, // DNP3
	44818, // EtherNet/IP
	47808, // BACnet
}

// ScanConfig controls the scan behavior.
type ScanConfig struct {
	Subnet      string `json:"subnet"`
	Ports       []int  `json:"ports"`
	TimeoutMs   int    `json:"timeout_ms"`
	Concurrency int    `json:"concurrency"`
}

func (c *ScanConfig) ApplyDefaults() {
	if len(c.Ports) == 0 {
		c.Ports = CommonPorts
	}
	if c.TimeoutMs == 0 {
		c.TimeoutMs = 500
	}
	if c.Concurrency == 0 {
		c.Concurrency = 50
	}
}

// HostResult holds scan results for one IP.
type HostResult struct {
	IP        string `json:"ip"`
	Alive     bool   `json:"alive"`
	OpenPorts []int  `json:"open_ports"`
}

// ScanSubnet scans all IPs in a subnet for open ports.
func ScanSubnet(cfg ScanConfig, progress func(done, total int)) []HostResult {
	cfg.ApplyDefaults()

	ips, err := expandSubnet(cfg.Subnet)
	if err != nil {
		slog.Error("invalid subnet", "subnet", cfg.Subnet, "error", err)
		return nil
	}

	timeout := time.Duration(cfg.TimeoutMs) * time.Millisecond
	total := len(ips)
	done := 0

	var mu sync.Mutex
	var results []HostResult
	sem := make(chan struct{}, cfg.Concurrency)
	var wg sync.WaitGroup

	for _, ip := range ips {
		wg.Add(1)
		sem <- struct{}{}

		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()

			hr := HostResult{IP: ip}
			for _, port := range cfg.Ports {
				addr := fmt.Sprintf("%s:%d", ip, port)
				conn, err := net.DialTimeout("tcp", addr, timeout)
				if err == nil {
					conn.Close()
					hr.OpenPorts = append(hr.OpenPorts, port)
					hr.Alive = true
				}
			}

			mu.Lock()
			if hr.Alive {
				results = append(results, hr)
			}
			done++
			if progress != nil && done%10 == 0 {
				progress(done, total)
			}
			mu.Unlock()
		}(ip)
	}

	wg.Wait()
	if progress != nil {
		progress(total, total)
	}

	return results
}

// expandSubnet converts CIDR notation to list of IPs.
func expandSubnet(cidr string) ([]string, error) {
	// Handle single IP
	if ip := net.ParseIP(cidr); ip != nil {
		return []string{cidr}, nil
	}

	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}

	// Remove network and broadcast for /24+
	if len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	}

	return ips, nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
