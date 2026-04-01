package discovery

import (
	"crypto/sha256"
	"fmt"
	"log/slog"
	"time"

	"github.com/seikaikyo/go-ot-security/internal/store"
)

// FullScan runs the complete discovery pipeline on a subnet.
func FullScan(cfg ScanConfig, db *store.DB, scanID string, progress func(phase string, done, total int)) error {
	cfg.ApplyDefaults()
	timeout := time.Duration(cfg.TimeoutMs) * time.Millisecond

	// Phase A+B: Host discovery + port scan
	if progress != nil {
		progress("port_scan", 0, 1)
	}
	hosts := ScanSubnet(cfg, func(done, total int) {
		if progress != nil {
			progress("port_scan", done, total)
		}
	})
	slog.Info("port scan complete", "alive", len(hosts))

	// Phase C+D: Protocol probes + fingerprinting
	for i, host := range hosts {
		if progress != nil {
			progress("probe", i+1, len(hosts))
		}

		asset := buildAsset(host, timeout)

		if err := db.UpsertAsset(asset); err != nil {
			slog.Error("upsert asset failed", "ip", host.IP, "error", err)
		}
	}

	slog.Info("discovery complete", "assets", len(hosts))
	return nil
}

func buildAsset(host HostResult, timeout time.Duration) *store.Asset {
	now := time.Now().Format(time.RFC3339)

	// Generate deterministic ID from IP
	h := sha256.Sum256([]byte(host.IP))
	id := fmt.Sprintf("asset-%x", h[:4])

	asset := &store.Asset{
		ID:        id,
		IP:        host.IP,
		OpenPorts: host.OpenPorts,
		FirstSeen: now,
		LastSeen:  now,
	}

	// MAC + vendor lookup
	mac := LookupMAC(host.IP)
	if mac != "" {
		asset.MAC = mac
		asset.Vendor = VendorFromMAC(mac)
	}

	// Protocol probes
	var protocols []string
	for _, port := range host.OpenPorts {
		probe := ProbePort(host.IP, port, timeout)
		if probe == nil {
			continue
		}

		protocols = append(protocols, probe.Protocol)

		// Extract vendor/model from probes
		if probe.Banner != "" {
			if asset.Vendor == "" {
				asset.Vendor = guessVendorFromBanner(probe.Banner, probe.Protocol)
			}
			if asset.Model == "" && probe.Protocol != "http" {
				asset.Model = probe.Banner
			}
		}
		if probe.Version != "" {
			asset.Firmware = probe.Version
		}
	}

	asset.Protocols = protocols
	asset.DeviceType = ClassifyDevice(protocols, host.OpenPorts)

	// Risk scoring
	score, factors := RiskScore(protocols, host.OpenPorts)
	asset.RiskScore = score
	asset.RiskFactors = factors

	return asset
}

func guessVendorFromBanner(banner, protocol string) string {
	lower := fmt.Sprintf("%s %s", banner, protocol)

	vendors := map[string][]string{
		"Siemens":              {"siemens", "s7", "simatic"},
		"Rockwell/Allen-Bradley": {"allen-bradley", "rockwell", "1756", "micrologix"},
		"Schneider Electric":   {"schneider", "modicon", "m340"},
		"ABB":                  {"abb"},
		"Advantech":            {"advantech", "adam"},
		"Beckhoff":             {"beckhoff", "twincat"},
		"WAGO":                 {"wago"},
		"Weintek":              {"weintek", "cmt", "emt"},
		"Omron":                {"omron", "cj2", "nx1"},
		"Mitsubishi":           {"mitsubishi", "melsec", "fx5"},
		"Keyence":              {"keyence", "kv-"},
		"Yokogawa":             {"yokogawa"},
		"Delta":                {"delta", "dvp"},
		"MOXA":                 {"moxa", "nport"},
	}

	for vendor, keywords := range vendors {
		for _, kw := range keywords {
			if containsCI(lower, kw) {
				return vendor
			}
		}
	}

	return ""
}

func containsCI(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && contains(toLower(s), toLower(substr)))
}

func toLower(s string) string {
	b := make([]byte, len(s))
	for i := range s {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
