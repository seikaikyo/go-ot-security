package monitor

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/seikaikyo/go-ot-security/internal/discovery"
	"github.com/seikaikyo/go-ot-security/internal/store"
	"github.com/seikaikyo/go-ot-security/internal/vuln"
)

// Monitor periodically re-scans the network and detects changes.
type Monitor struct {
	db       *store.DB
	alerts   *AlertEngine
	subnet   string
	interval time.Duration
	cancel   context.CancelFunc
	running  bool
}

// Config for the monitor.
type Config struct {
	Subnet     string `json:"subnet"`
	IntervalMs int    `json:"interval_ms"` // default 60000 (1 min)
}

func New(db *store.DB, alerts *AlertEngine) *Monitor {
	return &Monitor{
		db:     db,
		alerts: alerts,
	}
}

func (m *Monitor) Start(cfg Config) error {
	if m.running {
		return fmt.Errorf("monitor already running")
	}

	m.subnet = cfg.Subnet
	m.interval = time.Duration(cfg.IntervalMs) * time.Millisecond
	if m.interval < 10*time.Second {
		m.interval = 60 * time.Second
	}

	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	m.running = true

	slog.Info("monitor started", "subnet", m.subnet, "interval", m.interval)
	m.alerts.Fire("info", "monitor", "", "Monitor", fmt.Sprintf("Monitoring started for %s (interval: %s)", m.subnet, m.interval))

	go m.loop(ctx)
	return nil
}

func (m *Monitor) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	m.running = false
	slog.Info("monitor stopped")
}

func (m *Monitor) IsRunning() bool {
	return m.running
}

func (m *Monitor) Status() map[string]any {
	return map[string]any{
		"running":  m.running,
		"subnet":   m.subnet,
		"interval": m.interval.String(),
	}
}

func (m *Monitor) loop(ctx context.Context) {
	defer func() { m.running = false }()

	// Initial baseline
	m.scan()

	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.scan()
		}
	}
}

func (m *Monitor) scan() {
	// Get current baseline from DB
	oldAssets, _ := m.db.ListAssets()
	oldMap := make(map[string]store.Asset)
	for _, a := range oldAssets {
		oldMap[a.IP] = a
	}

	// Re-scan
	cfg := discovery.ScanConfig{
		Subnet:      m.subnet,
		TimeoutMs:   500,
		Concurrency: 30,
	}

	discovery.FullScan(cfg, m.db, fmt.Sprintf("monitor-%d", time.Now().Unix()), nil)

	// Get new state
	newAssets, _ := m.db.ListAssets()
	newMap := make(map[string]store.Asset)
	for _, a := range newAssets {
		newMap[a.IP] = a
	}

	// Detect changes
	m.detectNewDevices(oldMap, newMap)
	m.detectPortChanges(oldMap, newMap)
	m.detectVulnerabilities(newAssets)

	slog.Debug("monitor scan complete", "assets", len(newAssets))
}

func (m *Monitor) detectNewDevices(old, new map[string]store.Asset) {
	for ip, asset := range new {
		if _, existed := old[ip]; !existed {
			m.alerts.Fire("high", ip, MitreNewDevice, MitreName(MitreNewDevice),
				fmt.Sprintf("New device detected: %s (vendor: %s, type: %s, ports: %v)",
					ip, asset.Vendor, asset.DeviceType, asset.OpenPorts))
		}
	}

	// Device disappeared
	for ip := range old {
		if _, exists := new[ip]; !exists {
			m.alerts.Fire("medium", ip, "", "Device Offline",
				fmt.Sprintf("Device %s no longer responding", ip))
		}
	}
}

func (m *Monitor) detectPortChanges(old, new map[string]store.Asset) {
	for ip, newAsset := range new {
		oldAsset, existed := old[ip]
		if !existed {
			continue
		}

		oldPorts := makeIntSet(oldAsset.OpenPorts)
		newPorts := makeIntSet(newAsset.OpenPorts)

		// New ports opened
		for p := range newPorts {
			if !oldPorts[p] {
				severity := "medium"
				rule := MitreServiceChange
				if p == 23 || p == 21 {
					severity = "high"
					rule = MitreInsecureProto
				}
				m.alerts.Fire(severity, ip, rule, MitreName(rule),
					fmt.Sprintf("New port %d opened on %s", p, ip))
			}
		}

		// Ports closed
		for p := range oldPorts {
			if !newPorts[p] {
				m.alerts.Fire("info", ip, "", "Port Closed",
					fmt.Sprintf("Port %d closed on %s", p, ip))
			}
		}
	}
}

func (m *Monitor) detectVulnerabilities(assets []store.Asset) {
	for _, a := range assets {
		// Check for critical CVEs
		cves := vuln.LookupCVEs(a.Vendor, a.Model, a.Protocols)
		for _, cve := range cves {
			if cve.Severity == "critical" {
				m.alerts.Fire("critical", a.IP, MitreInitialAccess, MitreName(MitreInitialAccess),
					fmt.Sprintf("Critical CVE %s affects %s: %s", cve.ID, a.IP, cve.Description))
			}
		}

		// Default credentials
		creds := vuln.CheckDefaultCredentials(a.Vendor, a.Model, a.OpenPorts, a.Protocols)
		if len(creds) > 0 {
			m.alerts.Fire("high", a.IP, MitreDefaultCreds, MitreName(MitreDefaultCreds),
				fmt.Sprintf("Device %s (%s) matches %d default credential patterns",
					a.IP, a.Vendor, len(creds)))
		}

		// Insecure protocols
		insecure := vuln.CheckInsecureServices(a.OpenPorts, a.Protocols)
		for _, svc := range insecure {
			if svc.Severity == "critical" {
				m.alerts.Fire("high", a.IP, MitreInsecureProto, MitreName(MitreInsecureProto),
					fmt.Sprintf("%s on %s: %s", svc.Protocol, a.IP, svc.Message))
			}
		}
	}
}

func makeIntSet(ints []int) map[int]bool {
	s := make(map[int]bool)
	for _, i := range ints {
		s[i] = true
	}
	return s
}
