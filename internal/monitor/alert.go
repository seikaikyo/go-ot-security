package monitor

import (
	"fmt"
	"sync"
	"time"
)

// Alert represents a security event.
type Alert struct {
	ID        int       `json:"id"`
	Severity  string    `json:"severity"` // critical, high, medium, low, info
	Source    string    `json:"source"`   // IP or device ID
	Rule      string    `json:"rule"`     // MITRE technique ID or custom
	RuleName  string    `json:"rule_name"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
	Acked     bool      `json:"acked"`
}

// AlertEngine manages alerts in memory with SQLite persistence.
type AlertEngine struct {
	mu     sync.RWMutex
	alerts []Alert
	seq    int
	hooks  []func(Alert) // webhook callbacks
}

func NewAlertEngine() *AlertEngine {
	return &AlertEngine{}
}

func (e *AlertEngine) Fire(severity, source, rule, ruleName, message string) Alert {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.seq++
	a := Alert{
		ID:        e.seq,
		Severity:  severity,
		Source:    source,
		Rule:      rule,
		RuleName:  ruleName,
		Message:   message,
		Timestamp: time.Now(),
	}
	e.alerts = append(e.alerts, a)

	// Keep last 1000 alerts in memory
	if len(e.alerts) > 1000 {
		e.alerts = e.alerts[len(e.alerts)-1000:]
	}

	// Fire hooks asynchronously
	for _, hook := range e.hooks {
		go hook(a)
	}

	return a
}

func (e *AlertEngine) List(limit int) []Alert {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if limit <= 0 || limit > len(e.alerts) {
		limit = len(e.alerts)
	}

	// Return newest first
	result := make([]Alert, limit)
	for i := 0; i < limit; i++ {
		result[i] = e.alerts[len(e.alerts)-1-i]
	}
	return result
}

func (e *AlertEngine) Stats() map[string]int {
	e.mu.RLock()
	defer e.mu.RUnlock()

	stats := map[string]int{"total": len(e.alerts)}
	for _, a := range e.alerts {
		if !a.Acked {
			stats["unacked"]++
		}
		stats[a.Severity]++
	}
	return stats
}

func (e *AlertEngine) Ack(id int) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	for i := range e.alerts {
		if e.alerts[i].ID == id {
			e.alerts[i].Acked = true
			return true
		}
	}
	return false
}

func (e *AlertEngine) OnAlert(hook func(Alert)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.hooks = append(e.hooks, hook)
}

// MITRE ATT&CK for ICS technique IDs
const (
	MitreInitialAccess     = "T0819" // Internet Accessible Device
	MitreDefaultCreds      = "T0812" // Default Credentials
	MitreNewDevice         = "T0842" // Network Sniffing (proxy: new device)
	MitrePortChange        = "T0846" // Remote System Discovery
	MitreInsecureProto     = "T0883" // Internet Accessible Device
	MitreServiceChange     = "T0866" // Exploitation of Remote Services
	MitreLateralMovement   = "T0859" // Valid Accounts
)

// MITRE technique descriptions
var mitreNames = map[string]string{
	MitreInitialAccess:   "Internet Accessible Device",
	MitreDefaultCreds:    "Default Credentials",
	MitreNewDevice:       "Unauthorized Device",
	MitrePortChange:      "Remote System Discovery",
	MitreInsecureProto:   "Insecure Protocol",
	MitreServiceChange:   "Service Change Detected",
	MitreLateralMovement: "Valid Accounts (Default)",
}

func MitreName(id string) string {
	if name, ok := mitreNames[id]; ok {
		return fmt.Sprintf("%s: %s", id, name)
	}
	return id
}
