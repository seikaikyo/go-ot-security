package compliance

import (
	"github.com/seikaikyo/go-ot-security/internal/store"
	"github.com/seikaikyo/go-ot-security/internal/vuln"
)

// CheckResult is a single compliance control check result.
type CheckResult struct {
	ControlID   string `json:"control_id"`
	Title       string `json:"title"`
	Status      string `json:"status"` // pass, fail, warning, na
	Description string `json:"description"`
	Finding     string `json:"finding,omitempty"`
}

// FrameworkReport is the compliance report for one framework.
type FrameworkReport struct {
	Framework string        `json:"framework"`
	Version   string        `json:"version"`
	Summary   ReportSummary `json:"summary"`
	Controls  []CheckResult `json:"controls"`
}

type ReportSummary struct {
	Total   int     `json:"total"`
	Pass    int     `json:"pass"`
	Fail    int     `json:"fail"`
	Warning int     `json:"warning"`
	NA      int     `json:"na"`
	Score   float64 `json:"score"` // 0-100%
}

// FullReport contains all framework reports.
type FullReport struct {
	AssetCount  int               `json:"asset_count"`
	HighRisk    int               `json:"high_risk"`
	CVECount    int               `json:"cve_count"`
	Frameworks  []FrameworkReport `json:"frameworks"`
}

// DeviceContext holds all assessment data for compliance checks.
type DeviceContext struct {
	Assets      []store.Asset
	CVEMap      map[string][]vuln.CVE              // asset ID → CVEs
	CredMap     map[string][]vuln.CredentialWarning // asset ID → cred warnings
	InsecureMap map[string][]vuln.InsecureService   // asset ID → insecure services
}

// BuildContext runs vulnerability checks and builds context for compliance.
func BuildContext(assets []store.Asset) *DeviceContext {
	ctx := &DeviceContext{
		Assets:      assets,
		CVEMap:      make(map[string][]vuln.CVE),
		CredMap:     make(map[string][]vuln.CredentialWarning),
		InsecureMap: make(map[string][]vuln.InsecureService),
	}

	for _, a := range assets {
		ctx.CVEMap[a.ID] = vuln.LookupCVEs(a.Vendor, a.Model, a.Protocols)
		ctx.CredMap[a.ID] = vuln.CheckDefaultCredentials(a.Vendor, a.Model, a.OpenPorts, a.Protocols)
		ctx.InsecureMap[a.ID] = vuln.CheckInsecureServices(a.OpenPorts, a.Protocols)
	}

	return ctx
}

// RunAllFrameworks generates reports for all frameworks.
func RunAllFrameworks(ctx *DeviceContext) *FullReport {
	report := &FullReport{
		AssetCount: len(ctx.Assets),
	}

	// Count high risk and CVEs
	cveCount := 0
	for _, a := range ctx.Assets {
		if a.RiskScore >= 7 {
			report.HighRisk++
		}
		cveCount += len(ctx.CVEMap[a.ID])
	}
	report.CVECount = cveCount

	report.Frameworks = []FrameworkReport{
		RunIEC62443(ctx),
		RunNISTCSF(ctx),
		RunISO27001(ctx),
		RunSEMI187(ctx),
	}

	return report
}

func summarize(controls []CheckResult) ReportSummary {
	s := ReportSummary{Total: len(controls)}
	for _, c := range controls {
		switch c.Status {
		case "pass":
			s.Pass++
		case "fail":
			s.Fail++
		case "warning":
			s.Warning++
		case "na":
			s.NA++
		}
	}
	applicable := s.Total - s.NA
	if applicable > 0 {
		s.Score = float64(s.Pass) / float64(applicable) * 100
	}
	return s
}

// Helper: check if any asset has a specific condition
func anyAssetHas(ctx *DeviceContext, check func(a store.Asset) bool) bool {
	for _, a := range ctx.Assets {
		if check(a) {
			return true
		}
	}
	return false
}

func hasProtocol(a store.Asset, proto string) bool {
	for _, p := range a.Protocols {
		if p == proto {
			return true
		}
	}
	return false
}

func hasPort(a store.Asset, port int) bool {
	for _, p := range a.OpenPorts {
		if p == port {
			return true
		}
	}
	return false
}
