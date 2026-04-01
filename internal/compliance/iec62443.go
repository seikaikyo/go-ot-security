package compliance

import (
	"fmt"

	"github.com/seikaikyo/go-ot-security/internal/store"
)

// RunIEC62443 checks controls from IEC 62443 (Industrial Automation Security).
// References IEC 62443-3-3 system security requirements.
func RunIEC62443(ctx *DeviceContext) FrameworkReport {
	var controls []CheckResult

	// FR 1: Identification and Authentication Control
	controls = append(controls, checkIEC_FR1_1(ctx))
	controls = append(controls, checkIEC_FR1_2(ctx))

	// FR 2: Use Control
	controls = append(controls, checkIEC_FR2_1(ctx))

	// FR 3: System Integrity
	controls = append(controls, checkIEC_FR3_1(ctx))
	controls = append(controls, checkIEC_FR3_2(ctx))

	// FR 4: Data Confidentiality
	controls = append(controls, checkIEC_FR4_1(ctx))

	// FR 5: Restricted Data Flow
	controls = append(controls, checkIEC_FR5_1(ctx))
	controls = append(controls, checkIEC_FR5_2(ctx))

	// FR 6: Timely Response to Events
	controls = append(controls, checkIEC_FR6_1(ctx))

	// FR 7: Resource Availability
	controls = append(controls, checkIEC_FR7_1(ctx))

	return FrameworkReport{
		Framework: "IEC 62443",
		Version:   "IEC 62443-3-3",
		Summary:   summarize(controls),
		Controls:  controls,
	}
}

func checkIEC_FR1_1(ctx *DeviceContext) CheckResult {
	r := CheckResult{
		ControlID:   "FR1-SR1.1",
		Title:       "Human user identification and authentication",
		Description: "All human users shall be identified and authenticated",
	}

	hasTelnet := anyAssetHas(ctx, func(a store.Asset) bool { return hasPort(a, 23) })
	hasDefaultCreds := false
	for _, creds := range ctx.CredMap {
		if len(creds) > 0 {
			hasDefaultCreds = true
			break
		}
	}

	if hasTelnet {
		r.Status = "fail"
		r.Finding = "Telnet service detected — credentials transmitted in plaintext"
	} else if hasDefaultCreds {
		r.Status = "warning"
		r.Finding = "Devices with potential default credentials detected"
	} else {
		r.Status = "pass"
	}
	return r
}

func checkIEC_FR1_2(ctx *DeviceContext) CheckResult {
	r := CheckResult{
		ControlID:   "FR1-SR1.2",
		Title:       "Software process and device identification",
		Description: "All software processes and devices shall be identified",
	}

	unidentified := 0
	for _, a := range ctx.Assets {
		if a.Vendor == "" && a.DeviceType == "unknown" {
			unidentified++
		}
	}

	if unidentified == 0 {
		r.Status = "pass"
	} else {
		r.Status = "warning"
		r.Finding = fmt.Sprintf("%d devices could not be identified (unknown vendor/type)", unidentified)
	}
	return r
}

func checkIEC_FR2_1(ctx *DeviceContext) CheckResult {
	r := CheckResult{
		ControlID:   "FR2-SR2.1",
		Title:       "Authorization enforcement",
		Description: "All access shall be controlled by authorization policies",
	}

	noAuth := 0
	for _, a := range ctx.Assets {
		if hasProtocol(a, "modbus") || hasProtocol(a, "s7comm") || hasProtocol(a, "hsms") {
			noAuth++
		}
	}

	if noAuth == 0 {
		r.Status = "pass"
	} else {
		r.Status = "fail"
		r.Finding = fmt.Sprintf("%d devices use industrial protocols without built-in authorization", noAuth)
	}
	return r
}

func checkIEC_FR3_1(ctx *DeviceContext) CheckResult {
	r := CheckResult{
		ControlID:   "FR3-SR3.1",
		Title:       "Communication integrity",
		Description: "Communication channels shall provide integrity protection",
	}

	insecureCount := 0
	for _, services := range ctx.InsecureMap {
		insecureCount += len(services)
	}

	if insecureCount == 0 {
		r.Status = "pass"
	} else {
		r.Status = "fail"
		r.Finding = fmt.Sprintf("%d insecure services detected without integrity protection", insecureCount)
	}
	return r
}

func checkIEC_FR3_2(ctx *DeviceContext) CheckResult {
	r := CheckResult{
		ControlID:   "FR3-SR3.2",
		Title:       "Malicious code protection",
		Description: "Mechanisms shall protect against malicious code",
	}

	totalCVEs := 0
	criticalCVEs := 0
	for _, cves := range ctx.CVEMap {
		for _, cve := range cves {
			totalCVEs++
			if cve.Severity == "critical" {
				criticalCVEs++
			}
		}
	}

	if totalCVEs == 0 {
		r.Status = "pass"
	} else if criticalCVEs > 0 {
		r.Status = "fail"
		r.Finding = fmt.Sprintf("%d known CVEs matched (%d critical)", totalCVEs, criticalCVEs)
	} else {
		r.Status = "warning"
		r.Finding = fmt.Sprintf("%d known CVEs matched (no critical)", totalCVEs)
	}
	return r
}

func checkIEC_FR4_1(ctx *DeviceContext) CheckResult {
	r := CheckResult{
		ControlID:   "FR4-SR4.1",
		Title:       "Information confidentiality",
		Description: "Communication channels shall provide confidentiality protection",
	}

	hasTelnet := anyAssetHas(ctx, func(a store.Asset) bool { return hasPort(a, 23) })
	hasFTP := anyAssetHas(ctx, func(a store.Asset) bool { return hasPort(a, 21) })
	hasHTTP := anyAssetHas(ctx, func(a store.Asset) bool { return hasPort(a, 80) && !hasPort(a, 443) })

	if hasTelnet || hasFTP {
		r.Status = "fail"
		r.Finding = "Plaintext protocols detected (Telnet/FTP)"
	} else if hasHTTP {
		r.Status = "warning"
		r.Finding = "HTTP without HTTPS detected on management interfaces"
	} else {
		r.Status = "pass"
	}
	return r
}

func checkIEC_FR5_1(ctx *DeviceContext) CheckResult {
	r := CheckResult{
		ControlID:   "FR5-SR5.1",
		Title:       "Network segmentation",
		Description: "The control system network shall be segmented from non-control system networks",
	}

	// Check if IT-typical and OT devices coexist on same subnet
	hasIT := anyAssetHas(ctx, func(a store.Asset) bool {
		return a.DeviceType == "web_server" || a.DeviceType == "network_device"
	})
	hasOT := anyAssetHas(ctx, func(a store.Asset) bool {
		return a.DeviceType == "plc" || a.DeviceType == "hmi" || a.DeviceType == "rtu"
	})

	if hasIT && hasOT {
		r.Status = "warning"
		r.Finding = "IT and OT devices found on the same subnet — verify segmentation"
	} else {
		r.Status = "pass"
	}
	return r
}

func checkIEC_FR5_2(ctx *DeviceContext) CheckResult {
	r := CheckResult{
		ControlID:   "FR5-SR5.2",
		Title:       "Zone boundary protection",
		Description: "Zone boundaries shall be monitored and controlled",
	}
	// Cannot assess without network topology — mark as warning
	r.Status = "warning"
	r.Finding = "Zone boundary assessment requires network topology analysis (Phase 3)"
	return r
}

func checkIEC_FR6_1(ctx *DeviceContext) CheckResult {
	r := CheckResult{
		ControlID:   "FR6-SR6.1",
		Title:       "Audit log accessibility",
		Description: "Audit logs shall be accessible for review",
	}
	r.Status = "warning"
	r.Finding = "Audit log presence on individual devices not assessed in this scan"
	return r
}

func checkIEC_FR7_1(ctx *DeviceContext) CheckResult {
	r := CheckResult{
		ControlID:   "FR7-SR7.1",
		Title:       "Denial of service protection",
		Description: "Systems shall be resilient against denial of service attacks",
	}

	exposed := 0
	for _, a := range ctx.Assets {
		if len(a.OpenPorts) > 5 {
			exposed++
		}
	}

	if exposed == 0 {
		r.Status = "pass"
	} else {
		r.Status = "warning"
		r.Finding = fmt.Sprintf("%d devices have >5 open ports (increased attack surface)", exposed)
	}
	return r
}
