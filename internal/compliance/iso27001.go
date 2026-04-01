package compliance

import (
	"fmt"

	"github.com/seikaikyo/go-ot-security/internal/store"
)

// RunISO27001 checks controls mapped to ISO 27001:2022 Annex A.
func RunISO27001(ctx *DeviceContext) FrameworkReport {
	var controls []CheckResult

	controls = append(controls, checkISO_A5_9(ctx))
	controls = append(controls, checkISO_A5_10(ctx))
	controls = append(controls, checkISO_A8_1(ctx))
	controls = append(controls, checkISO_A8_7(ctx))
	controls = append(controls, checkISO_A8_9(ctx))
	controls = append(controls, checkISO_A8_20(ctx))
	controls = append(controls, checkISO_A8_21(ctx))

	return FrameworkReport{
		Framework: "ISO 27001",
		Version:   "2022 Annex A",
		Summary:   summarize(controls),
		Controls:  controls,
	}
}

func checkISO_A5_9(ctx *DeviceContext) CheckResult {
	r := CheckResult{
		ControlID:   "A.5.9",
		Title:       "Inventory of information and other associated assets",
		Description: "An inventory of information and associated assets shall be maintained",
	}

	if len(ctx.Assets) > 0 {
		r.Status = "pass"
		r.Finding = fmt.Sprintf("Asset inventory contains %d devices", len(ctx.Assets))
	} else {
		r.Status = "warning"
		r.Finding = "No assets in inventory — run a network scan"
	}
	return r
}

func checkISO_A5_10(ctx *DeviceContext) CheckResult {
	r := CheckResult{
		ControlID:   "A.5.10",
		Title:       "Acceptable use of information and other associated assets",
		Description: "Rules for acceptable use shall be identified and documented",
	}

	insecure := 0
	for _, svc := range ctx.InsecureMap {
		insecure += len(svc)
	}

	if insecure == 0 {
		r.Status = "pass"
	} else {
		r.Status = "warning"
		r.Finding = fmt.Sprintf("%d insecure services detected — document acceptable use policies", insecure)
	}
	return r
}

func checkISO_A8_1(ctx *DeviceContext) CheckResult {
	r := CheckResult{
		ControlID:   "A.8.1",
		Title:       "User endpoint devices",
		Description: "Endpoint devices shall be protected",
	}

	credIssues := 0
	for _, creds := range ctx.CredMap {
		credIssues += len(creds)
	}

	if credIssues == 0 {
		r.Status = "pass"
	} else {
		r.Status = "fail"
		r.Finding = fmt.Sprintf("%d devices with potential default credentials", credIssues)
	}
	return r
}

func checkISO_A8_7(ctx *DeviceContext) CheckResult {
	r := CheckResult{
		ControlID:   "A.8.7",
		Title:       "Protection against malware",
		Description: "Systems shall be protected against malware",
	}

	totalCVEs := 0
	for _, cves := range ctx.CVEMap {
		totalCVEs += len(cves)
	}

	if totalCVEs == 0 {
		r.Status = "pass"
	} else {
		r.Status = "warning"
		r.Finding = fmt.Sprintf("%d known vulnerabilities detected — patch management needed", totalCVEs)
	}
	return r
}

func checkISO_A8_9(ctx *DeviceContext) CheckResult {
	r := CheckResult{
		ControlID:   "A.8.9",
		Title:       "Configuration management",
		Description: "Configurations shall be established and managed",
	}
	r.Status = "warning"
	r.Finding = "Configuration management assessment requires Phase 4 (config snapshots)"
	return r
}

func checkISO_A8_20(ctx *DeviceContext) CheckResult {
	r := CheckResult{
		ControlID:   "A.8.20",
		Title:       "Networks security",
		Description: "Networks shall be secured and monitored",
	}

	hasIT := anyAssetHas(ctx, func(a store.Asset) bool {
		return a.DeviceType == "web_server" || a.DeviceType == "network_device"
	})
	hasOT := anyAssetHas(ctx, func(a store.Asset) bool {
		return a.DeviceType == "plc" || a.DeviceType == "hmi"
	})

	if hasIT && hasOT {
		r.Status = "warning"
		r.Finding = "IT and OT devices on same subnet — verify network segmentation"
	} else {
		r.Status = "pass"
	}
	return r
}

func checkISO_A8_21(ctx *DeviceContext) CheckResult {
	r := CheckResult{
		ControlID:   "A.8.21",
		Title:       "Security of network services",
		Description: "Security mechanisms and service levels for network services shall be identified",
	}

	hasTelnet := anyAssetHas(ctx, func(a store.Asset) bool { return hasPort(a, 23) })
	hasFTP := anyAssetHas(ctx, func(a store.Asset) bool { return hasPort(a, 21) })

	if hasTelnet || hasFTP {
		r.Status = "fail"
		r.Finding = "Insecure network services detected (Telnet/FTP)"
	} else {
		r.Status = "pass"
	}
	return r
}
