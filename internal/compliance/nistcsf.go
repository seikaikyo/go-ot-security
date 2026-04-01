package compliance

import "fmt"

// RunNISTCSF checks controls mapped to NIST Cybersecurity Framework 2.0.
func RunNISTCSF(ctx *DeviceContext) FrameworkReport {
	var controls []CheckResult

	// ID: Identify
	controls = append(controls, checkNIST_ID_AM(ctx))
	controls = append(controls, checkNIST_ID_RA(ctx))

	// PR: Protect
	controls = append(controls, checkNIST_PR_AC(ctx))
	controls = append(controls, checkNIST_PR_DS(ctx))
	controls = append(controls, checkNIST_PR_PS(ctx))

	// DE: Detect
	controls = append(controls, checkNIST_DE_CM(ctx))
	controls = append(controls, checkNIST_DE_AE(ctx))

	return FrameworkReport{
		Framework: "NIST CSF",
		Version:   "2.0",
		Summary:   summarize(controls),
		Controls:  controls,
	}
}

func checkNIST_ID_AM(ctx *DeviceContext) CheckResult {
	r := CheckResult{
		ControlID:   "ID.AM",
		Title:       "Asset Management",
		Description: "Physical devices, systems, and software are inventoried",
	}

	identified := 0
	for _, a := range ctx.Assets {
		if a.Vendor != "" || a.DeviceType != "unknown" {
			identified++
		}
	}

	total := len(ctx.Assets)
	if total == 0 {
		r.Status = "na"
		r.Finding = "No assets discovered"
	} else if identified == total {
		r.Status = "pass"
		r.Finding = fmt.Sprintf("All %d assets identified", total)
	} else {
		r.Status = "warning"
		r.Finding = fmt.Sprintf("%d of %d assets identified (%d unknown)", identified, total, total-identified)
	}
	return r
}

func checkNIST_ID_RA(ctx *DeviceContext) CheckResult {
	r := CheckResult{
		ControlID:   "ID.RA",
		Title:       "Risk Assessment",
		Description: "Asset vulnerabilities are identified and documented",
	}

	totalCVEs := 0
	for _, cves := range ctx.CVEMap {
		totalCVEs += len(cves)
	}

	if totalCVEs == 0 {
		r.Status = "pass"
		r.Finding = "No known CVEs matched against discovered assets"
	} else {
		r.Status = "warning"
		r.Finding = fmt.Sprintf("%d known CVEs matched — review and remediate", totalCVEs)
	}
	return r
}

func checkNIST_PR_AC(ctx *DeviceContext) CheckResult {
	r := CheckResult{
		ControlID:   "PR.AC",
		Title:       "Access Control",
		Description: "Access to assets is managed and protected",
	}

	credIssues := 0
	for _, creds := range ctx.CredMap {
		credIssues += len(creds)
	}

	if credIssues == 0 {
		r.Status = "pass"
	} else {
		r.Status = "fail"
		r.Finding = fmt.Sprintf("%d potential default credential issues detected", credIssues)
	}
	return r
}

func checkNIST_PR_DS(ctx *DeviceContext) CheckResult {
	r := CheckResult{
		ControlID:   "PR.DS",
		Title:       "Data Security",
		Description: "Data in transit is protected",
	}

	insecure := 0
	for _, svc := range ctx.InsecureMap {
		for _, s := range svc {
			if s.Severity == "critical" || s.Severity == "high" {
				insecure++
			}
		}
	}

	if insecure == 0 {
		r.Status = "pass"
	} else {
		r.Status = "fail"
		r.Finding = fmt.Sprintf("%d high/critical insecure services transmitting data in plaintext", insecure)
	}
	return r
}

func checkNIST_PR_PS(ctx *DeviceContext) CheckResult {
	r := CheckResult{
		ControlID:   "PR.PS",
		Title:       "Platform Security",
		Description: "Hardware/software platforms are managed consistent with risk strategy",
	}

	critical := 0
	for _, cves := range ctx.CVEMap {
		for _, cve := range cves {
			if cve.Severity == "critical" {
				critical++
			}
		}
	}

	if critical == 0 {
		r.Status = "pass"
	} else {
		r.Status = "fail"
		r.Finding = fmt.Sprintf("%d critical CVEs affect discovered platforms", critical)
	}
	return r
}

func checkNIST_DE_CM(ctx *DeviceContext) CheckResult {
	r := CheckResult{
		ControlID:   "DE.CM",
		Title:       "Continuous Monitoring",
		Description: "Assets are monitored for anomalies and potential cybersecurity events",
	}
	r.Status = "warning"
	r.Finding = "Continuous network monitoring not yet active (Phase 3)"
	return r
}

func checkNIST_DE_AE(ctx *DeviceContext) CheckResult {
	r := CheckResult{
		ControlID:   "DE.AE",
		Title:       "Adverse Event Analysis",
		Description: "Anomalies and adverse events are analyzed",
	}
	r.Status = "warning"
	r.Finding = "Event analysis requires network monitoring (Phase 3)"
	return r
}
