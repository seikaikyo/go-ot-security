package compliance

import (
	"fmt"

	_ "github.com/seikaikyo/go-ot-security/internal/store"
)

// RunSEMI187 checks controls mapped to SEMI E187 (Semiconductor Equipment Security).
// SEMI E187 is available from SEMI.org.
func RunSEMI187(ctx *DeviceContext) FrameworkReport {
	var controls []CheckResult

	controls = append(controls, checkSEMI_OS(ctx))
	controls = append(controls, checkSEMI_NW(ctx))
	controls = append(controls, checkSEMI_AC(ctx))
	controls = append(controls, checkSEMI_AV(ctx))
	controls = append(controls, checkSEMI_LOG(ctx))

	return FrameworkReport{
		Framework: "SEMI E187",
		Version:   "Semiconductor Equipment Security",
		Summary:   summarize(controls),
		Controls:  controls,
	}
}

func checkSEMI_OS(ctx *DeviceContext) CheckResult {
	r := CheckResult{
		ControlID:   "E187-OS",
		Title:       "Operating System Security",
		Description: "Equipment shall use a supported operating system with security patches",
	}

	semiEquip := 0
	for _, a := range ctx.Assets {
		if a.DeviceType == "semiconductor_equipment" {
			semiEquip++
		}
	}

	if semiEquip == 0 {
		r.Status = "na"
		r.Finding = "No semiconductor equipment detected"
	} else {
		r.Status = "warning"
		r.Finding = fmt.Sprintf("%d semiconductor equipment found — OS patch status requires manual verification", semiEquip)
	}
	return r
}

func checkSEMI_NW(ctx *DeviceContext) CheckResult {
	r := CheckResult{
		ControlID:   "E187-NW",
		Title:       "Network Security",
		Description: "Equipment shall only enable required network services",
	}

	excessive := 0
	for _, a := range ctx.Assets {
		if a.DeviceType == "semiconductor_equipment" && len(a.OpenPorts) > 3 {
			excessive++
		}
	}

	semiEquip := 0
	for _, a := range ctx.Assets {
		if a.DeviceType == "semiconductor_equipment" {
			semiEquip++
		}
	}

	if semiEquip == 0 {
		r.Status = "na"
		r.Finding = "No semiconductor equipment detected"
	} else if excessive > 0 {
		r.Status = "warning"
		r.Finding = fmt.Sprintf("%d semiconductor equipment with >3 open ports — verify all are required", excessive)
	} else {
		r.Status = "pass"
	}
	return r
}

func checkSEMI_AC(ctx *DeviceContext) CheckResult {
	r := CheckResult{
		ControlID:   "E187-AC",
		Title:       "Access Control",
		Description: "Equipment shall implement access control for all user interfaces",
	}

	hsmsNoAuth := 0
	for _, a := range ctx.Assets {
		if hasProtocol(a, "hsms") {
			hsmsNoAuth++
		}
	}

	if hsmsNoAuth > 0 {
		r.Status = "fail"
		r.Finding = fmt.Sprintf("%d devices use HSMS without authentication — SECS/GEM traffic is unprotected", hsmsNoAuth)
	} else {
		semiEquip := 0
		for _, a := range ctx.Assets {
			if a.DeviceType == "semiconductor_equipment" {
				semiEquip++
			}
		}
		if semiEquip == 0 {
			r.Status = "na"
			r.Finding = "No semiconductor equipment detected"
		} else {
			r.Status = "pass"
		}
	}
	return r
}

func checkSEMI_AV(ctx *DeviceContext) CheckResult {
	r := CheckResult{
		ControlID:   "E187-AV",
		Title:       "Anti-virus / Anti-malware",
		Description: "Equipment shall support malware protection mechanisms",
	}

	semiEquip := 0
	for _, a := range ctx.Assets {
		if a.DeviceType == "semiconductor_equipment" {
			semiEquip++
		}
	}

	if semiEquip == 0 {
		r.Status = "na"
		r.Finding = "No semiconductor equipment detected"
	} else {
		r.Status = "warning"
		r.Finding = "Malware protection status on equipment requires manual verification"
	}
	return r
}

func checkSEMI_LOG(ctx *DeviceContext) CheckResult {
	r := CheckResult{
		ControlID:   "E187-LOG",
		Title:       "Security Logging",
		Description: "Equipment shall log security-relevant events",
	}

	semiEquip := 0
	for _, a := range ctx.Assets {
		if a.DeviceType == "semiconductor_equipment" {
			semiEquip++
		}
	}

	if semiEquip == 0 {
		r.Status = "na"
		r.Finding = "No semiconductor equipment detected"
	} else {
		r.Status = "warning"
		r.Finding = "Security logging capability requires manual verification on equipment"
	}
	return r
}
