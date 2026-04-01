package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/seikaikyo/go-ot-security/internal/compliance"
	"github.com/seikaikyo/go-ot-security/internal/monitor"
	"github.com/seikaikyo/go-ot-security/internal/store"
	"github.com/seikaikyo/go-ot-security/internal/vuln"
)

// Reporter 負責將掃描結果回報給 coordinator
type Reporter struct {
	coordinatorURL string
	nodeID         string
	client         *http.Client
}

// NewReporter 建立 Reporter，若 coordinatorURL 為空則回傳 nil（停用回報功能）
func NewReporter(coordinatorURL, nodeID string) *Reporter {
	if coordinatorURL == "" {
		return nil
	}
	// 移除尾端斜線
	coordinatorURL = strings.TrimRight(coordinatorURL, "/")

	return &Reporter{
		coordinatorURL: coordinatorURL,
		nodeID:         nodeID,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// reportPayload 是送往 coordinator 的完整回報結構
type reportPayload struct {
	NodeID    string          `json:"node_id"`
	ScanID    string          `json:"scan_id"`
	Timestamp string          `json:"timestamp"`
	Subnet    string          `json:"subnet"`
	Summary   reportSummary   `json:"summary"`
	Compliance map[string]frameworkSummary `json:"compliance"`
	Alerts    []reportAlert   `json:"alerts"`
	Devices   []reportDevice  `json:"devices"`
}

type reportSummary struct {
	TotalDevices  int  `json:"total_devices"`
	OTDevices     int  `json:"ot_devices"`
	ITDevices     int  `json:"it_devices"`
	CriticalVulns int  `json:"critical_vulns"`
	HighVulns     int  `json:"high_vulns"`
	ITOTSeparated bool `json:"it_ot_separated"`
}

type frameworkSummary struct {
	Passed int     `json:"passed"`
	Total  int     `json:"total"`
	Score  float64 `json:"score"`
}

type reportAlert struct {
	Severity  string `json:"severity"`
	Type      string `json:"type"`
	Message   string `json:"message"`
	Technique string `json:"technique"`
	DeviceIP  string `json:"device_ip"`
}

type reportDevice struct {
	IP        string         `json:"ip"`
	Vendor    string         `json:"vendor"`
	Type      string         `json:"type"`
	Protocols []string       `json:"protocols"`
	RiskScore float64        `json:"risk_score"`
	Vulns     []reportVuln   `json:"vulns"`
}

type reportVuln struct {
	ID       string  `json:"id"`
	CVSS     float64 `json:"cvss"`
	Severity string  `json:"severity"`
}

// OT 裝置類型清單（與 store.GetStats 邏輯一致）
var otDeviceTypes = map[string]bool{
	"plc": true, "hmi": true, "rtu": true,
	"semiconductor_equipment": true, "opcua_server": true,
	"iot_gateway": true, "bac_controller": true, "legacy_device": true,
}

// IT 裝置類型清單
var itDeviceTypes = map[string]bool{
	"it_workstation": true, "it_server": true, "web_server": true,
	"it_switch": true, "it_router": true,
}

func isOTDevice(deviceType string) bool {
	return otDeviceTypes[deviceType]
}

func isITDevice(deviceType string) bool {
	return itDeviceTypes[deviceType] || strings.HasPrefix(deviceType, "it_")
}

// SendReport 將掃描結果組裝並 POST 至 coordinator
func (r *Reporter) SendReport(ctx context.Context, scan *store.ScanRecord, compReport *compliance.FullReport, alerts []monitor.Alert, assets []store.Asset) {
	if r == nil {
		return
	}

	payload := r.buildPayload(scan, compReport, alerts, assets)

	body, err := json.Marshal(payload)
	if err != nil {
		slog.Error("reporter: 序列化回報資料失敗", "error", err)
		return
	}

	url := fmt.Sprintf("%s/security/report", r.coordinatorURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		slog.Error("reporter: 建立 HTTP 請求失敗", "error", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		slog.Warn("reporter: 回報傳送失敗（coordinator 可能未啟動）", "url", url, "error", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		slog.Info("reporter: 回報已送達 coordinator", "scan_id", scan.ID, "status", resp.StatusCode)
	} else {
		slog.Warn("reporter: coordinator 回應非 2xx", "scan_id", scan.ID, "status", resp.StatusCode)
	}
}

func (r *Reporter) buildPayload(scan *store.ScanRecord, compReport *compliance.FullReport, alerts []monitor.Alert, assets []store.Asset) reportPayload {
	p := reportPayload{
		NodeID:    r.nodeID,
		ScanID:    scan.ID,
		Timestamp: time.Now().Format(time.RFC3339),
		Subnet:    scan.Subnet,
		Compliance: make(map[string]frameworkSummary),
	}

	// 統計裝置分類與弱點
	var otCount, itCount, critVulns, highVulns int
	for _, a := range assets {
		if isOTDevice(a.DeviceType) {
			otCount++
		}
		if isITDevice(a.DeviceType) {
			itCount++
		}

		// 查詢該裝置的 CVE
		cves := vuln.LookupCVEs(a.Vendor, a.Model, a.Protocols)
		var deviceVulns []reportVuln
		for _, c := range cves {
			switch c.Severity {
			case "critical":
				critVulns++
			case "high":
				highVulns++
			}
			deviceVulns = append(deviceVulns, reportVuln{
				ID:       c.ID,
				CVSS:     c.CVSS,
				Severity: c.Severity,
			})
		}

		protocols := a.Protocols
		if protocols == nil {
			protocols = []string{}
		}
		if deviceVulns == nil {
			deviceVulns = []reportVuln{}
		}

		p.Devices = append(p.Devices, reportDevice{
			IP:        a.IP,
			Vendor:    a.Vendor,
			Type:      a.DeviceType,
			Protocols: protocols,
			RiskScore: a.RiskScore,
			Vulns:     deviceVulns,
		})
	}

	// IT/OT 分離判斷（與 store.GetStats 邏輯一致）
	separated := true
	if itCount > 0 && otCount > 0 {
		separated = false
	}

	p.Summary = reportSummary{
		TotalDevices:  len(assets),
		OTDevices:     otCount,
		ITDevices:     itCount,
		CriticalVulns: critVulns,
		HighVulns:     highVulns,
		ITOTSeparated: separated,
	}

	// 合規框架摘要
	if compReport != nil {
		for _, fw := range compReport.Frameworks {
			key := strings.ToLower(strings.ReplaceAll(fw.Framework, " ", ""))
			p.Compliance[key] = frameworkSummary{
				Passed: fw.Summary.Pass,
				Total:  fw.Summary.Total,
				Score:  fw.Summary.Score,
			}
		}
	}

	// 告警
	for _, a := range alerts {
		p.Alerts = append(p.Alerts, reportAlert{
			Severity:  a.Severity,
			Type:      a.RuleName,
			Message:   a.Message,
			Technique: a.Rule,
			DeviceIP:  a.Source,
		})
	}
	if p.Alerts == nil {
		p.Alerts = []reportAlert{}
	}
	if p.Devices == nil {
		p.Devices = []reportDevice{}
	}

	return p
}
