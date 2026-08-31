package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/seikaikyo/go-common/response"
	cfgmgmt "github.com/seikaikyo/go-ot-security/internal/config"
	"github.com/seikaikyo/go-ot-security/internal/agent"
	"github.com/seikaikyo/go-ot-security/internal/compliance"
	"github.com/seikaikyo/go-ot-security/internal/discovery"
	"github.com/seikaikyo/go-ot-security/internal/monitor"
	"github.com/seikaikyo/go-ot-security/internal/store"
	"github.com/seikaikyo/go-ot-security/internal/vuln"
)

type Server struct {
	db       *store.DB
	scanMu   sync.Mutex
	scanning bool
	scanProg scanProgress
	monitor  *monitor.Monitor
	alerts   *monitor.AlertEngine
	snaps    *cfgmgmt.SnapshotStore
	reporter *agent.Reporter
	opts     Options
}

type scanProgress struct {
	Phase string `json:"phase"`
	Done  int    `json:"done"`
	Total int    `json:"total"`
}

// Options carries the access-control settings the API router needs.
type Options struct {
	// AuthToken is the shared bearer token required on every /api route.
	// Empty means the API fails closed rather than serving anonymously.
	AuthToken string
	// AllowedOrigins mirrors the CORS allowlist and is reused by the CSRF
	// guard on state-changing requests.
	AllowedOrigins []string
}

func New(db *store.DB, reporter *agent.Reporter, opts Options) *Server {
	alerts := monitor.NewAlertEngine()
	return &Server{
		db:       db,
		alerts:   alerts,
		monitor:  monitor.New(db, alerts),
		snaps:    cfgmgmt.NewSnapshotStore(),
		reporter: reporter,
		opts:     opts,
	}
}

func (s *Server) Router() chi.Router {
	r := chi.NewRouter()

	// Every API route sits behind the bearer token and, for writes, the
	// cross-site guard. The embedded static assets stay public so the
	// dashboard can boot and then authenticate.
	r.Group(func(api chi.Router) {
		api.Use(TokenAuth(s.opts.AuthToken))
		api.Use(CSRFGuard(s.opts.AllowedOrigins))

		api.Post("/api/scan", s.handleScan)
		api.Get("/api/scan/status", s.handleScanStatus)
		api.Get("/api/assets", s.handleListAssets)
		api.Get("/api/assets/{id}", s.handleGetAsset)
		api.Get("/api/topology", s.handleTopology)
		api.Get("/api/stats", s.handleStats)

		// Phase 2: Vulnerability + Compliance
		api.Get("/api/vuln/{id}", s.handleVuln)
		api.Get("/api/compliance", s.handleCompliance)

		// Phase 3: Monitoring
		api.Post("/api/monitor/start", s.handleMonitorStart)
		api.Post("/api/monitor/stop", s.handleMonitorStop)
		api.Get("/api/monitor/status", s.handleMonitorStatus)
		api.Get("/api/alerts", s.handleAlerts)
		api.Get("/api/alerts/stats", s.handleAlertStats)
		api.Post("/api/alerts/{id}/ack", s.handleAlertAck)

		// Phase 4: Config Management
		api.Post("/api/config/snapshot", s.handleSnapshot)
		api.Post("/api/config/golden", s.handleSetGolden)
		api.Get("/api/config/snapshots/{ip}", s.handleListSnapshots)
		api.Get("/api/config/diff/{ip}", s.handleDiff)
		api.Get("/api/config/devices", s.handleConfigDevices)
	})

	// Embedded frontend
	r.HandleFunc("/*", staticHandler())
	r.HandleFunc("/", staticHandler())

	return r
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Subnet      string `json:"subnet"`
		Ports       []int  `json:"ports"`
		TimeoutMs   int    `json:"timeout_ms"`
		Concurrency int    `json:"concurrency"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Err(w,http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Subnet == "" {
		response.Err(w,http.StatusBadRequest, "subnet is required")
		return
	}

	s.scanMu.Lock()
	if s.scanning {
		s.scanMu.Unlock()
		response.Err(w,http.StatusConflict, "scan already in progress")
		return
	}
	s.scanning = true
	s.scanMu.Unlock()

	scanID := fmt.Sprintf("scan-%d", time.Now().Unix())
	scanRec := &store.ScanRecord{
		ID:        scanID,
		Subnet:    req.Subnet,
		Status:    "running",
		StartedAt: time.Now().Format(time.RFC3339),
	}
	s.db.InsertScan(scanRec)

	cfg := discovery.ScanConfig{
		Subnet:      req.Subnet,
		Ports:       req.Ports,
		TimeoutMs:   req.TimeoutMs,
		Concurrency: req.Concurrency,
	}

	go func() {
		defer func() {
			s.scanMu.Lock()
			s.scanning = false
			s.scanMu.Unlock()
		}()

		slog.Info("scan started", "id", scanID, "subnet", req.Subnet)

		err := discovery.FullScan(cfg, s.db, scanID, func(phase string, done, total int) {
			s.scanMu.Lock()
			s.scanProg = scanProgress{Phase: phase, Done: done, Total: total}
			s.scanMu.Unlock()
		})

		scanRec.FinishedAt = time.Now().Format(time.RFC3339)
		if err != nil {
			scanRec.Status = "failed"
			scanRec.Error = err.Error()
			slog.Error("scan failed", "id", scanID, "error", err)
		} else {
			scanRec.Status = "completed"
			assets, _ := s.db.ListAssets()
			scanRec.AliveHosts = len(assets)
			slog.Info("scan completed", "id", scanID, "assets", len(assets))

			// 掃描完成後回報給 coordinator
			if s.reporter != nil {
				ctx := compliance.BuildContext(assets)
				compReport := compliance.RunAllFrameworks(ctx)
				recentAlerts := s.alerts.List(100)
				go s.reporter.SendReport(context.Background(), scanRec, compReport, recentAlerts, assets)
			}
		}
		s.db.UpdateScan(scanRec)
	}()

	response.OK(w,map[string]any{
		"scan_id": scanID,
		"status":  "running",
		"message": "scan started",
	})
}

func (s *Server) handleScanStatus(w http.ResponseWriter, r *http.Request) {
	s.scanMu.Lock()
	scanning := s.scanning
	prog := s.scanProg
	s.scanMu.Unlock()

	data := map[string]any{
		"scanning": scanning,
		"phase":    prog.Phase,
		"done":     prog.Done,
		"total":    prog.Total,
	}

	if !scanning {
		scan, err := s.db.GetLatestScan()
		if err == nil {
			data["last_scan"] = scan
		}
	}

	response.OK(w,data)
}

func (s *Server) handleListAssets(w http.ResponseWriter, r *http.Request) {
	assets, err := s.db.ListAssets()
	if err != nil {
		response.Err(w,http.StatusInternalServerError, "failed to list assets")
		return
	}
	if assets == nil {
		assets = []store.Asset{}
	}
	response.OK(w,assets)
}

func (s *Server) handleGetAsset(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	asset, err := s.db.GetAsset(id)
	if err != nil {
		response.Err(w,http.StatusNotFound, "asset not found")
		return
	}
	response.OK(w,asset)
}

func (s *Server) handleTopology(w http.ResponseWriter, r *http.Request) {
	assets, err := s.db.ListAssets()
	if err != nil {
		response.Err(w,http.StatusInternalServerError, "failed to list assets")
		return
	}

	type node struct {
		ID         string `json:"id"`
		IP         string `json:"ip"`
		DeviceType string `json:"type"`
		Vendor     string `json:"vendor"`
		RiskScore  float64 `json:"risk_score"`
	}

	nodes := make([]node, len(assets))
	for i, a := range assets {
		nodes[i] = node{
			ID:         a.ID,
			IP:         a.IP,
			DeviceType: a.DeviceType,
			Vendor:     a.Vendor,
			RiskScore:  a.RiskScore,
		}
	}

	response.OK(w,map[string]any{
		"nodes": nodes,
	})
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	response.OK(w,s.db.GetStats())
}

func (s *Server) handleVuln(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	asset, err := s.db.GetAsset(id)
	if err != nil {
		response.Err(w,http.StatusNotFound, "asset not found")
		return
	}

	cves := vuln.LookupCVEs(asset.Vendor, asset.Model, asset.Protocols)
	creds := vuln.CheckDefaultCredentials(asset.Vendor, asset.Model, asset.OpenPorts, asset.Protocols)
	insecure := vuln.CheckInsecureServices(asset.OpenPorts, asset.Protocols)

	response.OK(w,map[string]any{
		"asset_id":        id,
		"cves":            cves,
		"credentials":     creds,
		"insecure_services": insecure,
	})
}

func (s *Server) handleCompliance(w http.ResponseWriter, r *http.Request) {
	assets, err := s.db.ListAssets()
	if err != nil {
		response.Err(w,http.StatusInternalServerError, "failed to list assets")
		return
	}

	ctx := compliance.BuildContext(assets)
	report := compliance.RunAllFrameworks(ctx)
	response.OK(w,report)
}

func (s *Server) handleMonitorStart(w http.ResponseWriter, r *http.Request) {
	var cfg monitor.Config
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		response.Err(w,http.StatusBadRequest, "invalid request body")
		return
	}
	if cfg.Subnet == "" {
		response.Err(w,http.StatusBadRequest, "subnet is required")
		return
	}

	if err := s.monitor.Start(cfg); err != nil {
		response.Err(w,http.StatusConflict, err.Error())
		return
	}
	response.OK(w,map[string]any{"status": "started", "subnet": cfg.Subnet})
}

func (s *Server) handleMonitorStop(w http.ResponseWriter, r *http.Request) {
	s.monitor.Stop()
	response.OK(w,map[string]string{"status": "stopped"})
}

func (s *Server) handleMonitorStatus(w http.ResponseWriter, r *http.Request) {
	response.OK(w,s.monitor.Status())
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if q := r.URL.Query().Get("limit"); q != "" {
		if n, err := strconv.Atoi(q); err == nil && n > 0 {
			limit = n
		}
	}
	response.OK(w,s.alerts.List(limit))
}

func (s *Server) handleAlertStats(w http.ResponseWriter, r *http.Request) {
	response.OK(w,s.alerts.Stats())
}

func (s *Server) handleAlertAck(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		response.Err(w,http.StatusBadRequest, "invalid alert id")
		return
	}
	if s.alerts.Ack(id) {
		response.OK(w,map[string]string{"status": "acked"})
	} else {
		response.Err(w,http.StatusNotFound, "alert not found")
	}
}

// snapshotFailedMsg is the only text a client ever sees for a failed
// snapshot. Distinguishing "connection refused" from "timeout" would turn
// this endpoint into an internal port-scanning oracle.
const snapshotFailedMsg = "snapshot failed"

// errSnapshotTargetDenied covers every allowlist rejection with one message,
// so the caller cannot tell an unknown host from a closed port.
var errSnapshotTargetDenied = errors.New("host is not a discovered asset with that port open")

// validateSnapshotTarget confines the Modbus client to hosts this scanner has
// actually discovered. Without it, host and port come straight from the
// request body and the scanner becomes a pivot into the rest of the network.
//
// Rules:
//   - the host must be an IP literal, so there is no DNS name to rebind;
//   - that IP must belong to an asset already in the inventory;
//   - the port must be one of that asset's discovered open ports, or the
//     Modbus default 502.
func validateSnapshotTarget(assets []store.Asset, host string, port int) error {
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil {
		return errSnapshotTargetDenied
	}
	if port == 0 {
		port = 502
	}
	if port < 1 || port > 65535 {
		return errSnapshotTargetDenied
	}

	for _, a := range assets {
		assetIP := net.ParseIP(strings.TrimSpace(a.IP))
		if assetIP == nil || !assetIP.Equal(ip) {
			continue
		}
		if port == 502 {
			return nil
		}
		for _, open := range a.OpenPorts {
			if open == port {
				return nil
			}
		}
	}
	return errSnapshotTargetDenied
}

func (s *Server) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	var req cfgmgmt.SnapshotRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Err(w,http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Host == "" {
		response.Err(w,http.StatusBadRequest, "host is required")
		return
	}

	assets, err := s.db.ListAssets()
	if err != nil {
		slog.Error("snapshot allowlist lookup failed", "error", err)
		response.Err(w, http.StatusInternalServerError, "failed to list assets")
		return
	}
	if err := validateSnapshotTarget(assets, req.Host, req.Port); err != nil {
		slog.Warn("snapshot target denied", "host", req.Host, "port", req.Port, "remote", r.RemoteAddr)
		response.Err(w, http.StatusForbidden, errSnapshotTargetDenied.Error())
		return
	}

	snap, err := cfgmgmt.TakeSnapshot(req)
	if err != nil {
		slog.Warn("snapshot failed", "host", req.Host, "port", req.Port, "error", err)
		response.Err(w, http.StatusBadGateway, snapshotFailedMsg)
		return
	}

	s.snaps.Add(snap)

	// Check against golden image
	golden := s.snaps.GetGolden(snap.DeviceIP)
	if golden != nil {
		diff := cfgmgmt.DiffSnapshots(golden, snap)
		if len(diff.Changes) > 0 {
			s.alerts.Fire("high", snap.DeviceIP, "T0821", "Modify Controller Tasking",
				fmt.Sprintf("Config drift: %d registers changed from golden image on %s", len(diff.Changes), snap.DeviceIP))
		}
	}

	response.OK(w,snap)
}

func (s *Server) handleSetGolden(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DeviceIP   string `json:"device_ip"`
		SnapshotID string `json:"snapshot_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Err(w,http.StatusBadRequest, "invalid request body")
		return
	}

	if req.SnapshotID != "" {
		snap := s.snaps.Get(req.DeviceIP, req.SnapshotID)
		if snap == nil {
			response.Err(w,http.StatusNotFound, "snapshot not found")
			return
		}
		s.snaps.SetGolden(snap)
	} else {
		latest := s.snaps.Latest(req.DeviceIP)
		if latest == nil {
			response.Err(w,http.StatusNotFound, "no snapshots for device")
			return
		}
		s.snaps.SetGolden(latest)
	}

	response.OK(w,map[string]string{"status": "golden image set", "device": req.DeviceIP})
}

func (s *Server) handleListSnapshots(w http.ResponseWriter, r *http.Request) {
	ip := chi.URLParam(r, "ip")
	snaps := s.snaps.List(ip)

	// Return summary without full register data
	type snapSummary struct {
		ID        string `json:"id"`
		Label     string `json:"label"`
		Registers int    `json:"register_count"`
		Timestamp string `json:"timestamp"`
	}

	summaries := make([]snapSummary, len(snaps))
	for i, snap := range snaps {
		summaries[i] = snapSummary{
			ID:        snap.ID,
			Label:     snap.Label,
			Registers: len(snap.Registers),
			Timestamp: snap.Timestamp.Format(time.RFC3339),
		}
	}

	golden := s.snaps.GetGolden(ip)
	var goldenInfo *snapSummary
	if golden != nil {
		goldenInfo = &snapSummary{
			ID:        golden.ID,
			Label:     golden.Label,
			Registers: len(golden.Registers),
			Timestamp: golden.Timestamp.Format(time.RFC3339),
		}
	}

	response.OK(w,map[string]any{
		"device":    ip,
		"golden":    goldenInfo,
		"snapshots": summaries,
	})
}

func (s *Server) handleDiff(w http.ResponseWriter, r *http.Request) {
	ip := chi.URLParam(r, "ip")

	golden := s.snaps.GetGolden(ip)
	latest := s.snaps.Latest(ip)

	if golden == nil {
		response.Err(w,http.StatusNotFound, "no golden image set for device")
		return
	}
	if latest == nil {
		response.Err(w,http.StatusNotFound, "no snapshots for device")
		return
	}

	diff := cfgmgmt.DiffSnapshots(golden, latest)
	response.OK(w,diff)
}

func (s *Server) handleConfigDevices(w http.ResponseWriter, r *http.Request) {
	devices := s.snaps.ListDevices()
	if devices == nil {
		devices = []string{}
	}
	response.OK(w,devices)
}
