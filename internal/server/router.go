package server

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"strconv"

	"github.com/go-chi/chi/v5"
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
}

type scanProgress struct {
	Phase string `json:"phase"`
	Done  int    `json:"done"`
	Total int    `json:"total"`
}

func New(db *store.DB) *Server {
	alerts := monitor.NewAlertEngine()
	return &Server{
		db:      db,
		alerts:  alerts,
		monitor: monitor.New(db, alerts),
	}
}

func (s *Server) Router() chi.Router {
	r := chi.NewRouter()

	r.Post("/api/scan", s.handleScan)
	r.Get("/api/scan/status", s.handleScanStatus)
	r.Get("/api/assets", s.handleListAssets)
	r.Get("/api/assets/{id}", s.handleGetAsset)
	r.Get("/api/topology", s.handleTopology)
	r.Get("/api/stats", s.handleStats)

	// Phase 2: Vulnerability + Compliance
	r.Get("/api/vuln/{id}", s.handleVuln)
	r.Get("/api/compliance", s.handleCompliance)

	// Phase 3: Monitoring
	r.Post("/api/monitor/start", s.handleMonitorStart)
	r.Post("/api/monitor/stop", s.handleMonitorStop)
	r.Get("/api/monitor/status", s.handleMonitorStatus)
	r.Get("/api/alerts", s.handleAlerts)
	r.Get("/api/alerts/stats", s.handleAlertStats)
	r.Post("/api/alerts/{id}/ack", s.handleAlertAck)

	// Embedded frontend
	r.HandleFunc("/*", staticHandler())
	r.HandleFunc("/", staticHandler())

	return r
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Subnet      string `json:"subnet"`
		Ports       string `json:"ports"`
		TimeoutMs   int    `json:"timeout_ms"`
		Concurrency int    `json:"concurrency"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Subnet == "" {
		respondErr(w, http.StatusBadRequest, "subnet is required")
		return
	}

	s.scanMu.Lock()
	if s.scanning {
		s.scanMu.Unlock()
		respondErr(w, http.StatusConflict, "scan already in progress")
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
		}
		s.db.UpdateScan(scanRec)
	}()

	respondOK(w, map[string]any{
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

	respondOK(w, data)
}

func (s *Server) handleListAssets(w http.ResponseWriter, r *http.Request) {
	assets, err := s.db.ListAssets()
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to list assets")
		return
	}
	if assets == nil {
		assets = []store.Asset{}
	}
	respondOK(w, assets)
}

func (s *Server) handleGetAsset(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	asset, err := s.db.GetAsset(id)
	if err != nil {
		respondErr(w, http.StatusNotFound, "asset not found")
		return
	}
	respondOK(w, asset)
}

func (s *Server) handleTopology(w http.ResponseWriter, r *http.Request) {
	assets, err := s.db.ListAssets()
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to list assets")
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

	respondOK(w, map[string]any{
		"nodes": nodes,
	})
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	respondOK(w, s.db.GetStats())
}

func (s *Server) handleVuln(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	asset, err := s.db.GetAsset(id)
	if err != nil {
		respondErr(w, http.StatusNotFound, "asset not found")
		return
	}

	cves := vuln.LookupCVEs(asset.Vendor, asset.Model, asset.Protocols)
	creds := vuln.CheckDefaultCredentials(asset.Vendor, asset.Model, asset.OpenPorts, asset.Protocols)
	insecure := vuln.CheckInsecureServices(asset.OpenPorts, asset.Protocols)

	respondOK(w, map[string]any{
		"asset_id":        id,
		"cves":            cves,
		"credentials":     creds,
		"insecure_services": insecure,
	})
}

func (s *Server) handleCompliance(w http.ResponseWriter, r *http.Request) {
	assets, err := s.db.ListAssets()
	if err != nil {
		respondErr(w, http.StatusInternalServerError, "failed to list assets")
		return
	}

	ctx := compliance.BuildContext(assets)
	report := compliance.RunAllFrameworks(ctx)
	respondOK(w, report)
}

func (s *Server) handleMonitorStart(w http.ResponseWriter, r *http.Request) {
	var cfg monitor.Config
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		respondErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if cfg.Subnet == "" {
		respondErr(w, http.StatusBadRequest, "subnet is required")
		return
	}

	if err := s.monitor.Start(cfg); err != nil {
		respondErr(w, http.StatusConflict, err.Error())
		return
	}
	respondOK(w, map[string]any{"status": "started", "subnet": cfg.Subnet})
}

func (s *Server) handleMonitorStop(w http.ResponseWriter, r *http.Request) {
	s.monitor.Stop()
	respondOK(w, map[string]string{"status": "stopped"})
}

func (s *Server) handleMonitorStatus(w http.ResponseWriter, r *http.Request) {
	respondOK(w, s.monitor.Status())
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if q := r.URL.Query().Get("limit"); q != "" {
		if n, err := strconv.Atoi(q); err == nil && n > 0 {
			limit = n
		}
	}
	respondOK(w, s.alerts.List(limit))
}

func (s *Server) handleAlertStats(w http.ResponseWriter, r *http.Request) {
	respondOK(w, s.alerts.Stats())
}

func (s *Server) handleAlertAck(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		respondErr(w, http.StatusBadRequest, "invalid alert id")
		return
	}
	if s.alerts.Ack(id) {
		respondOK(w, map[string]string{"status": "acked"})
	} else {
		respondErr(w, http.StatusNotFound, "alert not found")
	}
}
