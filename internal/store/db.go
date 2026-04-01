package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	_ "modernc.org/sqlite"
)

type DB struct {
	conn *sql.DB
}

func Open(path string) (*DB, error) {
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	// WAL mode for concurrent reads
	conn.Exec("PRAGMA journal_mode=WAL")
	conn.Exec("PRAGMA busy_timeout=5000")

	db := &DB{conn: conn}
	if err := db.migrate(); err != nil {
		conn.Close()
		return nil, err
	}

	slog.Info("database opened", "path", path)
	return db, nil
}

func (db *DB) Close() {
	if db.conn != nil {
		db.conn.Close()
	}
}

func (db *DB) migrate() error {
	_, err := db.conn.Exec(`
		CREATE TABLE IF NOT EXISTS assets (
			id TEXT PRIMARY KEY,
			ip TEXT NOT NULL,
			mac TEXT DEFAULT '',
			hostname TEXT DEFAULT '',
			vendor TEXT DEFAULT '',
			model TEXT DEFAULT '',
			firmware TEXT DEFAULT '',
			device_type TEXT DEFAULT '',
			protocols TEXT DEFAULT '[]',
			open_ports TEXT DEFAULT '[]',
			risk_score REAL DEFAULT 0,
			risk_factors TEXT DEFAULT '[]',
			zone TEXT DEFAULT '',
			first_seen TEXT NOT NULL,
			last_seen TEXT NOT NULL,
			raw_data TEXT DEFAULT '{}'
		);
		CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets(ip);

		CREATE TABLE IF NOT EXISTS scans (
			id TEXT PRIMARY KEY,
			subnet TEXT NOT NULL,
			status TEXT NOT NULL,
			started_at TEXT NOT NULL,
			finished_at TEXT DEFAULT '',
			total_hosts INTEGER DEFAULT 0,
			alive_hosts INTEGER DEFAULT 0,
			error TEXT DEFAULT ''
		);

		CREATE TABLE IF NOT EXISTS alerts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			severity TEXT NOT NULL,
			source TEXT NOT NULL,
			rule TEXT NOT NULL,
			message TEXT NOT NULL,
			details TEXT DEFAULT '{}',
			timestamp TEXT NOT NULL,
			acked INTEGER DEFAULT 0
		);
		CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
	`)
	return err
}

// Asset operations

type Asset struct {
	ID          string   `json:"id"`
	IP          string   `json:"ip"`
	MAC         string   `json:"mac"`
	Hostname    string   `json:"hostname"`
	Vendor      string   `json:"vendor"`
	Model       string   `json:"model"`
	Firmware    string   `json:"firmware"`
	DeviceType  string   `json:"device_type"`
	Protocols   []string `json:"protocols"`
	OpenPorts   []int    `json:"open_ports"`
	RiskScore   float64  `json:"risk_score"`
	RiskFactors []string `json:"risk_factors"`
	Zone        string   `json:"zone"`
	FirstSeen   string   `json:"first_seen"`
	LastSeen    string   `json:"last_seen"`
}

func (db *DB) UpsertAsset(a *Asset) error {
	protocols, _ := json.Marshal(a.Protocols)
	ports, _ := json.Marshal(a.OpenPorts)
	factors, _ := json.Marshal(a.RiskFactors)

	_, err := db.conn.Exec(`
		INSERT INTO assets (id, ip, mac, hostname, vendor, model, firmware,
			device_type, protocols, open_ports, risk_score, risk_factors,
			zone, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			mac=excluded.mac, hostname=excluded.hostname,
			vendor=excluded.vendor, model=excluded.model,
			firmware=excluded.firmware, device_type=excluded.device_type,
			protocols=excluded.protocols, open_ports=excluded.open_ports,
			risk_score=excluded.risk_score, risk_factors=excluded.risk_factors,
			last_seen=excluded.last_seen
	`, a.ID, a.IP, a.MAC, a.Hostname, a.Vendor, a.Model, a.Firmware,
		a.DeviceType, string(protocols), string(ports), a.RiskScore,
		string(factors), a.Zone, a.FirstSeen, a.LastSeen)
	return err
}

func (db *DB) ListAssets() ([]Asset, error) {
	rows, err := db.conn.Query(`SELECT id, ip, mac, hostname, vendor, model,
		firmware, device_type, protocols, open_ports, risk_score, risk_factors,
		zone, first_seen, last_seen FROM assets ORDER BY risk_score DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var assets []Asset
	for rows.Next() {
		var a Asset
		var protocols, ports, factors string
		err := rows.Scan(&a.ID, &a.IP, &a.MAC, &a.Hostname, &a.Vendor,
			&a.Model, &a.Firmware, &a.DeviceType, &protocols, &ports,
			&a.RiskScore, &factors, &a.Zone, &a.FirstSeen, &a.LastSeen)
		if err != nil {
			continue
		}
		json.Unmarshal([]byte(protocols), &a.Protocols)
		json.Unmarshal([]byte(ports), &a.OpenPorts)
		json.Unmarshal([]byte(factors), &a.RiskFactors)
		assets = append(assets, a)
	}
	return assets, nil
}

func (db *DB) GetAsset(id string) (*Asset, error) {
	var a Asset
	var protocols, ports, factors string
	err := db.conn.QueryRow(`SELECT id, ip, mac, hostname, vendor, model,
		firmware, device_type, protocols, open_ports, risk_score, risk_factors,
		zone, first_seen, last_seen FROM assets WHERE id = ?`, id).
		Scan(&a.ID, &a.IP, &a.MAC, &a.Hostname, &a.Vendor, &a.Model,
			&a.Firmware, &a.DeviceType, &protocols, &ports, &a.RiskScore,
			&factors, &a.Zone, &a.FirstSeen, &a.LastSeen)
	if err != nil {
		return nil, err
	}
	json.Unmarshal([]byte(protocols), &a.Protocols)
	json.Unmarshal([]byte(ports), &a.OpenPorts)
	json.Unmarshal([]byte(factors), &a.RiskFactors)
	return &a, nil
}

func (db *DB) GetStats() map[string]any {
	var total, plcCount, hmiCount, highRisk int
	var itCount, otCount int
	db.conn.QueryRow("SELECT COUNT(*) FROM assets").Scan(&total)
	db.conn.QueryRow("SELECT COUNT(*) FROM assets WHERE device_type='plc'").Scan(&plcCount)
	db.conn.QueryRow("SELECT COUNT(*) FROM assets WHERE device_type='hmi'").Scan(&hmiCount)
	db.conn.QueryRow("SELECT COUNT(*) FROM assets WHERE risk_score >= 7").Scan(&highRisk)
	db.conn.QueryRow("SELECT COUNT(*) FROM assets WHERE device_type LIKE 'it_%' OR device_type='web_server'").Scan(&itCount)
	db.conn.QueryRow("SELECT COUNT(*) FROM assets WHERE device_type IN ('plc','hmi','rtu','semiconductor_equipment','opcua_server','iot_gateway','bac_controller','legacy_device')").Scan(&otCount)

	segregated := true
	if itCount > 0 && otCount > 0 {
		segregated = false
	}

	return map[string]any{
		"total_assets":    total,
		"plc_count":       plcCount,
		"hmi_count":       hmiCount,
		"high_risk_count": highRisk,
		"it_count":        itCount,
		"ot_count":        otCount,
		"it_ot_separated": segregated,
		"last_scan":       time.Now().Format(time.RFC3339),
	}
}

// Scan operations

type ScanRecord struct {
	ID         string `json:"id"`
	Subnet     string `json:"subnet"`
	Status     string `json:"status"`
	StartedAt  string `json:"started_at"`
	FinishedAt string `json:"finished_at"`
	TotalHosts int    `json:"total_hosts"`
	AliveHosts int    `json:"alive_hosts"`
	Error      string `json:"error,omitempty"`
}

func (db *DB) InsertScan(s *ScanRecord) error {
	_, err := db.conn.Exec(`INSERT INTO scans (id, subnet, status, started_at)
		VALUES (?, ?, ?, ?)`, s.ID, s.Subnet, s.Status, s.StartedAt)
	return err
}

func (db *DB) UpdateScan(s *ScanRecord) error {
	_, err := db.conn.Exec(`UPDATE scans SET status=?, finished_at=?,
		total_hosts=?, alive_hosts=?, error=? WHERE id=?`,
		s.Status, s.FinishedAt, s.TotalHosts, s.AliveHosts, s.Error, s.ID)
	return err
}

func (db *DB) GetLatestScan() (*ScanRecord, error) {
	var s ScanRecord
	err := db.conn.QueryRow(`SELECT id, subnet, status, started_at, finished_at,
		total_hosts, alive_hosts, error FROM scans ORDER BY started_at DESC LIMIT 1`).
		Scan(&s.ID, &s.Subnet, &s.Status, &s.StartedAt, &s.FinishedAt,
			&s.TotalHosts, &s.AliveHosts, &s.Error)
	if err != nil {
		return nil, err
	}
	return &s, nil
}
