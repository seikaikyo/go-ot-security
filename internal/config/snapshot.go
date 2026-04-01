package config

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/goburrow/modbus"
)

// RegisterValue holds a single register reading.
type RegisterValue struct {
	Address uint16 `json:"address"`
	Value   uint16 `json:"value"`
}

// Snapshot is a point-in-time capture of device registers.
type Snapshot struct {
	ID        string          `json:"id"`
	DeviceIP  string          `json:"device_ip"`
	Port      int             `json:"port"`
	UnitID    uint8           `json:"unit_id"`
	Registers []RegisterValue `json:"registers"`
	Timestamp time.Time       `json:"timestamp"`
	Label     string          `json:"label"` // "golden", "scheduled", "manual"
}

// SnapshotRequest defines what to capture.
type SnapshotRequest struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	UnitID   uint8  `json:"unit_id"`
	Start    uint16 `json:"start"`
	Count    uint16 `json:"count"`
	Label    string `json:"label"`
}

func (r *SnapshotRequest) applyDefaults() {
	if r.Port == 0 {
		r.Port = 502
	}
	if r.UnitID == 0 {
		r.UnitID = 1
	}
	if r.Count == 0 {
		r.Count = 100
	}
	if r.Label == "" {
		r.Label = "manual"
	}
}

// TakeSnapshot reads holding registers from a Modbus device.
func TakeSnapshot(req SnapshotRequest) (*Snapshot, error) {
	req.applyDefaults()

	addr := fmt.Sprintf("%s:%d", req.Host, req.Port)
	handler := modbus.NewTCPClientHandler(addr)
	handler.Timeout = 2 * time.Second
	handler.SlaveId = req.UnitID

	if err := handler.Connect(); err != nil {
		return nil, fmt.Errorf("connect %s: %w", addr, err)
	}
	defer handler.Close()

	client := modbus.NewClient(handler)

	var registers []RegisterValue
	batchSize := uint16(125)

	for offset := uint16(0); offset < req.Count; offset += batchSize {
		count := batchSize
		if offset+count > req.Count {
			count = req.Count - offset
		}

		data, err := client.ReadHoldingRegisters(req.Start+offset, count)
		if err != nil {
			slog.Warn("snapshot read error", "addr", req.Start+offset, "error", err)
			continue
		}

		for i := uint16(0); i < uint16(len(data)/2); i++ {
			val := binary.BigEndian.Uint16(data[i*2 : i*2+2])
			registers = append(registers, RegisterValue{
				Address: req.Start + offset + i,
				Value:   val,
			})
		}

		time.Sleep(10 * time.Millisecond)
	}

	snap := &Snapshot{
		ID:        fmt.Sprintf("snap-%d", time.Now().UnixMilli()),
		DeviceIP:  req.Host,
		Port:      req.Port,
		UnitID:    req.UnitID,
		Registers: registers,
		Timestamp: time.Now(),
		Label:     req.Label,
	}

	slog.Info("snapshot taken", "device", addr, "registers", len(registers), "label", req.Label)
	return snap, nil
}

// IsModbusDevice checks if a host has Modbus TCP open.
func IsModbusDevice(host string, port int) bool {
	if port == 0 {
		port = 502
	}
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 500*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
