package config

import (
	"encoding/json"
	"sync"
)

// SnapshotStore manages snapshots in memory.
type SnapshotStore struct {
	mu        sync.RWMutex
	snapshots map[string][]*Snapshot // device IP → snapshots (newest last)
	golden    map[string]*Snapshot   // device IP → golden image
}

func NewSnapshotStore() *SnapshotStore {
	return &SnapshotStore{
		snapshots: make(map[string][]*Snapshot),
		golden:    make(map[string]*Snapshot),
	}
}

func (s *SnapshotStore) Add(snap *Snapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.snapshots[snap.DeviceIP] = append(s.snapshots[snap.DeviceIP], snap)

	// Keep last 50 snapshots per device
	if len(s.snapshots[snap.DeviceIP]) > 50 {
		s.snapshots[snap.DeviceIP] = s.snapshots[snap.DeviceIP][len(s.snapshots[snap.DeviceIP])-50:]
	}
}

func (s *SnapshotStore) SetGolden(snap *Snapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()

	golden := *snap
	golden.Label = "golden"
	s.golden[snap.DeviceIP] = &golden
}

func (s *SnapshotStore) GetGolden(deviceIP string) *Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.golden[deviceIP]
}

func (s *SnapshotStore) List(deviceIP string) []*Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	snaps := s.snapshots[deviceIP]
	// Return newest first
	result := make([]*Snapshot, len(snaps))
	for i, snap := range snaps {
		result[len(snaps)-1-i] = snap
	}
	return result
}

func (s *SnapshotStore) ListDevices() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var devices []string
	for ip := range s.snapshots {
		devices = append(devices, ip)
	}
	return devices
}

func (s *SnapshotStore) Get(deviceIP, snapID string) *Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, snap := range s.snapshots[deviceIP] {
		if snap.ID == snapID {
			return snap
		}
	}
	return nil
}

func (s *SnapshotStore) Latest(deviceIP string) *Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	snaps := s.snapshots[deviceIP]
	if len(snaps) == 0 {
		return nil
	}
	return snaps[len(snaps)-1]
}

// ExportJSON exports all snapshots for a device as JSON.
func (s *SnapshotStore) ExportJSON(deviceIP string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data := map[string]any{
		"device":    deviceIP,
		"golden":    s.golden[deviceIP],
		"snapshots": s.snapshots[deviceIP],
	}
	return json.MarshalIndent(data, "", "  ")
}
