package config

import "fmt"

// Change represents a single register value change.
type Change struct {
	Address  uint16 `json:"address"`
	OldValue uint16 `json:"old_value"`
	NewValue uint16 `json:"new_value"`
}

// DiffResult is the comparison between two snapshots.
type DiffResult struct {
	DeviceIP  string   `json:"device_ip"`
	BaseLabel string   `json:"base_label"`
	BaseTime  string   `json:"base_time"`
	NewLabel  string   `json:"new_label"`
	NewTime   string   `json:"new_time"`
	Changes   []Change `json:"changes"`
	Added     int      `json:"added"`   // registers in new but not in base
	Removed   int      `json:"removed"` // registers in base but not in new
	Summary   string   `json:"summary"`
}

// DiffSnapshots compares two snapshots and returns changes.
func DiffSnapshots(base, current *Snapshot) *DiffResult {
	baseMap := make(map[uint16]uint16)
	for _, r := range base.Registers {
		baseMap[r.Address] = r.Value
	}

	newMap := make(map[uint16]uint16)
	for _, r := range current.Registers {
		newMap[r.Address] = r.Value
	}

	var changes []Change
	added := 0
	removed := 0

	// Check changes and additions
	for _, r := range current.Registers {
		oldVal, existed := baseMap[r.Address]
		if !existed {
			added++
			continue
		}
		if oldVal != r.Value {
			changes = append(changes, Change{
				Address:  r.Address,
				OldValue: oldVal,
				NewValue: r.Value,
			})
		}
	}

	// Check removals
	for addr := range baseMap {
		if _, exists := newMap[addr]; !exists {
			removed++
		}
	}

	summary := fmt.Sprintf("%d changed, %d added, %d removed out of %d registers",
		len(changes), added, removed, len(current.Registers))

	return &DiffResult{
		DeviceIP:  current.DeviceIP,
		BaseLabel: base.Label,
		BaseTime:  base.Timestamp.Format("2006-01-02T15:04:05Z07:00"),
		NewLabel:  current.Label,
		NewTime:   current.Timestamp.Format("2006-01-02T15:04:05Z07:00"),
		Changes:   changes,
		Added:     added,
		Removed:   removed,
		Summary:   summary,
	}
}
