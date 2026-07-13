package core

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const StateBackupVersion = 1

// StateBackup is a versioned, complete export of local scimtest state.
type StateBackup struct {
	Version         int                                     `json:"version"`
	ExportedAt      string                                  `json:"exported_at"`
	State           AppState                                `json:"state"`
	UserOperations  map[string][]OperationLog               `json:"user_operations,omitempty"`
	GroupOperations map[string][]OperationLog               `json:"group_operations,omitempty"`
	UserSync        map[string]map[string]ResourceSyncState `json:"user_sync,omitempty"`
	GroupSync       map[string]map[string]ResourceSyncState `json:"group_sync,omitempty"`
}

// NewStateBackup creates a complete export, including state omitted by AppState JSON.
func NewStateBackup(state AppState) StateBackup {
	return StateBackup{
		Version:         StateBackupVersion,
		ExportedAt:      NowTimestamp(),
		State:           state,
		UserOperations:  state.UserOperations,
		GroupOperations: state.GroupOperations,
		UserSync:        state.UserSync,
		GroupSync:       state.GroupSync,
	}
}

// RestoredState validates the backup version and reconstructs complete state.
func (b StateBackup) RestoredState() (AppState, error) {
	if b.Version != StateBackupVersion {
		return AppState{}, fmt.Errorf("unsupported backup version %d", b.Version)
	}
	state := b.State
	state.UserOperations = b.UserOperations
	state.GroupOperations = b.GroupOperations
	state.UserSync = b.UserSync
	state.GroupSync = b.GroupSync
	return state, nil
}

// WriteSafetyBackup stores a private snapshot beside the state database.
func WriteSafetyBackup(state AppState) (string, error) {
	statePath, err := stateFilePath()
	if err != nil {
		return "", err
	}
	directory := filepath.Join(filepath.Dir(statePath), "backups")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", fmt.Errorf("create backup directory: %w", err)
	}
	data, err := json.MarshalIndent(NewStateBackup(state), "", "  ")
	if err != nil {
		return "", fmt.Errorf("encode safety backup: %w", err)
	}
	name := fmt.Sprintf("pre-restore-%s.json", time.Now().UTC().Format("20060102T150405.000000000Z"))
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return "", fmt.Errorf("write safety backup: %w", err)
	}
	return path, nil
}
