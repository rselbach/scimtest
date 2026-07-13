package core

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStateBackupRoundTripIncludesSyncAndHistory(t *testing.T) {
	r := require.New(t)
	state := AppState{
		Users:          []User{{ID: "troy", Email: "troy@greendale.edu"}},
		UserOperations: map[string][]OperationLog{"troy": {{Kind: "local", Summary: "Created"}}},
		UserSync:       map[string]map[string]ResourceSyncState{"app-1": {"troy": {RemoteID: "remote-troy"}}},
	}
	data, err := json.Marshal(NewStateBackup(state))
	r.NoError(err)
	var decoded StateBackup
	r.NoError(json.Unmarshal(data, &decoded))

	restored, err := decoded.RestoredState()
	r.NoError(err)
	r.Equal(state.Users, restored.Users)
	r.Equal(state.UserOperations, restored.UserOperations)
	r.Equal(state.UserSync, restored.UserSync)
}

func TestStateBackupRejectsUnknownVersion(t *testing.T) {
	_, err := (StateBackup{Version: StateBackupVersion + 1}).RestoredState()
	require.EqualError(t, err, "unsupported backup version 2")
}
