package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)

func TestSaveAndLoadState(t *testing.T) {
	t.Setenv("SCIMTEST_STATE_FILE", filepath.Join(t.TempDir(), "state.db"))
	r := require.New(t)

	want := appState{
		Config: config{
			BaseURL:           "https://example.com/scim/v2",
			BearerToken:       "secret",
			AutoOpenSyncTrace: true,
		},
		Users: []user{{
			ID:         "local-1",
			GivenName:  "Troy",
			FamilyName: "Barnes",
			Email:      "troy@greendale.edu",
			Username:   "troy",
			Active:     true,
			RemoteID:   "remote-1",
			Dirty:      true,
		}},
		Groups: []group{{
			ID:          "group-1",
			DisplayName: "Study Group",
			MemberIDs:   []string{"local-1"},
			RemoteID:    "remote-group-1",
			Dirty:       true,
		}},
		UserOperations: map[string][]operationLog{
			"local-1": {{
				Kind:         "sync",
				Summary:      "Created",
				Operation:    "create",
				Method:       "POST",
				Path:         "/Users",
				RequestBody:  `{"userName":"troy"}`,
				Status:       "201 Created",
				ResponseBody: `{"id":"remote-1"}`,
				CreatedAt:    "2026-05-01T10:00:00Z",
			}},
		},
		GroupOperations: map[string][]operationLog{
			"group-1": {{
				Kind:         "sync",
				Summary:      "Synced",
				Operation:    "update",
				Method:       "PUT",
				Path:         "/Groups/remote-group-1",
				RequestBody:  `{"displayName":"Study Group"}`,
				Status:       "200 OK",
				ResponseBody: "",
				CreatedAt:    "2026-05-01T10:01:00Z",
			}},
		},
	}

	r.NoError(saveState(want))

	got, err := loadState()
	r.NoError(err)
	r.Equal(want, got)

	path, err := stateFilePath()
	r.NoError(err)

	info, err := os.Stat(path)
	r.NoError(err)
	r.NotZero(info.Size())
}

func TestLoadStateMigratesNameFromUsername(t *testing.T) {
	t.Setenv("SCIMTEST_STATE_FILE", filepath.Join(t.TempDir(), "state.db"))
	r := require.New(t)

	path, err := legacyStateFilePath()
	r.NoError(err)

	legacyJSON := []byte(`{
  "config": {},
  "users": [
    {
      "id": "local-1",
      "name": "Britta Perry",
      "username": "britta",
      "email": "britta@greendale.edu"
    }
  ]
}`)
	r.NoError(os.WriteFile(path, legacyJSON, 0o600))

	got, err := loadState()
	r.NoError(err)
	r.Len(got.Users, 1)
	r.Equal("Britta", got.Users[0].GivenName)
	r.Equal("Perry", got.Users[0].FamilyName)
	r.Equal("britta", got.Users[0].Username)
	r.True(got.Users[0].Active)
}

func TestValidateUserAllowsEmptyUsername(t *testing.T) {
	r := require.New(t)

	err := validateUser("Jeff", "Winger", "jeff@greendale.edu", "")
	r.NoError(err)
}

func TestLoadStateDefaultsActiveToTrue(t *testing.T) {
	t.Setenv("SCIMTEST_STATE_FILE", filepath.Join(t.TempDir(), "state.db"))
	r := require.New(t)

	path, err := legacyStateFilePath()
	r.NoError(err)

	legacyJSON := []byte(`{
  "config": {},
  "users": [
    {
      "id": "local-2",
      "given_name": "Abed",
      "family_name": "Nadir",
      "username": "abed",
      "email": "abed@greendale.edu"
    }
  ]
}`)
	r.NoError(os.WriteFile(path, legacyJSON, 0o600))

	got, err := loadState()
	r.NoError(err)
	r.Len(got.Users, 1)
	r.True(got.Users[0].Active)
}

func TestLoadStatePreservesInactiveUser(t *testing.T) {
	t.Setenv("SCIMTEST_STATE_FILE", filepath.Join(t.TempDir(), "state.db"))
	r := require.New(t)

	path, err := legacyStateFilePath()
	r.NoError(err)

	legacyJSON := []byte(`{
  "config": {},
  "users": [
    {
      "id": "local-3",
      "given_name": "Dean",
      "family_name": "Pelton",
      "username": "dean",
      "email": "dean@greendale.edu",
      "active": false
    }
  ]
}`)
	r.NoError(os.WriteFile(path, legacyJSON, 0o600))

	got, err := loadState()
	r.NoError(err)
	r.Len(got.Users, 1)
	r.False(got.Users[0].Active)
}

func TestLoadStateMigratesLegacyOperationLogsTable(t *testing.T) {
	t.Setenv("SCIMTEST_STATE_FILE", filepath.Join(t.TempDir(), "state.db"))
	r := require.New(t)

	path, err := stateFilePath()
	r.NoError(err)

	db, err := sql.Open("sqlite", path)
	r.NoError(err)
	defer func() {
		r.NoError(db.Close())
	}()

	_, err = db.Exec(`CREATE TABLE operation_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		resource_type TEXT NOT NULL,
		resource_id TEXT NOT NULL,
		label TEXT NOT NULL,
		operation TEXT NOT NULL,
		method TEXT NOT NULL,
		path TEXT NOT NULL,
		request_body TEXT NOT NULL,
		status TEXT NOT NULL,
		response_body TEXT NOT NULL,
		error_text TEXT NOT NULL,
		created_at TEXT NOT NULL
	)`)
	r.NoError(err)

	_, err = db.Exec(`INSERT INTO operation_logs(resource_type, resource_id, label, operation, method, path, request_body, status, response_body, error_text, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"user",
		"local-1",
		"Troy Barnes",
		"create",
		"POST",
		"/Users",
		`{"userName":"troy"}`,
		"201 Created",
		`{"id":"remote-1"}`,
		"",
		"2026-05-01T10:00:00Z",
	)
	r.NoError(err)
	r.NoError(db.Close())

	state, err := loadState()
	r.NoError(err)
	r.Len(state.UserOperations["local-1"], 1)
	r.Equal("sync", state.UserOperations["local-1"][0].Kind)
	r.Equal("", state.UserOperations["local-1"][0].Summary)
}

func TestAppendLocalOperationLogPrependsEntry(t *testing.T) {
	r := require.New(t)
	previousTime := currentTime
	currentTime = func() time.Time {
		return time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	}
	defer func() {
		currentTime = previousTime
	}()

	state := appState{
		UserOperations: map[string][]operationLog{
			"user-1": {
				{Kind: "sync", Summary: "Synced", CreatedAt: "2026-05-01T11:00:00Z"},
			},
		},
	}

	appendLocalOperationLog(&state, "user", "user-1", "Updated email")

	r.Len(state.UserOperations["user-1"], 2)
	r.Equal("local", state.UserOperations["user-1"][0].Kind)
	r.Equal("Updated email", state.UserOperations["user-1"][0].Summary)
	r.Equal("2026-05-01T12:00:00Z", state.UserOperations["user-1"][0].CreatedAt)
	r.Equal("Synced", state.UserOperations["user-1"][1].Summary)
}
