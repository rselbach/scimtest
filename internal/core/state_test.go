package core

import (
	"database/sql"
	"fmt"
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

	want := AppState{
		Config: Config{
			IDPBaseURL:      "https://demo.rgrok.rselbach.com",
			RgrokInstanceID: "12345678-1234-4234-8234-123456789abc",
		},
		Users: []User{{
			ID:         "local-1",
			GivenName:  "Troy",
			FamilyName: "Barnes",
			Email:      "troy@greendale.edu",
			Username:   "troy",
			Active:     true,
			RemoteID:   "remote-1",
			Dirty:      true,
		}},
		Groups: []Group{{
			ID:          "group-1",
			DisplayName: "Study Group",
			MemberIDs:   []string{"local-1"},
			RemoteID:    "remote-group-1",
			Dirty:       true,
		}},
		Apps: []App{{
			ID:                     "app-1",
			Name:                   "Study App",
			Slug:                   "study-app",
			Protocol:               "saml",
			SAMLACSURL:             "https://example.com/saml/acs",
			SAMLNameIDField:        "username",
			SAMLNameIDFormat:       SAMLNameIDFormatUnspecified,
			SAMLEmailAttributeName: DefaultSAMLEmailAttributeName,
			SCIMEnabled:            true,
			SCIMBaseURL:            "https://example.com/scim/v2",
			SCIMBearerToken:        "secret",
			SCIMAutoOpenTrace:      true,
		}},
		UserSync: map[string]map[string]ResourceSyncState{
			"app-1": {"local-1": {RemoteID: "remote-1", Dirty: true}},
		},
		GroupSync: map[string]map[string]ResourceSyncState{
			"app-1": {"group-1": {RemoteID: "remote-group-1", Dirty: true}},
		},
		UserOperations: map[string][]OperationLog{
			"local-1": {{
				Kind:               "sync",
				Summary:            "Created",
				Operation:          "create",
				Method:             "POST",
				Path:               "/Users",
				RequestBody:        `{"userName":"troy"}`,
				Status:             "201 Created",
				ResponseRetryAfter: "60",
				ResponseBody:       `{"id":"remote-1"}`,
				CreatedAt:          "2026-05-01T10:00:00Z",
			}},
		},
		GroupOperations: map[string][]OperationLog{
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

	r.NoError(SaveState(want))
	want.Users[0].RemoteID = ""
	want.Users[0].Dirty = false
	want.Groups[0].RemoteID = ""
	want.Groups[0].Dirty = false
	want.Environment = Environment{ID: DefaultEnvironmentID, Name: "Directory", Slug: "directory"}

	got, err := LoadState()
	r.NoError(err)
	r.Equal(want, got)

	path, err := stateFilePath()
	r.NoError(err)

	info, err := os.Stat(path)
	r.NoError(err)
	r.NotZero(info.Size())
}

func TestEnsureRgrokInstanceIDGeneratesAndReusesUUID(t *testing.T) {
	r := require.New(t)
	t.Setenv("SCIMTEST_STATE_FILE", filepath.Join(t.TempDir(), "state.db"))
	r.NoError(SaveState(AppState{}))

	first, err := EnsureRgrokInstanceID()
	r.NoError(err)
	r.True(validUUID(first))
	second, err := EnsureRgrokInstanceID()
	r.NoError(err)
	r.Equal(first, second)

	state, err := LoadState()
	r.NoError(err)
	r.Equal(first, state.Config.RgrokInstanceID)
}

func TestEnsureRgrokInstanceIDRepairsInvalidLegacyValue(t *testing.T) {
	r := require.New(t)
	t.Setenv("SCIMTEST_STATE_FILE", filepath.Join(t.TempDir(), "state.db"))
	r.NoError(SaveState(AppState{Config: Config{RgrokInstanceID: "legacy-invalid"}}))

	instanceID, err := EnsureRgrokInstanceID()
	r.NoError(err)
	r.True(validUUID(instanceID))
	r.NotEqual("legacy-invalid", instanceID)
}

func TestEnsureRgrokInstanceIDIgnoresLegacyTokenAndName(t *testing.T) {
	r := require.New(t)
	t.Setenv("SCIMTEST_STATE_FILE", filepath.Join(t.TempDir(), "state.db"))
	r.NoError(SaveState(AppState{}))
	db, err := openStateDB()
	r.NoError(err)
	_, err = db.Exec(`INSERT INTO config(key, value) VALUES ('rgrok_name', 'legacy-name'), ('rgrok_token', 'legacy-token')`)
	r.NoError(err)

	instanceID, err := EnsureRgrokInstanceID()
	r.NoError(err)
	r.True(validUUID(instanceID))
	state, err := LoadState()
	r.NoError(err)
	r.Equal(instanceID, state.Config.RgrokInstanceID)
}

func TestEnsureRgrokInstanceIDSurfacesStateError(t *testing.T) {
	r := require.New(t)
	root := t.TempDir()
	t.Setenv("SCIMTEST_STATE_FILE", filepath.Join(root, "parent-file", "state.db"))
	r.NoError(os.WriteFile(filepath.Join(root, "parent-file"), nil, 0o600))

	_, err := EnsureRgrokInstanceID()
	r.ErrorContains(err, "create state directory")
}

func TestStateDatabaseUsesPrivatePermissions(t *testing.T) {
	r := require.New(t)
	root := t.TempDir()
	path := filepath.Join(root, "nested", "state.db")
	t.Setenv("SCIMTEST_STATE_FILE", path)

	r.NoError(os.MkdirAll(filepath.Dir(path), 0o755))
	r.NoError(os.WriteFile(path, nil, 0o644))
	r.NoError(os.Chmod(path, 0o644))

	_, err := LoadState()
	r.NoError(err)

	info, err := os.Stat(path)
	r.NoError(err)
	r.Equal(os.FileMode(0o600), info.Mode().Perm())
}

// createTestEnvironment inserts an environment row directly; the product no
// longer creates environments, but migration tests need legacy-shaped
// databases.
func createTestEnvironment(t *testing.T, name string) Environment {
	t.Helper()
	r := require.New(t)
	id, err := NewID("env")
	r.NoError(err)
	env := Environment{ID: id, Name: name, Slug: Slugify(name)}
	db, err := openStateDB()
	r.NoError(err)
	_, err = db.Exec(`INSERT INTO environments(id, name, slug) VALUES(?, ?, ?)`, env.ID, env.Name, env.Slug)
	r.NoError(err)
	return env
}

func TestLoadStateFlattensExistingEnvironmentDirectories(t *testing.T) {
	r := require.New(t)
	t.Setenv("SCIMTEST_STATE_FILE", filepath.Join(t.TempDir(), "state.db"))

	defaultState := AppState{Users: []User{{ID: "default-user", GivenName: "Troy", FamilyName: "Barnes", Email: "troy@greendale.edu", Username: "troy", Active: true}}}
	r.NoError(SaveState(defaultState))
	staging := createTestEnvironment(t, "Staging Campus")
	stagingState := AppState{
		Environment: staging,
		Users:       []User{{ID: "staging-user", GivenName: "Abed", FamilyName: "Nadir", Email: "abed@greendale.edu", Username: "abed", Active: true}},
	}
	db, err := openStateDB()
	r.NoError(err)
	r.NoError(saveStateToDB(db, stagingState, false))

	global, err := LoadState()
	r.NoError(err)
	r.Len(global.Users, 2)
	r.NoError(SaveState(global))
	environments, err := loadEnvironmentsFromDB(db)
	r.NoError(err)
	r.Len(environments, 1)
	reloaded, err := LoadState()
	r.NoError(err)
	r.Len(reloaded.Users, 2)
}

func TestDefaultStateDirectoryUsesPrivatePermissions(t *testing.T) {
	r := require.New(t)
	root := t.TempDir()
	t.Setenv("SCIMTEST_STATE_FILE", "")
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))

	path, err := stateFilePath()
	r.NoError(err)
	dir := filepath.Dir(path)
	r.NoError(os.MkdirAll(dir, 0o755))
	r.NoError(os.Chmod(dir, 0o755))

	_, err = LoadState()
	r.NoError(err)

	info, err := os.Stat(dir)
	r.NoError(err)
	r.Equal(os.FileMode(0o700), info.Mode().Perm())
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

	got, err := LoadState()
	r.NoError(err)
	r.Len(got.Users, 1)
	r.Equal("Britta", got.Users[0].GivenName)
	r.Equal("Perry", got.Users[0].FamilyName)
	r.Equal("britta", got.Users[0].Username)
	r.True(got.Users[0].Active)
}

func TestSaveStateCapsOperationLogs(t *testing.T) {
	r := require.New(t)
	t.Setenv("SCIMTEST_STATE_FILE", filepath.Join(t.TempDir(), "state.db"))
	entries := make([]OperationLog, 0, maxOperationLogsPerResource+50)
	total := maxOperationLogsPerResource + 50
	for i := 0; i < total; i++ {
		// Newest first, matching how AppendOperationLogs prepends entries.
		age := total - 1 - i
		entries = append(entries, OperationLog{
			Kind:      "local",
			Summary:   fmt.Sprintf("Update %d", i),
			CreatedAt: fmt.Sprintf("2026-07-12T%02d:%02d:00Z", age/60, age%60),
		})
	}
	state := AppState{
		Users:          []User{{ID: "troy", GivenName: "Troy", FamilyName: "Barnes", Email: "troy@greendale.edu", Username: "troy", Active: true}},
		UserOperations: map[string][]OperationLog{"troy": entries},
	}

	r.NoError(SaveState(state))

	loaded, err := LoadState()
	r.NoError(err)
	r.Len(loaded.UserOperations["troy"], maxOperationLogsPerResource)
	r.Equal("Update 0", loaded.UserOperations["troy"][0].Summary)
}

func TestValidateUserAllowsEmptyFamilyName(t *testing.T) {
	r := require.New(t)

	r.NoError(ValidateUser("Magnitude", "magnitude@greendale.edu", "magnitude"))
	r.ErrorContains(ValidateUser("", "pop@greendale.edu", "pop"), "given name is required")
}

func TestSplitName(t *testing.T) {
	tests := map[string]struct {
		input      string
		wantGiven  string
		wantFamily string
	}{
		"empty":        {input: "  ", wantGiven: "", wantFamily: ""},
		"single token": {input: "Magnitude", wantGiven: "Magnitude", wantFamily: ""},
		"two tokens":   {input: "Troy Barnes", wantGiven: "Troy", wantFamily: "Barnes"},
		"many tokens":  {input: "Señor Ben Chang", wantGiven: "Señor", wantFamily: "Ben Chang"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			given, family := SplitName(tc.input)
			r.Equal(tc.wantGiven, given)
			r.Equal(tc.wantFamily, family)
		})
	}
}

func TestValidateUserAllowsEmptyUsername(t *testing.T) {
	r := require.New(t)

	err := ValidateUser("Jeff", "jeff@greendale.edu", "")
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

	got, err := LoadState()
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

	got, err := LoadState()
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

	state, err := LoadState()
	r.NoError(err)
	r.Len(state.UserOperations["local-1"], 1)
	r.Equal("sync", state.UserOperations["local-1"][0].Kind)
	r.Equal("", state.UserOperations["local-1"][0].Summary)
	r.Equal("", state.UserOperations["local-1"][0].ResponseRetryAfter)
}

func TestLoadStateMigratesPreEnvironmentDatabaseIntoDefault(t *testing.T) {
	t.Setenv("SCIMTEST_STATE_FILE", filepath.Join(t.TempDir(), "state.db"))
	r := require.New(t)
	path, err := stateFilePath()
	r.NoError(err)
	db, err := sql.Open("sqlite", path)
	r.NoError(err)
	_, err = db.Exec(`CREATE TABLE config (key TEXT PRIMARY KEY, value TEXT NOT NULL)`)
	r.NoError(err)
	_, err = db.Exec(`CREATE TABLE users (
		id TEXT PRIMARY KEY, given_name TEXT NOT NULL, family_name TEXT NOT NULL,
		email TEXT NOT NULL, username TEXT NOT NULL, active INTEGER NOT NULL,
		remote_id TEXT NOT NULL DEFAULT '', dirty INTEGER NOT NULL,
		deleted INTEGER NOT NULL, last_error TEXT NOT NULL DEFAULT '')`)
	r.NoError(err)
	_, err = db.Exec(`INSERT INTO config(key, value) VALUES ('base_url', 'https://legacy.test/scim'), ('bearer_token', 'legacy-token')`)
	r.NoError(err)
	_, err = db.Exec(`INSERT INTO users(id, given_name, family_name, email, username, active, remote_id, dirty, deleted, last_error) VALUES ('troy', 'Troy', 'Barnes', 'troy@greendale.edu', 'troy', 1, 'remote-troy', 0, 0, '')`)
	r.NoError(err)
	r.NoError(db.Close())

	state, err := LoadState()
	r.NoError(err)
	r.Equal(Environment{ID: DefaultEnvironmentID, Name: "Directory", Slug: "directory"}, state.Environment)
	r.Empty(state.Config.BaseURL)
	r.Empty(state.Config.BearerToken)
	r.Len(state.Users, 1)
	r.Empty(state.Users[0].RemoteID)
	r.Len(state.Apps, 1)
	r.True(state.Apps[0].SCIMEnabled)
	r.Equal("https://legacy.test/scim", state.Apps[0].SCIMBaseURL)
	r.Equal("legacy-token", state.Apps[0].SCIMBearerToken)
	r.Equal("remote-troy", state.UserSync[state.Apps[0].ID]["troy"].RemoteID)

	stateAgain, err := LoadState()
	r.NoError(err)
	r.Equal(state.Environment, stateAgain.Environment)
	r.Empty(stateAgain.Environments)
}

func TestEnvironmentSCIMConfigurationMigratesToApps(t *testing.T) {
	r := require.New(t)
	t.Setenv("SCIMTEST_STATE_FILE", filepath.Join(t.TempDir(), "state.db"))
	r.NoError(SaveState(AppState{}))
	legacyEnvironment := createTestEnvironment(t, "Legacy Staging")
	legacy := AppState{
		Environment: legacyEnvironment,
		Config:      Config{BaseURL: "https://legacy.test/scim", BearerToken: "legacy-token", AutoOpenSyncTrace: true},
		Users:       []User{{ID: "troy", GivenName: "Troy", FamilyName: "Barnes", Email: "troy@greendale.edu", Username: "troy", Active: true, RemoteID: "remote-troy"}},
		Apps:        []App{{ID: "legacy-app", Name: "Legacy Portal", Slug: "legacy-portal", Protocol: "saml", SAMLACSURL: "https://legacy.test/acs"}},
	}
	db, err := openStateDB()
	r.NoError(err)
	r.NoError(saveStateToDB(db, legacy, false))
	path, err := stateFilePath()
	r.NoError(err)
	db, err = sql.Open("sqlite", path)
	r.NoError(err)
	_, err = db.Exec(`DELETE FROM config WHERE key = 'app_scim_migrated'`)
	r.NoError(err)
	_, err = db.Exec(`UPDATE apps SET scim_enabled = 0, scim_base_url = '', scim_bearer_token = '', scim_auto_open_trace = 0`)
	r.NoError(err)
	_, err = db.Exec(`DELETE FROM app_user_sync`)
	r.NoError(err)
	r.NoError(db.Close())
	r.NoError(resetStateDBCache())

	db, err = openStateDB()
	r.NoError(err)
	migrated, err := loadStateFromDB(db, legacyEnvironment.ID)
	r.NoError(err)
	r.Len(migrated.Apps, 1)
	r.True(migrated.Apps[0].SCIMEnabled)
	r.Equal("https://legacy.test/scim", migrated.Apps[0].SCIMBaseURL)
	r.Equal("legacy-token", migrated.Apps[0].SCIMBearerToken)
	r.True(migrated.Apps[0].SCIMAutoOpenTrace)
	r.Equal(ResourceSyncState{RemoteID: "remote-troy"}, migrated.UserSync["legacy-app"]["troy"])
}

func TestStateForAppKeepsRemoteStateIndependent(t *testing.T) {
	r := require.New(t)
	state := AppState{
		Users:  []User{{ID: "troy", GivenName: "Troy", FamilyName: "Barnes", Email: "troy@greendale.edu", Username: "troy", Active: true}},
		Groups: []Group{{ID: "study-group", DisplayName: "Study Group", MemberIDs: []string{"troy"}}},
		Apps: []App{
			{ID: "app-a", Name: "Portal A", SCIMEnabled: true, SCIMBaseURL: "https://a.test/scim", SCIMBearerToken: "token-a"},
			{ID: "app-b", Name: "Portal B", SCIMEnabled: true, SCIMBaseURL: "https://b.test/scim", SCIMBearerToken: "token-b"},
		},
		UserSync: map[string]map[string]ResourceSyncState{
			"app-a": {"troy": {RemoteID: "remote-a"}},
			"app-b": {"troy": {RemoteID: "remote-b", Dirty: true}},
		},
	}

	projectedA, err := StateForApp(state, "app-a")
	r.NoError(err)
	r.Equal("https://a.test/scim", projectedA.Config.BaseURL)
	r.Equal("remote-a", projectedA.Users[0].RemoteID)
	r.False(projectedA.Users[0].Dirty)

	projectedB, err := StateForApp(state, "app-b")
	r.NoError(err)
	r.Equal("https://b.test/scim", projectedB.Config.BaseURL)
	r.Equal("remote-b", projectedB.Users[0].RemoteID)
	r.True(projectedB.Users[0].Dirty)
}

func TestStateForAppKeepsLocalHistoryAndScopesSyncHistory(t *testing.T) {
	r := require.New(t)
	state := AppState{
		Apps: []App{
			{ID: "app-a", Name: "Portal A", SCIMEnabled: true},
			{ID: "app-b", Name: "Portal B", SCIMEnabled: true},
		},
		UserOperations: map[string][]OperationLog{
			"troy": {
				{Kind: "local", Summary: "Updated locally"},
				{AppID: "app-a", Kind: "sync", Summary: "Synced to A"},
				{AppID: "app-b", Kind: "sync", Summary: "Synced to B"},
				{Kind: "sync", Summary: "Legacy unscoped sync"},
			},
		},
	}

	projected, err := StateForApp(state, "app-a")
	r.NoError(err)
	r.Equal([]OperationLog{
		{Kind: "local", Summary: "Updated locally"},
		{AppID: "app-a", Kind: "sync", Summary: "Synced to A"},
	}, projected.UserOperations["troy"])
}

func TestOperationLogAppIDRoundTrips(t *testing.T) {
	r := require.New(t)
	t.Setenv("SCIMTEST_STATE_FILE", filepath.Join(t.TempDir(), "state.db"))
	state := AppState{
		Users: []User{{ID: "troy", GivenName: "Troy", FamilyName: "Barnes", Email: "troy@greendale.edu", Username: "troy", Active: true}},
		Apps:  []App{{ID: "app-local", Name: "dev-local", Slug: "dev-local", Protocol: "scim", SCIMEnabled: true}},
		UserOperations: map[string][]OperationLog{
			"troy": {{AppID: "app-local", Kind: "sync", Summary: "Created"}},
		},
	}

	r.NoError(SaveState(state))
	loaded, err := LoadState()
	r.NoError(err)
	r.Equal("app-local", loaded.UserOperations["troy"][0].AppID)
}

func TestMarkDirtyUpdatesEverySyncApp(t *testing.T) {
	r := require.New(t)
	state := AppState{Apps: []App{
		{ID: "app-a", SCIMEnabled: true},
		{ID: "app-b", SCIMEnabled: true},
		{ID: "app-c"},
	}}

	MarkUserDirtyForApps(&state, "troy", false)
	MarkGroupDirtyForApps(&state, "study-group", false)

	r.True(state.UserSync["app-a"]["troy"].Dirty)
	r.True(state.UserSync["app-b"]["troy"].Dirty)
	r.NotContains(state.UserSync, "app-c")
	r.True(state.GroupSync["app-a"]["study-group"].Dirty)
	r.True(state.GroupSync["app-b"]["study-group"].Dirty)
	r.NotContains(state.GroupSync, "app-c")
}

func TestMergeAppImportPreservesOtherAppRemoteIDs(t *testing.T) {
	r := require.New(t)
	state := AppState{
		Users: []User{
			{ID: "troy", GivenName: "Troy", FamilyName: "Barnes", Email: "troy@greendale.edu", Username: "troy", Active: true},
			{ID: "abed", GivenName: "Abed", FamilyName: "Nadir", Email: "abed@greendale.edu", Username: "abed", Active: true},
		},
		Apps: []App{{ID: "app-a", SCIMEnabled: true}, {ID: "app-b", SCIMEnabled: true}},
		UserSync: map[string]map[string]ResourceSyncState{
			"app-a": {"troy": {RemoteID: "a-troy"}, "abed": {RemoteID: "a-abed"}},
			"app-b": {"troy": {RemoteID: "b-troy"}, "abed": {RemoteID: "b-abed"}},
		},
	}
	imported := AppState{Users: []User{{ID: "troy", GivenName: "Troy", FamilyName: "Barnes", Email: "troy@greendale.edu", Username: "troy", Active: true, RemoteID: "a-troy"}}}

	MergeAppImportState(&state, "app-a", imported)

	r.Len(state.Users, 2)
	r.True(state.Users[1].Deleted)
	r.Equal("a-troy", state.UserSync["app-a"]["troy"].RemoteID)
	r.False(state.UserSync["app-a"]["troy"].Dirty)
	r.Equal("b-troy", state.UserSync["app-b"]["troy"].RemoteID)
	r.True(state.UserSync["app-b"]["troy"].Dirty)
	r.Equal("b-abed", state.UserSync["app-b"]["abed"].RemoteID)
	r.True(state.UserSync["app-b"]["abed"].Deleted)
}

func TestMergeAppImportRetainsOperationHistory(t *testing.T) {
	r := require.New(t)
	state := AppState{
		Users:  []User{{ID: "troy", Active: true}},
		Groups: []Group{{ID: "study-group", DisplayName: "Study Group"}},
		Apps:   []App{{ID: "app-a", SCIMEnabled: true}},
		UserOperations: map[string][]OperationLog{
			"troy": {{AppID: "app-b", Kind: "sync", Summary: "Created", CreatedAt: "2026-05-01T10:00:00Z"}},
		},
		GroupOperations: map[string][]OperationLog{
			"study-group": {{Kind: "local", Summary: "Created locally", CreatedAt: "2026-05-01T10:00:00Z"}},
		},
	}
	imported := AppState{
		Users:  []User{{ID: "troy", Active: true, RemoteID: "remote-troy"}},
		Groups: []Group{{ID: "study-group", DisplayName: "Study Group", RemoteID: "remote-study-group"}},
		UserOperations: map[string][]OperationLog{
			"troy": {{Kind: "local", Summary: "Imported from SCIM", CreatedAt: "2026-05-01T11:00:00Z"}},
		},
		GroupOperations: map[string][]OperationLog{
			"study-group": {{Kind: "local", Summary: "Imported from SCIM", CreatedAt: "2026-05-01T11:00:00Z"}},
		},
	}

	MergeAppImportState(&state, "app-a", imported)

	r.Equal([]string{"Imported from SCIM", "Created"}, []string{
		state.UserOperations["troy"][0].Summary,
		state.UserOperations["troy"][1].Summary,
	})
	r.Equal([]string{"Imported from SCIM", "Created locally"}, []string{
		state.GroupOperations["study-group"][0].Summary,
		state.GroupOperations["study-group"][1].Summary,
	})
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

	state := AppState{
		UserOperations: map[string][]OperationLog{
			"user-1": {
				{Kind: "sync", Summary: "Synced", CreatedAt: "2026-05-01T11:00:00Z"},
			},
		},
	}

	AppendLocalOperationLog(&state, "user", "user-1", "Updated email")

	r.Len(state.UserOperations["user-1"], 2)
	r.Equal("local", state.UserOperations["user-1"][0].Kind)
	r.Equal("Updated email", state.UserOperations["user-1"][0].Summary)
	r.Equal("2026-05-01T12:00:00Z", state.UserOperations["user-1"][0].CreatedAt)
	r.Equal("Synced", state.UserOperations["user-1"][1].Summary)
}

func TestLoadStateOrdersOperationLogsNewestFirst(t *testing.T) {
	t.Setenv("SCIMTEST_STATE_FILE", filepath.Join(t.TempDir(), "state.db"))
	r := require.New(t)

	state := AppState{
		Users: []User{{
			ID:         "user-1",
			GivenName:  "Troy",
			FamilyName: "Barnes",
			Email:      "troy@greendale.edu",
			Username:   "troy",
			Active:     true,
		}},
		UserOperations: map[string][]OperationLog{
			"user-1": {
				{Kind: "local", Summary: "Updated email", CreatedAt: "2026-05-01T12:00:00Z"},
				{Kind: "sync", Summary: "Synced", CreatedAt: "2026-05-01T11:00:00Z"},
			},
		},
	}

	r.NoError(SaveState(state))

	loaded, err := LoadState()
	r.NoError(err)
	r.Len(loaded.UserOperations["user-1"], 2)
	r.Equal("Updated email", loaded.UserOperations["user-1"][0].Summary)
	r.Equal("Synced", loaded.UserOperations["user-1"][1].Summary)
}

func TestUserGroupsExcludesDeletedGroups(t *testing.T) {
	r := require.New(t)
	state := AppState{
		Groups: []Group{{
			ID:          "g1",
			DisplayName: "Study Group",
			MemberIDs:   []string{"troy"},
		}, {
			ID:          "g2",
			DisplayName: "Air Conditioning Repair",
			MemberIDs:   []string{"troy"},
			Deleted:     true,
		}, {
			ID:          "g3",
			DisplayName: "Glee Club",
			MemberIDs:   []string{"regionals"},
		}},
	}

	r.Equal([]string{"Study Group"}, UserGroups(state, "troy"))
}

func TestValidateAppRequiresSafeSAMLACSURL(t *testing.T) {
	tests := map[string]struct {
		acsURL  string
		wantErr string
	}{
		"empty": {
			wantErr: "SAML ACS URL is required",
		},
		"relative": {
			acsURL:  "/saml/acs",
			wantErr: "absolute HTTP(S) URL",
		},
		"network path": {
			acsURL:  "//sp.greendale.test/acs",
			wantErr: "absolute HTTP(S) URL",
		},
		"unsafe scheme": {
			acsURL:  "javascript:alert(1)",
			wantErr: "absolute HTTP(S) URL",
		},
		"fragment": {
			acsURL:  "https://sp.greendale.test/acs#fragment",
			wantErr: "absolute HTTP(S) URL",
		},
		"valid": {
			acsURL: "https://sp.greendale.test/acs",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			err := ValidateApp(App{
				ID:         "app-1",
				Name:       "Greendale",
				Slug:       "greendale",
				Protocol:   "saml",
				SAMLACSURL: tc.acsURL,
			}, nil)
			if tc.wantErr == "" {
				r.NoError(err)
				return
			}
			r.ErrorContains(err, tc.wantErr)
		})
	}
}

func TestValidateHTTPBaseURL(t *testing.T) {
	tests := map[string]struct {
		value    string
		required bool
		wantErr  string
	}{
		"optional empty": {},
		"required empty": {required: true, wantErr: "SCIM base URL is required"},
		"relative":       {value: "/scim/v2", wantErr: "must be an absolute URL"},
		"wrong scheme":   {value: "file:///tmp/scim", wantErr: "must use HTTP or HTTPS"},
		"credentials":    {value: "https://dean:pelton@greendale.test/scim", wantErr: "must not contain credentials"},
		"query":          {value: "https://greendale.test/scim?secret=chang", wantErr: "must not contain a query string"},
		"fragment":       {value: "https://greendale.test/scim#users", wantErr: "must not contain a fragment"},
		"valid":          {value: "https://greendale.test/scim/v2"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			err := ValidateHTTPBaseURL("SCIM base URL", tc.value, tc.required)
			if tc.wantErr == "" {
				r.NoError(err)
				return
			}
			r.ErrorContains(err, tc.wantErr)
		})
	}
}

func TestValidateAppRequiresSafeOIDCRedirect(t *testing.T) {
	tests := map[string]struct {
		redirects []string
		allowAny  bool
		wantErr   string
	}{
		"missing":       {wantErr: "at least one OIDC redirect URI is required"},
		"explicit any":  {allowAny: true},
		"relative":      {redirects: []string{"/callback"}, wantErr: "absolute HTTP(S) URL"},
		"custom scheme": {redirects: []string{"greendale://callback"}, wantErr: "absolute HTTP(S) URL"},
		"fragment":      {redirects: []string{"https://greendale.test/callback#fragment"}, wantErr: "absolute HTTP(S) URL"},
		"valid":         {redirects: []string{"http://localhost:3000/callback"}},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			err := ValidateApp(App{
				ID:                   "app-1",
				Name:                 "Greendale",
				Slug:                 "greendale",
				Protocol:             "oidc",
				OIDCClientID:         "greendale-client",
				OIDCRedirectURIs:     tc.redirects,
				AllowAnyOIDCRedirect: tc.allowAny,
			}, nil)
			if tc.wantErr == "" {
				r.NoError(err)
				return
			}
			r.ErrorContains(err, tc.wantErr)
		})
	}
}
