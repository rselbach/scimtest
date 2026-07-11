package core

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

	want := AppState{
		Config: Config{
			BaseURL:           "https://example.com/scim/v2",
			BearerToken:       "secret",
			AutoOpenSyncTrace: true,
			IDPBaseURL:        "https://demo.rgrok.rselbach.com",
			RgrokName:         "demo",
			RgrokToken:        "rgrok-token",
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
		}},
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

	got, err := LoadState()
	r.NoError(err)
	r.Equal(want, got)

	path, err := stateFilePath()
	r.NoError(err)

	info, err := os.Stat(path)
	r.NoError(err)
	r.NotZero(info.Size())
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

func TestValidateUserAllowsEmptyUsername(t *testing.T) {
	r := require.New(t)

	err := ValidateUser("Jeff", "Winger", "jeff@greendale.edu", "")
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
