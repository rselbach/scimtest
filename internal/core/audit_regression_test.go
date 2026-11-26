package core

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSCIMClientRefusesRedirects(t *testing.T) {
	r := require.New(t)
	redirected := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		redirected = true
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	scimServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, target.URL+"/steal", http.StatusFound)
	}))
	defer scimServer.Close()

	client, err := NewSCIMClient(Config{BaseURL: scimServer.URL, BearerToken: "greendale-secret"})
	r.NoError(err)

	_, err = client.listUsers()
	r.Error(err)
	r.False(redirected, "SCIM client must not follow HTTP redirects")
}

func TestSCIMRejectsDotSegmentAndTraversalRemoteIDs(t *testing.T) {
	tests := map[string]string{
		"empty":     "",
		"dot":       ".",
		"dotdot":    "..",
		"slash":     "a/b",
		"backslash": `a\b`,
		"control":   "troy\x00barnes",
	}
	for name, remoteID := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			_, err := scimResourcePath("/Users", remoteID)
			r.Error(err)
		})
	}
}

func TestSCIMListResourcesRejectsNegativeCountsAndExceedingLimits(t *testing.T) {
	r := require.New(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/scim+json")
		_ = json.NewEncoder(w).Encode(SCIMListResponse[SCIMUserResource]{
			TotalResults: -1,
			StartIndex:   1,
			ItemsPerPage: 1,
			Resources:    []SCIMUserResource{{ID: "u-1", UserName: "troy"}},
		})
	}))
	defer srv.Close()

	res := ImportStateFromSCIMWithContext(context.Background(), AppState{
		Config: Config{BaseURL: srv.URL, BearerToken: "greendale-secret"},
	})
	r.Error(res.Fatal)
	r.Contains(res.Fatal.Error(), "negative counts")
}

func TestSaveEnvironmentStateRejectsCrossEnvironmentSyncMaps(t *testing.T) {
	t.Setenv("SCIMTEST_STATE_FILE", filepath.Join(t.TempDir(), "state.db"))
	r := require.New(t)

	err := SaveEnvironmentState(AppState{
		Environment: Environment{ID: "env-a", Name: "Greendale A", Slug: "greendale-a"},
		Apps:        []App{{ID: "env-a", Name: "Greendale A", Slug: "greendale-a", Protocol: "oidc"}},
		UserSync: map[string]map[string]ResourceSyncState{
			"env-b": {"troy": {RemoteID: "forged", Dirty: true}},
		},
	})
	r.Error(err)
	r.Contains(err.Error(), "does not belong to environment")
}

func TestValidateRestoredStateRejectsUnsafeValuesAndDropsOrphanLogs(t *testing.T) {
	r := require.New(t)
	badScheme := AppState{
		Environment: Environment{ID: "env-a", Name: "Greendale", Slug: "greendale"},
		Apps: []App{{
			ID:               "env-a",
			Name:             "Greendale",
			Slug:             "greendale",
			Protocol:         "oidc",
			OIDCRedirectURIs: []string{"javascript:alert(1)"},
		}},
	}
	r.Error(ValidateRestoredState(&badScheme, nil))

	badSlug := AppState{
		Environment: Environment{ID: "env-a", Name: "Greendale", Slug: "../admin"},
		Apps: []App{{
			ID:       "env-a",
			Name:     "Greendale",
			Slug:     "../admin",
			Protocol: "oidc",
		}},
	}
	r.Error(ValidateRestoredState(&badSlug, nil))

	badPEM := AppState{
		Environment: Environment{ID: "env-a", Name: "Greendale", Slug: "greendale"},
		Apps:        []App{{ID: "env-a", Name: "Greendale", Slug: "greendale", Protocol: "oidc"}},
		Config: Config{
			SigningKeys: []SigningKey{{ID: "k1", PrivateKeyPEM: "not-a-key", CertificatePEM: "not-a-cert"}},
		},
	}
	r.Error(ValidateRestoredState(&badPEM, nil))

	valid := AppState{
		Environment: Environment{ID: "env-a", Name: "Greendale", Slug: "greendale"},
		Apps:        []App{{ID: "env-a", Name: "Greendale", Slug: "greendale", Protocol: "oidc"}},
		Users:       []User{{ID: "troy", GivenName: "Troy", FamilyName: "Barnes", Email: "troy@greendale.edu", Username: "troy", Active: true}},
		UserOperations: map[string][]OperationLog{
			"troy":   {{Kind: "local", Summary: "Created"}},
			"orphan": {{Kind: "local", Summary: "Stale"}},
		},
	}
	r.NoError(ValidateRestoredState(&valid, nil))
	r.Contains(valid.UserOperations, "troy")
	r.NotContains(valid.UserOperations, "orphan")
}

func TestSaveEnvironmentStateAllowsDefaultSlug(t *testing.T) {
	t.Setenv("SCIMTEST_STATE_FILE", filepath.Join(t.TempDir(), "state.db"))
	r := require.New(t)

	// Initialize default database so env_default exists with slug "default".
	_, err := LoadState()
	r.NoError(err)

	err = SaveEnvironmentState(AppState{
		Environment: Environment{ID: "app_default_test", Name: "Default", Slug: "default"},
		Apps:        []App{{ID: "app_default_test", Name: "Default", Slug: "default", Protocol: "oidc"}},
	})
	r.NoError(err)
}

func TestMergeAppImportStateAndPurgeCleansRemovedResources(t *testing.T) {
	r := require.New(t)
	state := AppState{
		Apps:  []App{{ID: "app-1", Name: "Greendale", Slug: "greendale", Protocol: "scim", SCIMEnabled: true}},
		Users: []User{{ID: "troy", GivenName: "Troy", Email: "troy@greendale.edu", Username: "troy", Active: true}},
		UserSync: map[string]map[string]ResourceSyncState{
			"app-1": {"troy": {RemoteID: "r-troy"}},
		},
	}
	imported := AppState{
		Users: []User{{ID: "abed", GivenName: "Abed", Email: "abed@greendale.edu", Username: "abed", Active: true, RemoteID: "r-abed"}},
	}

	MergeAppImportState(&state, "app-1", imported)
	PurgeFullySyncedDeletions(&state)

	r.Len(state.Users, 1)
	r.Equal("abed", state.Users[0].ID)
}

func TestDeletingUserMarksMemberGroupsDirty(t *testing.T) {
	r := require.New(t)
	state := AppState{
		Apps:   []App{{ID: "app-1", Name: "Greendale", Slug: "greendale", Protocol: "scim", SCIMEnabled: true}},
		Users:  []User{{ID: "troy", GivenName: "Troy", Email: "troy@greendale.edu", Username: "troy", Active: true}},
		Groups: []Group{{ID: "study", DisplayName: "Study Group", MemberIDs: []string{"troy"}}},
		UserSync: map[string]map[string]ResourceSyncState{
			"app-1": {"troy": {RemoteID: "r-troy"}},
		},
		GroupSync: map[string]map[string]ResourceSyncState{
			"app-1": {"study": {RemoteID: "r-study"}},
		},
	}

	state.Users[0].Deleted = true
	MarkUserDirty(&state, "troy", true)

	r.True(state.GroupSync["app-1"]["study"].Dirty, "group containing deleted user must be marked dirty")
}

func TestAppendOperationLogsSkipsEmptyResourceID(t *testing.T) {
	r := require.New(t)
	state := AppState{}
	AppendOperationLogs(&state, "app-1", []SyncTraceEntry{
		{ResourceType: "user", ResourceID: "", ResponseBody: "huge-collection-listing"},
		{ResourceType: "user", ResourceID: "troy", Operation: "create"},
	})
	r.NotContains(state.UserOperations, "")
	r.Contains(state.UserOperations, "troy")
}

func TestSaveGlobalConfigDoesNotOverwriteExistingTunnelInstanceID(t *testing.T) {
	t.Setenv("SCIMTEST_STATE_FILE", filepath.Join(t.TempDir(), "state.db"))
	r := require.New(t)

	_, err := LoadState()
	r.NoError(err)
	rotatedID, _, err := RotateTunnelInstanceIdentity()
	r.NoError(err)

	r.NoError(SaveGlobalConfig(Config{
		IDPBaseURL:       "https://idp.greendale.edu",
		TunnelInstanceID: "stale-id",
	}))
	state, err := LoadState()
	r.NoError(err)
	r.Equal(rotatedID, state.Config.TunnelInstanceID)
}

func TestRetryAfterHugeValuesDoNotOverflow(t *testing.T) {
	r := require.New(t)
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)

	delay, ok := retryAfterDelay("10000000000", now)
	r.True(ok)
	r.Greater(delay, time.Duration(0))
	r.NotEqual("now", ParseRetryAfter("10000000000", now))

	r.NotEqual("1 second", humanRetryAfter(time.Duration(math.MaxInt64)))
}

func TestValidateHTTPBaseURLRejectsForceQueryAndBareFragment(t *testing.T) {
	tests := map[string]string{
		"trailing question mark": "https://scim.greendale.edu/v2?",
		"bare hash":              "https://scim.greendale.edu/v2#",
		"empty hostname":         "https://:8080/v2",
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			r.Error(ValidateHTTPBaseURL("SCIM base URL", raw, true))
		})
	}
}

func TestValidateRestoredStateAllowsDeletedOrPurgedManagerAndRejectsSelfManager(t *testing.T) {
	r := require.New(t)
	validWithMissingManager := AppState{
		Users: []User{
			{ID: "dean", GivenName: "Craig", FamilyName: "Pelton", Email: "dean@greendale.edu", Username: "dean", Deleted: true},
			{ID: "troy", GivenName: "Troy", FamilyName: "Barnes", Email: "troy@greendale.edu", Username: "troy", Active: true, ManagerID: "dean"},
			{ID: "abed", GivenName: "Abed", FamilyName: "Nadir", Email: "abed@greendale.edu", Username: "abed", Active: true, ManagerID: "purged-manager"},
		},
	}
	r.NoError(ValidateRestoredState(&validWithMissingManager, nil))

	selfManaged := AppState{
		Users: []User{
			{ID: "jeff", GivenName: "Jeff", FamilyName: "Winger", Email: "jeff@greendale.edu", Username: "jeff", Active: true, ManagerID: "jeff"},
		},
	}
	r.ErrorContains(ValidateRestoredState(&selfManaged, nil), "cannot manage themselves")
}

func TestSCIMClientAppendTraceTracksBytesAcrossRingEviction(t *testing.T) {
	r := require.New(t)
	client := &SCIMClient{}
	small := strings.Repeat("a", 64)
	for range maxSCIMTraceEntries {
		client.appendTrace(SyncTraceEntry{ResponseBody: small})
	}
	r.Len(client.traces, maxSCIMTraceEntries)
	r.Equal(maxSCIMTraceEntries*len(small), client.traceBytes)

	large := strings.Repeat("b", 128<<10)
	for range 200 {
		client.appendTrace(SyncTraceEntry{ResponseBody: large})
	}
	r.Len(client.traces, maxSCIMTraceEntries)
	r.LessOrEqual(client.traceBytes, 16<<20)
	var actual int
	for _, tr := range client.traces {
		actual += len(tr.ResponseBody)
	}
	r.Equal(actual, client.traceBytes)
}
