package web

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	rgrokclient "github.com/rselbach/rgrok/client"
	"github.com/stretchr/testify/require"
)

func TestIndexRendersDashboard(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)

	state := appState{
		Config: config{BaseURL: "https://example.com/scim"},
		Users: []user{{
			ID:         "u1",
			GivenName:  "Troy",
			FamilyName: "Barnes",
			Username:   "tbarnes",
			Email:      "troy@example.com",
			Active:     true,
		}},
		Groups: []group{{
			ID:          "g1",
			DisplayName: "Greendale Study Group",
			MemberIDs:   []string{"u1"},
		}},
		UserOperations:  map[string][]operationLog{},
		GroupOperations: map[string][]operationLog{},
	}
	r.NoError(saveState(state))

	app := &webApp{}

	userReq := httptest.NewRequest(http.MethodGet, "/?tab=users", nil)
	userRec := httptest.NewRecorder()
	app.routes().ServeHTTP(userRec, userReq)
	r.Equal(http.StatusOK, userRec.Code)
	userBody := userRec.Body.String()
	r.Contains(userBody, "tbarnes")
	r.Contains(userBody, "https://example.com/scim")
	r.Contains(userBody, "SCIM Control Surface")

	groupReq := httptest.NewRequest(http.MethodGet, "/?tab=groups", nil)
	groupRec := httptest.NewRecorder()
	app.routes().ServeHTTP(groupRec, groupReq)
	r.Equal(http.StatusOK, groupRec.Code)
	r.Contains(groupRec.Body.String(), "Greendale Study Group")
}

func TestToggleActiveUpdatesStateAndHistory(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)

	state := appState{
		Users: []user{{
			ID:         "u1",
			GivenName:  "Annie",
			FamilyName: "Edison",
			Username:   "aedison",
			Email:      "annie@example.com",
			Active:     true,
		}},
		UserOperations:  map[string][]operationLog{},
		GroupOperations: map[string][]operationLog{},
	}
	r.NoError(saveState(state))

	app := &webApp{}
	form := url.Values{"tab": {"users"}}
	req := httptest.NewRequest(http.MethodPost, "/users/u1/toggle-active", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	r.Equal(http.StatusSeeOther, rec.Code)
	updated, err := loadState()
	r.NoError(err)
	r.Len(updated.Users, 1)
	r.False(updated.Users[0].Active)
	r.True(updated.Users[0].Dirty)
	r.Equal("", updated.Users[0].LastError)
	r.Equal("Deactivated", updated.UserOperations["u1"][0].Summary)
}

func TestSyncPersistsRemoteStateAndTraceCookie(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.Equal(http.MethodPost, req.Method)
		r.Equal("/Users", req.URL.Path)
		w.Header().Set("Content-Type", "application/scim+json")
		_, err := fmt.Fprint(w, `{"id":"remote-user-1"}`)
		r.NoError(err)
	}))
	defer server.Close()

	state := appState{
		Config: config{
			BaseURL:           server.URL,
			BearerToken:       "token",
			AutoOpenSyncTrace: true,
		},
		Users: []user{{
			ID:         "u1",
			GivenName:  "Shirley",
			FamilyName: "Bennett",
			Username:   "sbennett",
			Email:      "shirley@example.com",
			Active:     true,
			Dirty:      true,
		}},
		UserOperations:  map[string][]operationLog{},
		GroupOperations: map[string][]operationLog{},
	}
	r.NoError(saveState(state))

	app := &webApp{}
	form := url.Values{"tab": {"users"}}
	req := httptest.NewRequest(http.MethodPost, "/sync", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	r.Equal(http.StatusSeeOther, rec.Code)
	updated, err := loadState()
	r.NoError(err)
	r.Equal("remote-user-1", updated.Users[0].RemoteID)
	r.False(updated.Users[0].Dirty)
	r.NotEmpty(updated.UserOperations["u1"])
	r.Contains(rec.Header().Get("Set-Cookie"), "scimtest_trace=")
	r.Contains(app.traceContent(), "POST /Users")
}

func TestSyncRateLimitRendersReadableError(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.Equal(http.MethodPut, req.Method)
		r.Equal("/Users/remote-dean", req.URL.Path)
		w.Header().Set("Content-Type", "application/scim+json")
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
		_, err := fmt.Fprint(w, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"detail":"Too many requests. Please retry after the rate limit resets.","status":"429"}`)
		r.NoError(err)
	}))
	defer server.Close()

	state := appState{
		Config: config{
			BaseURL:     server.URL,
			BearerToken: "token",
		},
		Users: []user{{
			ID:         "u1",
			GivenName:  "Dean",
			FamilyName: "Pelton",
			Username:   "deanp",
			Email:      "dean@example.com",
			Active:     true,
			RemoteID:   "remote-dean",
			Dirty:      true,
		}},
		UserOperations:  map[string][]operationLog{},
		GroupOperations: map[string][]operationLog{},
	}
	r.NoError(saveState(state))

	app := &webApp{}
	form := url.Values{"tab": {"users"}}
	syncReq := httptest.NewRequest(http.MethodPost, "/sync", strings.NewReader(form.Encode()))
	syncReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	syncRec := httptest.NewRecorder()

	app.routes().ServeHTTP(syncRec, syncReq)

	r.Equal(http.StatusSeeOther, syncRec.Code)
	updated, err := loadState()
	r.NoError(err)
	r.Contains(updated.Users[0].LastError, "Try again in 1 minute")
	r.NotContains(updated.Users[0].LastError, "schemas")
	r.Equal("60", updated.UserOperations["u1"][0].ResponseRetryAfter)
	r.Contains(app.traceContent(), "Retry-After: 60")

	indexReq := httptest.NewRequest(http.MethodGet, "/?tab=users", nil)
	indexRec := httptest.NewRecorder()
	app.routes().ServeHTTP(indexRec, indexReq)

	r.Equal(http.StatusOK, indexRec.Code)
	body := indexRec.Body.String()
	r.Contains(body, "user Dean Pelton: SCIM server rate limit hit (429 Too Many Requests). Try again in 1 minute.")
	r.NotContains(body, "schemas")

	historyReq := httptest.NewRequest(http.MethodGet, "/?tab=users&historyType=user&historyID=u1", nil)
	historyRec := httptest.NewRecorder()
	app.routes().ServeHTTP(historyRec, historyReq)

	r.Equal(http.StatusOK, historyRec.Code)
	r.Contains(historyRec.Body.String(), "Retry-After: 60")
}

func TestIndexRendersLegacyRateLimitErrorReadable(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)

	state := appState{
		Config: config{BaseURL: "https://example.com/scim"},
		Users: []user{{
			ID:         "u1",
			GivenName:  "Dean",
			FamilyName: "Pelton",
			Username:   "deanp",
			Email:      "dean@example.com",
			Active:     true,
			RemoteID:   "remote-dean",
			Dirty:      true,
			LastError:  `SCIM PUT /Users/remote-dean returned 429 Too Many Requests; rate limited; retry after 1m0s: {"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"detail":"Too many requests.","status":"429"}`,
		}},
		UserOperations:  map[string][]operationLog{},
		GroupOperations: map[string][]operationLog{},
	}
	r.NoError(saveState(state))

	app := &webApp{}
	req := httptest.NewRequest(http.MethodGet, "/?tab=users", nil)
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	r.Equal(http.StatusOK, rec.Code)
	body := rec.Body.String()
	r.Contains(body, "user Dean Pelton: SCIM server rate limit hit (429 Too Many Requests). Try again in 1 minute.")
	r.NotContains(body, "schemas")
	r.NotContains(body, "1m0s")
}

func TestSCIMDisabledHidesSyncControlsAndColumns(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)

	state := appState{
		Config: config{
			BaseURL:      "https://example.com/scim",
			SCIMDisabled: true,
		},
		Users: []user{{
			ID:         "u1",
			GivenName:  "Troy",
			FamilyName: "Barnes",
			Username:   "tbarnes",
			Email:      "troy@example.com",
			Active:     true,
			RemoteID:   "remote-u1",
			Dirty:      true,
			LastError:  "sync failed",
		}},
		Groups: []group{{
			ID:          "g1",
			DisplayName: "Greendale Study Group",
			MemberIDs:   []string{"u1"},
			RemoteID:    "remote-g1",
			Dirty:       true,
		}},
		UserOperations:  map[string][]operationLog{},
		GroupOperations: map[string][]operationLog{},
	}
	r.NoError(saveState(state))

	app := &webApp{}
	userReq := httptest.NewRequest(http.MethodGet, "/?tab=users", nil)
	userRec := httptest.NewRecorder()
	app.routes().ServeHTTP(userRec, userReq)

	r.Equal(http.StatusOK, userRec.Code)
	userBody := userRec.Body.String()
	r.Contains(userBody, "SCIM")
	r.Contains(userBody, "disabled")
	r.NotContains(userBody, ">Sync<")
	r.NotContains(userBody, ">Import<")
	r.NotContains(userBody, ">Reset<")
	r.NotContains(userBody, "<th>Status</th>")
	r.NotContains(userBody, "<th>Remote ID</th>")
	r.NotContains(userBody, "remote-u1")
	r.NotContains(userBody, "sync failed")

	groupReq := httptest.NewRequest(http.MethodGet, "/?tab=groups", nil)
	groupRec := httptest.NewRecorder()
	app.routes().ServeHTTP(groupRec, groupReq)

	r.Equal(http.StatusOK, groupRec.Code)
	groupBody := groupRec.Body.String()
	r.Contains(groupBody, "Greendale Study Group")
	r.NotContains(groupBody, "<th>Status</th>")
	r.NotContains(groupBody, "<th>Remote ID</th>")
	r.NotContains(groupBody, "remote-g1")
}

func TestSCIMDisabledRejectsSync(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)

	state := appState{
		Config:          config{SCIMDisabled: true},
		UserOperations:  map[string][]operationLog{},
		GroupOperations: map[string][]operationLog{},
	}
	r.NoError(saveState(state))

	app := &webApp{}
	form := url.Values{"tab": {"users"}}
	req := httptest.NewRequest(http.MethodPost, "/sync", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	r.Equal(http.StatusSeeOther, rec.Code)
	r.Contains(rec.Header().Get("Set-Cookie"), "SCIM+is+disabled")
}

func TestConfigRendersRgrokSetupLink(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{}))

	app := &webApp{}
	req := httptest.NewRequest(http.MethodGet, "/?tab=users&modal=config", nil)
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	r.Equal(http.StatusOK, rec.Code)
	body := rec.Body.String()
	r.Contains(body, "Set up rgrok tunnel")
	r.Contains(body, "/?modal=config&amp;rgrok=1&amp;tab=users")
	r.Contains(body, `name="idp_base_url"`)
	r.NotContains(body, `name="idp_base_url" value="" placeholder="http://example.com" autocomplete="off" disabled`)
}

func TestConfigRendersEstablishedRgrokTunnel(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{}))

	app := &webApp{
		rgrokTunnel: &activeRgrokTunnel{
			Name:      "demo",
			PublicURL: "https://demo.rgrok.rselbach.com",
			Tunnel:    &fakeTunnel{},
		},
	}
	req := httptest.NewRequest(http.MethodGet, "/?tab=users&modal=config", nil)
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	r.Equal(http.StatusOK, rec.Code)
	body := rec.Body.String()
	r.Contains(body, "Tunnel established.")
	r.Contains(body, `form="rgrok-cancel-form">Cancel</button>`)
	r.Contains(body, `value="https://demo.rgrok.rselbach.com"`)
	r.Contains(body, `autocomplete="off" disabled`)
	r.NotContains(body, "Set up rgrok tunnel")
}

func TestRgrokSetupStartsTunnel(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{}))

	var got rgrokclient.Config
	var gotCtx context.Context
	tunnel := &fakeTunnel{}
	app := &webApp{
		localPort: 8080,
		rgrokStart: func(ctx context.Context, cfg rgrokclient.Config) (*startedRgrokTunnel, error) {
			gotCtx = ctx
			got = cfg
			return &startedRgrokTunnel{
				PublicURL: "https://demo.rgrok.rselbach.com",
				Tunnel:    tunnel,
			}, nil
		},
	}
	form := url.Values{
		"tab":         {"apps"},
		"rgrok_name":  {"Demo"},
		"rgrok_token": {"token-123"},
	}
	req := httptest.NewRequest(http.MethodPost, "/rgrok/setup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	r.Equal(http.StatusSeeOther, rec.Code)
	r.Contains(rec.Header().Get("Location"), "modal=config")
	r.Equal("https://rgrok.rselbach.com", got.ServerBaseURL)
	r.Equal("token-123", got.Token)
	r.Equal("demo", got.Name)
	r.Equal(8080, got.LocalPort)
	r.Equal("https://demo.rgrok.rselbach.com", app.rgrokPublicURL())
	r.False(tunnel.closed)
	r.NoError(gotCtx.Err())

	state, err := loadState()
	r.NoError(err)
	r.Equal("demo", state.Config.RgrokName)
	r.Equal("token-123", state.Config.RgrokToken)
	r.Equal("https://demo.rgrok.rselbach.com", state.Config.IDPBaseURL)
}

func TestRgrokSetupRedirectsBackToDialogOnError(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)

	app := &webApp{localPort: 8080}
	form := url.Values{
		"tab":         {"users"},
		"rgrok_name":  {"bad_name"},
		"rgrok_token": {"token-123"},
	}
	req := httptest.NewRequest(http.MethodPost, "/rgrok/setup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	r.Equal(http.StatusSeeOther, rec.Code)
	location := rec.Header().Get("Location")
	r.Contains(location, "modal=config")
	r.Contains(location, "rgrok=1")
	r.Contains(location, "rgrok_error=")
	r.Empty(app.rgrokPublicURL())
}

func TestRgrokCancelClosesTunnel(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{
		Config: config{
			IDPBaseURL: "https://demo.rgrok.rselbach.com",
			RgrokName:  "demo",
			RgrokToken: "token-123",
		},
	}))

	tunnel := &fakeTunnel{}
	app := &webApp{
		rgrokTunnel: &activeRgrokTunnel{
			Name:      "demo",
			PublicURL: "https://demo.rgrok.rselbach.com",
			Tunnel:    tunnel,
		},
	}
	form := url.Values{"tab": {"users"}}
	req := httptest.NewRequest(http.MethodPost, "/rgrok/cancel", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	r.Equal(http.StatusSeeOther, rec.Code)
	r.True(tunnel.closed)
	r.Empty(app.rgrokPublicURL())

	state, err := loadState()
	r.NoError(err)
	r.Empty(state.Config.RgrokName)
	r.Empty(state.Config.RgrokToken)
	r.Empty(state.Config.IDPBaseURL)
}

func TestRestoreSavedRgrokTunnel(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{
		Config: config{
			RgrokName:  "demo",
			RgrokToken: "token-123",
		},
	}))

	var got rgrokclient.Config
	tunnel := &fakeTunnel{}
	app := &webApp{
		localPort: 8080,
		rgrokStart: func(ctx context.Context, cfg rgrokclient.Config) (*startedRgrokTunnel, error) {
			got = cfg
			return &startedRgrokTunnel{
				PublicURL: "https://demo.rgrok.rselbach.com",
				Tunnel:    tunnel,
			}, nil
		},
	}

	app.restoreSavedRgrokTunnel()

	r.Equal("https://rgrok.rselbach.com", got.ServerBaseURL)
	r.Equal("token-123", got.Token)
	r.Equal("demo", got.Name)
	r.Equal(8080, got.LocalPort)
	r.Equal("https://demo.rgrok.rselbach.com", app.rgrokPublicURL())
	r.False(tunnel.closed)

	state, err := loadState()
	r.NoError(err)
	r.Equal("demo", state.Config.RgrokName)
	r.Equal("token-123", state.Config.RgrokToken)
	r.Equal("https://demo.rgrok.rselbach.com", state.Config.IDPBaseURL)
}

type fakeTunnel struct {
	closed bool
}

func (f *fakeTunnel) Close() error {
	f.closed = true
	return nil
}

func setTestStateFile(t *testing.T) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.db")
	t.Setenv("SCIMTEST_STATE_FILE", path)
	r := require.New(t)
	r.NoError(os.RemoveAll(path))
}
