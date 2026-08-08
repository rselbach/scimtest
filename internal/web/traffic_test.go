package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTrafficRecordingTogglesAtRuntime(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	svc := newTestIDPApp(t)
	r.NoError(saveState(appState{
		Users: []user{{ID: "usr-1", GivenName: "Troy", FamilyName: "Barnes", Email: "troy@greendale.edu", Username: "troy", Active: true}},
		Apps: []app{{
			ID:               "app-1",
			Name:             "Example",
			Slug:             "example",
			Protocol:         "oidc",
			OIDCClientID:     "example-client",
			OIDCClientSecret: "secret",
			OIDCRedirectURIs: []string{"http://client.test/callback"},
		}},
	}))

	// Recording is off until enabled on this hand-built app; a discovery
	// call records nothing.
	discovery := func() {
		rec := httptest.NewRecorder()
		svc.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oidc/example/.well-known/openid-configuration", nil))
		r.Equal(http.StatusOK, rec.Code)
	}
	discovery()
	r.Empty(svc.traffic.snapshot())

	// Turn recording on through the settings endpoint; stdout debug
	// output stays off.
	settingsRec := httptest.NewRecorder()
	settingsReq := httptest.NewRequest(http.MethodPost, "/traffic/settings", strings.NewReader(url.Values{"record": {"on"}}.Encode()))
	settingsReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	svc.routes().ServeHTTP(settingsRec, settingsReq)
	r.Equal(http.StatusSeeOther, settingsRec.Code)
	r.True(svc.trafficRecordEnabled())
	r.False(svc.debugRPEnabled())

	discovery()
	entries := svc.traffic.snapshot()
	r.Len(entries, 1)
	r.Contains(entries[0], "RP interaction")

	// The Traffic page renders the captured transcript.
	pageRec := httptest.NewRecorder()
	svc.routes().ServeHTTP(pageRec, httptest.NewRequest(http.MethodGet, "/traffic", nil))
	r.Equal(http.StatusOK, pageRec.Code)
	body := pageRec.Body.String()
	r.Contains(body, "openid-configuration")
	r.Contains(body, `class="app"`)
	r.Contains(body, `class="side-item active" href="/traffic" aria-current="page"`)
	r.Contains(body, "SCIM Control Surface")
	r.Contains(body, "Recent exchanges")
}

func TestTrafficSecretsRequireRecording(t *testing.T) {
	r := require.New(t)
	svc := newTestIDPApp(t)
	// Asking for secrets without recording must not enable secret capture.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/traffic/settings", strings.NewReader(url.Values{"record_secrets": {"on"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	svc.routes().ServeHTTP(rec, req)
	r.False(svc.debugSecretsEnabled())
}
