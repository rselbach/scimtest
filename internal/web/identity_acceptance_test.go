package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSharedIdentityAcceptance(t *testing.T) {
	implementations := map[string]func(*testing.T) http.Handler{"Go": liveAcceptanceAPI}
	if binary := os.Getenv("SCIMTEST_ACCEPTANCE_RUST_BIN"); binary != "" {
		implementations["Rust"] = func(t *testing.T) http.Handler {
			return rustAcceptanceAPI(t, binary)
		}
	}
	for implementation, start := range implementations {
		t.Run(implementation, func(t *testing.T) {
			for name, tc := range map[string]func(*testing.T, http.Handler){
				"OIDC browser chooser":    acceptanceOIDCBrowserChooser,
				"SAML browser chooser":    acceptanceSAMLBrowserChooser,
				"SAML single logout":      acceptanceSharedSAMLLogout,
				"OIDC playground":         acceptancePlayground,
				"browser OIDC playground": acceptanceBrowserPlayground,
				"resilience and faults":   acceptanceResilienceAndFaults,
				"lifecycle SCIM":          acceptanceLifecycleSCIM,
			} {
				t.Run(name, func(t *testing.T) { tc(t, start(t)) })
			}
		})
	}
}

func liveAcceptanceAPI(t *testing.T) http.Handler {
	t.Helper()
	r := require.New(t)
	service, handler := newAcceptanceAPI(t)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	base, err := url.Parse(server.URL)
	r.NoError(err)
	service.adminHost, service.adminURL = base.Host, server.URL
	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return acceptanceHTTPHandler(t, client, base, service.instanceToken)
}

type sharedIdentity struct {
	handler     http.Handler
	environment app
	base        string
	troy        user
	abed        user
}

func newSharedIdentity(t *testing.T, handler http.Handler) sharedIdentity {
	t.Helper()
	fixture := sharedIdentity{handler: handler}
	fixture.environment = acceptanceEnvironment(t, handler, `{"name":"Greendale Portal","slug":"greendale","oidc_enabled":true,"oidc_client_id":"greendale-client","oidc_client_secret":"study-group-secret","oidc_redirect_uris":["http://greendale.test/callback"],"saml_enabled":true,"saml_entity_id":"greendale-sp","saml_acs_url":"http://greendale.test/saml","include_groups_claim":true}`)
	fixture.base = "/api/v1/environments/" + fixture.environment.ID
	fixture.troy = personaUser(t, handler, fixture.base, "Troy", "Barnes", "tbarnes", "troy.barnes@greendale.edu")
	fixture.abed = personaUser(t, handler, fixture.base, "Abed", "Nadir", "anadir", "abed.nadir@greendale.edu")
	return fixture
}

func (f sharedIdentity) authorizeValues() url.Values {
	return url.Values{
		"response_type": {"code"}, "client_id": {"greendale-client"},
		"redirect_uri": {"http://greendale.test/callback"},
		"scope":        {"openid profile email groups"}, "state": {"study&group"},
	}
}

func (f sharedIdentity) browser(method, path string, values url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	var body string
	if method == http.MethodGet {
		if len(values) > 0 {
			path += "?" + values.Encode()
		}
	} else {
		body = values.Encode()
	}
	req := httptest.NewRequest(method, "http://127.0.0.1:8080"+path, strings.NewReader(body))
	if method != http.MethodGet {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

func (f sharedIdentity) authorize(t *testing.T, values url.Values, cookies ...*http.Cookie) (*http.Cookie, map[string]any) {
	t.Helper()
	r := require.New(t)
	result := f.browser(http.MethodPost, "/oidc/greendale/authorize", values, cookies...)
	r.Equal(http.StatusFound, result.Code, result.Body.String())
	location, err := url.Parse(result.Header().Get("Location"))
	r.NoError(err)
	r.Equal("study&group", location.Query().Get("state"))
	r.NotEmpty(location.Query().Get("code"))
	response := f.exchange(location.Query().Get("code"), "study-group-secret")
	r.Equal(http.StatusOK, response.Code, response.Body.String())
	var tokens map[string]any
	r.NoError(json.Unmarshal(response.Body.Bytes(), &tokens))
	return sessionCookie(t, result), tokens
}

func (f sharedIdentity) exchange(code, secret string) *httptest.ResponseRecorder {
	return f.browser(http.MethodPost, "/oidc/greendale/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"client_id": {"greendale-client"}, "client_secret": {secret},
		"redirect_uri": {"http://greendale.test/callback"},
	})
}

func (f sharedIdentity) decode(t *testing.T, method, path, body string, status int, destination any) {
	t.Helper()
	response := acceptanceRequest(t, f.handler, method, f.base+path, body, status)
	require.New(t).NoError(json.Unmarshal(response.Body.Bytes(), destination))
}

func (f sharedIdentity) startRun(t *testing.T, kind string, input any) lifecycleRun {
	t.Helper()
	body, err := json.Marshal(input)
	require.New(t).NoError(err)
	var run lifecycleRun
	f.decode(t, http.MethodPost, "/lifecycle/"+kind, string(body), http.StatusAccepted, &run)
	return run
}

func (f sharedIdentity) waitRun(t *testing.T, id string) lifecycleRun {
	t.Helper()
	r := require.New(t)
	var run lifecycleRun
	r.Eventually(func() bool {
		f.decode(t, http.MethodGet, "/lifecycle/"+id, "", http.StatusOK, &run)
		return run.Status != lifecycleRunning
	}, 10*time.Second, 20*time.Millisecond, "run %s did not finish background work", id)
	return run
}

func sharedJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	require.New(t).NoError(err)
	return string(encoded)
}
