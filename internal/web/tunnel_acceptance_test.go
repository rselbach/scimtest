package web

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"
)

func TestSharedTunnelAcceptance(t *testing.T) {
	implementations := []string{"Go"}
	if os.Getenv("SCIMTEST_ACCEPTANCE_RUST_TUNNEL_FIXTURE") != "" {
		implementations = append(implementations, "Rust")
	}
	for _, implementation := range implementations {
		t.Run(implementation, func(t *testing.T) {
			for name, tc := range map[string]func(*testing.T, string){
				"enrollment account switching and recovery": acceptanceTunnelAccount,
				"public identity and local boundaries":      acceptanceTunnelPublicIdentity,
				"reconnect and restart stability":           acceptanceTunnelRestart,
			} {
				t.Run(name, func(t *testing.T) { tc(t, implementation) })
			}
		})
	}
}

func acceptanceTunnelAccount(t *testing.T, implementation string) {
	r := require.New(t)
	server := newSharedTunnelServer(t, true)
	server.pollError = http.StatusTooManyRequests
	runtime := startSharedTunnelApp(t, implementation, server, filepath.Join(t.TempDir(), "state.db"))
	account := runtime.waitAccount(t, "authorizing")
	r.False(account["linked"].(bool))
	r.Equal("GREEN-DALE", account["enrollment_code"])
	enrollment, err := url.Parse(account["enrollment_url"].(string))
	r.NoError(err)
	r.Equal("/enroll/browser", enrollment.Path)
	r.Equal("desktop", enrollment.Query().Get("presentation"))
	r.Equal("one-use", enrollment.Query().Get("handoff"))
	acceptanceRequest(t, runtime.handler, http.MethodGet, "/api/v1/environments", "", http.StatusUnauthorized)
	status := acceptanceRequest(t, runtime.handler, http.MethodGet, "/api/v1/status", "", http.StatusOK)
	r.Contains(status.Body.String(), `"locked":true`)
	r.NotContains(status.Body.String(), sharedTunnelDeviceSecret)
	started := acceptanceRequest(t, runtime.handler, http.MethodPost, "/api/v1/account/start", `{}`, http.StatusOK)
	r.NotContains(started.Body.String(), sharedTunnelDeviceSecret)
	server.approve("troy-barnes")
	account = runtime.waitAccount(t, "connected")
	r.True(account["linked"].(bool))
	r.Equal("troy-barnes", account["login"])
	server.mu.Lock()
	polls := server.polls
	server.mu.Unlock()
	r.GreaterOrEqual(polls, 2, "enrollment must recover from a transient 429")
	environment := acceptanceEnvironment(t, runtime.handler, `{"name":"Greendale Portal","slug":"greendale"}`)
	registrations := server.registrations()
	first := registrations[len(registrations)-1]
	r.Equal(sharedTunnelDeviceSecret, first.grant)
	server.mu.Lock()
	server.approved = false
	server.mu.Unlock()
	acceptanceRequest(t, runtime.handler, http.MethodPost, "/api/v1/account/logout", `{}`, http.StatusOK)
	account = runtime.waitAccount(t, "authorizing")
	r.False(account["linked"].(bool))
	registrations = server.registrations()
	second := registrations[len(registrations)-1]
	r.NotEqual(first.publicKey, second.publicKey, "logout must rotate the installation key")
	r.NotEqual(first.instanceID, second.instanceID, "logout must rotate the legacy installation ID")
	acceptanceRequest(t, runtime.handler, http.MethodGet, "/api/v1/environments", "", http.StatusUnauthorized)
	server.approve("abed-nadir")
	account = runtime.waitAccount(t, "connected")
	r.Equal("abed-nadir", account["login"])
	acceptanceRequest(t, runtime.handler, http.MethodGet, "/api/v1/environments/"+environment.ID, "", http.StatusOK)
	server.disconnect(websocket.ClosePolicyViolation, "installation revoked")
	account = runtime.waitAccount(t, "failed")
	r.False(account["linked"].(bool))
	r.Contains(account["error"], "revoked this installation")
	acceptanceRequest(t, runtime.handler, http.MethodGet, "/api/v1/environments", "", http.StatusUnauthorized)
	tunnel := acceptanceRequest(t, runtime.handler, http.MethodGet, "/api/v1/tunnel", "", http.StatusOK)
	var snapshot map[string]any
	r.NoError(json.Unmarshal(tunnel.Body.Bytes(), &snapshot))
	r.False(snapshot["connected"].(bool))
	r.True(snapshot["retry_available"].(bool))
	r.NotContains(snapshot, "public_url")
	acceptanceRequest(t, runtime.handler, http.MethodPost, "/api/v1/account/retry", `{}`, http.StatusOK)
	account = runtime.waitAccount(t, "connected")
	r.Equal("abed-nadir", account["login"])
	registrations = server.registrations()
	r.Equal(second.publicKey, registrations[len(registrations)-1].publicKey, "retry must retain the installation key")
}

func acceptanceTunnelPublicIdentity(t *testing.T, implementation string) {
	r := require.New(t)
	server := newSharedTunnelServer(t, false)
	runtime := startSharedTunnelApp(t, implementation, server, filepath.Join(t.TempDir(), "state.db"))
	runtime.waitAccount(t, "connected")
	f := newSharedIdentity(t, runtime.handler)
	acceptanceRequest(t, runtime.handler, http.MethodPatch, f.base, `{"allow_any_oidc_redirect":true,"oidc_jwt_access_tokens":true,"oidc_access_token_audience":"https://api.greendale.edu"}`, http.StatusOK)
	public := "https://scimtest.example/greendale"
	discovery := server.forward(http.MethodGet, "/greendale/oidc/greendale/.well-known/openid-configuration", "198.51.100.8", nil)
	r.Equal(http.StatusOK, discovery.Code, discovery.Body.String())
	var configuration map[string]any
	r.NoError(json.Unmarshal(discovery.Body.Bytes(), &configuration))
	r.Equal(public+"/oidc/greendale", configuration["issuer"])
	r.Equal(public+"/oidc/greendale/token", configuration["token_endpoint"])
	metadata := server.forward(http.MethodGet, "/greendale/saml/greendale/metadata", "198.51.100.8", nil)
	r.Equal(http.StatusOK, metadata.Code, metadata.Body.String())
	r.Contains(metadata.Body.String(), public+"/saml/greendale/sso")
	for _, path := range []string{
		"/oidc/greendale/jwks", "/greendale-other/oidc/greendale/jwks",
		"/greendale/api/v1/status", "/greendale/api/v1/environments", "/greendale/-/ready",
		"/greendale/apps/greendale/config.json", "/greendale/inspect/oidc/greendale",
		"/greendale/inspect/oidc/greendale/playground", "/greendale/inspect/oidc/greendale/playground/callback",
	} {
		r.Equal(http.StatusNotFound, server.forward(http.MethodGet, path, "203.0.113.7", nil).Code, path)
	}
	values := f.authorizeValues()
	for _, visitor := range []string{"", "198.51.100.8", "invalid", "198.51.100.8, 203.0.113.7"} {
		r.Equal(http.StatusForbidden, server.forward(http.MethodGet, "/greendale/oidc/greendale/authorize", visitor, values).Code, visitor)
		r.Equal(http.StatusForbidden, server.forward(http.MethodGet, "/greendale/saml/greendale/sso", visitor, nil).Code, visitor)
	}
	for _, visitor := range []string{"203.0.113.7", "::ffff:203.0.113.7", "203.0.113.7, 192.0.2.3"} {
		chooser := server.forward(http.MethodGet, "/greendale/oidc/greendale/authorize", visitor, values)
		r.Equal(http.StatusOK, chooser.Code, chooser.Body.String())
		r.Contains(chooser.Body.String(), "Troy Barnes")
	}
	unregistered := f.authorizeValues()
	unregistered.Set("redirect_uri", "https://citycollege.example/callback")
	r.Equal(http.StatusBadRequest, server.forward(http.MethodGet, "/greendale/oidc/greendale/authorize", "203.0.113.7", unregistered).Code)
	local := f.browser(http.MethodGet, "/oidc/greendale/authorize", unregistered)
	r.Equal(http.StatusOK, local.Code, local.Body.String())
	chooser := server.forward(http.MethodGet, "/greendale/oidc/greendale/authorize", "203.0.113.7", values)
	form := chooserSubmitForm(t, chooser.Body.String(), "Continue")
	form.Set("user_id", f.troy.ID)
	form.Set("authn_strength", "mfa")
	authorized := server.forward(http.MethodPost, "/greendale/oidc/greendale/authorize", "203.0.113.7", form)
	r.Equal(http.StatusFound, authorized.Code, authorized.Body.String())
	redirect, err := url.Parse(authorized.Header().Get("Location"))
	r.NoError(err)
	r.Equal("study&group", redirect.Query().Get("state"))
	r.NotEmpty(redirect.Query().Get("code"))
	token := server.forward(http.MethodPost, "/greendale/oidc/greendale/token", "198.51.100.8", url.Values{
		"grant_type": {"authorization_code"}, "code": {redirect.Query().Get("code")},
		"client_id": {"greendale-client"}, "client_secret": {"study-group-secret"}, "redirect_uri": {"http://greendale.test/callback"},
	})
	r.Equal(http.StatusOK, token.Code, token.Body.String())
	var tokens map[string]any
	r.NoError(json.Unmarshal(token.Body.Bytes(), &tokens))
	claims := decodeIDTokenClaims(t, tokens["id_token"].(string))
	r.Equal(public+"/oidc/greendale", claims["iss"])
	r.Equal(f.troy.ID, claims["sub"])
	r.Equal(mfaContext, claims["acr"])
	userinfo := server.forward(http.MethodGet, "/greendale/oidc/greendale/userinfo", "198.51.100.8", nil, http.Header{"Authorization": {"Bearer " + tokens["access_token"].(string)}})
	r.Equal(http.StatusOK, userinfo.Code, userinfo.Body.String())
	r.Contains(userinfo.Body.String(), "troy.barnes@greendale.edu")
	connection := acceptanceRequest(t, runtime.handler, http.MethodGet, f.base+"/connection", "", http.StatusOK)
	r.Contains(connection.Body.String(), public)
	playground := f.browser(http.MethodGet, "/inspect/oidc/greendale/playground", nil)
	r.Equal(http.StatusFound, playground.Code, playground.Body.String())
	start, err := url.Parse(playground.Header().Get("Location"))
	r.NoError(err)
	r.Equal(runtime.base, start.Scheme+"://"+start.Host)
	r.Equal(runtime.base+"/inspect/oidc/greendale/playground/callback", start.Query().Get("redirect_uri"))
}

func acceptanceTunnelRestart(t *testing.T, implementation string) {
	r := require.New(t)
	server := newSharedTunnelServer(t, false)
	state := filepath.Join(t.TempDir(), "state.db")
	runtime := startSharedTunnelApp(t, implementation, server, state)
	runtime.waitAccount(t, "connected")
	f := newSharedIdentity(t, runtime.handler)
	first := server.registrations()[0]
	server.mu.Lock()
	previous := server.current
	server.mu.Unlock()
	server.disconnect(websocket.CloseServiceRestart, "Greendale maintenance")
	r.Eventually(func() bool {
		server.mu.Lock()
		defer server.mu.Unlock()
		return server.current != previous
	}, 10*time.Second, 10*time.Millisecond)
	runtime.waitAccount(t, "connected")
	registrations := server.registrations()
	r.GreaterOrEqual(len(registrations), 2)
	r.Equal(first.publicKey, registrations[len(registrations)-1].publicKey)
	r.Equal(first.instanceID, registrations[len(registrations)-1].instanceID)
	reconnected := server.forward(http.MethodGet, "/greendale/oidc/greendale/.well-known/openid-configuration", "198.51.100.8", nil)
	r.Equal(http.StatusOK, reconnected.Code, reconnected.Body.String())
	runtime.stop()
	restarted := startSharedTunnelApp(t, implementation, server, state)
	account := restarted.waitAccount(t, "connected")
	r.Equal("troy-barnes", account["login"])
	registrations = server.registrations()
	r.GreaterOrEqual(len(registrations), 3)
	r.Equal(first.publicKey, registrations[len(registrations)-1].publicKey)
	r.Equal(first.instanceID, registrations[len(registrations)-1].instanceID)
	acceptanceRequest(t, restarted.handler, http.MethodGet, f.base, "", http.StatusOK)
	discovery := server.forward(http.MethodGet, "/greendale/oidc/greendale/.well-known/openid-configuration", "198.51.100.8", nil)
	r.Equal(http.StatusOK, discovery.Code, discovery.Body.String())
	r.Contains(discovery.Body.String(), `"issuer":"https://scimtest.example/greendale/oidc/greendale"`)
}
