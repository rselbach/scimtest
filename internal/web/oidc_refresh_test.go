package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOfflineAccessIssuesRefreshToken(t *testing.T) {
	tests := map[string]struct {
		scope       string
		wantRefresh bool
	}{
		"offline_access":    {scope: "openid email offline_access", wantRefresh: true},
		"no offline_access": {scope: "openid email"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			svc := oidcFaultTestApp(t)
			body := tokenBody(t, redeemToken(t, svc, authorizeForCode(t, svc, url.Values{"scope": {tc.scope}})))
			_, hasRefresh := body["refresh_token"]
			require.Equal(t, tc.wantRefresh, hasRefresh)
		})
	}
}

func TestRefreshTokenRotatesAndReissuesIDToken(t *testing.T) {
	r := require.New(t)
	svc := oidcFaultTestApp(t)
	first := tokenBody(t, redeemToken(t, svc, authorizeForCode(t, svc, url.Values{"scope": {"openid email offline_access"}, "nonce": {"n-1"}})))
	original := decodeIDTokenClaims(t, first["id_token"].(string))

	refreshed := refreshTokens(t, svc, first["refresh_token"].(string), nil)
	r.Equal(http.StatusOK, refreshed.Code, refreshed.Body.String())
	body := tokenBody(t, refreshed)
	r.NotEqual(first["refresh_token"], body["refresh_token"], "refresh must rotate the token")
	r.NotEqual(first["access_token"], body["access_token"])
	claims := decodeIDTokenClaims(t, body["id_token"].(string))
	for _, claim := range []string{"iss", "sub", "aud", "email"} {
		r.Equal(original[claim], claims[claim], claim)
	}
	r.NotContains(claims, "nonce", "OIDC Core 12.2: a refreshed ID token should not carry a nonce")

	reused := refreshTokens(t, svc, first["refresh_token"].(string), nil)
	r.Equal(http.StatusBadRequest, reused.Code)
	r.Contains(reused.Body.String(), "invalid_grant")

	userinfo := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/oidc/example/userinfo", nil)
	request.Header.Set("Authorization", "Bearer "+body["access_token"].(string))
	svc.routes().ServeHTTP(userinfo, request)
	r.Equal(http.StatusOK, userinfo.Code)
	r.Contains(userinfo.Body.String(), "troy@greendale.edu")
}

func TestRefreshTokenScopeCanOnlyNarrow(t *testing.T) {
	r := require.New(t)
	svc := oidcFaultTestApp(t)
	first := tokenBody(t, redeemToken(t, svc, authorizeForCode(t, svc, url.Values{"scope": {"openid email offline_access"}})))

	widened := refreshTokens(t, svc, first["refresh_token"].(string), url.Values{"scope": {"openid profile"}})
	r.Equal(http.StatusBadRequest, widened.Code)
	r.Contains(widened.Body.String(), "invalid_scope")

	narrowed := tokenBody(t, refreshTokens(t, svc, first["refresh_token"].(string), url.Values{"scope": {"openid"}}))
	r.Equal("openid", narrowed["scope"])
	r.NotContains(decodeIDTokenClaims(t, narrowed["id_token"].(string)), "email")

	restored := tokenBody(t, refreshTokens(t, svc, narrowed["refresh_token"].(string), nil))
	r.Equal("openid email offline_access", restored["scope"], "the rotated token keeps the original grant")
}

func TestRefreshTokenRejectsDeactivatedUser(t *testing.T) {
	r := require.New(t)
	svc := oidcFaultTestApp(t)
	first := tokenBody(t, redeemToken(t, svc, authorizeForCode(t, svc, url.Values{"scope": {"openid offline_access"}})))

	state, err := loadState()
	r.NoError(err)
	state.Users[0].Active = false
	r.NoError(saveState(state))

	rec := refreshTokens(t, svc, first["refresh_token"].(string), nil)
	r.Equal(http.StatusBadRequest, rec.Code)
	r.Contains(rec.Body.String(), "user is inactive or missing")
}

func TestDiscoveryAdvertisesRefreshTokens(t *testing.T) {
	r := require.New(t)
	svc := oidcFaultTestApp(t)
	rec := httptest.NewRecorder()
	svc.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oidc/example/.well-known/openid-configuration", nil))
	r.Equal(http.StatusOK, rec.Code)
	var discovery struct {
		GrantTypes []string `json:"grant_types_supported"`
		Scopes     []string `json:"scopes_supported"`
	}
	r.NoError(json.Unmarshal(rec.Body.Bytes(), &discovery))
	r.Contains(discovery.GrantTypes, "refresh_token")
	r.Contains(discovery.Scopes, "offline_access")
}

func refreshTokens(t *testing.T, svc *webApp, refreshToken string, extra url.Values) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}}
	for key, values := range extra {
		form[key] = values
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/oidc/example/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("example-client", "secret")
	svc.routes().ServeHTTP(rec, req)
	return rec
}

func tokenBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	return body
}
