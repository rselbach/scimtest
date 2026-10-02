package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// clientRequest posts form to one of the example environment's client
// endpoints with the given Basic secret, or no client authentication when
// secret is empty.
func clientRequest(t *testing.T, svc *webApp, endpoint string, secret string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/oidc/example/"+endpoint, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if secret != "" {
		req.SetBasicAuth("example-client", secret)
	}
	svc.routes().ServeHTTP(rec, req)
	return rec
}

func introspect(t *testing.T, svc *webApp, token string) map[string]any {
	t.Helper()
	return tokenBody(t, clientRequest(t, svc, "introspect", "secret", url.Values{"token": {token}}))
}

func revoke(t *testing.T, svc *webApp, token string) {
	t.Helper()
	rec := clientRequest(t, svc, "revoke", "secret", url.Values{"token": {token}})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Empty(t, rec.Body.String())
}

func userinfoStatus(t *testing.T, svc *webApp, access string) int {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/oidc/example/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	svc.routes().ServeHTTP(rec, req)
	return rec.Code
}

func TestClientCredentialsIssuesAccessTokenOnly(t *testing.T) {
	tests := map[string]struct {
		jwt bool
	}{
		"opaque": {},
		"JWT":    {jwt: true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			svc := oidcFaultTestApp(t)
			if tc.jwt {
				svc = jwtAccessTokenTestApp(t, "https://api.greendale.edu")
			}
			body := tokenBody(t, clientRequest(t, svc, "token", "secret", url.Values{"grant_type": {"client_credentials"}, "scope": {"courses.read"}}))
			r.Equal("Bearer", body["token_type"])
			r.Equal(float64(3600), body["expires_in"])
			r.Equal("courses.read", body["scope"])
			r.NotContains(body, "id_token")
			r.NotContains(body, "refresh_token")
			access := body["access_token"].(string)
			r.Equal(http.StatusUnauthorized, userinfoStatus(t, svc, access), "a client token has no user for userinfo")

			if !tc.jwt {
				r.NotContains(access, ".")
				return
			}
			r.NoError(verifyWithJWKS(t, svc, access))
			r.Equal("at+jwt", decodeJWTHeader(t, access)["typ"])
			claims := decodeIDTokenClaims(t, access)
			r.Equal("example-client", claims["sub"], "RFC 9068 section 2.2: the client is the subject")
			r.Equal("example-client", claims["client_id"])
			r.Equal("https://api.greendale.edu", claims["aud"])
			r.Equal("courses.read", claims["scope"])
			for _, claim := range []string{"auth_time", "acr", "amr"} {
				r.NotContains(claims, claim, "no user signed in")
			}
		})
	}
}

func TestClientCredentialsRejectsUnauthenticatedAndPublicClients(t *testing.T) {
	tests := map[string]struct {
		public     bool
		secret     string
		wantStatus int
		wantError  string
	}{
		"wrong secret":   {secret: "wrong", wantStatus: http.StatusUnauthorized, wantError: "invalid_client"},
		"no credentials": {wantStatus: http.StatusUnauthorized, wantError: "invalid_client"},
		"public client":  {public: true, wantStatus: http.StatusBadRequest, wantError: "unauthorized_client"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			svc := oidcFaultTestApp(t)
			form := url.Values{"grant_type": {"client_credentials"}}
			if tc.public {
				state, err := loadState()
				r.NoError(err)
				state.Apps[0].OIDCPublicClient = true
				state.Apps[0].OIDCClientSecret = ""
				r.NoError(saveState(state))
				form.Set("client_id", "example-client")
			}
			rec := clientRequest(t, svc, "token", tc.secret, form)
			r.Equal(tc.wantStatus, rec.Code)
			r.Contains(rec.Body.String(), tc.wantError)
			r.Empty(svc.accessTokens)
		})
	}
}

func TestIntrospection(t *testing.T) {
	tests := map[string]struct {
		token func(t *testing.T, svc *webApp) string
		want  map[string]any
	}{
		"access token": {
			token: func(t *testing.T, svc *webApp) string {
				return tokenBody(t, redeemToken(t, svc, authorizeForCode(t, svc, nil)))["access_token"].(string)
			},
			want: map[string]any{"active": true, "token_type": "Bearer", "client_id": "example-client", "scope": "openid email", "sub": "usr-1", "username": "troy"},
		},
		"refresh token": {
			token: func(t *testing.T, svc *webApp) string {
				return tokenBody(t, redeemToken(t, svc, authorizeForCode(t, svc, url.Values{"scope": {"openid offline_access"}})))["refresh_token"].(string)
			},
			want: map[string]any{"active": true, "client_id": "example-client", "scope": "openid offline_access", "sub": "usr-1", "username": "troy"},
		},
		"client_credentials token": {
			token: func(t *testing.T, svc *webApp) string {
				return tokenBody(t, clientRequest(t, svc, "token", "secret", url.Values{"grant_type": {"client_credentials"}, "scope": {"courses.read"}}))["access_token"].(string)
			},
			want: map[string]any{"active": true, "token_type": "Bearer", "client_id": "example-client", "scope": "courses.read", "sub": "example-client"},
		},
		"expired": {
			token: func(t *testing.T, svc *webApp) string {
				access := tokenBody(t, redeemToken(t, svc, authorizeForCode(t, svc, nil)))["access_token"].(string)
				svc.oidcMu.Lock()
				defer svc.oidcMu.Unlock()
				token := svc.accessTokens[access]
				token.ExpiresAt = time.Now().Add(-time.Second)
				svc.accessTokens[access] = token
				return access
			},
			want: map[string]any{"active": false},
		},
		"revoked by an administrator": {
			token: func(t *testing.T, svc *webApp) string {
				access := tokenBody(t, redeemToken(t, svc, authorizeForCode(t, svc, nil)))["access_token"].(string)
				svc.revokeOIDCTokens("example", "")
				return access
			},
			want: map[string]any{"active": false},
		},
		"deactivated user": {
			token: func(t *testing.T, svc *webApp) string {
				access := tokenBody(t, redeemToken(t, svc, authorizeForCode(t, svc, nil)))["access_token"].(string)
				state, err := loadState()
				require.NoError(t, err)
				state.Users[0].Active = false
				require.NoError(t, saveState(state))
				return access
			},
			want: map[string]any{"active": false},
		},
		"unknown": {
			token: func(*testing.T, *webApp) string { return "pierce-hawthorne" },
			want:  map[string]any{"active": false},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			svc := oidcFaultTestApp(t)
			body := introspect(t, svc, tc.token(t, svc))
			if tc.want["active"] == false {
				r.Equal(tc.want, body)
				return
			}
			r.Equal("http://example.com/oidc/example", body["iss"])
			r.Greater(body["exp"], body["iat"])
			for _, claim := range []string{"iss", "iat", "exp"} {
				delete(body, claim)
			}
			r.Equal(tc.want, body)
		})
	}
}

func TestIntrospectionReportsJWTAudience(t *testing.T) {
	r := require.New(t)
	svc := jwtAccessTokenTestApp(t, "https://api.greendale.edu")
	access := tokenBody(t, redeemToken(t, svc, authorizeForCode(t, svc, nil)))["access_token"].(string)
	body := introspect(t, svc, access)
	claims := decodeIDTokenClaims(t, access)
	r.Equal(true, body["active"])
	r.Equal("https://api.greendale.edu", body["aud"])
	r.Equal(claims["iat"], body["iat"])
	r.Equal(claims["exp"], body["exp"])
}

func TestClientEndpointsRequireAuthenticationAndToken(t *testing.T) {
	tests := map[string]struct {
		secret         string
		form           url.Values
		wantStatus     int
		wantError      string
		wantChallenged bool
	}{
		"wrong secret":   {secret: "wrong", form: url.Values{"token": {"t"}}, wantStatus: http.StatusUnauthorized, wantError: "invalid_client", wantChallenged: true},
		"no credentials": {form: url.Values{"token": {"t"}}, wantStatus: http.StatusUnauthorized, wantError: "invalid_client"},
		"wrong form secret": {
			form:       url.Values{"token": {"t"}, "client_id": {"example-client"}, "client_secret": {"wrong"}},
			wantStatus: http.StatusUnauthorized, wantError: "invalid_client",
		},
		"missing token": {secret: "secret", form: url.Values{}, wantStatus: http.StatusBadRequest, wantError: "invalid_request"},
	}
	for _, endpoint := range []string{"introspect", "revoke"} {
		for name, tc := range tests {
			t.Run(endpoint+"/"+name, func(t *testing.T) {
				r := require.New(t)
				svc := oidcFaultTestApp(t)
				access := tokenBody(t, redeemToken(t, svc, authorizeForCode(t, svc, nil)))["access_token"].(string)
				form := url.Values{}
				for key, values := range tc.form {
					form[key] = values
				}
				if form.Has("token") {
					form.Set("token", access)
				}
				rec := clientRequest(t, svc, endpoint, tc.secret, form)
				r.Equal(tc.wantStatus, rec.Code)
				r.Contains(rec.Body.String(), tc.wantError)
				r.Equal(tc.wantChallenged, rec.Header().Get("WWW-Authenticate") != "")
				r.Equal(http.StatusOK, userinfoStatus(t, svc, access), "a rejected request revokes nothing")
			})
		}
	}
}

func TestClientEndpointsAcceptPublicClientID(t *testing.T) {
	r := require.New(t)
	svc := oidcFaultTestApp(t)
	state, err := loadState()
	r.NoError(err)
	state.Apps[0].OIDCPublicClient = true
	state.Apps[0].OIDCClientSecret = ""
	r.NoError(saveState(state))
	svc.accessTokens["greendale-token"] = accessToken{AppSlug: "example", ClientID: "example-client", UserID: "usr-1", IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}

	introspected := clientRequest(t, svc, "introspect", "", url.Values{"token": {"greendale-token"}, "client_id": {"example-client"}})
	r.Equal(true, tokenBody(t, introspected)["active"])
	revoked := clientRequest(t, svc, "revoke", "", url.Values{"token": {"greendale-token"}, "client_id": {"example-client"}})
	r.Equal(http.StatusOK, revoked.Code)
	r.Empty(svc.accessTokens)
}

func TestRevocation(t *testing.T) {
	r := require.New(t)
	svc := oidcFaultTestApp(t)
	offline := url.Values{"scope": {"openid email offline_access"}}
	first := tokenBody(t, redeemToken(t, svc, authorizeForCode(t, svc, offline)))
	refreshed := tokenBody(t, refreshTokens(t, svc, first["refresh_token"].(string), nil))
	other := tokenBody(t, redeemToken(t, svc, authorizeForCode(t, svc, offline)))

	revoke(t, svc, other["access_token"].(string))
	r.Equal(http.StatusUnauthorized, userinfoStatus(t, svc, other["access_token"].(string)))
	r.Equal(true, introspect(t, svc, other["refresh_token"].(string))["active"], "revoking an access token leaves its refresh token")

	revoke(t, svc, refreshed["refresh_token"].(string))
	for name, access := range map[string]any{"first": first["access_token"], "refreshed": refreshed["access_token"]} {
		r.Equal(http.StatusUnauthorized, userinfoStatus(t, svc, access.(string)), name)
		r.Equal(false, introspect(t, svc, access.(string))["active"], name)
	}
	rec := refreshTokens(t, svc, refreshed["refresh_token"].(string), nil)
	r.Equal(http.StatusBadRequest, rec.Code)
	r.Contains(rec.Body.String(), "invalid_grant")

	r.Equal(true, introspect(t, svc, other["refresh_token"].(string))["active"], "another grant is untouched")
	revoke(t, svc, "pierce-hawthorne")
	revoke(t, svc, refreshed["refresh_token"].(string))
}

func TestClientEndpointsAreAdvertised(t *testing.T) {
	tests := map[string]struct {
		public         bool
		wantGrantTypes []string
		wantAuth       []string
	}{
		"confidential client": {wantGrantTypes: []string{"authorization_code", "refresh_token", "client_credentials"}, wantAuth: []string{"client_secret_basic", "client_secret_post"}},
		"public client":       {public: true, wantGrantTypes: []string{"authorization_code", "refresh_token"}, wantAuth: []string{"none"}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			svc := oidcFaultTestApp(t)
			state, err := loadState()
			r.NoError(err)
			state.Apps[0].OIDCPublicClient = tc.public
			r.NoError(saveState(state))
			rec := httptest.NewRecorder()
			svc.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oidc/example/.well-known/openid-configuration", nil))
			r.Equal(http.StatusOK, rec.Code)
			var discovery struct {
				Issuer                string   `json:"issuer"`
				Introspection         string   `json:"introspection_endpoint"`
				Revocation            string   `json:"revocation_endpoint"`
				GrantTypes            []string `json:"grant_types_supported"`
				IntrospectionAuth     []string `json:"introspection_endpoint_auth_methods_supported"`
				RevocationAuth        []string `json:"revocation_endpoint_auth_methods_supported"`
				TokenEndpointAuthMeth []string `json:"token_endpoint_auth_methods_supported"`
			}
			r.NoError(json.Unmarshal(rec.Body.Bytes(), &discovery))
			r.Equal(discovery.Issuer+"/introspect", discovery.Introspection)
			r.Equal(discovery.Issuer+"/revoke", discovery.Revocation)
			r.Equal(tc.wantGrantTypes, discovery.GrantTypes)
			r.Equal(tc.wantAuth, discovery.IntrospectionAuth)
			r.Equal(tc.wantAuth, discovery.RevocationAuth)
			r.Equal(tc.wantAuth, discovery.TokenEndpointAuthMeth)
		})
	}
}

func TestConfigExportListsClientEndpoints(t *testing.T) {
	r := require.New(t)
	_, handler := newAcceptanceAPI(t)
	environment := acceptanceEnvironment(t, handler, `{"name":"Greendale API","slug":"greendale-api","oidc_enabled":true,"oidc_client_id":"greendale-client","oidc_redirect_uris":["http://greendale.test/callback"]}`)
	rec := acceptanceRequest(t, handler, http.MethodGet, "/apps/"+environment.ID+"/config.json", "", http.StatusOK)
	var export appConfigExport
	r.NoError(json.Unmarshal(rec.Body.Bytes(), &export))
	r.NotNil(export.OIDC)
	r.Equal(export.OIDC.Issuer+"/introspect", export.OIDC.IntrospectionURL)
	r.Equal(export.OIDC.Issuer+"/revoke", export.OIDC.RevocationURL)
}

func TestTokenHoldersSkipClientCredentialsTokens(t *testing.T) {
	r := require.New(t)
	svc := oidcFaultTestApp(t)
	tokenBody(t, clientRequest(t, svc, "token", "secret", url.Values{"grant_type": {"client_credentials"}}))
	tokenBody(t, redeemToken(t, svc, authorizeForCode(t, svc, nil)))
	r.Equal([]oidcTokenHolder{{UserID: "usr-1", User: "Troy Barnes", AccessTokens: 1}}, svc.oidcTokenHolders("example", []user{{ID: "usr-1", GivenName: "Troy", FamilyName: "Barnes"}}))
	r.Equal(2, svc.revokeOIDCTokens("example", ""), "Revoke all includes the client's own token")
}
