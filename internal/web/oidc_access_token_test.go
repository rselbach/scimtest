package web

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// jwtAccessTokenTestApp is oidcFaultTestApp with JWT access tokens enabled.
func jwtAccessTokenTestApp(t *testing.T, audience string) *webApp {
	t.Helper()
	svc := oidcFaultTestApp(t)
	state, err := loadState()
	require.NoError(t, err)
	state.Apps[0].OIDCJWTAccessTokens = true
	state.Apps[0].OIDCAccessTokenAudience = audience
	require.NoError(t, saveState(state))
	return svc
}

// verifyWithJWKS checks token's RS256 signature against the key its kid names
// in the environment's published JWKS, the way a resource server would.
func verifyWithJWKS(t *testing.T, svc *webApp, token string) error {
	t.Helper()
	rec := httptest.NewRecorder()
	svc.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oidc/example/jwks", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	var jwks struct {
		Keys []struct {
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &jwks))

	header := decodeJWTHeader(t, token)
	if header["alg"] != "RS256" {
		return fmt.Errorf("alg %v is not RS256", header["alg"])
	}
	for _, key := range jwks.Keys {
		if key.Kid != header["kid"] {
			continue
		}
		n, err := base64.RawURLEncoding.DecodeString(key.N)
		require.NoError(t, err)
		e, err := base64.RawURLEncoding.DecodeString(key.E)
		require.NoError(t, err)
		public := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		parts := strings.Split(token, ".")
		signature, err := base64.RawURLEncoding.DecodeString(parts[2])
		require.NoError(t, err)
		digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		return rsa.VerifyPKCS1v15(public, crypto.SHA256, digest[:], signature)
	}
	return errors.New("the JWKS does not publish the token's kid")
}

func TestJWTAccessTokenFollowsRFC9068(t *testing.T) {
	tests := map[string]struct {
		audience string
		want     string
	}{
		"default audience":    {want: "example-client"},
		"configured audience": {audience: " https://api.greendale.edu ", want: "https://api.greendale.edu"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			svc := jwtAccessTokenTestApp(t, tc.audience)
			body := tokenBody(t, redeemToken(t, svc, authorizeForCode(t, svc, url.Values{"nonce": {"n-1"}})))
			access := body["access_token"].(string)

			r.Equal(map[string]any{"typ": "at+jwt", "alg": "RS256", "kid": "scimtest-dev"}, decodeJWTHeader(t, access))
			r.NoError(verifyWithJWKS(t, svc, access))
			claims := decodeIDTokenClaims(t, access)
			idClaims := decodeIDTokenClaims(t, body["id_token"].(string))
			r.Equal(idClaims["iss"], claims["iss"])
			r.Equal("usr-1", claims["sub"])
			r.Equal(tc.want, claims["aud"])
			r.Equal("example-client", claims["client_id"])
			r.Equal("openid email", claims["scope"])
			r.NotEmpty(claims["jti"])
			r.Equal(claims["iat"].(float64)+3600, claims["exp"])
			r.Equal(float64(3600), body["expires_in"])
			r.Equal(idClaims["auth_time"], claims["auth_time"])
			r.Equal(idClaims["acr"], claims["acr"])
			r.NotContains(claims, "nonce")
			r.NotContains(claims, "email", "access tokens carry no profile claims")
		})
	}
}

func TestAccessTokensStayOpaqueByDefault(t *testing.T) {
	svc := oidcFaultTestApp(t)
	body := tokenBody(t, redeemToken(t, svc, authorizeForCode(t, svc, nil)))
	require.NotContains(t, body["access_token"], ".")
}

func TestJWTAccessTokenWorksForUserinfoAndRefresh(t *testing.T) {
	r := require.New(t)
	svc := jwtAccessTokenTestApp(t, "https://api.greendale.edu")
	first := tokenBody(t, redeemToken(t, svc, authorizeForCode(t, svc, url.Values{"scope": {"openid email offline_access"}})))
	refreshed := tokenBody(t, refreshTokens(t, svc, first["refresh_token"].(string), url.Values{"scope": {"openid email"}}))

	for name, body := range map[string]map[string]any{"code exchange": first, "refresh": refreshed} {
		access := body["access_token"].(string)
		r.Equal("at+jwt", decodeJWTHeader(t, access)["typ"], name)
		r.NoError(verifyWithJWKS(t, svc, access), name)
		r.Equal("https://api.greendale.edu", decodeIDTokenClaims(t, access)["aud"], name)

		userinfo := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/oidc/example/userinfo", nil)
		request.Header.Set("Authorization", "Bearer "+access)
		svc.routes().ServeHTTP(userinfo, request)
		r.Equal(http.StatusOK, userinfo.Code, name)
		r.Contains(userinfo.Body.String(), "troy@greendale.edu", name)
	}
	r.Equal("openid email", decodeIDTokenClaims(t, refreshed["access_token"].(string))["scope"])
	r.NotEqual(decodeIDTokenClaims(t, first["access_token"].(string))["jti"], decodeIDTokenClaims(t, refreshed["access_token"].(string))["jti"])
}

func TestFaultsApplyToJWTAccessTokens(t *testing.T) {
	tests := map[string]struct {
		faults     url.Values
		wantHeader map[string]any
		wantClaim  string
		wantSkew   float64
		wantValid  bool
	}{
		"wrong issuer":      {faults: url.Values{"fault_tamper": {"wrong_issuer"}}, wantClaim: "iss", wantValid: true},
		"wrong audience":    {faults: url.Values{"fault_tamper": {"wrong_audience"}}, wantClaim: "aud", wantValid: true},
		"unknown kid":       {faults: url.Values{"fault_tamper": {"unknown_kid"}}, wantHeader: map[string]any{"typ": "at+jwt", "alg": "RS256", "kid": "scimtest-unknown"}},
		"alg none":          {faults: url.Values{"fault_tamper": {"alg_none"}}, wantHeader: map[string]any{"typ": "at+jwt", "alg": "none"}},
		"broken signature":  {faults: url.Values{"fault_break_signature": {"true"}}},
		"clock skew":        {faults: url.Values{"fault_clock_skew": {"10m"}}, wantSkew: 600, wantValid: true},
		"ID token TTL":      {faults: url.Values{"fault_id_token_ttl": {"-1h"}}, wantValid: true},
		"nonce mismatch":    {faults: url.Values{"fault_tamper": {"nonce_mismatch"}}, wantValid: true},
		"dropped ID claims": {faults: url.Values{"fault_drop_claims": {"sub"}}, wantValid: true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			svc := jwtAccessTokenTestApp(t, "")
			clean := tokenBody(t, redeemToken(t, svc, authorizeForCode(t, svc, url.Values{"nonce": {"n-1"}})))["access_token"].(string)
			extra := url.Values{"nonce": {"n-1"}}
			for key, values := range tc.faults {
				extra[key] = values
			}
			faulted := tokenBody(t, redeemToken(t, svc, authorizeForCode(t, svc, extra)))["access_token"].(string)

			wantHeader := tc.wantHeader
			if wantHeader == nil {
				wantHeader = map[string]any{"typ": "at+jwt", "alg": "RS256", "kid": "scimtest-dev"}
			}
			r.Equal(wantHeader, decodeJWTHeader(t, faulted))
			cleanClaims := decodeIDTokenClaims(t, clean)
			claims := decodeIDTokenClaims(t, faulted)
			for _, claim := range []string{"iss", "aud", "sub", "client_id", "scope"} {
				want := cleanClaims[claim]
				if claim == tc.wantClaim {
					want = want.(string) + "-wrong"
				}
				r.Equal(want, claims[claim], claim)
			}
			r.NotContains(claims, "nonce")
			r.InDelta(cleanClaims["iat"].(float64)+tc.wantSkew, claims["iat"], 5)
			r.Equal(claims["iat"].(float64)+3600, claims["exp"])
			err := verifyWithJWKS(t, svc, faulted)
			if tc.wantValid {
				r.NoError(err)
				return
			}
			r.Error(err)
		})
	}
}

func TestAPIConfiguresJWTAccessTokens(t *testing.T) {
	r := require.New(t)
	_, handler := newAcceptanceAPI(t)
	environment := acceptanceEnvironment(t, handler, `{"name":"Greendale API","slug":"greendale-api","oidc_enabled":true,"oidc_client_id":"greendale-client","oidc_redirect_uris":["http://greendale.test/callback"],"oidc_jwt_access_tokens":true}`)
	r.True(environment.OIDCJWTAccessTokens)
	r.Empty(environment.OIDCAccessTokenAudience)
	base := "/api/v1/environments/" + environment.ID

	exported := func() oidcConfigExport {
		t.Helper()
		rec := acceptanceRequest(t, handler, http.MethodGet, "/apps/"+environment.ID+"/config.json", "", http.StatusOK)
		var export appConfigExport
		r.NoError(json.Unmarshal(rec.Body.Bytes(), &export))
		r.NotNil(export.OIDC)
		return *export.OIDC
	}
	r.Equal(oidcConfigExport{JWTAccessTokens: true, AccessTokenAudience: "greendale-client"}, accessTokenExport(exported()))

	acceptanceRequest(t, handler, http.MethodPatch, base, `{"oidc_access_token_audience":"https://api.greendale.edu"}`, http.StatusOK)
	stored := acceptanceRequest(t, handler, http.MethodGet, base, "", http.StatusOK)
	r.Contains(stored.Body.String(), `"oidc_jwt_access_tokens":true`)
	r.Contains(stored.Body.String(), `"oidc_access_token_audience":"https://api.greendale.edu"`)
	r.Equal(oidcConfigExport{JWTAccessTokens: true, AccessTokenAudience: "https://api.greendale.edu"}, accessTokenExport(exported()))

	acceptanceRequest(t, handler, http.MethodPatch, base, `{"oidc_jwt_access_tokens":false}`, http.StatusOK)
	r.Equal(oidcConfigExport{}, accessTokenExport(exported()), "opaque tokens export no audience")

	acceptanceRequest(t, handler, http.MethodPatch, base, `{"oidc_jwt_access_tokens":true,"oidc_enabled":false,"saml_enabled":true,"saml_entity_id":"greendale-sp","saml_acs_url":"http://greendale.test/saml"}`, http.StatusOK)
	cleared := acceptanceRequest(t, handler, http.MethodGet, base, "", http.StatusOK)
	r.NotContains(cleared.Body.String(), "oidc_jwt_access_tokens")
	r.NotContains(cleared.Body.String(), "oidc_access_token_audience")
}

// accessTokenExport keeps only the access token fields of an OIDC export.
func accessTokenExport(export oidcConfigExport) oidcConfigExport {
	return oidcConfigExport{JWTAccessTokens: export.JWTAccessTokens, AccessTokenAudience: export.AccessTokenAudience}
}

func TestAPIOIDCPlaygroundDecodesJWTAccessToken(t *testing.T) {
	r := require.New(t)
	handler, environmentID, adminURL := newAPIPlayground(t, false)
	opaque := apiPlaygroundRequest(t, handler, environmentID, adminURL, `{"user_id":"user-troy"}`)
	r.Nil(opaque.AccessTokenClaims)

	state, err := loadState()
	r.NoError(err)
	state.Apps[0].OIDCJWTAccessTokens = true
	r.NoError(saveState(state))
	result := apiPlaygroundRequest(t, handler, environmentID, adminURL, `{"user_id":"user-troy"}`)
	r.Equal(http.StatusOK, result.UserinfoStatus)
	r.Equal(map[string]any{"typ": "at+jwt", "alg": "RS256", "kid": "scimtest-dev"}, result.AccessTokenHeader)
	claims, ok := result.AccessTokenClaims.(map[string]any)
	r.True(ok)
	r.Equal("user-troy", claims["sub"])
	r.Equal("greendale-client", claims["aud"])
}

func TestJWTAccessTokensUseRotatedEnvironmentKey(t *testing.T) {
	r := require.New(t)
	svc := jwtAccessTokenTestApp(t, "https://api.greendale.edu")
	first := tokenBody(t, redeemToken(t, svc, authorizeForCode(t, svc, url.Values{"scope": {"openid offline_access"}})))
	state, err := loadState()
	r.NoError(err)
	rotated, err := svc.rotateEnvironmentSigningKey(state.Apps[0], 0, time.Now())
	r.NoError(err)
	key, err := svc.activeSigningKey(rotated)
	r.NoError(err)
	r.Error(verifyWithJWKS(t, svc, first["access_token"].(string)))
	fresh := tokenBody(t, redeemToken(t, svc, authorizeForCode(t, svc, nil)))
	refreshed := tokenBody(t, refreshTokens(t, svc, first["refresh_token"].(string), nil))
	for name, tokens := range map[string]map[string]any{"authorization code": fresh, "refresh": refreshed} {
		for _, field := range []string{"access_token", "id_token"} {
			token := tokens[field].(string)
			r.Equal(key.ID, decodeJWTHeader(t, token)["kid"], name, field)
			r.NoError(verifyWithJWKS(t, svc, token), name, field)
		}
	}
}
