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

func TestInspectorRevokesUserTokens(t *testing.T) {
	tests := map[string]struct {
		userID      string
		wantRevoked bool
	}{
		"one user":   {userID: "usr-1", wantRevoked: true},
		"every user": {wantRevoked: true},
		"other user": {userID: "usr-2"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			svc := oidcFaultTestApp(t)
			tokens := tokenBody(t, redeemToken(t, svc, authorizeForCode(t, svc, url.Values{"scope": {"openid email offline_access"}})))

			page := httptest.NewRecorder()
			svc.routes().ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/inspect/oidc/example", nil))
			r.Contains(page.Body.String(), "Active tokens")
			r.Contains(page.Body.String(), `name="user_id" value="usr-1"`)

			form := url.Values{"return_tab": {"oidc-inspector"}}
			if tc.userID != "" {
				form.Set("user_id", tc.userID)
			}
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/inspect/oidc/example/revoke", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			svc.routes().ServeHTTP(rec, req)
			r.Equal(http.StatusSeeOther, rec.Code)

			refresh := refreshTokens(t, svc, tokens["refresh_token"].(string), nil)
			userinfo := httptest.NewRecorder()
			userinfoReq := httptest.NewRequest(http.MethodGet, "/oidc/example/userinfo", nil)
			userinfoReq.Header.Set("Authorization", "Bearer "+tokens["access_token"].(string))
			svc.routes().ServeHTTP(userinfo, userinfoReq)
			if !tc.wantRevoked {
				r.Equal(http.StatusOK, refresh.Code)
				r.Equal(http.StatusOK, userinfo.Code)
				return
			}
			r.Equal(http.StatusBadRequest, refresh.Code)
			r.Contains(refresh.Body.String(), "invalid_grant")
			r.Equal(http.StatusUnauthorized, userinfo.Code)
			r.Empty(svc.oidcTokenHolders("example", nil))
		})
	}
}

func TestOIDCTokenHoldersCountsPerUser(t *testing.T) {
	r := require.New(t)
	svc := oidcFaultTestApp(t)
	redeemToken(t, svc, authorizeForCode(t, svc, url.Values{"scope": {"openid offline_access"}}))
	redeemToken(t, svc, authorizeForCode(t, svc, nil))

	holders := svc.oidcTokenHolders("example", []user{{ID: "usr-1", GivenName: "Troy", FamilyName: "Barnes", Email: "troy@greendale.edu"}})
	r.Equal([]oidcTokenHolder{{UserID: "usr-1", User: "Troy Barnes", AccessTokens: 2, RefreshTokens: 1}}, holders)
}

func TestAPIRevokesOIDCTokens(t *testing.T) {
	r := require.New(t)
	handler, environmentID, adminURL := newAPIPlayground(t, false)
	parsed, err := url.Parse(adminURL)
	r.NoError(err)
	call := func(method, path string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, "/api/v1/environments/"+environmentID+path, nil)
		request.Host = parsed.Host
		request.Header.Set(instanceTokenHeader, "playground-token")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	apiPlaygroundRequest(t, handler, environmentID, adminURL, `{"user_id":"user-troy"}`)

	listed := call(http.MethodGet, "/oidc/tokens")
	r.Equal(http.StatusOK, listed.Code, listed.Body.String())
	var holders struct {
		Holders []oidcTokenHolder `json:"holders"`
	}
	r.NoError(json.Unmarshal(listed.Body.Bytes(), &holders))
	r.Len(holders.Holders, 1)
	r.Equal("user-troy", holders.Holders[0].UserID)

	unknown := call(http.MethodDelete, "/oidc/tokens?user_id=user-nobody")
	r.Equal(http.StatusNotFound, unknown.Code)

	revoked := call(http.MethodDelete, "/oidc/tokens?user_id=user-troy")
	r.Equal(http.StatusOK, revoked.Code, revoked.Body.String())
	r.JSONEq(`{"revoked":1}`, revoked.Body.String())
	r.JSONEq(`{"holders":[]}`, call(http.MethodGet, "/oidc/tokens").Body.String())
}
