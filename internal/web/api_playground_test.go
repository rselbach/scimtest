package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func newAPIPlayground(t *testing.T, public bool) (http.Handler, string, string) {
	t.Helper()
	setTestStateFile(t)
	svc := newTestIDPApp(t)
	svc.instanceToken = "playground-token"
	environmentID := "app-playground"
	secret := "study-group-secret"
	if public {
		secret = ""
	}
	state := appState{
		Environment: environment{ID: environmentID, Name: "Greendale", Slug: "greendale"},
		Apps:        []app{{ID: environmentID, Name: "Greendale", Slug: "greendale", Protocol: "oidc", OIDCClientID: "greendale-client", OIDCClientSecret: secret, OIDCPublicClient: public}},
		Users:       []user{{ID: "user-troy", GivenName: "Troy", FamilyName: "Barnes", Email: "troy@greendale.edu", Username: "tbarnes", Active: true}, {ID: "user-chang", GivenName: "Ben", FamilyName: "Chang", Email: "chang@greendale.edu", Username: "chang", Active: false}},
	}
	require.NoError(t, saveEnvironmentState(state))
	server := httptest.NewServer(svc.routes())
	t.Cleanup(server.Close)
	parsed, err := url.Parse(server.URL)
	require.NoError(t, err)
	svc.adminHost = parsed.Host
	svc.adminURL = server.URL
	return svc.routes(), environmentID, server.URL
}

func apiPlaygroundRequest(t *testing.T, handler http.Handler, environmentID, adminURL, body string) apiOIDCPlaygroundResult {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/environments/"+environmentID+"/oidc/playground", strings.NewReader(body))
	request.Header.Set(instanceTokenHeader, "playground-token")
	request.Header.Set("Content-Type", "application/json")
	parsed, err := url.Parse(adminURL)
	require.NoError(t, err)
	request.Host = parsed.Host
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	var result apiOIDCPlaygroundResult
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &result))
	return result
}

func TestAPIOIDCPlaygroundRunsConfidentialAndPublicFlows(t *testing.T) {
	for _, public := range []bool{false, true} {
		t.Run(fmt.Sprintf("public=%t", public), func(t *testing.T) {
			handler, environmentID, adminURL := newAPIPlayground(t, public)
			result := apiPlaygroundRequest(t, handler, environmentID, adminURL, `{"user_id":"user-troy"}`)
			require.Equal(t, http.StatusFound, result.AuthorizeStatus)
			require.Equal(t, http.StatusOK, result.TokenStatus)
			require.Equal(t, http.StatusOK, result.UserinfoStatus)
			require.NotEmpty(t, result.Code)
			claims, ok := result.IDTokenClaims.(map[string]any)
			require.True(t, ok)
			require.Equal(t, "troy@greendale.edu", claims["email"])
			userinfo, ok := result.Userinfo.(map[string]any)
			require.True(t, ok)
			require.Equal(t, "troy@greendale.edu", userinfo["email"])
		})
	}
}

func TestAPIOIDCPlaygroundReturnsFlowErrors(t *testing.T) {
	handler, environmentID, adminURL := newAPIPlayground(t, false)

	inactive := apiPlaygroundRequest(t, handler, environmentID, adminURL, `{"user_id":"user-chang"}`)
	require.NotEmpty(t, inactive.Error)
	require.Empty(t, inactive.Code)

	fault := apiPlaygroundRequest(t, handler, environmentID, adminURL, `{"user_id":"user-troy","faults":{"token_error":"temporarily_unavailable"}}`)
	require.Equal(t, http.StatusBadRequest, fault.TokenStatus)
	require.Equal(t, "temporarily_unavailable", fault.Error)
}

func TestAPIProtocolSignInRejectsInactiveUserAsJSON(t *testing.T) {
	handler, environmentID, adminURL := newAPIPlayground(t, false)
	parsed, err := url.Parse(adminURL)
	require.NoError(t, err)
	configured, err := loadStateForApp(environmentID)
	require.NoError(t, err)
	configured.Apps[0].OIDCRedirectURIs = []string{adminURL + "/callback"}
	require.NoError(t, saveEnvironmentState(configured))

	request := httptest.NewRequest(http.MethodPost, "/api/v1/environments/"+environmentID+"/oidc/authorize", strings.NewReader(`{"user_id":"user-chang","client_id":"greendale-client","response_type":"code","scope":"openid","redirect_uri":"`+adminURL+`/callback"}`))
	request.Host = parsed.Host
	request.Header.Set(instanceTokenHeader, "playground-token")
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	require.Equal(t, http.StatusBadRequest, response.Code)
	require.Equal(t, "application/json", response.Header().Get("Content-Type"))
	require.Contains(t, response.Body.String(), "active user is required")

	state, err := loadStateForApp(environmentID)
	require.NoError(t, err)
	state.Apps[0].Protocol = "both"
	state.Apps[0].SAMLEntityID = "greendale-sp"
	state.Apps[0].SAMLACSURL = adminURL + "/saml/callback"
	require.NoError(t, saveEnvironmentState(state))
	request = httptest.NewRequest(http.MethodPost, "/api/v1/environments/"+environmentID+"/saml/sign-in", strings.NewReader(`{"user_id":"user-chang"}`))
	request.Host = parsed.Host
	request.Header.Set(instanceTokenHeader, "playground-token")
	request.Header.Set("Content-Type", "application/json")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	require.Equal(t, http.StatusBadRequest, response.Code)
	require.Equal(t, "application/json", response.Header().Get("Content-Type"))
	require.Contains(t, response.Body.String(), "active user is required")

	request = httptest.NewRequest(http.MethodPost, "/api/v1/environments/"+environmentID+"/saml/sign-in", strings.NewReader(`{"user_id":"user-troy","redirect_query":"SAMLRequest=signed-request&SigAlg=algorithm&Signature=signature","saml_request":"tampered-request"}`))
	request.Host = parsed.Host
	request.Header.Set(instanceTokenHeader, "playground-token")
	request.Header.Set("Content-Type", "application/json")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	require.Equal(t, http.StatusBadRequest, response.Code)
	require.Contains(t, response.Body.String(), "cannot be combined")
}
