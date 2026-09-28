package web

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func newAcceptanceAPI(t *testing.T) (*webApp, http.Handler) {
	t.Helper()
	setTestStateFile(t)
	svc := newTestIDPApp(t)
	svc.instanceToken = "greendale-local-instance"
	svc.adminHost = "127.0.0.1:8080"
	svc.adminURL = "http://" + svc.adminHost
	return svc, svc.routes()
}

func acceptanceRequest(t *testing.T, handler http.Handler, method, path, body string, want int) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, "http://127.0.0.1:8080"+path, strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set(instanceTokenHeader, "greendale-local-instance")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, want, rec.Code, "%s %s: %s", method, path, rec.Body.String())
	require.Contains(t, rec.Header().Get("Content-Type"), "application/json", "%s %s", method, path)
	require.Empty(t, rec.Header().Get("Location"))
	require.True(t, json.Valid(rec.Body.Bytes()), rec.Body.String())
	return rec
}

func acceptanceEnvironment(t *testing.T, handler http.Handler, body string) app {
	t.Helper()
	rec := acceptanceRequest(t, handler, http.MethodPost, "/api/v1/environments", body, http.StatusCreated)
	var result app
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &result))
	require.NotEmpty(t, result.ID)
	return result
}

func acceptanceUser(t *testing.T, handler http.Handler, environmentID string) user {
	t.Helper()
	rec := acceptanceRequest(t, handler, http.MethodPost, "/api/v1/environments/"+environmentID+"/users", `{"given_name":"Troy","family_name":"Barnes","email":"troy@greendale.edu"}`, http.StatusCreated)
	var result user
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &result))
	require.NotEmpty(t, result.ID)
	return result
}

func TestAPIAcceptancePartialSCIMConfiguration(t *testing.T) {
	_, handler := newAcceptanceAPI(t)
	environment := acceptanceEnvironment(t, handler, `{"name":"Greendale Directory","slug":"greendale-directory","scim_enabled":true,"scim_base_url":"http://greendale.test/scim/v2"}`)
	base := "/api/v1/environments/" + environment.ID
	require.False(t, environment.SCIMEnabled)

	rec := acceptanceRequest(t, handler, http.MethodPatch, base, `{"name":"Greendale Directory Revised"}`, http.StatusOK)
	var updated app
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &updated))
	require.Equal(t, environment.SCIMBaseURL, updated.SCIMBaseURL)
	require.False(t, updated.SCIMEnabled)

	rec = acceptanceRequest(t, handler, http.MethodPatch, base, `{"scim_bearer_token":"greendale-test-token"}`, http.StatusOK)
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &updated))
	require.Equal(t, environment.SCIMBaseURL, updated.SCIMBaseURL)
	require.Equal(t, "greendale-test-token", updated.SCIMBearerToken)
	require.True(t, updated.SCIMEnabled)

	acceptanceRequest(t, handler, http.MethodPatch, base, `{"scim_bearer_token":""}`, http.StatusOK)
	rec = acceptanceRequest(t, handler, http.MethodGet, base, "", http.StatusOK)
	updated = app{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &updated))
	require.Equal(t, environment.SCIMBaseURL, updated.SCIMBaseURL)
	require.Empty(t, updated.SCIMBearerToken)
	require.False(t, updated.SCIMEnabled)
}

func TestAPIAcceptanceSCIMDeletionHistory(t *testing.T) {
	_, handler := newAcceptanceAPI(t)
	environment := acceptanceEnvironment(t, handler, `{"name":"Greendale Directory","slug":"greendale-directory","scim_enabled":true,"scim_base_url":"http://greendale.test/scim/v2","scim_bearer_token":"greendale-test-token"}`)
	base := "/api/v1/environments/" + environment.ID
	troy := acceptanceUser(t, handler, environment.ID)
	rec := acceptanceRequest(t, handler, http.MethodPost, base+"/groups", fmt.Sprintf(`{"display_name":"Study Group","member_ids":[%q,%q]}`, troy.ID, troy.ID), http.StatusCreated)
	var studyGroup group
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &studyGroup))
	require.Equal(t, []string{troy.ID}, studyGroup.MemberIDs)

	for resource, id := range map[string]string{"users": troy.ID, "groups": studyGroup.ID} {
		t.Run(resource, func(t *testing.T) {
			path := base + "/" + resource + "/" + id
			acceptanceRequest(t, handler, http.MethodDelete, path, "", http.StatusOK)
			acceptanceRequest(t, handler, http.MethodPost, path+"/restore", `{}`, http.StatusOK)
			acceptanceRequest(t, handler, http.MethodPost, base+"/"+resource+"/bulk-delete", fmt.Sprintf(`{"ids":[%q]}`, id), http.StatusOK)
			rec := acceptanceRequest(t, handler, http.MethodGet, path+"/operations", "", http.StatusOK)
			var operations []operationLog
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &operations))
			summaries := make([]string, 0, len(operations))
			for _, operation := range operations {
				summaries = append(summaries, operation.Summary)
			}
			require.ElementsMatch(t, []string{"Created", "Marked for deletion", "Restored", "Marked for deletion in bulk"}, summaries)
		})
	}
}

func TestAPIAcceptanceRecordingDisablesSecrets(t *testing.T) {
	service, handler := newAcceptanceAPI(t)
	acceptanceRequest(t, handler, http.MethodPatch, "/api/v1/config", `{"record_traffic":true,"record_secrets":true}`, http.StatusOK)
	require.True(t, service.debugSecrets.Load())
	acceptanceRequest(t, handler, http.MethodPatch, "/api/v1/config", `{"record_traffic":false}`, http.StatusOK)
	require.False(t, service.debugSecrets.Load())
}

func TestAPIAcceptanceDirectoryAndBackup(t *testing.T) {
	_, handler := newAcceptanceAPI(t)
	first := acceptanceEnvironment(t, handler, `{"name":"Greendale Portal","slug":"greendale","oidc_enabled":true,"oidc_client_id":"greendale-client","oidc_client_secret":"study-group-secret","oidc_redirect_uris":["http://greendale.test/callback"]}`)
	second := acceptanceEnvironment(t, handler, `{"name":"City College","slug":"city-college"}`)
	base := "/api/v1/environments/" + first.ID
	troy := acceptanceUser(t, handler, first.ID)
	userPath := base + "/users/" + troy.ID

	groupResponse := acceptanceRequest(t, handler, http.MethodPost, base+"/groups", fmt.Sprintf(`{"display_name":"Study Group","member_ids":[%q]}`, troy.ID), http.StatusCreated)
	var studyGroup group
	require.NoError(t, json.Unmarshal(groupResponse.Body.Bytes(), &studyGroup))
	require.Equal(t, []string{troy.ID}, studyGroup.MemberIDs)
	groupPath := base + "/groups/" + studyGroup.ID

	rec := acceptanceRequest(t, handler, http.MethodPatch, userPath, `{"family_name":"","active":false}`, http.StatusOK)
	var updated user
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &updated))
	require.Equal(t, "Troy", updated.GivenName)
	require.Empty(t, updated.FamilyName)
	require.Equal(t, "troy@greendale.edu", updated.Email)
	require.False(t, updated.Active)
	rec = acceptanceRequest(t, handler, http.MethodGet, userPath, "", http.StatusOK)
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &updated))
	require.False(t, updated.Active)

	acceptanceRequest(t, handler, http.MethodPatch, groupPath, `{"member_ids":[]}`, http.StatusOK)
	rec = acceptanceRequest(t, handler, http.MethodGet, groupPath, "", http.StatusOK)
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &studyGroup))
	require.Empty(t, studyGroup.MemberIDs)
	require.Equal(t, "Study Group", studyGroup.DisplayName)

	acceptanceRequest(t, handler, http.MethodPatch, base, `{"name":"Greendale Portal Revised"}`, http.StatusOK)
	rec = acceptanceRequest(t, handler, http.MethodGet, base+"/connection", "", http.StatusOK)
	var connection appConfigExport
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &connection))
	require.NotNil(t, connection.OIDC)
	require.Equal(t, "study-group-secret", connection.OIDC.ClientSecret)
	require.Equal(t, []string{"http://greendale.test/callback"}, connection.OIDC.RedirectURIs)

	req := httptest.NewRequest(http.MethodPatch, "http://127.0.0.1:8080"+userPath+"?environment="+second.ID+"&app="+second.ID, strings.NewReader(`{"given_name":"Abed"}`))
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set(instanceTokenHeader, "greendale-local-instance")
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: environmentCookieName, Value: second.ID})
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	rec = acceptanceRequest(t, handler, http.MethodGet, userPath, "", http.StatusOK)
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &updated))
	require.Equal(t, "Abed", updated.GivenName)
	rec = acceptanceRequest(t, handler, http.MethodGet, "/api/v1/environments/"+second.ID+"/users", "", http.StatusOK)
	var otherUsers []user
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &otherUsers))
	require.Empty(t, otherUsers)
	acceptanceRequest(t, handler, http.MethodGet, "/api/v1/environments/"+second.ID+"/users/"+troy.ID, "", http.StatusNotFound)
	acceptanceRequest(t, handler, http.MethodPost, "/api/v1/environments/missing/users", `{"given_name":"Annie","email":"annie@greendale.edu"}`, http.StatusNotFound)

	backup := acceptanceRequest(t, handler, http.MethodGet, base+"/backup", "", http.StatusOK).Body.String()
	acceptanceRequest(t, handler, http.MethodPatch, userPath, `{"given_name":"Jeff"}`, http.StatusOK)
	acceptanceRequest(t, handler, http.MethodPost, base+"/restore", backup, http.StatusOK)
	rec = acceptanceRequest(t, handler, http.MethodGet, userPath, "", http.StatusOK)
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &updated))
	require.Equal(t, "Abed", updated.GivenName)
	require.False(t, updated.Active)

	acceptanceRequest(t, handler, http.MethodDelete, userPath, "", http.StatusOK)
	acceptanceRequest(t, handler, http.MethodGet, userPath, "", http.StatusNotFound)
	acceptanceRequest(t, handler, http.MethodDelete, "/api/v1/environments/"+second.ID, "", http.StatusOK)
	acceptanceRequest(t, handler, http.MethodDelete, base, "", http.StatusOK)
	rec = acceptanceRequest(t, handler, http.MethodGet, "/api/v1/environments", "", http.StatusOK)
	var environments []app
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &environments))
	require.Empty(t, environments)
}

func TestAPIAcceptanceSignInProtocols(t *testing.T) {
	_, handler := newAcceptanceAPI(t)
	environment := acceptanceEnvironment(t, handler, `{"name":"Greendale Portal","slug":"greendale","oidc_enabled":true,"oidc_client_id":"greendale-client","oidc_client_secret":"study-group-secret","oidc_redirect_uris":["http://greendale.test/callback"],"saml_enabled":true,"saml_entity_id":"greendale-sp","saml_acs_url":"http://greendale.test/saml","include_groups_claim":true}`)
	base := "/api/v1/environments/" + environment.ID
	troy := acceptanceUser(t, handler, environment.ID)
	acceptanceRequest(t, handler, http.MethodPost, base+"/groups", fmt.Sprintf(`{"display_name":"Study Group","member_ids":[%q]}`, troy.ID), http.StatusCreated)

	authorize := acceptanceRequest(t, handler, http.MethodPost, base+"/oidc/authorize", fmt.Sprintf(`{"user_id":%q,"response_type":"code","client_id":"greendale-client","redirect_uri":"http://greendale.test/callback","scope":"openid profile email groups","state":"greendale-state","nonce":"greendale-nonce"}`, troy.ID), http.StatusOK)
	var authorization struct {
		Code        string `json:"code"`
		RedirectURI string `json:"redirect_uri"`
		State       string `json:"state"`
	}
	require.NoError(t, json.Unmarshal(authorize.Body.Bytes(), &authorization))
	require.NotEmpty(t, authorization.Code)
	require.Equal(t, "greendale-state", authorization.State)
	require.Contains(t, authorization.RedirectURI, "http://greendale.test/callback")

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authorization.Code},
		"client_id":     {"greendale-client"},
		"client_secret": {"study-group-secret"},
		"redirect_uri":  {"http://greendale.test/callback"},
	}
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/oidc/greendale/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokens := httptest.NewRecorder()
	handler.ServeHTTP(tokens, req)
	require.Equal(t, http.StatusOK, tokens.Code, tokens.Body.String())
	var tokenResponse struct {
		IDToken     string `json:"id_token"`
		AccessToken string `json:"access_token"`
	}
	require.NoError(t, json.Unmarshal(tokens.Body.Bytes(), &tokenResponse))
	parts := strings.Split(tokenResponse.IDToken, ".")
	require.Len(t, parts, 3)
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, json.Unmarshal(claimsJSON, &claims))
	require.Equal(t, "troy@greendale.edu", claims["email"])
	require.Equal(t, "greendale-nonce", claims["nonce"])
	require.Contains(t, claims["groups"], "Study Group")

	req = httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/oidc/greendale/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tokenResponse.AccessToken)
	userinfo := httptest.NewRecorder()
	handler.ServeHTTP(userinfo, req)
	require.Equal(t, http.StatusOK, userinfo.Code)
	require.Contains(t, userinfo.Body.String(), "troy@greendale.edu")

	saml := acceptanceRequest(t, handler, http.MethodPost, base+"/saml/sign-in", fmt.Sprintf(`{"user_id":%q,"relay_state":"study-session"}`, troy.ID), http.StatusOK)
	var samlResponse struct {
		ACSURL       string `json:"acs_url"`
		SAMLResponse string `json:"saml_response"`
		RelayState   string `json:"relay_state"`
	}
	require.NoError(t, json.Unmarshal(saml.Body.Bytes(), &samlResponse))
	require.Equal(t, "http://greendale.test/saml", samlResponse.ACSURL)
	require.Equal(t, "study-session", samlResponse.RelayState)
	assertion, err := base64.StdEncoding.DecodeString(samlResponse.SAMLResponse)
	require.NoError(t, err)
	require.Contains(t, string(assertion), "troy@greendale.edu")
	require.Contains(t, string(assertion), "SignatureValue")

	for _, endpoint := range []string{"inspections/oidc", "inspections/saml", "flows"} {
		rec := acceptanceRequest(t, handler, http.MethodGet, base+"/"+endpoint, "", http.StatusOK)
		require.Contains(t, rec.Body.String(), "Troy")
	}
}

func TestAPIAcceptanceSCIMSyncAndImport(t *testing.T) {
	_, handler := newAcceptanceAPI(t)
	var remoteMu sync.Mutex
	var remoteUser map[string]any
	var requests []string
	syncStarted := make(chan struct{})
	releaseSync := make(chan struct{})
	var startOnce sync.Once
	allowSync := sync.OnceFunc(func() { close(releaseSync) })
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodGet && req.URL.Path == "/Users" {
			startOnce.Do(func() {
				close(syncStarted)
				select {
				case <-releaseSync:
				case <-req.Context().Done():
				}
			})
		}
		remoteMu.Lock()
		defer remoteMu.Unlock()
		requests = append(requests, req.Method+" "+req.URL.Path)
		if req.Header.Get("Authorization") != "Bearer greendale-scim" {
			http.Error(w, "wrong credentials", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/scim+json")
		var response any
		switch {
		case req.URL.Path == "/ServiceProviderConfig":
			response = map[string]any{"patch": map[string]bool{"supported": false}, "filter": map[string]bool{"supported": false}}
		case req.Method == http.MethodGet && req.URL.Path == "/Groups":
			response = map[string]any{"totalResults": 0, "Resources": []any{}}
		case req.Method == http.MethodGet && req.URL.Path == "/Users":
			resources := []any{}
			if remoteUser != nil {
				resources = append(resources, remoteUser)
			}
			response = map[string]any{"totalResults": len(resources), "startIndex": 1, "itemsPerPage": len(resources), "Resources": resources}
		case req.Method == http.MethodGet && req.URL.Path == "/Users/remote-troy":
			response = remoteUser
		case req.Method == http.MethodPost && req.URL.Path == "/Users", req.Method == http.MethodPut && req.URL.Path == "/Users/remote-troy":
			if err := json.NewDecoder(req.Body).Decode(&remoteUser); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			remoteUser["id"] = "remote-troy"
			response = remoteUser
		default:
			http.Error(w, "unexpected request", http.StatusNotFound)
			return
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Errorf("write SCIM response: %v", err)
		}
	}))
	t.Cleanup(target.Close)
	t.Cleanup(allowSync)
	environment := acceptanceEnvironment(t, handler, fmt.Sprintf(`{"name":"Greendale SCIM","slug":"greendale-scim","scim_enabled":true,"scim_base_url":%q,"scim_bearer_token":"greendale-scim"}`, target.URL))
	base := "/api/v1/environments/" + environment.ID
	troy := acceptanceUser(t, handler, environment.ID)
	acceptanceRequest(t, handler, http.MethodPost, base+"/scim/discover", `{}`, http.StatusOK)
	plan := acceptanceRequest(t, handler, http.MethodGet, base+"/sync/plan", "", http.StatusOK)
	require.Contains(t, plan.Body.String(), troy.ID)
	acceptanceRequest(t, handler, http.MethodPost, base+"/sync/start", `{}`, http.StatusAccepted)
	select {
	case <-syncStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("sync did not reach the SCIM server")
	}
	acceptanceRequest(t, handler, http.MethodPatch, base+"/users/"+troy.ID, `{"given_name":"Jeff"}`, http.StatusConflict)
	acceptanceRequest(t, handler, http.MethodPost, base+"/tools/seed-sample", `{}`, http.StatusConflict)
	acceptanceRequest(t, handler, http.MethodPost, base+"/sync/reset", `{}`, http.StatusConflict)
	allowSync()
	var job syncJobSnapshot
	deadline := time.Now().Add(5 * time.Second)
	for {
		rec := acceptanceRequest(t, handler, http.MethodGet, base+"/sync/status", "", http.StatusOK)
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &job))
		if job.Done {
			break
		}
		require.True(t, time.Now().Before(deadline), "sync did not complete")
		time.Sleep(10 * time.Millisecond)
	}
	require.True(t, job.Success, job.Error)
	remoteMu.Lock()
	require.Equal(t, "troy@greendale.edu", remoteUser["userName"])
	require.Contains(t, requests, "POST /Users")
	remoteMu.Unlock()
	rec := acceptanceRequest(t, handler, http.MethodGet, base+"/users/"+troy.ID, "", http.StatusOK)
	var synced user
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &synced))
	require.Equal(t, "remote-troy", synced.RemoteID)
	require.False(t, synced.Dirty)
	trace := acceptanceRequest(t, handler, http.MethodGet, base+"/sync/trace", "", http.StatusOK)
	require.Contains(t, trace.Body.String(), "/Users")
	history := acceptanceRequest(t, handler, http.MethodGet, base+"/users/"+troy.ID+"/operations", "", http.StatusOK)
	require.Contains(t, history.Body.String(), "remote-troy")

	acceptanceRequest(t, handler, http.MethodPost, base+"/import/preview", `{}`, http.StatusOK)
	acceptanceRequest(t, handler, http.MethodPatch, base+"/users/"+troy.ID, `{"given_name":"Abed"}`, http.StatusOK)
	acceptanceRequest(t, handler, http.MethodPost, base+"/import/apply", `{}`, http.StatusConflict)
	rec = acceptanceRequest(t, handler, http.MethodGet, base+"/users/"+troy.ID, "", http.StatusOK)
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &synced))
	require.Equal(t, "Abed", synced.GivenName)

	acceptanceRequest(t, handler, http.MethodPost, base+"/import/preview", `{}`, http.StatusOK)
	acceptanceRequest(t, handler, http.MethodPost, base+"/import/apply", `{}`, http.StatusOK)
	rec = acceptanceRequest(t, handler, http.MethodGet, base+"/users/"+troy.ID, "", http.StatusOK)
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &synced))
	require.Equal(t, "Troy", synced.GivenName)
}

func TestAPIAcceptanceGuards(t *testing.T) {
	svc, handler := newAcceptanceAPI(t)
	environment := acceptanceEnvironment(t, handler, `{"name":"Greendale"}`)
	base := "/api/v1/environments/" + environment.ID
	troy := acceptanceUser(t, handler, environment.ID)

	tests := map[string]struct {
		method      string
		path        string
		body        string
		token       string
		host        string
		origin      string
		contentType string
		want        int
	}{
		"missing token":   {method: http.MethodGet, path: "/api/v1/status", want: http.StatusUnauthorized},
		"wrong token":     {method: http.MethodGet, path: "/api/v1/status", token: "wrong", want: http.StatusUnauthorized},
		"wrong host":      {method: http.MethodGet, path: "/api/v1/status", token: svc.instanceToken, host: "example.test", want: http.StatusMisdirectedRequest},
		"cross origin":    {method: http.MethodPatch, path: base, body: `{"name":"City College"}`, token: svc.instanceToken, origin: "https://example.test", want: http.StatusForbidden},
		"unknown route":   {method: http.MethodGet, path: "/api/v1/unknown", token: svc.instanceToken, want: http.StatusNotFound},
		"unknown method":  {method: http.MethodPut, path: "/api/v1/environments", body: `{}`, token: svc.instanceToken, want: http.StatusMethodNotAllowed},
		"null body":       {method: http.MethodPatch, path: base, body: `null`, token: svc.instanceToken, want: http.StatusBadRequest},
		"null field":      {method: http.MethodPatch, path: base, body: `{"name":null}`, token: svc.instanceToken, want: http.StatusBadRequest},
		"malformed body":  {method: http.MethodPatch, path: base, body: `{"name":`, token: svc.instanceToken, want: http.StatusBadRequest},
		"trailing object": {method: http.MethodPatch, path: base, body: `{"name":"Changed"} {}`, token: svc.instanceToken, want: http.StatusBadRequest},
		"unknown field":   {method: http.MethodPatch, path: base, body: `{"name":"Changed","unknown":true}`, token: svc.instanceToken, want: http.StatusBadRequest},
		"wrong type":      {method: http.MethodPatch, path: base, body: `{"oidc_enabled":"true"}`, token: svc.instanceToken, want: http.StatusBadRequest},
		"plain text":      {method: http.MethodPatch, path: base, body: `{"name":"Changed"}`, token: svc.instanceToken, contentType: "text/plain", want: http.StatusUnsupportedMediaType},
		"invalid action":  {method: http.MethodPost, path: base + "/tools/clear-local", body: `{"unknown":true}`, token: svc.instanceToken, want: http.StatusBadRequest},
		"missing sync":    {method: http.MethodPost, path: "/api/v1/environments/missing/sync/start", body: `{}`, token: svc.instanceToken, want: http.StatusNotFound},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "http://127.0.0.1:8080"+tc.path, strings.NewReader(tc.body))
			req.RemoteAddr = "127.0.0.1:12345"
			req.Header.Set(instanceTokenHeader, tc.token)
			req.Header.Set("Content-Type", "application/json")
			if tc.contentType != "" {
				req.Header.Set("Content-Type", tc.contentType)
			}
			if tc.host != "" {
				req.Host = tc.host
			}
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			require.Equal(t, tc.want, rec.Code, rec.Body.String())
			require.Contains(t, rec.Header().Get("Content-Type"), "application/json")
			var failure map[string]any
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &failure))
			require.NotEmpty(t, failure["error"])
		})
	}

	rec := acceptanceRequest(t, handler, http.MethodGet, base, "", http.StatusOK)
	var unchanged app
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &unchanged))
	require.Equal(t, "Greendale", unchanged.Name)
	acceptanceRequest(t, handler, http.MethodGet, base+"/users/"+troy.ID, "", http.StatusOK)

	svc.requireGitHubAccount = true
	acceptanceRequest(t, handler, http.MethodGet, "/api/v1/status", "", http.StatusOK)
	lockedHandler := svc.routes()
	acceptanceRequest(t, lockedHandler, http.MethodGet, "/api/v1/status", "", http.StatusOK)
	acceptanceRequest(t, lockedHandler, http.MethodGet, "/api/v1/account", "", http.StatusOK)
	acceptanceRequest(t, lockedHandler, http.MethodGet, base, "", http.StatusUnauthorized)
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/api/v1/account", nil)
	rec = httptest.NewRecorder()
	lockedHandler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusUnauthorized, rec.Code)

	tunnelResponse := httptest.NewRecorder()
	svc.idpRoutes().ServeHTTP(tunnelResponse, httptest.NewRequest(http.MethodGet, "/api/v1", nil))
	require.Equal(t, http.StatusNotFound, tunnelResponse.Code)
}
