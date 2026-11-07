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

const personaGUIDPattern = `^[0-9a-f]{8}-[0-9a-f]{4}-8[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`

func TestAPIAcceptancePersonaClaims(t *testing.T) {
	tests := map[string]struct {
		persona string
		want    map[string]any
		wantNot []string
	}{
		"generic keeps scimtest's claims": {
			persona: "generic",
			want:    map[string]any{"preferred_username": "tbarnes", "email_verified": true, "groups": []any{"Study Group"}},
			wantNot: []string{"oid", "tid", "upn", "ver", "hd", "_claim_names", "_claim_sources"},
		},
		"entra ID": {
			persona: "entra",
			want:    map[string]any{"preferred_username": "tbarnes@greendale.edu", "upn": "tbarnes@greendale.edu", "groups": []any{"Study Group"}},
			wantNot: []string{"email_verified", "ver", "hd", "_claim_names"},
		},
		"okta": {
			persona: "okta",
			want:    map[string]any{"ver": float64(1), "groups": []any{"Everyone", "Study Group"}, "email_verified": true, "preferred_username": "tbarnes"},
			wantNot: []string{"oid", "tid", "upn", "hd"},
		},
		"google": {
			persona: "google",
			want:    map[string]any{"hd": "greendale.edu", "email_verified": true, "groups": []any{"Study Group"}},
			wantNot: []string{"oid", "tid", "upn", "ver"},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			_, handler := newAcceptanceAPI(t)
			environment := personaEnvironment(t, handler, fmt.Sprintf(`"persona":%q`, tc.persona))
			r.Equal(tc.persona, environment.Persona)
			base := "/api/v1/environments/" + environment.ID
			troy := personaUser(t, handler, base, "Troy", "Barnes", "tbarnes", "troy.barnes@greendale.edu")
			acceptanceRequest(t, handler, http.MethodPost, base+"/groups", fmt.Sprintf(`{"display_name":"Study Group","member_ids":[%q]}`, troy.ID), http.StatusCreated)

			claims, accessToken := personaSignIn(t, handler, base, troy.ID, "openid profile email groups")
			userinfo := personaUserinfo(t, handler, accessToken)
			for source, got := range map[string]map[string]any{"ID token": claims, "userinfo": userinfo} {
				for claim, want := range tc.want {
					r.Equal(want, got[claim], "%s %s", source, claim)
				}
				for _, claim := range tc.wantNot {
					r.NotContains(got, claim, source)
				}
			}
			r.Equal(claims["sub"], userinfo["sub"])
			if tc.persona == "entra" {
				r.Regexp(personaGUIDPattern, claims["oid"])
				r.Regexp(personaGUIDPattern, claims["tid"])
				r.Equal(claims["oid"], userinfo["oid"])
			}
		})
	}
}

func TestEntraIdentifiersAreStable(t *testing.T) {
	r := require.New(t)
	_, handler := newAcceptanceAPI(t)
	environment := personaEnvironment(t, handler, `"persona":"entra"`)
	base := "/api/v1/environments/" + environment.ID
	troy := personaUser(t, handler, base, "Troy", "Barnes", "tbarnes", "troy.barnes@greendale.edu")
	abed := personaUser(t, handler, base, "Abed", "Nadir", "anadir", "abed.nadir@greendale.edu")

	first, _ := personaSignIn(t, handler, base, troy.ID, "openid profile")
	second, _ := personaSignIn(t, handler, base, troy.ID, "openid profile")
	other, _ := personaSignIn(t, handler, base, abed.ID, "openid profile")
	restarted := newTestIDPApp(t)
	restarted.instanceToken = "greendale-local-instance"
	restarted.adminHost = "127.0.0.1:8080"
	restarted.adminURL = "http://" + restarted.adminHost
	afterRestart, _ := personaSignIn(t, restarted.routes(), base, troy.ID, "openid profile")

	r.Equal(first["oid"], second["oid"])
	r.Equal(first["oid"], afterRestart["oid"])
	r.Equal(first["tid"], afterRestart["tid"])
	r.NotEqual(first["oid"], other["oid"])
	r.Equal(first["tid"], other["tid"])

	openidOnly, _ := personaSignIn(t, handler, base, troy.ID, "openid")
	r.Equal(first["tid"], openidOnly["tid"])
	r.NotContains(openidOnly, "oid")
	r.NotContains(openidOnly, "upn")
}

func TestAPIAcceptanceEntraGroupsOverage(t *testing.T) {
	r := require.New(t)
	_, handler := newAcceptanceAPI(t)
	environment := personaEnvironment(t, handler, `"persona":"entra","groups_overage_threshold":1`)
	r.Equal(1, environment.GroupsOverageThreshold)
	base := "/api/v1/environments/" + environment.ID
	troy := personaUser(t, handler, base, "Troy", "Barnes", "tbarnes", "troy.barnes@greendale.edu")
	abed := personaUser(t, handler, base, "Abed", "Nadir", "anadir", "abed.nadir@greendale.edu")
	acceptanceRequest(t, handler, http.MethodPost, base+"/groups", fmt.Sprintf(`{"display_name":"Study Group","member_ids":[%q,%q]}`, troy.ID, abed.ID), http.StatusCreated)
	acceptanceRequest(t, handler, http.MethodPost, base+"/groups", fmt.Sprintf(`{"display_name":"Air Conditioning Repair Annex","member_ids":[%q]}`, troy.ID), http.StatusCreated)

	troyClaims, troyToken := personaSignIn(t, handler, base, troy.ID, "openid profile groups")
	r.NotContains(troyClaims, "groups")
	r.Equal(map[string]any{"groups": "src1"}, troyClaims["_claim_names"])
	endpoint := "http://127.0.0.1:8080/oidc/greendale/users/" + troyClaims["oid"].(string) + "/getMemberObjects"
	r.Equal(map[string]any{"src1": map[string]any{"endpoint": endpoint}}, troyClaims["_claim_sources"])
	r.Equal(troyClaims["_claim_sources"], personaUserinfo(t, handler, troyToken)["_claim_sources"])

	abedClaims, abedToken := personaSignIn(t, handler, base, abed.ID, "openid profile groups")
	r.Equal([]any{"Study Group"}, abedClaims["groups"])
	r.NotContains(abedClaims, "_claim_names")
	_, troyWithoutGroups := personaSignIn(t, handler, base, troy.ID, "openid profile")

	path := strings.TrimPrefix(endpoint, "http://127.0.0.1:8080")
	tests := map[string]struct {
		path          string
		authorization string
		body          string
		want          int
		wantBody      string
	}{
		"own groups": {
			path: path, authorization: "Bearer " + troyToken, body: `{"securityEnabledOnly":false}`,
			want: http.StatusOK, wantBody: `"value":["Air Conditioning Repair Annex","Study Group"]`,
		},
		"missing token": {
			path: path, body: `{"securityEnabledOnly":false}`,
			want: http.StatusUnauthorized, wantBody: `"code":"InvalidAuthenticationToken"`,
		},
		"unknown token": {
			path: path, authorization: "Bearer chang-was-here", body: `{"securityEnabledOnly":false}`,
			want: http.StatusUnauthorized, wantBody: `"code":"InvalidAuthenticationToken"`,
		},
		"another user's token": {
			path: path, authorization: "Bearer " + abedToken, body: `{"securityEnabledOnly":false}`,
			want: http.StatusForbidden, wantBody: `"code":"Authorization_RequestDenied"`,
		},
		"token without the groups scope": {
			path: path, authorization: "Bearer " + troyWithoutGroups, body: `{"securityEnabledOnly":false}`,
			want: http.StatusForbidden, wantBody: `"code":"Authorization_RequestDenied"`,
		},
		"missing securityEnabledOnly": {
			path: path, authorization: "Bearer " + troyToken, body: `{}`,
			want: http.StatusBadRequest, wantBody: `"code":"Request_BadRequest"`,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			rec := personaMemberObjects(handler, tc.path, tc.authorization, tc.body)
			require.Equal(t, tc.want, rec.Code, rec.Body.String())
			require.Contains(t, rec.Body.String(), tc.wantBody)
		})
	}

	acceptanceRequest(t, handler, http.MethodPatch, base, `{"persona":"okta"}`, http.StatusOK)
	rec := personaMemberObjects(handler, path, "Bearer "+troyToken, `{"securityEnabledOnly":false}`)
	r.Equal(http.StatusNotFound, rec.Code)
}

func TestAPIAcceptancePersonaSettingsPersist(t *testing.T) {
	r := require.New(t)
	_, handler := newAcceptanceAPI(t)
	environment := personaEnvironment(t, handler, `"persona":"entra","groups_overage_threshold":150`)
	base := "/api/v1/environments/" + environment.ID
	stored := func() app {
		var found app
		r.NoError(json.Unmarshal(acceptanceRequest(t, handler, http.MethodGet, base, "", http.StatusOK).Body.Bytes(), &found))
		return found
	}

	r.Equal("entra", stored().Persona)
	r.Equal(150, stored().GroupsOverageThreshold)

	backup := acceptanceRequest(t, handler, http.MethodGet, base+"/backup", "", http.StatusOK).Body.String()
	r.Contains(backup, `"persona":"entra"`)
	acceptanceRequest(t, handler, http.MethodPatch, base, `{"persona":"google","groups_overage_threshold":0}`, http.StatusOK)
	r.Equal("google", stored().Persona)
	r.Zero(stored().GroupsOverageThreshold)

	acceptanceRequest(t, handler, http.MethodPost, base+"/restore", backup, http.StatusOK)
	r.Equal("entra", stored().Persona)
	r.Equal(150, stored().GroupsOverageThreshold)

	for name, body := range map[string]string{
		"unknown persona":    `{"persona":"auth0"}`,
		"negative threshold": `{"groups_overage_threshold":-1}`,
	} {
		t.Run(name, func(t *testing.T) {
			acceptanceRequest(t, handler, http.MethodPatch, base, body, http.StatusBadRequest)
		})
	}
}

func TestDiscoveryListsPersonaClaims(t *testing.T) {
	tests := map[string]struct {
		persona string
		want    []string
		wantNot []string
	}{
		"generic": {persona: "", want: []string{"email_verified"}, wantNot: []string{"oid", "tid", "upn", "ver", "hd"}},
		"entra":   {persona: personaEntra, want: []string{"oid", "tid", "upn"}, wantNot: []string{"email_verified"}},
		"okta":    {persona: personaOkta, want: []string{"ver", "email_verified"}, wantNot: []string{"oid", "hd"}},
		"google":  {persona: personaGoogle, want: []string{"hd", "email_verified"}, wantNot: []string{"oid", "ver"}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			claims := oidcClaimsSupported(app{Persona: tc.persona})
			for _, claim := range tc.want {
				require.Contains(t, claims, claim)
			}
			for _, claim := range tc.wantNot {
				require.NotContains(t, claims, claim)
			}
		})
	}
}

func TestPersonaClaimsYieldToRenamedMappings(t *testing.T) {
	r := require.New(t)
	troy := user{ID: "troy", GivenName: "Troy", FamilyName: "Barnes", Username: "tbarnes", Email: "troy.barnes@greendale.edu"}
	state := appState{Users: []user{troy}, Groups: []group{{DisplayName: "Study Group", MemberIDs: []string{"troy"}}}}
	scope := "openid profile email groups"

	generic := userClaims(state, app{IncludeGroupsClaim: true}, troy, scope, "")
	r.Equal(generic, userClaims(state, app{IncludeGroupsClaim: true, Persona: personaGeneric}, troy, scope, ""))
	r.Equal(map[string]any{
		"sub": "troy", "name": "Troy Barnes", "given_name": "Troy", "family_name": "Barnes",
		"preferred_username": "tbarnes", "email": "troy.barnes@greendale.edu", "email_verified": true,
		"groups": []string{"Study Group"},
	}, generic)

	mapped := userClaims(state, app{
		Persona: personaEntra, IncludeGroupsClaim: true,
		OIDCClaimMappings: oidcClaimMappings{Username: "upn", Groups: "roles"},
	}, troy, scope, "")
	r.Equal("tbarnes", mapped["upn"])
	r.Equal("tbarnes@greendale.edu", mapped["preferred_username"])
	r.Equal([]string{"Study Group"}, mapped["roles"])

	okta := userClaims(state, app{Persona: personaOkta, IncludeGroupsClaim: true, OIDCClaimMappings: oidcClaimMappings{Groups: "roles"}}, troy, scope, "")
	r.Equal([]string{"Everyone", "Study Group"}, okta["roles"])

	gmail := troy
	gmail.Email = "britta.perry@gmail.com"
	r.NotContains(userClaims(appState{Users: []user{gmail}}, app{Persona: personaGoogle}, gmail, scope, ""), "hd")
}

func TestAppFormSavesPersona(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	svc := newTestIDPApp(t)
	form := url.Values{
		"name":                     {"Greendale Portal"},
		"slug":                     {"greendale"},
		"chooser_mode":             {"list"},
		"persona":                  {"okta"},
		"groups_overage_threshold": {"175"},
	}
	req := httptest.NewRequest(http.MethodPost, "/apps/save", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	svc.routes().ServeHTTP(rec, req)
	r.Equal(http.StatusSeeOther, rec.Code, rec.Body.String())

	state, err := loadState()
	r.NoError(err)
	r.Len(state.Apps, 1)
	r.Equal("okta", state.Apps[0].Persona)
	r.Equal(175, state.Apps[0].GroupsOverageThreshold)

	page := httptest.NewRecorder()
	svc.routes().ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/?modal=app&id="+state.Apps[0].ID+"&environment="+state.Apps[0].ID, nil))
	r.Equal(http.StatusOK, page.Code)
	r.Contains(page.Body.String(), `<option value="okta" selected>Okta</option>`)
	r.Contains(page.Body.String(), `name="groups_overage_threshold" min="0" step="1" inputmode="numeric" value="175"`)

	form.Set("id", state.Apps[0].ID)
	form.Set("persona", "google")
	form.Set("groups_overage_threshold", "two hundred")
	req = httptest.NewRequest(http.MethodPost, "/apps/save", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	svc.routes().ServeHTTP(rec, req)
	r.Equal(http.StatusSeeOther, rec.Code)
	state, err = loadState()
	r.NoError(err)
	r.Equal("okta", state.Apps[0].Persona)

	retry := httptest.NewRequest(http.MethodGet, rec.Header().Get("Location"), nil)
	for _, cookie := range rec.Result().Cookies() {
		retry.AddCookie(cookie)
	}
	page = httptest.NewRecorder()
	svc.routes().ServeHTTP(page, retry)
	r.Equal(http.StatusOK, page.Code)
	r.Contains(page.Body.String(), "groups overage threshold must be a whole number")
	r.Contains(page.Body.String(), `<option value="google" selected>Google</option>`)
}

// personaEnvironment creates the greendale OIDC environment with extra JSON
// fields.
func personaEnvironment(t *testing.T, handler http.Handler, fields string) app {
	t.Helper()
	return acceptanceEnvironment(t, handler, `{"name":"Greendale Portal","slug":"greendale",`+fields+`,"include_groups_claim":true,"oidc_enabled":true,"oidc_client_id":"greendale-client","oidc_client_secret":"study-group-secret","oidc_redirect_uris":["http://greendale.test/callback"]}`)
}

func personaUser(t *testing.T, handler http.Handler, base string, given, family, username, email string) user {
	t.Helper()
	rec := acceptanceRequest(t, handler, http.MethodPost, base+"/users", fmt.Sprintf(`{"given_name":%q,"family_name":%q,"username":%q,"email":%q}`, given, family, username, email), http.StatusCreated)
	var created user
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &created))
	return created
}

// personaSignIn runs the greendale authorization code flow for userID and
// returns the ID token claims and the access token.
func personaSignIn(t *testing.T, handler http.Handler, base string, userID string, scope string) (map[string]any, string) {
	t.Helper()
	authorize := acceptanceRequest(t, handler, http.MethodPost, base+"/oidc/authorize", fmt.Sprintf(`{"user_id":%q,"response_type":"code","client_id":"greendale-client","redirect_uri":"http://greendale.test/callback","scope":%q}`, userID, scope), http.StatusOK)
	var authorization struct {
		Code string `json:"code"`
	}
	require.NoError(t, json.Unmarshal(authorize.Body.Bytes(), &authorization))
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authorization.Code},
		"client_id":     {"greendale-client"},
		"client_secret": {"study-group-secret"},
		"redirect_uri":  {"http://greendale.test/callback"},
	}
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/oidc/greendale/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var tokens struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &tokens))
	return decodeIDTokenClaims(t, tokens.IDToken), tokens.AccessToken
}

func personaUserinfo(t *testing.T, handler http.Handler, accessToken string) map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/oidc/greendale/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var claims map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &claims))
	return claims
}

func personaMemberObjects(handler http.Handler, path string, authorization string, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080"+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}
