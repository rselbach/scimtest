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

func TestIDTokenCarriesSessionID(t *testing.T) {
	r := require.New(t)
	svc := oidcFaultTestApp(t)
	signedIn := oidcAuthorize(t, svc, http.MethodPost, url.Values{"user_id": {"usr-1"}, "scope": {"openid offline_access"}})
	cookie := sessionCookie(t, signedIn)
	tokens := tokenBody(t, redeemToken(t, svc, redirectQuery(t, signedIn).Get("code")))
	sid := decodeIDTokenClaims(t, tokens["id_token"].(string))["sid"]
	r.Equal(cookie.Value, sid)

	sessions := svc.liveIdPSessions("example")
	r.Len(sessions, 1)
	r.Equal(sid, sessions[0].SessionID)
	r.Equal("usr-1", sessions[0].UserID)
	r.Equal([]string{"oidc"}, sessions[0].Protocols)

	refreshed := tokenBody(t, refreshTokens(t, svc, tokens["refresh_token"].(string), nil))
	r.Equal(sid, decodeIDTokenClaims(t, refreshed["id_token"].(string))["sid"])

	passive := oidcAuthorize(t, svc, http.MethodGet, url.Values{"prompt": {"none"}}, cookie)
	r.Equal(sid, idTokenClaimsForCode(t, svc, redirectQuery(t, passive).Get("code"))["sid"])
	r.Len(svc.liveIdPSessions("example"), 1)
}

func TestBrowserSignInJoinsOrReplacesSession(t *testing.T) {
	tests := map[string]struct {
		userID      string
		wantSameSID bool
		wantEvent   string
	}{
		"same user signs in again": {userID: "usr-1", wantSameSID: true},
		"another user signs in":    {userID: "usr-abed", wantEvent: "replaced by a sign-in as Abed Nadir"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			svc := oidcFaultTestApp(t)
			state, err := loadState()
			r.NoError(err)
			state.Users = append(state.Users, user{ID: "usr-abed", GivenName: "Abed", FamilyName: "Nadir", Username: "anadir", Email: "abed@greendale.edu", Active: true})
			r.NoError(saveState(state))
			first := oidcAuthorize(t, svc, http.MethodPost, url.Values{"user_id": {"usr-1"}})
			cookie := sessionCookie(t, first)

			second := oidcAuthorize(t, svc, http.MethodPost, url.Values{"user_id": {tc.userID}, "prompt": {"login"}}, cookie)
			claims := idTokenClaimsForCode(t, svc, redirectQuery(t, second).Get("code"))
			r.Equal(tc.userID, claims["sub"])
			r.Equal(tc.wantSameSID, claims["sid"] == cookie.Value)
			r.Equal(claims["sid"], sessionCookie(t, second).Value)
			sessions := svc.liveIdPSessions("example")
			r.Len(sessions, 1)
			r.Equal(claims["sid"], sessions[0].SessionID)
			if tc.wantEvent != "" {
				r.Contains(flowDetails(svc, "example"), "Session "+cookie.Value+" ended: "+tc.wantEvent)
			}
		})
	}
}

func TestSAMLSignInJoinsBrowserSession(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	svc := newTestIDPApp(t)
	state, troy := troyGreendaleSAMLState("")
	state.Apps[0].Protocol = "both"
	state.Apps[0].OIDCClientID = "greendale-client"
	state.Apps[0].OIDCClientSecret = "secret"
	state.Apps[0].OIDCRedirectURIs = []string{"https://sp.greendale.test/callback"}
	r.NoError(saveState(state))

	form := url.Values{"response_type": {"code"}, "client_id": {"greendale-client"}, "redirect_uri": {"https://sp.greendale.test/callback"}, "scope": {"openid"}, "user_id": {troy.ID}}
	req := httptest.NewRequest(http.MethodPost, "/oidc/greendale/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	oidcSignIn := httptest.NewRecorder()
	svc.routes().ServeHTTP(oidcSignIn, req)
	cookie := sessionCookie(t, oidcSignIn)

	samlSignIn := postSAMLSSO(t, svc, url.Values{"user_id": {troy.ID}}, cookie)
	postedSAMLAssertion(t, samlSignIn)
	r.Equal(cookie.Value, sessionCookie(t, samlSignIn).Value)
	sessions := svc.liveIdPSessions("greendale")
	r.Len(sessions, 1)
	r.Equal([]string{"oidc", "saml"}, sessions[0].Protocols)
}

func TestDiscoveryAdvertisesEndSessionEndpoint(t *testing.T) {
	r := require.New(t)
	svc := oidcFaultTestApp(t)
	rec := httptest.NewRecorder()
	svc.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oidc/example/.well-known/openid-configuration", nil))
	r.Equal(http.StatusOK, rec.Code)
	var discovery struct {
		EndSession string   `json:"end_session_endpoint"`
		Claims     []string `json:"claims_supported"`
	}
	r.NoError(json.Unmarshal(rec.Body.Bytes(), &discovery))
	r.Equal("http://example.com/oidc/example/logout", discovery.EndSession)
	r.Contains(discovery.Claims, "sid")
}

func TestEndSessionEndpoint(t *testing.T) {
	const registered = "http://client.test/callback"
	tests := map[string]struct {
		faults        url.Values // applied to the sign-in whose ID token is the hint
		hint          bool
		withoutCookie bool
		values        url.Values
		wantConfirm   bool
		wantStatus    int
		wantLocation  string
		wantError     string
	}{
		"hint for the browser's session": {
			hint:         true,
			values:       url.Values{"post_logout_redirect_uri": {registered}, "state": {"study-group"}},
			wantStatus:   http.StatusFound,
			wantLocation: registered + "?state=study-group",
		},
		"hint without a redirect":  {hint: true, wantStatus: http.StatusOK},
		"expired hint":             {faults: url.Values{"fault_id_token_ttl": {"-1h"}}, hint: true, values: url.Values{"post_logout_redirect_uri": {registered}}, wantStatus: http.StatusFound, wantLocation: registered},
		"hint without the cookie":  {hint: true, withoutCookie: true, values: url.Values{"post_logout_redirect_uri": {registered}}, wantConfirm: true, wantStatus: http.StatusFound, wantLocation: registered},
		"client_id without a hint": {values: url.Values{"client_id": {"example-client"}, "post_logout_redirect_uri": {registered}, "state": {"study-group"}}, wantConfirm: true, wantStatus: http.StatusFound, wantLocation: registered + "?state=study-group"},
		"unregistered redirect": {
			hint:       true,
			values:     url.Values{"post_logout_redirect_uri": {"http://client.test/elsewhere"}},
			wantStatus: http.StatusBadRequest,
			wantError:  "not a registered redirect URI",
		},
		"redirect without a hint or client_id": {values: url.Values{"post_logout_redirect_uri": {registered}}, wantStatus: http.StatusBadRequest, wantError: "requires id_token_hint or client_id"},
		"wrong client_id":                      {values: url.Values{"client_id": {"other-client"}}, wantStatus: http.StatusBadRequest, wantError: "client_id is invalid"},
		"hint for another client":              {faults: url.Values{"fault_tamper": {"wrong_audience"}}, hint: true, wantStatus: http.StatusBadRequest, wantError: "not issued to this client"},
		"hint from another issuer":             {faults: url.Values{"fault_tamper": {"wrong_issuer"}}, hint: true, wantStatus: http.StatusBadRequest, wantError: "not issued by this environment"},
		"hint with a broken signature":         {faults: url.Values{"fault_break_signature": {"1"}}, hint: true, wantStatus: http.StatusBadRequest, wantError: "signature is invalid"},
		"unsigned hint":                        {faults: url.Values{"fault_tamper": {"alg_none"}}, hint: true, wantStatus: http.StatusBadRequest, wantError: "must be signed with RS256"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			svc := oidcFaultTestApp(t)
			signInValues := url.Values{"user_id": {"usr-1"}}
			for key, values := range tc.faults {
				signInValues[key] = values
			}
			signedIn := oidcAuthorize(t, svc, http.MethodPost, signInValues)
			cookie := sessionCookie(t, signedIn)
			idToken := tokenBody(t, redeemToken(t, svc, redirectQuery(t, signedIn).Get("code")))["id_token"].(string)

			values := url.Values{}
			for key, vals := range tc.values {
				values[key] = vals
			}
			if tc.hint {
				values.Set("id_token_hint", idToken)
			}
			var cookies []*http.Cookie
			if !tc.withoutCookie {
				cookies = append(cookies, cookie)
			}
			rec := oidcLogout(t, svc, http.MethodGet, values, cookies...)
			if tc.wantConfirm {
				r.Equal(http.StatusOK, rec.Code)
				r.Contains(rec.Body.String(), "Sign out of Example?")
				r.Len(svc.liveIdPSessions("example"), 1, "confirmation must not end the session")
				rec = oidcLogout(t, svc, http.MethodPost, chooserSubmitForm(t, rec.Body.String(), "Sign out"), cookies...)
			}
			r.Equal(tc.wantStatus, rec.Code, rec.Body.String())
			r.Equal(tc.wantLocation, rec.Header().Get("Location"))
			if tc.wantError != "" {
				r.Contains(rec.Body.String(), tc.wantError)
				r.Len(svc.liveIdPSessions("example"), 1)
				r.Equal("failed", svc.flowEvents("example")[0].Outcome)
				return
			}
			if tc.wantStatus == http.StatusOK {
				r.Contains(rec.Body.String(), "Troy Barnes is signed out of Example.")
			}
			r.Empty(svc.liveIdPSessions("example"))
			r.Contains(flowDetails(svc, "example"), "Session "+cookie.Value+" ended: RP-initiated logout")
			if !tc.withoutCookie {
				cleared := rec.Result().Cookies()
				r.Len(cleared, 1)
				r.Equal(signInCookieName("example"), cleared[0].Name)
				r.Negative(cleared[0].MaxAge)
			}

			passive := oidcAuthorize(t, svc, http.MethodGet, url.Values{"prompt": {"none"}}, cookie)
			r.Equal("login_required", redirectQuery(t, passive).Get("error"))
			chooser := oidcAuthorize(t, svc, http.MethodGet, nil, cookie)
			r.NotContains(chooser.Body.String(), "Reuse session")
		})
	}
}

func TestEndSessionWithoutLiveSession(t *testing.T) {
	r := require.New(t)
	svc := oidcFaultTestApp(t)
	rec := oidcLogout(t, svc, http.MethodGet, url.Values{"client_id": {"example-client"}, "post_logout_redirect_uri": {"http://client.test/callback"}, "state": {"study-group"}})
	r.Equal(http.StatusFound, rec.Code)
	r.Equal("http://client.test/callback?state=study-group", rec.Header().Get("Location"))
	r.Contains(flowDetails(svc, "example"), "No live session to end; redirected to http://client.test/callback")
}

func TestInspectorEndsSessions(t *testing.T) {
	tests := map[string]struct {
		sessionID string // "live" names the signed-in session
		wantEnded bool
	}{
		"one session":   {sessionID: "live", wantEnded: true},
		"every session": {wantEnded: true},
		"other session": {sessionID: "greendale-session"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			svc := oidcFaultTestApp(t)
			cookie := sessionCookie(t, oidcAuthorize(t, svc, http.MethodPost, url.Values{"user_id": {"usr-1"}}))

			page := httptest.NewRecorder()
			svc.routes().ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/inspect/oidc/example", nil))
			r.Contains(page.Body.String(), "IdP sessions")
			r.Contains(page.Body.String(), `name="session_id" value="`+cookie.Value+`"`)

			form := url.Values{"return_tab": {"oidc-inspector"}}
			switch tc.sessionID {
			case "":
			case "live":
				form.Set("session_id", cookie.Value)
			default:
				form.Set("session_id", tc.sessionID)
			}
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/inspect/oidc/example/sessions/end", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			svc.routes().ServeHTTP(rec, req)
			r.Equal(http.StatusSeeOther, rec.Code)

			passive := redirectQuery(t, oidcAuthorize(t, svc, http.MethodGet, url.Values{"prompt": {"none"}}, cookie))
			if !tc.wantEnded {
				r.Len(svc.liveIdPSessions("example"), 1)
				r.NotEmpty(passive.Get("code"))
				return
			}
			r.Empty(svc.liveIdPSessions("example"))
			r.Equal("login_required", passive.Get("error"))
			r.Contains(flowDetails(svc, "example"), "Session "+cookie.Value+" ended: ended from the OIDC inspector")
		})
	}
}

func TestDirectoryChangesEndSessions(t *testing.T) {
	tests := map[string]struct {
		path       string
		wantReason string
	}{
		"deactivated": {path: "/users/usr-1/toggle-active", wantReason: "user deactivated"},
		"deleted":     {path: "/users/usr-1/delete", wantReason: "user deleted"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			svc := oidcFaultTestApp(t)
			cookie := sessionCookie(t, oidcAuthorize(t, svc, http.MethodPost, url.Values{"user_id": {"usr-1"}}))

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(url.Values{"environment": {"app-1"}}.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			svc.routes().ServeHTTP(rec, req)
			r.Equal(http.StatusSeeOther, rec.Code)

			r.Empty(svc.liveIdPSessions("example"))
			r.Contains(flowDetails(svc, "example"), "Session "+cookie.Value+" ended: "+tc.wantReason)
		})
	}
}

func TestAPIEndsSessions(t *testing.T) {
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
	result := apiPlaygroundRequest(t, handler, environmentID, adminURL, `{"user_id":"user-troy"}`)
	claims, ok := result.IDTokenClaims.(map[string]any)
	r.True(ok)

	listed := call(http.MethodGet, "/sessions")
	r.Equal(http.StatusOK, listed.Code, listed.Body.String())
	var body struct {
		Sessions []idpSessionView `json:"sessions"`
	}
	r.NoError(json.Unmarshal(listed.Body.Bytes(), &body))
	r.Len(body.Sessions, 1)
	r.Equal(claims["sid"], body.Sessions[0].SessionID)
	r.Equal("user-troy", body.Sessions[0].UserID)
	r.Equal("password", body.Sessions[0].AuthnStrength)

	unknown := call(http.MethodDelete, "/sessions?session_id=greendale-session")
	r.Equal(http.StatusNotFound, unknown.Code)

	ended := call(http.MethodDelete, "/sessions?session_id="+body.Sessions[0].SessionID)
	r.Equal(http.StatusOK, ended.Code, ended.Body.String())
	r.JSONEq(`{"ended":1}`, ended.Body.String())
	r.JSONEq(`{"sessions":[]}`, call(http.MethodGet, "/sessions").Body.String())
}

// sessionCookie returns the IdP session cookie a sign-in response set.
func sessionCookie(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, cookie := range rec.Result().Cookies() {
		if strings.HasPrefix(cookie.Name, "scimtest_chooser_") && cookie.Value != "" {
			return cookie
		}
	}
	t.Fatalf("response set no session cookie: %v", rec.Result().Cookies())
	return nil
}

// oidcLogout sends an end session request for oidcFaultTestApp.
func oidcLogout(t *testing.T, svc *webApp, method string, values url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/oidc/example/logout?"+values.Encode(), nil)
	if method == http.MethodPost {
		req = httptest.NewRequest(http.MethodPost, "/oidc/example/logout", strings.NewReader(values.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	svc.routes().ServeHTTP(rec, req)
	return rec
}

// flowDetails joins an environment's flow activity details.
func flowDetails(svc *webApp, slug string) string {
	var details []string
	for _, event := range svc.flowEvents(slug) {
		details = append(details, event.Detail)
	}
	return strings.Join(details, "\n")
}
