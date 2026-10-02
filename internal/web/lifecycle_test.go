package web

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLifecycleLeaverAcrossProtocols(t *testing.T) {
	r := require.New(t)
	target := newFakeSCIM(t)
	receiver := newLogoutReceiver(t, http.StatusOK)
	svc := lifecycleTestApp(t, func(found *app) {
		found.SCIMBaseURL = target.URL
		found.OIDCBackchannelLogoutURI = receiver.URL
	})
	provisionDirectory(t, svc)
	cookie, tokens := lifecycleOIDCSignIn(t, svc, "usr-troy", "openid email groups")
	lifecycleSAMLSignIn(t, svc, "usr-troy", cookie)
	sessionID := cookie.Value

	run := startLifecycle(t, svc, lifecycleLeaver, `{"user_id":"usr-troy"}`)

	r.Equal(lifecycleLeaver, run.Kind)
	r.Equal("Troy Barnes", run.User)
	r.Equal([]string{"deactivate", "sessions", "backchannel-" + sessionID, "saml-logout-" + sessionID, "revoke", "scim-user"}, stepIDs(run))
	r.Equal(lifecycleOK, lifecycleStepByID(t, run, "deactivate").Status)
	r.Equal("Ended session "+sessionID+" (oidc, saml)", lifecycleStepByID(t, run, "sessions").Detail)
	samlStep := lifecycleStepByID(t, run, "saml-logout-"+sessionID)
	r.Equal(lifecycleNeedsBrowser, samlStep.Status)
	r.Equal("http://127.0.0.1:8080/?environment=app-1&tab=lifecycle#lifecycle-run-"+run.ID, samlStep.BrowserURL)
	r.Equal("Revoked 1 tokens", lifecycleStepByID(t, run, "revoke").Detail)

	waitForLifecycle(svc)
	run = getLifecycleRun(t, svc, run.ID)
	r.Equal(lifecycleWaiting, run.Status, "the SAML logout still needs a browser")

	backchannel := lifecycleStepByID(t, run, "backchannel-"+sessionID)
	r.Equal(lifecycleOK, backchannel.Status, backchannel.Detail)
	r.Len(backchannel.Messages, 1)
	r.Equal("Logout token", backchannel.Messages[0].Sent)
	r.Equal(receiver.URL, backchannel.Messages[0].To)
	r.Equal("HTTP 200 OK", backchannel.Messages[0].Response)
	r.Len(receiver.tokens(), 1)
	r.Equal(sessionID, logoutTokenClaims(r, receiver.tokens()[0])["sid"])

	scim := lifecycleStepByID(t, run, "scim-user")
	r.Equal(lifecycleOK, scim.Status, scim.Detail)
	update := lastMessage(t, scim)
	troyPath := "/Users/" + remoteUserID(t, "usr-troy")
	r.Equal("PUT "+troyPath, update.Sent)
	r.Equal(target.URL+troyPath, update.To)
	r.Equal("200 OK", update.Response)
	r.Contains(update.Body, `"active":false`)
	r.Equal(false, target.resource(troyPath)["active"])

	state, err := loadStateForApp("app-1")
	r.NoError(err)
	troy, _ := userByID(state.Users, "usr-troy")
	r.False(troy.Active)
	r.Empty(svc.liveIdPSessions("greendale"))
	userinfo := lifecycleUserinfo(svc, tokens["access_token"].(string))
	r.Equal(http.StatusUnauthorized, userinfo.Code)

	sent := sendLifecycleSAMLLogout(t, svc, run.ID, samlStep.ID, "redirect")
	request, _ := receivedSAMLLogoutMessage(t, svc, sent, samlHTTPRedirectBinding, "SAMLRequest")
	requestID := request.SelectAttrValue("ID", "")
	run = getLifecycleRun(t, svc, run.ID)
	samlStep = lifecycleStepByID(t, run, samlStep.ID)
	r.Equal(lifecycleWaiting, samlStep.Status)
	r.Empty(samlStep.BrowserURL)
	r.Equal("LogoutRequest "+requestID+" (HTTP-Redirect)", lastMessage(t, samlStep).Sent)
	r.Equal(testSPSLOURL, lastMessage(t, samlStep).To)

	answer := sendSAMLLogoutMessage(t, svc, "greendale", samlHTTPRedirectBinding, "SAMLResponse", testSPLogoutResponse(requestID, samlStatusSuccess), "", nil)
	r.Equal(http.StatusOK, answer.Code, answer.Body.String())

	run = getLifecycleRun(t, svc, run.ID)
	samlStep = lifecycleStepByID(t, run, samlStep.ID)
	r.Equal(lifecycleOK, samlStep.Status, samlStep.Detail)
	r.Equal("LogoutResponse: the SP answered Success", lastMessage(t, samlStep).Response)
	r.Equal(lifecycleOK, run.Status)
	r.Contains(flowDetails(svc, "greendale"), "Leaver scenario started")
}

func TestLifecycleMoverChecksNextTokenAndAssertion(t *testing.T) {
	tests := map[string]struct {
		scope      string
		wantOIDC   string
		wantDetail string
	}{
		"app requests groups": {
			scope:      "openid email groups",
			wantOIDC:   lifecycleOK,
			wantDetail: "The ID token carried the new groups: Glee Club",
		},
		"app leaves out the groups scope": {
			scope:      "openid email",
			wantOIDC:   lifecycleFailed,
			wantDetail: "The ID token carried no groups",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			target := newFakeSCIM(t)
			svc := lifecycleTestApp(t, func(found *app) { found.SCIMBaseURL = target.URL })
			provisionDirectory(t, svc)

			run := startLifecycle(t, svc, lifecycleMover, `{"user_id":"usr-troy","add_group_ids":["grp-glee"],"remove_group_ids":["grp-study"]}`)

			r.Equal([]string{"groups", "scim-group-grp-glee", "scim-group-grp-study", "oidc-groups", "saml-groups"}, stepIDs(run))
			r.Equal("Added to Glee Club; removed from Study Group", lifecycleStepByID(t, run, "groups").Detail)
			r.Equal(lifecycleWaiting, lifecycleStepByID(t, run, "oidc-groups").Status)
			r.Equal(lifecycleWaiting, lifecycleStepByID(t, run, "saml-groups").Status)

			waitForLifecycle(svc)
			run = getLifecycleRun(t, svc, run.ID)
			for _, id := range []string{"scim-group-grp-glee", "scim-group-grp-study"} {
				step := lifecycleStepByID(t, run, id)
				r.Equal(lifecycleOK, step.Status, step.Detail)
				r.True(strings.HasPrefix(lastMessage(t, step).Sent, "PUT /Groups/remote-"), lastMessage(t, step).Sent)
			}
			troy := `"value":"` + remoteUserID(t, "usr-troy") + `"`
			r.Contains(lastMessage(t, lifecycleStepByID(t, run, "scim-group-grp-glee")).Body, troy)
			r.NotContains(lastMessage(t, lifecycleStepByID(t, run, "scim-group-grp-study")).Body, troy)
			r.Equal(lifecycleWaiting, run.Status)

			_, tokens := lifecycleOIDCSignIn(t, svc, "usr-troy", tc.scope)
			lifecycleSAMLSignIn(t, svc, "usr-troy")

			run = getLifecycleRun(t, svc, run.ID)
			oidcStep := lifecycleStepByID(t, run, "oidc-groups")
			r.Equal(tc.wantOIDC, oidcStep.Status)
			r.Equal(tc.wantDetail, oidcStep.Detail)
			r.Len(oidcStep.Messages, 1)
			r.Equal("ID token", oidcStep.Messages[0].Sent)
			r.Equal("greendale-portal", oidcStep.Messages[0].To)
			if tc.wantOIDC == lifecycleOK {
				r.Equal([]any{"Glee Club"}, decodeIDTokenClaims(t, tokens["id_token"].(string))["groups"])
			}
			samlStep := lifecycleStepByID(t, run, "saml-groups")
			r.Equal(lifecycleOK, samlStep.Status, samlStep.Detail)
			r.Equal("The SAML assertion carried the new groups: Glee Club", samlStep.Detail)
			r.Equal("https://sp.greendale.test/acs", samlStep.Messages[0].To)

			lifecycleUserinfo(svc, tokens["access_token"].(string))
			run = getLifecycleRun(t, svc, run.ID)
			r.Len(lifecycleStepByID(t, run, "oidc-groups").Messages, 1, "only the next response settles the check")
		})
	}
}

func TestLifecycleJoinerProvisionsUser(t *testing.T) {
	r := require.New(t)
	target := newFakeSCIM(t)
	svc := lifecycleTestApp(t, func(found *app) { found.SCIMBaseURL = target.URL })
	provisionDirectory(t, svc)

	run := startLifecycle(t, svc, lifecycleJoiner, `{"given_name":"Britta","family_name":"Perry","email":"britta@greendale.edu","group_ids":["grp-study"]}`)

	r.Equal([]string{"create", "groups", "scim-user", "scim-group-grp-study"}, stepIDs(run))
	r.Equal("Britta Perry", run.User)
	r.Equal("Added to Study Group", lifecycleStepByID(t, run, "groups").Detail)

	waitForLifecycle(svc)
	run = getLifecycleRun(t, svc, run.ID)
	r.Equal(lifecycleOK, run.Status)
	create := lifecycleStepByID(t, run, "scim-user")
	r.Equal(lifecycleOK, create.Status, create.Detail)
	posted := lastMessage(t, create)
	r.Equal("POST /Users", posted.Sent)
	r.Equal("201 Created", posted.Response)
	r.Contains(posted.Body, `"userName":"britta@greendale.edu"`)
	brittaID := remoteUserID(t, run.UserID)
	group := lifecycleStepByID(t, run, "scim-group-grp-study")
	r.Equal(lifecycleOK, group.Status, group.Detail)
	r.Contains(lastMessage(t, group).Body, `"value":"`+brittaID+`"`)

	britta := target.resource("/Users/" + brittaID)
	r.Equal("britta@greendale.edu", britta["userName"])
	r.Equal(run.UserID, britta["externalId"])
}

func TestLifecycleSkipsUnconfiguredProtocols(t *testing.T) {
	tests := map[string]struct {
		configure  func(*app)
		kind       string
		body       string
		wantStatus map[string]string
		wantDetail map[string]string
	}{
		"leaver without SCIM, back-channel, or SAML Single Logout": {
			configure: func(found *app) {
				withoutSCIM(found)
				found.SAMLSLOURL = ""
			},
			kind: lifecycleLeaver,
			body: `{"user_id":"usr-troy"}`,
			wantStatus: map[string]string{
				"deactivate": lifecycleOK, "sessions": lifecycleSkipped, "backchannel": lifecycleSkipped,
				"saml-logout": lifecycleSkipped, "revoke": lifecycleOK, "scim": lifecycleSkipped,
			},
			wantDetail: map[string]string{
				"sessions":    "Troy Barnes had no live IdP sessions",
				"backchannel": "Set the environment's back-channel logout URI to send logout tokens",
				"saml-logout": "Set the SP's Single Logout URL on the environment to send LogoutRequests",
				"scim":        "SCIM is not enabled for this environment",
			},
		},
		"leaver in a SCIM-only environment": {
			configure: func(found *app) {
				withoutOIDC(found)
				withoutSAML(found)
				found.SCIMBearerToken = ""
			},
			kind: lifecycleLeaver,
			body: `{"user_id":"usr-troy"}`,
			wantStatus: map[string]string{
				"deactivate": lifecycleOK, "sessions": lifecycleSkipped, "backchannel": lifecycleSkipped,
				"saml-logout": lifecycleSkipped, "revoke": lifecycleSkipped, "scim": lifecycleSkipped,
			},
			wantDetail: map[string]string{
				"sessions":    "The environment has no OIDC or SAML configuration",
				"backchannel": "OIDC is not enabled for this environment",
				"saml-logout": "SAML is not enabled for this environment",
				"revoke":      "OIDC is not enabled for this environment",
				"scim":        "Set the environment's SCIM base URL and bearer token to provision",
			},
		},
		"mover without a groups claim or SAML": {
			configure: func(found *app) {
				withoutSAML(found)
				withoutSCIM(found)
				found.IncludeGroupsClaim = false
			},
			kind: lifecycleMover,
			body: `{"user_id":"usr-troy","add_group_ids":["grp-glee"]}`,
			wantStatus: map[string]string{
				"groups": lifecycleOK, "scim": lifecycleSkipped, "oidc-groups": lifecycleSkipped, "saml-groups": lifecycleSkipped,
			},
			wantDetail: map[string]string{
				"oidc-groups": "The environment does not send groups; turn on the groups claim to check them",
				"saml-groups": "SAML is not enabled for this environment",
			},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			svc := lifecycleTestApp(t, func(found *app) {
				found.SCIMBaseURL = "https://scim.greendale.test"
				tc.configure(found)
			})

			run := startLifecycle(t, svc, tc.kind, tc.body)
			waitForLifecycle(svc)
			run = getLifecycleRun(t, svc, run.ID)

			got := make(map[string]string)
			for _, step := range run.Steps {
				got[step.ID] = step.Status
			}
			r.Equal(tc.wantStatus, got)
			for id, want := range tc.wantDetail {
				r.Equal(want, lifecycleStepByID(t, run, id).Detail, id)
			}
		})
	}
}

func TestLifecycleRecordsAppFailuresWithoutStopping(t *testing.T) {
	t.Run("leaver", func(t *testing.T) {
		r := require.New(t)
		target := newFakeSCIM(t)
		receiver := newLogoutReceiver(t, http.StatusInternalServerError)
		svc := lifecycleTestApp(t, func(found *app) {
			found.SCIMBaseURL = target.URL
			found.OIDCBackchannelLogoutURI = receiver.URL
		})
		provisionDirectory(t, svc)
		target.fail("PUT /Users", http.StatusInternalServerError)
		cookie, _ := lifecycleOIDCSignIn(t, svc, "usr-troy", "openid")

		run := startLifecycle(t, svc, lifecycleLeaver, `{"user_id":"usr-troy"}`)
		waitForLifecycle(svc)
		run = getLifecycleRun(t, svc, run.ID)

		r.Equal(lifecycleFailed, run.Status)
		backchannel := lifecycleStepByID(t, run, "backchannel-"+cookie.Value)
		r.Equal(lifecycleFailed, backchannel.Status)
		r.Equal("HTTP 500 Internal Server Error; the app did not accept it", backchannel.Messages[0].Response)
		r.Equal(lifecycleOK, lifecycleStepByID(t, run, "revoke").Status)
		scim := lifecycleStepByID(t, run, "scim-user")
		r.Equal(lifecycleFailed, scim.Status)
		failed := lastMessage(t, scim)
		r.Equal("PUT /Users/"+remoteUserID(t, "usr-troy"), failed.Sent)
		r.Equal(lifecycleFailed, failed.Outcome)
		r.Contains(failed.Response, "500 Internal Server Error")
	})
	t.Run("joiner", func(t *testing.T) {
		r := require.New(t)
		target := newFakeSCIM(t)
		svc := lifecycleTestApp(t, func(found *app) { found.SCIMBaseURL = target.URL })
		provisionDirectory(t, svc)
		target.fail("POST /Users", http.StatusConflict)

		run := startLifecycle(t, svc, lifecycleJoiner, `{"given_name":"Britta","family_name":"Perry","email":"britta@greendale.edu","group_ids":["grp-study"]}`)
		waitForLifecycle(svc)
		run = getLifecycleRun(t, svc, run.ID)

		r.Equal(lifecycleOK, lifecycleStepByID(t, run, "create").Status)
		r.Equal(lifecycleFailed, lifecycleStepByID(t, run, "scim-user").Status)
		group := lifecycleStepByID(t, run, "scim-group-grp-study")
		r.Equal(lifecycleSkipped, group.Status)
		r.Equal("Skipped because the user was not provisioned", group.Detail)
		r.Empty(group.Messages)
	})
}

func TestLifecycleRejectsInvalidRequests(t *testing.T) {
	tests := map[string]struct {
		path      string
		body      string
		want      int
		wantError string
	}{
		"unknown leaver": {
			path: "/api/v1/environments/app-1/lifecycle/leaver", body: `{"user_id":"usr-chang"}`,
			want: http.StatusNotFound, wantError: `user "usr-chang" not found`,
		},
		"mover without groups": {
			path: "/api/v1/environments/app-1/lifecycle/mover", body: `{"user_id":"usr-troy"}`,
			want: http.StatusBadRequest, wantError: "choose at least one group to add or remove",
		},
		"mover already in the group": {
			path: "/api/v1/environments/app-1/lifecycle/mover", body: `{"user_id":"usr-troy","add_group_ids":["grp-study"]}`,
			want: http.StatusBadRequest, wantError: "Troy Barnes is already in Study Group",
		},
		"mover not in the group": {
			path: "/api/v1/environments/app-1/lifecycle/mover", body: `{"user_id":"usr-troy","remove_group_ids":["grp-glee"]}`,
			want: http.StatusBadRequest, wantError: "Troy Barnes is not in Glee Club",
		},
		"inactive mover": {
			path: "/api/v1/environments/app-1/lifecycle/mover", body: `{"user_id":"usr-pierce","add_group_ids":["grp-glee"]}`,
			want: http.StatusBadRequest, wantError: "Pierce Hawthorne is inactive; activate the user before moving them",
		},
		"joiner with an unknown group": {
			path: "/api/v1/environments/app-1/lifecycle/joiner", body: `{"given_name":"Britta","email":"britta@greendale.edu","group_ids":["grp-chang"]}`,
			want: http.StatusNotFound, wantError: `group "grp-chang" not found`,
		},
		"unknown environment": {
			path: "/api/v1/environments/app-chang/lifecycle/leaver", body: `{"user_id":"usr-troy"}`,
			want: http.StatusNotFound,
		},
		"unknown run": {
			path: "/api/v1/environments/app-1/lifecycle/lifecycle_chang",
			want: http.StatusNotFound, wantError: `lifecycle run "lifecycle_chang" not found`,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			svc := lifecycleTestApp(t, withoutSCIM)
			method := http.MethodPost
			if tc.body == "" {
				method = http.MethodGet
			}

			rec := acceptanceRequest(t, svc.routes(), method, tc.path, tc.body, tc.want)

			if tc.wantError != "" {
				r.JSONEq(fmt.Sprintf(`{"error":%q}`, tc.wantError), rec.Body.String())
			}
			state, err := loadStateForApp("app-1")
			r.NoError(err)
			r.Len(state.Users, 3, "a rejected scenario changes nothing")
			r.Empty(svc.lifecycleRunsFor("greendale"))
		})
	}
}

func TestLifecycleTab(t *testing.T) {
	r := require.New(t)
	svc := lifecycleTestApp(t, withoutSCIM)
	cookie, _ := lifecycleOIDCSignIn(t, svc, "usr-troy", "openid")
	lifecycleSAMLSignIn(t, svc, "usr-troy", cookie)

	form := url.Values{"kind": {lifecycleLeaver}, "tab": {"lifecycle"}, "user_id": {"usr-troy"}}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/inspect/lifecycle/greendale/run", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	svc.routes().ServeHTTP(rec, req)

	r.Equal(http.StatusSeeOther, rec.Code, rec.Body.String())
	runs := svc.lifecycleRunsFor("greendale")
	r.Len(runs, 1)
	r.Equal("/?environment=app-1&tab=lifecycle#lifecycle-run-"+runs[0].ID, rec.Header().Get("Location"))

	page := httptest.NewRecorder()
	svc.routes().ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/?environment=app-1&tab=lifecycle", nil))
	r.Equal(http.StatusOK, page.Code)
	body := page.Body.String()
	r.Contains(body, `<h1>Lifecycle</h1>`)
	r.Contains(body, `tab=lifecycle" aria-current="page"`)
	r.Contains(body, `Leaver: Troy Barnes`)
	r.Contains(body, `action="/inspect/lifecycle/greendale/saml-logout"`)
	r.Contains(body, `name="step_id" value="saml-logout-`+cookie.Value+`"`)
	r.Contains(body, `Needs browser`)
	r.Contains(body, `<option value="usr-abed">Abed Nadir (abed@greendale.edu)</option>`)
	r.NotContains(body, `window.location.reload`, "nothing is running, so the page does not refresh itself")

	bad := httptest.NewRecorder()
	badReq := httptest.NewRequest(http.MethodPost, "/inspect/lifecycle/greendale/run", strings.NewReader(url.Values{"kind": {lifecycleMover}, "user_id": {"usr-troy"}}.Encode()))
	badReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	svc.routes().ServeHTTP(bad, badReq)
	r.Equal(http.StatusSeeOther, bad.Code)
	r.Equal("/?environment=app-1&error=choose+at+least+one+group+to+add+or+remove&tab=lifecycle", bad.Header().Get("Location"))
}

// lifecycleTestApp serves Greendale over OIDC, SAML, and SCIM with Troy and
// Abed in the Study Group, an empty Glee Club, and inactive Pierce.
// configure adjusts the environment before it is saved.
func lifecycleTestApp(t *testing.T, configure func(*app)) *webApp {
	t.Helper()
	setTestStateFile(t)
	svc := newTestIDPApp(t)
	svc.instanceToken = "greendale-local-instance"
	environment := app{
		ID:                                   "app-1",
		Name:                                 "Greendale",
		Slug:                                 "greendale",
		Protocol:                             "both",
		OIDCClientID:                         "greendale-portal",
		OIDCClientSecret:                     "secret",
		OIDCRedirectURIs:                     []string{"https://portal.greendale.test/callback"},
		OIDCBackchannelLogoutSessionRequired: true,
		SAMLEntityID:                         "urn:greendale:sp",
		SAMLACSURL:                           "https://sp.greendale.test/acs",
		SAMLSLOURL:                           testSPSLOURL,
		SAMLNameIDField:                      defaultSAMLNameIDField,
		SAMLNameIDFormat:                     samlNameIDFormatForField(defaultSAMLNameIDField),
		SAMLEmailAttributeName:               defaultSAMLEmailAttributeName,
		IncludeGroupsClaim:                   true,
		SCIMEnabled:                          true,
		SCIMBearerToken:                      "greendale-scim",
	}
	configure(&environment)
	require.NoError(t, saveState(appState{
		Config: config{IDPBaseURL: "http://idp.test"},
		Users: []user{
			{ID: "usr-troy", GivenName: "Troy", FamilyName: "Barnes", Email: "troy@greendale.edu", Username: "tbarnes", Active: true},
			{ID: "usr-abed", GivenName: "Abed", FamilyName: "Nadir", Email: "abed@greendale.edu", Username: "anadir", Active: true},
			{ID: "usr-pierce", GivenName: "Pierce", FamilyName: "Hawthorne", Email: "pierce@greendale.edu", Username: "phawthorne"},
		},
		Groups: []group{
			{ID: "grp-study", DisplayName: "Study Group", MemberIDs: []string{"usr-troy", "usr-abed"}},
			{ID: "grp-glee", DisplayName: "Glee Club"},
		},
		Apps: []app{environment},
	}))
	return svc
}

// withoutOIDC, withoutSAML, and withoutSCIM remove one protocol's setup from
// a lifecycleTestApp environment.
func withoutOIDC(found *app) {
	found.Protocol = strings.Replace(strings.Replace(found.Protocol, "both", "saml", 1), "oidc", "scim", 1)
	found.OIDCClientID, found.OIDCClientSecret, found.OIDCRedirectURIs = "", "", nil
}

func withoutSAML(found *app) {
	found.Protocol = strings.Replace(strings.Replace(found.Protocol, "both", "oidc", 1), "saml", "scim", 1)
	found.SAMLEntityID, found.SAMLACSURL, found.SAMLSLOURL = "", "", ""
}

func withoutSCIM(found *app) {
	found.SCIMEnabled = false
	found.SCIMBaseURL, found.SCIMBearerToken = "", ""
}

// provisionDirectory syncs the whole directory to the SCIM target.
func provisionDirectory(t *testing.T, svc *webApp) {
	t.Helper()
	acceptanceRequest(t, svc.routes(), http.MethodPost, "/api/v1/environments/app-1/sync/start", "", http.StatusAccepted)
	job := waitForSyncDone(t, svc)
	require.True(t, job.Success, job.Error)
}

// lifecycleOIDCSignIn signs userID in to Greendale with scope and redeems the
// code. It returns the session cookie and the token response.
func lifecycleOIDCSignIn(t *testing.T, svc *webApp, userID, scope string, cookies ...*http.Cookie) (*http.Cookie, map[string]any) {
	t.Helper()
	values := url.Values{
		"response_type": {"code"},
		"client_id":     {"greendale-portal"},
		"redirect_uri":  {"https://portal.greendale.test/callback"},
		"scope":         {scope},
		"user_id":       {userID},
		"prompt":        {"login"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oidc/greendale/authorize", strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	authorized := httptest.NewRecorder()
	svc.routes().ServeHTTP(authorized, req)
	cookie := sessionCookie(t, authorized)

	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {redirectQuery(t, authorized).Get("code")},
		"redirect_uri": {"https://portal.greendale.test/callback"},
	}
	tokenReq := httptest.NewRequest(http.MethodPost, "/oidc/greendale/token", strings.NewReader(form.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenReq.SetBasicAuth("greendale-portal", "secret")
	redeemed := httptest.NewRecorder()
	svc.routes().ServeHTTP(redeemed, tokenReq)
	return cookie, tokenBody(t, redeemed)
}

func lifecycleSAMLSignIn(t *testing.T, svc *webApp, userID string, cookies ...*http.Cookie) {
	t.Helper()
	rec := postSAMLSSOTo(t, svc, "greendale", url.Values{"user_id": {userID}}, cookies...)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
}

func lifecycleUserinfo(svc *webApp, accessToken string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/oidc/greendale/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	rec := httptest.NewRecorder()
	svc.routes().ServeHTTP(rec, req)
	return rec
}

func startLifecycle(t *testing.T, svc *webApp, kind, body string) lifecycleRun {
	t.Helper()
	rec := acceptanceRequest(t, svc.routes(), http.MethodPost, "/api/v1/environments/app-1/lifecycle/"+kind, body, http.StatusAccepted)
	var run lifecycleRun
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &run))
	return run
}

func getLifecycleRun(t *testing.T, svc *webApp, id string) lifecycleRun {
	t.Helper()
	rec := acceptanceRequest(t, svc.routes(), http.MethodGet, "/api/v1/environments/app-1/lifecycle/"+id, "", http.StatusOK)
	var run lifecycleRun
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &run))
	return run
}

// waitForLifecycle waits for the runs' SCIM pushes and logout tokens.
func waitForLifecycle(svc *webApp) {
	svc.lifecycleWork.Wait()
	svc.logoutDeliveries.Wait()
}

// sendLifecycleSAMLLogout presses a SAML logout step's Send LogoutRequest.
func sendLifecycleSAMLLogout(t *testing.T, svc *webApp, runID, stepID, binding string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"run_id": {runID}, "step_id": {stepID}, "binding": {binding}}
	req := httptest.NewRequest(http.MethodPost, "/inspect/lifecycle/greendale/saml-logout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	svc.routes().ServeHTTP(rec, req)
	return rec
}

func stepIDs(run lifecycleRun) []string {
	ids := make([]string, len(run.Steps))
	for i, step := range run.Steps {
		ids[i] = step.ID
	}
	return ids
}

func lifecycleStepByID(t *testing.T, run lifecycleRun, id string) lifecycleStep {
	t.Helper()
	for _, step := range run.Steps {
		if step.ID == id {
			return step
		}
	}
	t.Fatalf("run %s has no step %q: %v", run.ID, id, stepIDs(run))
	return lifecycleStep{}
}

func lastMessage(t *testing.T, step lifecycleStep) lifecycleMessage {
	t.Helper()
	require.NotEmpty(t, step.Messages, "step %s", step.ID)
	return step.Messages[len(step.Messages)-1]
}

// fakeSCIM is an in-memory SCIM service provider. It numbers resources
// remote-1, remote-2, and so on, in creation order.
type fakeSCIM struct {
	URL       string
	t         *testing.T
	mu        sync.Mutex
	created   int
	resources map[string]map[string]any // by path, such as /Users/remote-1
	failures  map[string]int            // by method and collection, such as "PUT /Users"
}

func newFakeSCIM(t *testing.T) *fakeSCIM {
	t.Helper()
	fake := &fakeSCIM{t: t, resources: make(map[string]map[string]any), failures: make(map[string]int)}
	server := httptest.NewServer(http.HandlerFunc(fake.serve))
	t.Cleanup(server.Close)
	fake.URL = server.URL
	return fake
}

func (f *fakeSCIM) fail(route string, status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failures[route] = status
}

func (f *fakeSCIM) resource(path string) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.resources[path]
}

func (f *fakeSCIM) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	collection := "/" + strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")[0]
	if status := f.failures[r.Method+" "+collection]; status != 0 {
		http.Error(w, "Greendale SCIM refused the request", status)
		return
	}
	var resource map[string]any
	if r.Method == http.MethodPost || r.Method == http.MethodPut {
		body, err := io.ReadAll(r.Body)
		if err == nil {
			err = json.Unmarshal(body, &resource)
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	status, response := http.StatusOK, any(resource)
	switch {
	case r.Method == http.MethodGet && r.URL.Path == collection:
		matches := []map[string]any{}
		externalID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Query().Get("filter"), `externalId eq "`), `"`)
		for path, stored := range f.resources {
			if strings.HasPrefix(path, collection+"/") && (externalID == "" || stored["externalId"] == externalID) {
				matches = append(matches, stored)
			}
		}
		response = map[string]any{"totalResults": len(matches), "startIndex": 1, "itemsPerPage": len(matches), "Resources": matches}
	case r.Method == http.MethodPost && r.URL.Path == collection:
		f.created++
		resource["id"] = fmt.Sprintf("remote-%d", f.created)
		f.resources[collection+"/"+resource["id"].(string)] = resource
		status = http.StatusCreated
	case r.Method == http.MethodPut && f.resources[r.URL.Path] != nil:
		resource["id"] = strings.TrimPrefix(r.URL.Path, collection+"/")
		f.resources[r.URL.Path] = resource
	case r.Method == http.MethodGet && f.resources[r.URL.Path] != nil:
		response = f.resources[r.URL.Path]
	default:
		http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		f.t.Errorf("write SCIM response: %v", err)
	}
}

// remoteUserID returns the SCIM id that userID was provisioned under.
func remoteUserID(t *testing.T, userID string) string {
	t.Helper()
	state, err := loadStateForApp("app-1")
	require.NoError(t, err)
	remoteID := state.UserSync["app-1"][userID].RemoteID
	require.NotEmpty(t, remoteID, "%s was not provisioned", userID)
	return remoteID
}
