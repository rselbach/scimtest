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

func acceptancePlayground(t *testing.T, handler http.Handler) {
	f := newSharedIdentity(t, handler)
	for _, public := range []bool{false, true} {
		secret := "study-group-secret"
		if public {
			secret = ""
		}
		acceptanceRequest(t, handler, http.MethodPatch, f.base, sharedJSON(t, map[string]any{"oidc_public_client": public, "oidc_client_secret": secret}), http.StatusOK)
		var result apiOIDCPlaygroundResult
		f.decode(t, http.MethodPost, "/oidc/playground", sharedJSON(t, map[string]any{"user_id": f.troy.ID, "refresh": true}), http.StatusOK, &result)
		r := require.New(t)
		r.Empty(result.Error)
		r.Equal(http.StatusFound, result.AuthorizeStatus)
		r.Equal(http.StatusOK, result.TokenStatus)
		r.Equal(http.StatusOK, result.UserinfoStatus)
		r.Equal(http.StatusOK, result.RefreshStatus)
		r.NotEmpty(result.Token["refresh_token"])
		r.NotEqual(result.Token["refresh_token"], result.Refresh["refresh_token"])
		claims := result.RefreshedClaims.(map[string]any)
		r.Equal("troy.barnes@greendale.edu", claims["email"])
		r.NotContains(claims, "nonce")
	}
	for name, tc := range map[string]struct {
		faults string
		want   string
	}{
		"unknown":   {faults: `{"tamper":["bogus"]}`, want: `ignored unknown fault_tamper \"bogus\"`},
		"SAML-only": {faults: `{"tamper":["wrong_recipient"]}`, want: "tamper wrong_recipient is not valid for an OIDC playground flow"},
		"SAML TTL":  {faults: `{"assertion_ttl":"-1m"}`, want: "assertion_ttl is not valid for an OIDC playground flow"},
	} {
		t.Run(name, func(t *testing.T) {
			response := acceptanceRequest(t, handler, http.MethodPost, f.base+"/oidc/playground", `{"user_id":"`+f.troy.ID+`","faults":`+tc.faults+`}`, http.StatusBadRequest)
			require.New(t).Contains(response.Body.String(), tc.want)
		})
	}
}

func acceptanceResilienceAndFaults(t *testing.T, handler http.Handler) {
	r := require.New(t)
	f := newSharedIdentity(t, handler)
	acceptanceRequest(t, handler, http.MethodPut, f.base+"/faults", `{"drop_claims":["email"],"id_token_ttl":"-1m"}`, http.StatusOK)
	values := f.authorizeValues()
	values.Set("user_id", f.troy.ID)
	_, tokens := f.authorize(t, values)
	claims := decodeIDTokenClaims(t, tokens["id_token"].(string))
	r.NotContains(claims, "email")
	r.Less(claims["exp"], claims["iat"])
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/oidc/greendale/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tokens["access_token"].(string))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	r.Equal(http.StatusOK, response.Code)
	var userinfo map[string]any
	r.NoError(json.Unmarshal(response.Body.Bytes(), &userinfo))
	r.NotContains(userinfo, "email")
	_, tokens = f.authorize(t, values)
	r.Equal("troy.barnes@greendale.edu", decodeIDTokenClaims(t, tokens["id_token"].(string))["email"])
	var run resilienceRun
	f.decode(t, http.MethodPost, "/scenarios/arm", `{"preset_id":"token-outage","count":2}`, http.StatusCreated, &run)
	r.Equal(resilienceRunArmed, run.State)
	authorized := f.browser(http.MethodPost, "/oidc/greendale/authorize", values)
	r.Equal(http.StatusFound, authorized.Code)
	location, err := url.Parse(authorized.Header().Get("Location"))
	r.NoError(err)
	code := location.Query().Get("code")
	r.NotEmpty(code)
	r.Equal(http.StatusUnauthorized, f.exchange(code, "chang-was-here").Code)
	r.Equal(http.StatusBadRequest, f.exchange("chang-was-here", "study-group-secret").Code)
	for range 2 {
		response = f.exchange(code, "study-group-secret")
		r.Equal(http.StatusServiceUnavailable, response.Code)
		r.Equal("5", response.Header().Get("Retry-After"))
		r.Equal("no-store", response.Header().Get("Cache-Control"))
		r.Equal("no-cache", response.Header().Get("Pragma"))
		r.Contains(response.Body.String(), "temporarily_unavailable")
	}
	r.Equal(http.StatusOK, f.exchange(code, "study-group-secret").Code)
	var scenario struct{ Run *resilienceRun }
	f.decode(t, http.MethodGet, "/scenarios", "", http.StatusOK, &scenario)
	r.NotNil(scenario.Run)
	r.Equal(resilienceRunCompleted, scenario.Run.State)
	r.Equal("2 of 2 injections applied", scenario.Run.progress())
	f.decode(t, http.MethodPost, "/scenarios/arm", `{"preset_id":"token-outage","count":1}`, http.StatusCreated, &run)
	f.decode(t, http.MethodPost, "/scenarios/disarm", `{}`, http.StatusOK, &run)
	r.Equal(resilienceRunDisarmed, run.State)
	acceptanceRequest(t, handler, http.MethodPost, f.base+"/scenarios/disarm", `{}`, http.StatusConflict)
}

func acceptanceLifecycleSCIM(t *testing.T, handler http.Handler) {
	r := require.New(t)
	f := newSharedIdentity(t, handler)
	target := newFakeSCIM(t)
	receiver := newLogoutReceiver(t, http.StatusOK)
	acceptanceRequest(t, handler, http.MethodPatch, f.base, sharedJSON(t, map[string]any{
		"scim_enabled": true, "scim_base_url": target.URL, "scim_bearer_token": "greendale-scim",
		"oidc_backchannel_logout_uri": receiver.URL, "oidc_backchannel_logout_session_required": true,
	}), http.StatusOK)
	var study, glee group
	f.decode(t, http.MethodPost, "/groups", sharedJSON(t, map[string]any{"display_name": "Study Group", "member_ids": []string{f.troy.ID, f.abed.ID}}), http.StatusCreated, &study)
	f.decode(t, http.MethodPost, "/groups", `{"display_name":"Glee Club"}`, http.StatusCreated, &glee)
	acceptanceRequest(t, handler, http.MethodPost, f.base+"/sync/start", `{}`, http.StatusAccepted)
	var job syncJobSnapshot
	r.Eventually(func() bool {
		f.decode(t, http.MethodGet, "/sync/status", "", http.StatusOK, &job)
		return job.Done
	}, 10*time.Second, 20*time.Millisecond)
	r.True(job.Success, job.Error)
	joined := f.startRun(t, lifecycleJoiner, map[string]any{"given_name": "Britta", "family_name": "Perry", "email": "britta@greendale.edu", "group_ids": []string{study.ID}})
	joined = f.waitRun(t, joined.ID)
	r.Equal(lifecycleOK, joined.Status)
	var britta user
	f.decode(t, http.MethodGet, "/users/"+joined.UserID, "", http.StatusOK, &britta)
	r.NotEmpty(britta.RemoteID)
	r.Equal("britta@greendale.edu", target.resource("/Users/" + britta.RemoteID)["userName"])
	r.Contains(lastMessage(t, lifecycleStepByID(t, joined, "scim-group-"+study.ID)).Body, `"value":"`+britta.RemoteID+`"`)
	moved := f.startRun(t, lifecycleMover, map[string]any{"user_id": f.troy.ID, "add_group_ids": []string{glee.ID}, "remove_group_ids": []string{study.ID}})
	moved = f.waitRun(t, moved.ID)
	r.Equal(lifecycleWaiting, moved.Status)
	values := f.authorizeValues()
	values.Set("user_id", f.troy.ID)
	cookie, tokens := f.authorize(t, values)
	response := f.browser(http.MethodPost, "/saml/greendale/sso", url.Values{"user_id": {f.troy.ID}}, cookie)
	r.Equal(http.StatusOK, response.Code, response.Body.String())
	f.decode(t, http.MethodGet, "/lifecycle/"+moved.ID, "", http.StatusOK, &moved)
	r.Equal(lifecycleOK, moved.Status)
	r.Equal("The ID token carried the new groups: Glee Club", lifecycleStepByID(t, moved, "oidc-groups").Detail)
	r.Equal("The SAML assertion carried the new groups: Glee Club", lifecycleStepByID(t, moved, "saml-groups").Detail)
	leaver := f.startRun(t, lifecycleLeaver, map[string]any{"user_id": f.troy.ID})
	leaver = f.waitRun(t, leaver.ID)
	r.Equal(lifecycleOK, leaver.Status)
	r.Equal(lifecycleOK, lifecycleStepByID(t, leaver, "backchannel-"+cookie.Value).Status)
	r.Equal(lifecycleOK, lifecycleStepByID(t, leaver, "scim-user").Status)
	r.Len(receiver.tokens(), 1)
	r.Equal(cookie.Value, decodeIDTokenClaims(t, receiver.tokens()[0])["sid"])
	var troy user
	f.decode(t, http.MethodGet, "/users/"+f.troy.ID, "", http.StatusOK, &troy)
	r.False(troy.Active)
	r.Equal(false, target.resource("/Users/" + troy.RemoteID)["active"])
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/oidc/greendale/userinfo", nil)
	request.Header.Set("Authorization", "Bearer "+tokens["access_token"].(string))
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	r.Equal(http.StatusUnauthorized, response.Code)
	var runs struct{ Runs []lifecycleRun }
	f.decode(t, http.MethodGet, "/lifecycle", "", http.StatusOK, &runs)
	r.Len(runs.Runs, 3)
	var flows []flowEvent
	f.decode(t, http.MethodGet, "/flows", "", http.StatusOK, &flows)
	found := false
	for _, flow := range flows {
		found = found || strings.Contains(flow.Detail, "Leaver scenario started")
	}
	r.True(found, "lifecycle start must appear in flow activity")
}
