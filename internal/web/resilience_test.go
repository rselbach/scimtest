package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestResilienceEndpointRunAppliesConfiguredCount(t *testing.T) {
	r := require.New(t)
	svc := &webApp{}
	now := time.Date(2026, time.August, 14, 10, 0, 0, 0, time.UTC)

	run, err := svc.armResilienceRun("greendale", "token-outage", 2, now)
	r.NoError(err)
	r.Equal(resilienceRunArmed, run.State)

	for range 2 {
		action, ok := svc.reserveResilienceEndpointAction("greendale", "token", now)
		r.True(ok)
		r.Equal(503, action.Status)
		svc.completeResilienceEndpointAction("greendale", "token", action, now)
	}
	_, ok := svc.reserveResilienceEndpointAction("greendale", "token", now)
	r.False(ok)

	run, ok = svc.resilienceRun("greendale", now)
	r.True(ok)
	r.Equal(resilienceRunCompleted, run.State)
	r.Equal("2 of 2 injections applied", run.progress())
	r.Len(run.Decisions, 2)
}

func TestTokenOutageRecoversWithoutConsumingAuthorizationCode(t *testing.T) {
	r := require.New(t)
	svc := oidcFaultTestApp(t)
	_, err := svc.armResilienceRun("example", "token-outage", 2, time.Now())
	r.NoError(err)
	code := authorizeForCode(t, svc, nil)

	for range 2 {
		response := redeemToken(t, svc, code)
		r.Equal(http.StatusServiceUnavailable, response.Code)
		r.Equal("5", response.Header().Get("Retry-After"))
		r.Equal("no-store", response.Header().Get("Cache-Control"))
		r.Equal("no-cache", response.Header().Get("Pragma"))
		var body map[string]any
		r.NoError(json.Unmarshal(response.Body.Bytes(), &body))
		r.Equal("temporarily_unavailable", body["error"])
	}
	response := redeemToken(t, svc, code)
	r.Equal(http.StatusOK, response.Code)
	run, ok := svc.resilienceRun("example", time.Now())
	r.True(ok)
	r.Equal(resilienceRunCompleted, run.State)
}

func TestResilienceFlowPresetUsesExistingFaultPipeline(t *testing.T) {
	r := require.New(t)
	svc := oidcFaultTestApp(t)
	_, err := svc.armResilienceRun("example", "expired-token", 0, time.Now())
	r.NoError(err)

	code := authorizeForCode(t, svc, nil)
	response := redeemToken(t, svc, code)
	r.Equal(http.StatusOK, response.Code)
	var body map[string]any
	r.NoError(json.Unmarshal(response.Body.Bytes(), &body))
	claims := decodeIDTokenClaims(t, body["id_token"].(string))
	r.Less(claims["exp"].(float64), claims["iat"].(float64))
}

func TestDroppedClaimsAlsoApplyToUserinfo(t *testing.T) {
	r := require.New(t)
	svc := oidcFaultTestApp(t)
	code := authorizeForCode(t, svc, url.Values{"fault_drop_claims": {"email"}})
	tokenResponse := redeemToken(t, svc, code)
	r.Equal(http.StatusOK, tokenResponse.Code)
	var tokenBody map[string]any
	r.NoError(json.Unmarshal(tokenResponse.Body.Bytes(), &tokenBody))

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/oidc/example/userinfo", nil)
	request.Header.Set("Authorization", "Bearer "+tokenBody["access_token"].(string))
	svc.routes().ServeHTTP(response, request)
	r.Equal(http.StatusOK, response.Code)
	var claims map[string]any
	r.NoError(json.Unmarshal(response.Body.Bytes(), &claims))
	r.NotContains(claims, "email")
}

func TestResilienceDelayStopsWhenRequestIsCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.False(t, waitForResilienceDelay(ctx, time.Minute))
}

func TestResiliencePageShowsProtocolPresets(t *testing.T) {
	r := require.New(t)
	svc := oidcFaultTestApp(t)
	response := httptest.NewRecorder()
	svc.routes().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/inspect/resilience/example", nil))

	r.Equal(http.StatusOK, response.Code)
	r.Contains(response.Body.String(), "Token endpoint outage")
	r.Contains(response.Body.String(), "Expired ID token")
	r.NotContains(response.Body.String(), "SAML authentication failure")
	r.Contains(response.Body.String(), "</html>")
	r.NotContains(response.Body.String(), "nil pointer")
}

func TestInvalidTokenRequestsDoNotConsumeScenario(t *testing.T) {
	r := require.New(t)
	svc := oidcFaultTestApp(t)
	_, err := svc.armResilienceRun("example", "token-outage", 2, time.Now())
	r.NoError(err)
	code := authorizeForCode(t, svc, nil)

	tests := map[string]struct {
		code       string
		grantType  string
		secret     string
		wantStatus int
	}{
		"bad client credentials": {code: code, grantType: "authorization_code", secret: "wrong", wantStatus: http.StatusUnauthorized},
		"unsupported grant":      {code: code, grantType: "client_credentials", secret: "secret", wantStatus: http.StatusBadRequest},
		"unknown code":           {code: "unknown", grantType: "authorization_code", secret: "secret", wantStatus: http.StatusBadRequest},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			form := url.Values{
				"grant_type":   {tc.grantType},
				"code":         {tc.code},
				"redirect_uri": {"http://client.test/callback"},
			}
			response := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, "/oidc/example/token", strings.NewReader(form.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			request.SetBasicAuth("example-client", tc.secret)
			svc.routes().ServeHTTP(response, request)
			require.Equal(t, tc.wantStatus, response.Code)
		})
	}
	run, ok := svc.resilienceRun("example", time.Now())
	r.True(ok)
	r.Equal("0 of 2 injections applied", run.progress())
}

func TestCanceledTokenDelayRemainsArmed(t *testing.T) {
	r := require.New(t)
	svc := oidcFaultTestApp(t)
	_, err := svc.armResilienceRun("example", "slow-token", 0, time.Now())
	r.NoError(err)
	code := authorizeForCode(t, svc, nil)
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {"http://client.test/callback"},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request := httptest.NewRequest(http.MethodPost, "/oidc/example/token", strings.NewReader(form.Encode())).WithContext(ctx)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth("example-client", "secret")
	response := httptest.NewRecorder()
	svc.routes().ServeHTTP(response, request)

	run, ok := svc.resilienceRun("example", time.Now())
	r.True(ok)
	r.Equal(resilienceRunArmed, run.State)
	r.Equal("0 of 1 injections applied", run.progress())
	r.Len(run.Decisions, 1)
	r.Equal("canceled", run.Decisions[0].Outcome)
	svc.oidcMu.Lock()
	stored := svc.authCodes[code]
	svc.oidcMu.Unlock()
	r.False(stored.Redeeming)
}

func TestResiliencePageArmsAndDisarmsScenario(t *testing.T) {
	r := require.New(t)
	svc := oidcFaultTestApp(t)

	arm := httptest.NewRecorder()
	armRequest := httptest.NewRequest(http.MethodPost, "/inspect/resilience/example/arm", strings.NewReader(url.Values{
		"preset": {"token-outage"},
		"count":  {"3"},
	}.Encode()))
	armRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	svc.routes().ServeHTTP(arm, armRequest)
	r.Equal(http.StatusSeeOther, arm.Code)
	r.Equal("/inspect/resilience/example", arm.Header().Get("Location"))

	page := httptest.NewRecorder()
	svc.routes().ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/inspect/resilience/example", nil))
	r.Contains(page.Body.String(), "Active scenario")
	r.Contains(page.Body.String(), "0 of 3 injections applied")
	r.NotContains(page.Body.String(), "Choose a failure")

	disarm := httptest.NewRecorder()
	svc.routes().ServeHTTP(disarm, httptest.NewRequest(http.MethodPost, "/inspect/resilience/example/disarm", nil))
	r.Equal(http.StatusSeeOther, disarm.Code)
	run, ok := svc.resilienceRun("example", time.Now())
	r.True(ok)
	r.Equal(resilienceRunDisarmed, run.State)
	r.Equal("0 of 3 injections applied", run.progress())
}

func TestResiliencePageRejectsUnavailablePreset(t *testing.T) {
	r := require.New(t)
	svc := oidcFaultTestApp(t)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/inspect/resilience/example/arm", strings.NewReader(url.Values{
		"preset": {"saml-auth-failed"},
	}.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	svc.routes().ServeHTTP(response, request)

	r.Equal(http.StatusSeeOther, response.Code)
	r.Contains(response.Header().Get("Location"), "scenario+is+not+available")
	_, ok := svc.resilienceRun("example", time.Now())
	r.False(ok)
}

func TestResilienceFlowFaultAppliesOnce(t *testing.T) {
	r := require.New(t)
	svc := &webApp{}
	now := time.Date(2026, time.August, 14, 10, 0, 0, 0, time.UTC)

	_, err := svc.armResilienceRun("greendale", "expired-token", 0, now)
	r.NoError(err)
	r.True(svc.takeResilienceFlowFaults("greendale", now).IDTokenTTLSet)
	r.False(svc.takeResilienceFlowFaults("greendale", now).active())
}

func TestResilienceRunExpires(t *testing.T) {
	r := require.New(t)
	svc := &webApp{}
	now := time.Date(2026, time.August, 14, 10, 0, 0, 0, time.UTC)

	_, err := svc.armResilienceRun("greendale", "slow-token", 0, now)
	r.NoError(err)
	run, ok := svc.resilienceRun("greendale", now.Add(resilienceRunLifetime))
	r.True(ok)
	r.Equal(resilienceRunExpired, run.State)
	r.False(run.active())
	r.Len(run.Decisions, 1)
}

func TestExpiredResilienceRunCanBeReplaced(t *testing.T) {
	r := require.New(t)
	svc := &webApp{}
	now := time.Date(2026, time.August, 14, 10, 0, 0, 0, time.UTC)

	_, err := svc.armResilienceRun("greendale", "slow-token", 0, now)
	r.NoError(err)
	run, err := svc.armResilienceRun("greendale", "expired-token", 0, now.Add(resilienceRunLifetime))
	r.NoError(err)
	r.Equal("expired-token", run.PresetID)
}

func TestResilienceRejectsConcurrentRun(t *testing.T) {
	r := require.New(t)
	svc := &webApp{}
	now := time.Date(2026, time.August, 14, 10, 0, 0, 0, time.UTC)

	_, err := svc.armResilienceRun("greendale", "slow-token", 0, now)
	r.NoError(err)
	_, err = svc.armResilienceRun("greendale", "expired-token", 0, now)
	r.EqualError(err, "a resilience scenario is already active")
}

func TestResiliencePresetsMatchApplicationProtocols(t *testing.T) {
	tests := map[string]struct {
		app      app
		wantIDs  []string
		rejectID string
	}{
		"OIDC": {
			app:      app{Protocol: "oidc"},
			wantIDs:  []string{"token-outage", "slow-token", "expired-token", "broken-signature", "missing-email"},
			rejectID: "saml-auth-failed",
		},
		"SAML": {
			app:      app{Protocol: "saml"},
			wantIDs:  []string{"broken-signature", "saml-auth-failed"},
			rejectID: "token-outage",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var ids []string
			for _, preset := range resiliencePresetsForApp(tc.app) {
				ids = append(ids, preset.ID)
			}
			require.ElementsMatch(t, tc.wantIDs, ids)
			require.NotContains(t, ids, tc.rejectID)
		})
	}
}
