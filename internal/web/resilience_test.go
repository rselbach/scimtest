package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
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
		action, ok := svc.takeResilienceEndpointAction("greendale", "token", now)
		r.True(ok)
		r.Equal(503, action.Status)
	}
	_, ok := svc.takeResilienceEndpointAction("greendale", "token", now)
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
