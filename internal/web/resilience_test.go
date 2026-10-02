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

func TestResilienceDashboardShowsProtocolPresets(t *testing.T) {
	r := require.New(t)
	svc := oidcFaultTestApp(t)
	legacy := httptest.NewRecorder()
	svc.routes().ServeHTTP(legacy, httptest.NewRequest(http.MethodGet, "/inspect/resilience/example", nil))
	r.Equal(http.StatusSeeOther, legacy.Code)
	r.Equal("/?environment=app-1&tab=resilience", legacy.Header().Get("Location"))

	response := httptest.NewRecorder()
	svc.routes().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/?tab=resilience&environment=app-1", nil))

	r.Equal(http.StatusOK, response.Code)
	r.Contains(response.Body.String(), `class="side-item active" href="/?environment=app-1&amp;tab=resilience"`)
	r.Contains(response.Body.String(), `<input type="hidden" name="tab" value="resilience">`)
	r.Contains(response.Body.String(), `<h1>Fault Injection</h1>`)
	r.Contains(response.Body.String(), `id="app-shell"`)
	r.NotContains(response.Body.String(), "Provision to")
	r.NotContains(response.Body.String(), ">Add user</a>")
	r.Contains(response.Body.String(), "Token endpoint outage")
	r.Contains(response.Body.String(), "Expired ID token")
	r.NotContains(response.Body.String(), "SAML authentication failure")
	r.Contains(response.Body.String(), "</html>")
	r.NotContains(response.Body.String(), "nil pointer")
}

func TestResilienceDashboardMatchesEnvironmentSetup(t *testing.T) {
	tests := map[string]struct {
		app       app
		arm       string
		want      string
		doNotWant string
	}{
		"unfinished OIDC": {
			app:       app{ID: "app-1", Name: "Greendale Portal", Slug: "greendale", Protocol: "oidc"},
			arm:       "slow-token",
			want:      "Finish OIDC setup",
			doNotWant: "Open built-in RP",
		},
		"SAML": {
			app:       app{ID: "app-1", Name: "Greendale Portal", Slug: "greendale", Protocol: "saml", SAMLACSURL: "https://client.test/saml/acs"},
			want:      "SAML authentication failure",
			doNotWant: "Token endpoint outage",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			setTestStateFile(t)
			svc := newTestIDPApp(t)
			require.NoError(t, saveState(appState{Apps: []app{tc.app}}))
			if tc.arm != "" {
				_, err := svc.armResilienceRun(tc.app.Slug, tc.arm, 0, time.Now())
				require.NoError(t, err)
			}
			response := httptest.NewRecorder()
			svc.routes().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/?tab=resilience&environment=app-1", nil))

			require.Equal(t, http.StatusOK, response.Code)
			require.Contains(t, response.Body.String(), tc.want)
			require.NotContains(t, response.Body.String(), tc.doNotWant)
		})
	}
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
	r.Equal("/?environment=app-1&tab=resilience", arm.Header().Get("Location"))

	page := httptest.NewRecorder()
	svc.routes().ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/?tab=resilience&environment=app-1", nil))
	r.Contains(page.Body.String(), "Active scenario")
	r.Contains(page.Body.String(), "0 of 3 injections applied")
	r.NotContains(page.Body.String(), "Choose a failure")
	r.Contains(page.Body.String(), `<span class="badge dirty">Armed</span>`)

	disarm := httptest.NewRecorder()
	svc.routes().ServeHTTP(disarm, httptest.NewRequest(http.MethodPost, "/inspect/resilience/example/disarm", nil))
	r.Equal(http.StatusSeeOther, disarm.Code)
	r.Equal("/?environment=app-1&tab=resilience", disarm.Header().Get("Location"))
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
	action, ok := svc.reserveResilienceEndpointAction("greendale", "token", now)
	r.True(ok)
	run, ok := svc.resilienceRun("greendale", now.Add(resilienceRunLifetime))
	r.True(ok)
	r.Equal(resilienceRunExpired, run.State)
	r.False(run.active())
	r.Zero(run.InFlight)
	r.Len(run.Decisions, 1)
	r.False(svc.completeResilienceEndpointAction("greendale", "token", action, now.Add(resilienceRunLifetime)))
}

func TestDisarmingResilienceRunCancelsReservedAction(t *testing.T) {
	r := require.New(t)
	svc := &webApp{}
	now := time.Date(2026, time.August, 14, 10, 0, 0, 0, time.UTC)

	_, err := svc.armResilienceRun("greendale", "slow-token", 0, now)
	r.NoError(err)
	action, ok := svc.reserveResilienceEndpointAction("greendale", "token", now)
	r.True(ok)
	r.True(svc.disarmResilienceRun("greendale", now.Add(time.Second)))
	r.False(svc.completeResilienceEndpointAction("greendale", "token", action, now.Add(3*time.Second)))
	run, ok := svc.resilienceRun("greendale", now.Add(3*time.Second))
	r.True(ok)
	r.Equal(resilienceRunDisarmed, run.State)
	r.Zero(run.InFlight)
	r.Equal("0 of 1 injections applied", run.progress())
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
	r.EqualError(err, "a fault injection scenario is already active")
}

func TestResiliencePresetsMatchApplicationProtocols(t *testing.T) {
	tests := map[string]struct {
		app      app
		wantIDs  []string
		rejectID string
	}{
		"OIDC": {
			app:      app{Protocol: "oidc"},
			wantIDs:  []string{"token-outage", "slow-token", "stale-jwks", "expired-token", "broken-signature", "missing-email", "unsigned-id-token", "wrong-audience"},
			rejectID: "saml-auth-failed",
		},
		"SAML": {
			app:      app{Protocol: "saml"},
			wantIDs:  []string{"broken-signature", "wrong-audience", "replayed-assertion", "saml-auth-failed"},
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

func TestTokenOutageAppliesToRefreshWithoutConsumingToken(t *testing.T) {
	r := require.New(t)
	svc := oidcFaultTestApp(t)
	first := tokenBody(t, redeemToken(t, svc, authorizeForCode(t, svc, url.Values{"scope": {"openid offline_access"}})))
	_, err := svc.armResilienceRun("example", "token-outage", 1, time.Now())
	r.NoError(err)

	outage := refreshTokens(t, svc, first["refresh_token"].(string), nil)
	r.Equal(http.StatusServiceUnavailable, outage.Code)
	r.Contains(outage.Body.String(), "temporarily_unavailable")

	recovered := refreshTokens(t, svc, first["refresh_token"].(string), nil)
	r.Equal(http.StatusOK, recovered.Code, recovered.Body.String())
	run, ok := svc.resilienceRun("example", time.Now())
	r.True(ok)
	r.Equal(resilienceRunCompleted, run.State)
	r.Equal("token (refresh_token)", run.Decisions[len(run.Decisions)-1].Phase)
}

func TestSlowRefreshHoldsTokenUntilDelayEnds(t *testing.T) {
	r := require.New(t)
	svc := oidcFaultTestApp(t)
	first := tokenBody(t, redeemToken(t, svc, authorizeForCode(t, svc, url.Values{"scope": {"openid offline_access"}})))
	presented := first["refresh_token"].(string)
	_, err := svc.armResilienceRun("example", "slow-token", 0, time.Now())
	r.NoError(err)
	svc.resilienceMu.Lock()
	run := svc.resilienceRuns["example"]
	run.Action.Delay = 200 * time.Millisecond
	svc.resilienceRuns["example"] = run
	svc.resilienceMu.Unlock()

	slow := make(chan *httptest.ResponseRecorder)
	go func() { slow <- refreshTokens(t, svc, presented, nil) }()
	r.Eventually(func() bool {
		svc.oidcMu.Lock()
		defer svc.oidcMu.Unlock()
		return svc.refreshTokens[presented].Redeeming
	}, time.Second, 5*time.Millisecond)

	concurrent := refreshTokens(t, svc, presented, nil)
	r.Equal(http.StatusBadRequest, concurrent.Code)
	r.Contains(concurrent.Body.String(), "invalid_grant")
	delayed := <-slow
	r.Equal(http.StatusOK, delayed.Code, delayed.Body.String())

	reused := refreshTokens(t, svc, presented, nil)
	r.Equal(http.StatusBadRequest, reused.Code, "the delayed refresh rotated the token")
}

func TestCanceledRefreshDelayKeepsToken(t *testing.T) {
	r := require.New(t)
	svc := oidcFaultTestApp(t)
	first := tokenBody(t, redeemToken(t, svc, authorizeForCode(t, svc, url.Values{"scope": {"openid offline_access"}})))
	presented := first["refresh_token"].(string)
	_, err := svc.armResilienceRun("example", "slow-token", 0, time.Now())
	r.NoError(err)

	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {presented}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request := httptest.NewRequest(http.MethodPost, "/oidc/example/token", strings.NewReader(form.Encode())).WithContext(ctx)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth("example-client", "secret")
	svc.routes().ServeHTTP(httptest.NewRecorder(), request)

	run, ok := svc.resilienceRun("example", time.Now())
	r.True(ok)
	r.Equal(resilienceRunArmed, run.State)
	r.Equal("token (refresh_token)", run.Decisions[0].Phase)
	r.Equal("canceled", run.Decisions[0].Outcome)
	svc.oidcMu.Lock()
	stored, found := svc.refreshTokens[presented]
	svc.oidcMu.Unlock()
	r.True(found)
	r.False(stored.Redeeming)
}

func TestSlowTokenValidatesCurrentGrantAndUser(t *testing.T) {
	for grantType, wantAccessCount := range map[string]int{"authorization_code": 0, "refresh_token": 1} {
		t.Run(grantType, func(t *testing.T) {
			for name, tc := range map[string]struct {
				method string
				body   string
				expire bool
				want   int
			}{
				"deactivated user": {method: http.MethodPatch, body: `{"active":false}`, want: http.StatusBadRequest},
				"deleted user":     {method: http.MethodDelete, want: http.StatusBadRequest},
				"expired grant":    {expire: true, want: http.StatusBadRequest},
				"updated email":    {method: http.MethodPatch, body: `{"email":"troy.barnes@greendale.edu"}`, want: http.StatusOK},
			} {
				t.Run(name, func(t *testing.T) {
					r := require.New(t)
					svc := oidcFaultTestApp(t)
					presented := authorizeForCode(t, svc, url.Values{"scope": {"openid email offline_access"}})
					form := url.Values{"grant_type": {grantType}, "code": {presented}, "redirect_uri": {"http://client.test/callback"}}
					if grantType == "refresh_token" {
						first := tokenBody(t, redeemToken(t, svc, presented))
						presented = first["refresh_token"].(string)
						form = url.Values{"grant_type": {grantType}, "refresh_token": {presented}}
					}
					svc.instanceToken = "greendale-local-instance"
					svc.adminHost = "127.0.0.1:8080"
					svc.adminURL = "http://" + svc.adminHost
					_, err := svc.armResilienceRun("example", "slow-token", 0, time.Now())
					r.NoError(err)
					svc.resilienceMu.Lock()
					run := svc.resilienceRuns["example"]
					run.Action.Delay = 300 * time.Millisecond
					svc.resilienceRuns["example"] = run
					svc.resilienceMu.Unlock()

					ctx, cancel := context.WithCancel(context.Background())
					finished := make(chan struct{})
					t.Cleanup(func() {
						cancel()
						select {
						case <-finished:
						case <-time.After(time.Second):
							t.Error("delayed token exchange did not stop")
						}
					})
					request := httptest.NewRequest(http.MethodPost, "/oidc/example/token", strings.NewReader(form.Encode())).WithContext(ctx)
					request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					request.SetBasicAuth("example-client", "secret")
					delayed := httptest.NewRecorder()
					go func() {
						defer close(finished)
						svc.routes().ServeHTTP(delayed, request)
					}()
					r.Eventually(func() bool {
						svc.oidcMu.Lock()
						defer svc.oidcMu.Unlock()
						if grantType == "authorization_code" {
							return svc.authCodes[presented].Redeeming
						}
						return svc.refreshTokens[presented].Redeeming
					}, time.Second, time.Millisecond)

					if tc.expire {
						svc.oidcMu.Lock()
						switch grantType {
						case "authorization_code":
							code := svc.authCodes[presented]
							code.ExpiresAt = time.Now().Add(-time.Second)
							svc.authCodes[presented] = code
						case "refresh_token":
							grant := svc.refreshTokens[presented]
							grant.ExpiresAt = time.Now().Add(-time.Second)
							svc.refreshTokens[presented] = grant
						}
						svc.oidcMu.Unlock()
					}
					if tc.method != "" {
						acceptanceRequest(t, svc.routes(), tc.method, "/api/v1/environments/app-1/users/usr-1", tc.body, http.StatusOK)
					}
					select {
					case <-finished:
					case <-time.After(time.Second):
						t.Fatal("delayed token exchange did not finish")
					}
					r.Equal(tc.want, delayed.Code, delayed.Body.String())
					svc.oidcMu.Lock()
					_, found := svc.refreshTokens[presented]
					if grantType == "authorization_code" {
						_, found = svc.authCodes[presented]
					}
					svc.oidcMu.Unlock()
					r.False(found, "presented grant must be removed")
					if tc.want == http.StatusOK {
						body := tokenBody(t, delayed)
						r.Equal("troy.barnes@greendale.edu", decodeIDTokenClaims(t, body["id_token"].(string))["email"])
						return
					}
					r.Contains(delayed.Body.String(), "invalid_grant")
					r.NotContains(delayed.Body.String(), "access_token")
					r.NotContains(delayed.Body.String(), "id_token")
					r.NotContains(delayed.Body.String(), "refresh_token")
					svc.oidcMu.Lock()
					accessCount, refreshCount := len(svc.accessTokens), len(svc.refreshTokens)
					svc.oidcMu.Unlock()
					r.Equal(wantAccessCount, accessCount, "rejected exchange must not mint an access token")
					r.Zero(refreshCount, "rejected exchange must not mint a refresh token")
				})
			}
		})
	}
}
