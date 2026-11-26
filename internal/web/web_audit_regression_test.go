package web

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	scimtestclient "github.com/rselbach/scimtest/client"
	"github.com/stretchr/testify/require"
)

func TestTunneledIdPSessionCookieIsPathScopedAndSecure(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	state := appState{
		Config: config{IDPBaseURL: "https://scimtest.rselbach.com/greendale-room"},
		Users:  []user{{ID: "troy", GivenName: "Troy", FamilyName: "Barnes", Email: "troy@greendale.edu", Username: "troy", Active: true}},
		Apps: []app{{
			ID:               "greendale",
			Name:             "Greendale",
			Slug:             "greendale",
			Protocol:         "oidc",
			OIDCClientID:     "greendale-client",
			OIDCClientSecret: "greendale-secret",
			OIDCRedirectURIs: []string{"https://rp.greendale.test/callback"},
		}},
	}
	r.NoError(saveState(state))
	svc := newTestIDPApp(t)
	svc.tunnel.active = &activeTunnel{PathPrefix: "/greendale-room", PublicURL: "https://scimtest.rselbach.com/greendale-room", ClientIP: "198.51.100.10"}

	form := url.Values{
		"response_type": {"code"},
		"client_id":     {"greendale-client"},
		"redirect_uri":  {"https://rp.greendale.test/callback"},
		"scope":         {"openid"},
		"user_id":       {"troy"},
	}
	req := httptest.NewRequest(http.MethodPost, "/greendale-room/oidc/greendale/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Forwarded-For", "198.51.100.10")
	rec := httptest.NewRecorder()
	svc.tunneledIDPRoutes().ServeHTTP(rec, req)

	r.Equal(http.StatusFound, rec.Code)
	cookies := rec.Result().Cookies()
	r.Len(cookies, 1)
	r.Equal("/greendale-room/", cookies[0].Path)
	r.True(cookies[0].Secure)
}

func TestOIDCLogoutRejectsForgedConfirmWithoutToken(t *testing.T) {
	r := require.New(t)
	svc := oidcFaultTestApp(t)
	signedIn := oidcAuthorize(t, svc, http.MethodPost, url.Values{"user_id": {"usr-1"}})
	cookie := sessionCookie(t, signedIn)
	idToken := tokenBody(t, redeemToken(t, svc, redirectQuery(t, signedIn).Get("code")))["id_token"].(string)

	// Forged POST with static confirm=1 and no confirm_token must not end the session.
	forged := oidcLogout(t, svc, http.MethodPost, url.Values{
		"id_token_hint": {idToken},
		"confirm":       {"1"},
	})
	r.Equal(http.StatusOK, forged.Code)
	r.Contains(forged.Body.String(), "Sign out of Example?")
	r.Len(svc.liveIdPSessions("example"), 1)
	_ = cookie
}

func TestOIDCClientAuthRejectsEmptyConfidentialSecretAndMismatchedTokenClientID(t *testing.T) {
	r := require.New(t)
	emptySecretApp := app{
		Slug:             "greendale",
		OIDCClientID:     "greendale-client",
		OIDCClientSecret: "",
		OIDCPublicClient: false,
	}
	req := httptest.NewRequest(http.MethodPost, "/oidc/greendale/token", strings.NewReader("client_id=greendale-client&client_secret="))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.False(clientAuthenticated(req, emptySecretApp))

	emptyClientIDApp := app{Slug: "greendale", OIDCPublicClient: true}
	r.False(clientAuthenticated(httptest.NewRequest(http.MethodPost, "/oidc/greendale/token", nil), emptyClientIDApp))

	// Access token bound to old client ID must not introspect as active after client ID changes.
	svc := oidcFaultTestApp(t)
	svc.oidcMu.Lock()
	svc.accessTokens["tok-old"] = accessToken{
		AppSlug:   "example",
		ClientID:  "old-client",
		UserID:    "usr-1",
		Scope:     "openid",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	svc.oidcMu.Unlock()
	state, err := loadStateForAppSlug("example")
	r.NoError(err)
	resp, _, _ := svc.introspectToken(httptest.NewRequest(http.MethodPost, "/oidc/example/introspect", nil), state, state.Apps[0], "tok-old")
	r.Equal(false, resp["active"])
}

func TestDebugBodyRedactionAndTrafficCaps(t *testing.T) {
	r := require.New(t)

	// Invalid percent escape in form body must fail closed instead of leaking secrets.
	r.Equal("[REDACTED]", debugBody("application/x-www-form-urlencoded", []byte("client_secret=supersecret&bad=%ZZ"), false))
	// Leading whitespace before Content-Type must still be parsed as form-encoded.
	redacted := debugBody("  application/x-www-form-urlencoded; charset=utf-8", []byte("client_secret=supersecret&grant_type=client_credentials"), false)
	r.NotContains(redacted, "supersecret")

	// Truncated JSON response must fail closed instead of leaking raw tokens.
	r.Equal("[REDACTED]", debugResponseBody("application/json; charset=utf-8", `{"access_token":"secret-tok","padding":"unterminated`, false))
	r.Equal("[REDACTED]", debugResponseBody("application/scim+json", `{"access_token":"secret-tok"`, false))

	// Truncated HTML hidden input without closing quote must still be redacted.
	truncatedSAML := `<form><input type="hidden" name="SAMLResponse" value="PHNhbWw6UmVzcG9uc2U+secret`
	redactedSAML := debugResponseBody("text/html; charset=utf-8", truncatedSAML, false)
	r.NotContains(redactedSAML, "PHNhbWw6UmVzcG9uc2U+secret")
	r.Contains(redactedSAML, "[REDACTED]")

	// Traffic log enforces total byte cap even below maxTrafficEntries.
	var tl trafficLog
	big := strings.Repeat("a", 512<<10)
	for range 20 {
		tl.add(big)
	}
	r.LessOrEqual(tl.totalBytes, maxTrafficTotalBytes)
}

func TestAdminRoutesSetSecurityAndNoStoreHeaders(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{}))
	svc := newTestIDPApp(t)

	rec := httptest.NewRecorder()
	svc.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	r.Equal("DENY", rec.Header().Get("X-Frame-Options"))
	r.Contains(rec.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'")
	r.Equal("nosniff", rec.Header().Get("X-Content-Type-Options"))
	r.Equal("no-store", rec.Header().Get("Cache-Control"))
}

func TestResilienceFlowScenarioRespectsProtocolOnDualProtocolEnvironment(t *testing.T) {
	r := require.New(t)
	svc := newTestIDPApp(t)
	now := time.Now()
	_, err := svc.armResilienceRun("greendale", "saml-auth-failed", 1, now)
	r.NoError(err)

	// OIDC flow must not consume a SAML-only resilience scenario.
	oidcFaults := svc.takeResilienceFlowFaults("greendale", "oidc", now)
	r.False(oidcFaults.active())

	// SAML flow consumes the SAML scenario.
	samlFaults := svc.takeResilienceFlowFaults("greendale", "saml", now)
	r.True(samlFaults.active())
}

func TestAPISyncEndpointsReturn404ForUnknownOrDefaultEnvironment(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{
		Apps: []app{{ID: "greendale", Name: "Greendale", Slug: "greendale", Protocol: "oidc"}},
	}))
	svc := newTestIDPApp(t)
	svc.instanceToken = "greendale-api-token"

	paths := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/environments/env_default/sync/plan"},
		{http.MethodGet, "/api/v1/environments/nonexistent/sync/status"},
		{http.MethodPost, "/api/v1/environments/env_default/sync/cancel"},
		{http.MethodPost, "/api/v1/environments/nonexistent/sync/reconcile"},
	}
	for _, tc := range paths {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		req.Header.Set("X-Scimtest-Instance-Token", svc.instanceToken)
		rec := httptest.NewRecorder()
		svc.routes().ServeHTTP(rec, req)
		r.Equal(http.StatusNotFound, rec.Code, tc.method+" "+tc.path)
	}
}

func TestAPIRestoreRejectsInvalidBackupPayload(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{
		Apps: []app{{ID: "greendale", Name: "Greendale", Slug: "greendale", Protocol: "oidc"}},
	}))
	svc := newTestIDPApp(t)
	svc.instanceToken = "greendale-api-token"

	badBackup := newStateBackup(appState{
		Environment: environment{ID: "greendale", Name: "Greendale", Slug: "greendale"},
		Apps: []app{{
			ID:               "greendale",
			Name:             "Greendale",
			Slug:             "greendale",
			Protocol:         "oidc",
			OIDCRedirectURIs: []string{"javascript:alert(1)"},
		}},
	})
	payload, err := json.Marshal(badBackup)
	r.NoError(err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/environments/greendale/restore", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Scimtest-Instance-Token", svc.instanceToken)
	rec := httptest.NewRecorder()
	svc.routes().ServeHTTP(rec, req)
	r.Equal(http.StatusBadRequest, rec.Code)
}

func TestDesktopAuthRetryReturnsImmediatelyWhileEnrollmentIsPending(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{}))
	oldProfileID, oldRequired := tunnelApplicationProfileID, tunnelReleaseProfileRequired
	t.Cleanup(func() {
		tunnelApplicationProfileID, tunnelReleaseProfileRequired = oldProfileID, oldRequired
	})
	tunnelApplicationProfileID = strings.Repeat("a", 32)
	tunnelReleaseProfileRequired = "true"

	release := make(chan struct{})
	defer close(release)
	svc := &webApp{
		requireGitHubAccount: true,
		tunnelSupported:      true,
		tunnelStart: func(ctx context.Context, cfg scimtestclient.Config) (*startedTunnel, error) {
			if cfg.OnEnrollmentRequired != nil {
				cfg.OnEnrollmentRequired(scimtestclient.Enrollment{
					URL:              "https://admin.example.test/enroll?code=troy-abed",
					VerificationCode: "troy-abed",
				})
			}
			select {
			case <-release:
			case <-ctx.Done():
			}
			return nil, context.Canceled
		},
	}
	svc.setTunnelError("previous failure")

	done := make(chan int, 1)
	go func() {
		rec := httptest.NewRecorder()
		svc.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/desktop/auth/retry", nil))
		done <- rec.Code
	}()

	select {
	case code := <-done:
		r.Equal(http.StatusSeeOther, code)
	case <-time.After(2 * time.Second):
		r.Fail("POST /desktop/auth/retry blocked instead of returning immediately")
	}
	_ = svc.closeAutomaticTunnel()
}
