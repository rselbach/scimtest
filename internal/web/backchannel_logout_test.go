package web

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestBackchannelLogoutToken(t *testing.T) {
	tests := map[string]struct {
		sessionRequired bool
	}{
		"sub only":         {},
		"session required": {sessionRequired: true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			receiver := newLogoutReceiver(t, http.StatusOK)
			svc := backchannelTestApp(t, receiver.URL, tc.sessionRequired)
			cookie, idToken := backchannelSignIn(t, svc, "usr-1")
			idClaims := decodeIDTokenClaims(t, idToken)

			endSessionFromInspector(t, svc, cookie.Value)
			svc.logoutDeliveries.Wait()

			deliveries := receiver.received()
			r.Len(deliveries, 1)
			r.Equal(http.MethodPost, deliveries[0].Method)
			r.Equal("application/x-www-form-urlencoded", deliveries[0].ContentType)
			token := deliveries[0].Token
			r.Equal(map[string]any{"typ": "logout+jwt", "alg": "RS256", "kid": "scimtest-dev"}, decodeJWTHeader(t, token))
			parts := strings.Split(token, ".")
			digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
			signature, err := base64.RawURLEncoding.DecodeString(parts[2])
			r.NoError(err)
			r.NoError(rsa.VerifyPKCS1v15(&svc.signingKey.PublicKey, crypto.SHA256, digest[:], signature))

			claims := decodeIDTokenClaims(t, token)
			r.Equal(idClaims["iss"], claims["iss"])
			r.Equal("example-client", claims["aud"])
			r.Equal("usr-1", claims["sub"])
			r.Equal(map[string]any{backchannelLogoutEvent: map[string]any{}}, claims["events"])
			r.NotEmpty(claims["jti"])
			r.Greater(claims["exp"], claims["iat"])
			r.NotContains(claims, "nonce")
			if tc.sessionRequired {
				r.Equal(idClaims["sid"], claims["sid"])
			} else {
				r.NotContains(claims, "sid")
			}

			event := svc.flowEvents("example")[0]
			r.Equal("oidc", event.Protocol)
			r.Equal(backchannelLogoutFlowStage, event.Stage)
			r.Equal("ok", event.Outcome)
			r.Equal("Troy Barnes", event.User)
			r.Equal("Logout token for session "+cookie.Value+" sent to "+receiver.URL+": HTTP 200 OK", event.Detail)
		})
	}
}

func TestEverySessionEndSendsLogoutToken(t *testing.T) {
	directoryAction := func(path string) func(*testing.T, *webApp, *http.Cookie, string) {
		return func(t *testing.T, svc *webApp, _ *http.Cookie, _ string) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(url.Values{"environment": {"app-1"}}.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			svc.routes().ServeHTTP(rec, req)
			require.Equal(t, http.StatusSeeOther, rec.Code, rec.Body.String())
		}
	}
	tests := map[string]struct {
		end func(t *testing.T, svc *webApp, cookie *http.Cookie, idToken string)
	}{
		"end session endpoint": {end: func(t *testing.T, svc *webApp, cookie *http.Cookie, idToken string) {
			rec := oidcLogout(t, svc, http.MethodGet, url.Values{"id_token_hint": {idToken}}, cookie)
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		}},
		"inspector": {end: func(t *testing.T, svc *webApp, cookie *http.Cookie, _ string) {
			endSessionFromInspector(t, svc, cookie.Value)
		}},
		"API": {end: func(t *testing.T, svc *webApp, cookie *http.Cookie, _ string) {
			acceptanceRequest(t, svc.routes(), http.MethodDelete, "/api/v1/environments/app-1/sessions?session_id="+cookie.Value, "", http.StatusOK)
		}},
		"user deactivated": {end: directoryAction("/users/usr-1/toggle-active")},
		"user deleted":     {end: directoryAction("/users/usr-1/delete")},
		"replaced by another user": {end: func(t *testing.T, svc *webApp, cookie *http.Cookie, _ string) {
			state, err := loadState()
			require.NoError(t, err)
			state.Users = append(state.Users, user{ID: "usr-abed", GivenName: "Abed", FamilyName: "Nadir", Username: "anadir", Email: "abed@greendale.edu", Active: true})
			require.NoError(t, saveState(state))
			rec := oidcAuthorize(t, svc, http.MethodPost, url.Values{"user_id": {"usr-abed"}, "prompt": {"login"}}, cookie)
			require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())
		}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			receiver := newLogoutReceiver(t, http.StatusOK)
			svc := backchannelTestApp(t, receiver.URL, true)
			cookie, idToken := backchannelSignIn(t, svc, "usr-1")

			tc.end(t, svc, cookie, idToken)
			svc.logoutDeliveries.Wait()

			deliveries := receiver.received()
			r.Len(deliveries, 1)
			claims := decodeIDTokenClaims(t, deliveries[0].Token)
			r.Equal("usr-1", claims["sub"])
			r.Equal(cookie.Value, claims["sid"])
		})
	}
}

func TestBackchannelLogoutSkipsSessionsWithoutIDTokens(t *testing.T) {
	tests := map[string]struct {
		withoutURI bool
		redeem     bool
	}{
		"no back-channel logout URI": {withoutURI: true, redeem: true},
		"code never redeemed":        {},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			receiver := newLogoutReceiver(t, http.StatusOK)
			uri := receiver.URL
			if tc.withoutURI {
				uri = ""
			}
			svc := backchannelTestApp(t, uri, true)
			signedIn := oidcAuthorize(t, svc, http.MethodPost, url.Values{"user_id": {"usr-1"}})
			cookie := sessionCookie(t, signedIn)
			if tc.redeem {
				redeemToken(t, svc, redirectQuery(t, signedIn).Get("code"))
			}

			endSessionFromInspector(t, svc, cookie.Value)
			svc.logoutDeliveries.Wait()

			r.Empty(receiver.received())
			for _, event := range svc.flowEvents("example") {
				r.NotEqual(backchannelLogoutFlowStage, event.Stage)
			}
		})
	}
}

func TestBackchannelLogoutRecordsAppResponse(t *testing.T) {
	tests := map[string]struct {
		status       int
		hang         bool
		unreachable  bool
		wantOutcome  string
		wantDetail   string
		wantResponse string
	}{
		"accepted": {status: http.StatusOK, wantOutcome: "ok", wantDetail: ": HTTP 200 OK", wantResponse: "HTTP 200 OK"},
		"rejected": {
			status:       http.StatusBadRequest,
			wantOutcome:  "failed",
			wantDetail:   ": HTTP 400 Bad Request; the app did not accept it: invalid logout token",
			wantResponse: "HTTP 400 Bad Request",
		},
		"timed out":   {hang: true, wantOutcome: "failed", wantDetail: "context deadline exceeded", wantResponse: "----- no response:"},
		"unreachable": {unreachable: true, wantOutcome: "failed", wantDetail: "connection refused", wantResponse: "----- no response:"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			shortenBackchannelLogoutTimeout(t)
			receiver := newLogoutReceiver(t, tc.status)
			if tc.hang {
				receiver.release = make(chan struct{})
			}
			if tc.unreachable {
				receiver.server.Close()
			}
			svc := backchannelTestApp(t, receiver.URL, true)
			svc.trafficRecord.Store(true)
			cookie, _ := backchannelSignIn(t, svc, "usr-1")

			endSessionFromInspector(t, svc, cookie.Value)
			svc.logoutDeliveries.Wait()

			event := svc.flowEvents("example")[0]
			r.Equal(backchannelLogoutFlowStage, event.Stage)
			r.Equal(tc.wantOutcome, event.Outcome, event.Detail)
			r.Contains(event.Detail, "Logout token for session "+cookie.Value)
			r.Contains(event.Detail, tc.wantDetail)

			transcript := svc.traffic.snapshot()[0]
			r.Contains(transcript, "===== Back-channel logout ")
			r.Contains(transcript, "POST "+receiver.URL+" HTTP/1.1")
			r.Contains(transcript, "logout_token=%5BREDACTED%5D")
			r.Contains(transcript, `"typ":"logout+jwt"`)
			r.Contains(transcript, `"sid":"`+cookie.Value+`"`)
			r.Contains(transcript, tc.wantResponse)
		})
	}
}

func TestEndingSessionDoesNotWaitForLogoutDelivery(t *testing.T) {
	r := require.New(t)
	receiver := newLogoutReceiver(t, http.StatusOK)
	receiver.release = make(chan struct{})
	svc := backchannelTestApp(t, receiver.URL, false)
	cookie, _ := backchannelSignIn(t, svc, "usr-1")

	endSessionFromInspector(t, svc, cookie.Value)
	select {
	case <-receiver.arrived:
	case <-time.After(5 * time.Second):
		t.Fatal("the logout token never reached the app")
	}
	close(receiver.release)
	svc.logoutDeliveries.Wait()

	r.Equal("ok", svc.flowEvents("example")[0].Outcome, svc.flowEvents("example")[0].Detail)
}

func TestBackchannelLogoutTamperFaults(t *testing.T) {
	tests := map[string]struct {
		fault       tamperFault
		status      int
		check       func(r *require.Assertions, tokens []string)
		wantOutcome string
		wantDetail  string
	}{
		"unsigned": {
			fault:  tamperLogoutAlgNone,
			status: http.StatusBadRequest,
			check: func(r *require.Assertions, tokens []string) {
				r.Len(tokens, 1)
				r.True(strings.HasSuffix(tokens[0], "."), "an unsigned token has an empty signature")
				header, err := base64.RawURLEncoding.DecodeString(strings.Split(tokens[0], ".")[0])
				r.NoError(err)
				r.JSONEq(`{"typ":"logout+jwt","alg":"none"}`, string(header))
			},
			wantOutcome: "ok",
			wantDetail:  ": HTTP 400 Bad Request; the app rejected it",
		},
		"wrong audience": {
			fault:  tamperLogoutWrongAudience,
			status: http.StatusOK,
			check: func(r *require.Assertions, tokens []string) {
				r.Len(tokens, 1)
				r.Equal("example-client-wrong", logoutTokenClaims(r, tokens[0])["aud"])
			},
			wantOutcome: "failed",
			wantDetail:  ": HTTP 200 OK; the app accepted a tampered logout token",
		},
		"missing events": {
			fault:  tamperLogoutMissingEvents,
			status: http.StatusOK,
			check: func(r *require.Assertions, tokens []string) {
				r.Len(tokens, 1)
				r.NotContains(logoutTokenClaims(r, tokens[0]), "events")
			},
			wantOutcome: "failed",
			wantDetail:  ": HTTP 200 OK; the app accepted a tampered logout token",
		},
		"repeated jti": {
			fault:  tamperLogoutRepeatedJTI,
			status: http.StatusOK,
			check: func(r *require.Assertions, tokens []string) {
				r.Len(tokens, 2)
				r.Equal(tokens[0], tokens[1], "the replay repeats the delivered token and its jti")
				r.Contains(logoutTokenClaims(r, tokens[0]), "events")
			},
			wantOutcome: "failed",
			wantDetail:  ": HTTP 200 OK; the app accepted a tampered logout token",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			receiver := newLogoutReceiver(t, tc.status)
			svc := backchannelTestApp(t, receiver.URL, true)
			form := url.Values{"fault_tamper": {string(tc.fault)}, "return_tab": {"oidc-inspector"}}
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/inspect/faults/example/arm", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			svc.routes().ServeHTTP(rec, req)
			r.Equal(http.StatusSeeOther, rec.Code, rec.Body.String())

			cookie, idToken := backchannelSignIn(t, svc, "usr-1")
			r.NotContains(decodeJWTHeader(t, idToken)["alg"], "none", "a sign-in must not consume logout token faults")
			r.Equal([]tamperFault{tc.fault}, svc.peekArmedFaults("example").Tamper)

			endSessionFromInspector(t, svc, cookie.Value)
			svc.logoutDeliveries.Wait()
			tc.check(r, receiver.tokens())
			event := svc.flowEvents("example")[0]
			r.Equal(tc.wantOutcome, event.Outcome, event.Detail)
			r.Equal("Tampered logout token ("+string(tc.fault)+") for session "+cookie.Value+" sent to "+receiver.URL+tc.wantDetail, event.Detail)
			r.False(svc.peekArmedFaults("example").active(), "the fault applies to one logout token")

			cookie, _ = backchannelSignIn(t, svc, "usr-1")
			endSessionFromInspector(t, svc, cookie.Value)
			svc.logoutDeliveries.Wait()
			tokens := receiver.tokens()
			clean := tokens[len(tokens)-1]
			r.Equal("RS256", decodeJWTHeader(t, clean)["alg"])
			claims := logoutTokenClaims(r, clean)
			r.Equal("example-client", claims["aud"])
			r.Contains(claims, "events")
		})
	}
}

func TestBackchannelLogoutSettings(t *testing.T) {
	r := require.New(t)
	_, handler := newAcceptanceAPI(t)
	created := acceptanceEnvironment(t, handler, `{"name":"Greendale","oidc_enabled":true,"oidc_redirect_uris":["http://greendale.test/callback"],"oidc_backchannel_logout_uri":"http://greendale.test/backchannel-logout","oidc_backchannel_logout_session_required":true}`)
	r.Equal("http://greendale.test/backchannel-logout", created.OIDCBackchannelLogoutURI)
	r.True(created.OIDCBackchannelLogoutSessionRequired)
	base := "/api/v1/environments/" + created.ID
	get := func() app {
		var got app
		r.NoError(json.Unmarshal(acceptanceRequest(t, handler, http.MethodGet, base, "", http.StatusOK).Body.Bytes(), &got))
		return got
	}

	invalid := acceptanceRequest(t, handler, http.MethodPatch, base, `{"oidc_backchannel_logout_uri":"/backchannel-logout"}`, http.StatusBadRequest)
	r.Contains(invalid.Body.String(), "back-channel logout URI")

	discovery := httptest.NewRecorder()
	handler.ServeHTTP(discovery, httptest.NewRequest(http.MethodGet, "/oidc/"+created.Slug+"/.well-known/openid-configuration", nil))
	r.Equal(http.StatusOK, discovery.Code)
	var metadata map[string]any
	r.NoError(json.Unmarshal(discovery.Body.Bytes(), &metadata))
	r.Equal(true, metadata["backchannel_logout_supported"])
	r.Equal(true, metadata["backchannel_logout_session_supported"])

	backup := acceptanceRequest(t, handler, http.MethodGet, base+"/backup", "", http.StatusOK).Body.String()
	acceptanceRequest(t, handler, http.MethodPatch, base, `{"oidc_backchannel_logout_uri":"http://greendale.test/other","oidc_backchannel_logout_session_required":false}`, http.StatusOK)
	acceptanceRequest(t, handler, http.MethodPost, base+"/restore", backup, http.StatusOK)
	restored := get()
	r.Equal("http://greendale.test/backchannel-logout", restored.OIDCBackchannelLogoutURI)
	r.True(restored.OIDCBackchannelLogoutSessionRequired)

	acceptanceRequest(t, handler, http.MethodPatch, base, `{"oidc_enabled":false}`, http.StatusOK)
	cleared := get()
	r.Empty(cleared.OIDCBackchannelLogoutURI)
	r.False(cleared.OIDCBackchannelLogoutSessionRequired)
}

// logoutDelivery is one request an app's back-channel logout endpoint got.
type logoutDelivery struct {
	Method      string
	ContentType string
	Token       string
}

// logoutReceiver is an app's back-channel logout endpoint. It records each
// request, then answers with status. With release set, it holds each answer
// until release closes or the request is canceled.
type logoutReceiver struct {
	URL     string
	server  *httptest.Server
	status  int
	release chan struct{}
	arrived chan struct{}

	mu         sync.Mutex
	deliveries []logoutDelivery
}

func newLogoutReceiver(t *testing.T, status int) *logoutReceiver {
	t.Helper()
	receiver := &logoutReceiver{status: status, arrived: make(chan struct{}, 10)}
	receiver.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		receiver.mu.Lock()
		receiver.deliveries = append(receiver.deliveries, logoutDelivery{Method: r.Method, ContentType: r.Header.Get("Content-Type"), Token: r.PostForm.Get("logout_token")})
		receiver.mu.Unlock()
		receiver.arrived <- struct{}{}
		if receiver.release != nil {
			select {
			case <-receiver.release:
			case <-r.Context().Done():
				return
			}
		}
		if receiver.status >= http.StatusBadRequest {
			http.Error(w, "invalid logout token", receiver.status)
			return
		}
		w.WriteHeader(receiver.status)
	}))
	t.Cleanup(receiver.server.Close)
	receiver.URL = receiver.server.URL + "/backchannel-logout"
	return receiver
}

func (l *logoutReceiver) received() []logoutDelivery {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]logoutDelivery(nil), l.deliveries...)
}

func (l *logoutReceiver) tokens() []string {
	var tokens []string
	for _, delivery := range l.received() {
		tokens = append(tokens, delivery.Token)
	}
	return tokens
}

// backchannelTestApp is oidcFaultTestApp with a back-channel logout URI. It
// also accepts the instance token that acceptanceRequest sends.
func backchannelTestApp(t *testing.T, logoutURI string, sessionRequired bool) *webApp {
	t.Helper()
	svc := oidcFaultTestApp(t)
	svc.instanceToken = "greendale-local-instance"
	state, err := loadState()
	require.NoError(t, err)
	state.Apps[0].OIDCBackchannelLogoutURI = logoutURI
	state.Apps[0].OIDCBackchannelLogoutSessionRequired = sessionRequired
	require.NoError(t, saveState(state))
	return svc
}

// backchannelSignIn signs userID in and redeems the code, so the session has
// issued an ID token. It returns the session cookie and the ID token.
func backchannelSignIn(t *testing.T, svc *webApp, userID string, cookies ...*http.Cookie) (*http.Cookie, string) {
	t.Helper()
	signedIn := oidcAuthorize(t, svc, http.MethodPost, url.Values{"user_id": {userID}, "prompt": {"login"}}, cookies...)
	cookie := sessionCookie(t, signedIn)
	tokens := tokenBody(t, redeemToken(t, svc, redirectQuery(t, signedIn).Get("code")))
	return cookie, tokens["id_token"].(string)
}

// endSessionFromInspector ends sessionID with the OIDC inspector's button.
func endSessionFromInspector(t *testing.T, svc *webApp, sessionID string) {
	t.Helper()
	form := url.Values{"return_tab": {"oidc-inspector"}, "session_id": {sessionID}}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/inspect/oidc/example/sessions/end", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	svc.routes().ServeHTTP(rec, req)
	require.Equal(t, http.StatusSeeOther, rec.Code, rec.Body.String())
}

func logoutTokenClaims(r *require.Assertions, token string) map[string]any {
	payload, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[1])
	r.NoError(err)
	var claims map[string]any
	r.NoError(json.Unmarshal(payload, &claims))
	return claims
}

// shortenBackchannelLogoutTimeout keeps timeout tests fast.
func shortenBackchannelLogoutTimeout(t *testing.T) {
	t.Helper()
	previous := backchannelLogoutTimeout
	backchannelLogoutTimeout = 200 * time.Millisecond
	t.Cleanup(func() { backchannelLogoutTimeout = previous })
}

func TestBackchannelLogoutUsesRotatedEnvironmentKey(t *testing.T) {
	r := require.New(t)
	receiver := newLogoutReceiver(t, http.StatusOK)
	svc := backchannelTestApp(t, receiver.URL, true)
	cookie, _ := backchannelSignIn(t, svc, "usr-1")
	state, err := loadState()
	r.NoError(err)
	rotated, err := svc.rotateEnvironmentSigningKey(state.Apps[0], 0, time.Now())
	r.NoError(err)
	key, err := svc.activeSigningKey(rotated)
	r.NoError(err)
	endSessionFromInspector(t, svc, cookie.Value)
	svc.logoutDeliveries.Wait()
	deliveries := receiver.received()
	r.Len(deliveries, 1)
	r.Equal(key.ID, decodeJWTHeader(t, deliveries[0].Token)["kid"])
	r.NoError(verifyWithJWKS(t, svc, deliveries[0].Token))
	r.Equal(cookie.Value, decodeIDTokenClaims(t, deliveries[0].Token)["sid"])
}
