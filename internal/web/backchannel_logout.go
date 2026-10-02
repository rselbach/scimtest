package web

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"
)

// backchannelLogoutEvent is the events member that marks a JWT as a logout
// token (OpenID Connect Back-Channel Logout 1.0, section 2.4).
const backchannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"

const (
	logoutTokenLifetime        = 2 * time.Minute
	maxLogoutResponseBytes     = 64 << 10
	maxLogoutFlowDetailRunes   = 200
	backchannelLogoutFlowStage = "backchannel-logout"
)

// backchannelLogoutTimeout bounds each logout request, so an app that hangs
// delays only its own logout. Tests shorten it.
var backchannelLogoutTimeout = 5 * time.Second

// backchannelLogoutClient never follows redirects: the logout token must
// reach the registered URI itself.
var backchannelLogoutClient = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// logoutResultRetention is how long a session's logout token results stay
// readable after delivery, so a lifecycle checklist can show them.
const logoutResultRetention = 24 * time.Hour

// backchannelLogoutResult is one logout token that scimtest sent, or skipped,
// for an ended session, and how the app answered.
type backchannelLogoutResult struct {
	Token    string // what was sent, such as "Logout token"
	URI      string
	Response string // the app's status, or why no answer arrived
	Outcome  string // ok, failed, or skipped
	At       time.Time
}

// rememberLogoutResult records a logout token result for sessionID and drops
// results older than logoutResultRetention.
func (a *webApp) rememberLogoutResult(sessionID string, result backchannelLogoutResult) {
	result.At = time.Now()
	a.logoutResultMu.Lock()
	defer a.logoutResultMu.Unlock()
	if a.logoutResults == nil {
		a.logoutResults = make(map[string][]backchannelLogoutResult)
	}
	for id, results := range a.logoutResults {
		if result.At.Sub(results[len(results)-1].At) > logoutResultRetention {
			delete(a.logoutResults, id)
		}
	}
	a.logoutResults[sessionID] = append(a.logoutResults[sessionID], result)
}

// logoutResultsFor returns sessionID's logout token results, oldest first.
func (a *webApp) logoutResultsFor(sessionID string) []backchannelLogoutResult {
	a.logoutResultMu.Lock()
	defer a.logoutResultMu.Unlock()
	return slices.Clone(a.logoutResults[sessionID])
}

// sendBackchannelLogouts posts a logout token for each ended session that
// issued ID tokens. Delivery runs in the background, so a slow or unreachable
// app never stalls the request that ended the session.
func (a *webApp) sendBackchannelLogouts(ended []idpSession) {
	var pending []idpSession
	for _, session := range ended {
		if session.OIDCIssuer != "" {
			pending = append(pending, session)
		}
	}
	if len(pending) == 0 {
		return
	}
	a.logoutDeliveries.Add(1)
	go func() {
		defer a.logoutDeliveries.Done()
		for _, session := range pending {
			a.sendBackchannelLogout(session)
		}
	}()
}

// sendBackchannelLogout posts session's logout token to its environment's
// back-channel logout URI, if one is set. Armed logout token faults apply to
// this token and are consumed by it.
func (a *webApp) sendBackchannelLogout(session idpSession) {
	state, err := loadStateForAppSlug(session.AppSlug)
	if err != nil {
		if !errors.Is(err, errAppNotFound) {
			log.Printf("back-channel logout for session %s: %v", session.ID, err)
		}
		a.rememberLogoutResult(session.ID, backchannelLogoutResult{Token: "Logout token", Response: "the environment could not be loaded", Outcome: "skipped"})
		return
	}
	found, ok := appBySlug(state.Apps, session.AppSlug)
	if !ok || !supportsOIDC(found) || found.OIDCBackchannelLogoutURI == "" {
		a.rememberLogoutResult(session.ID, backchannelLogoutResult{Token: "Logout token", Response: "no back-channel logout URI is set", Outcome: "skipped"})
		return
	}
	faults := a.takeArmedLogoutFaults(found.Slug)
	token, err := a.logoutToken(found, session, faults, time.Now())
	if err != nil {
		a.recordFlowEvent(found.Slug, "oidc", backchannelLogoutFlowStage, "failed", session.User, "Logout token for session "+session.ID+": "+err.Error())
		a.rememberLogoutResult(session.ID, backchannelLogoutResult{Token: "Logout token", URI: found.OIDCBackchannelLogoutURI, Response: err.Error(), Outcome: "failed"})
		return
	}
	tampers := slices.DeleteFunc(slices.Clone(faults.Tamper), func(fault tamperFault) bool { return fault == tamperLogoutRepeatedJTI })
	a.postLogoutToken(found, session, token, tampers)
	if faults.tampers(tamperLogoutRepeatedJTI) {
		a.postLogoutToken(found, session, token, append(tampers, tamperLogoutRepeatedJTI))
	}
}

// logoutToken builds and signs session's logout token. It carries sub, and
// sid too when the environment requires the session. Tamper faults leave it
// unsigned, aim it at another audience, or drop events.
func (a *webApp) logoutToken(found app, session idpSession, faults faultOptions, now time.Time) (string, error) {
	jti, err := randomSecret(16)
	if err != nil {
		return "", err
	}
	claims := map[string]any{
		"iss":    session.OIDCIssuer,
		"sub":    session.SignIn.UserID,
		"aud":    found.OIDCClientID,
		"iat":    now.Unix(),
		"exp":    now.Add(logoutTokenLifetime).Unix(),
		"jti":    jti,
		"events": map[string]any{backchannelLogoutEvent: map[string]any{}},
	}
	if found.OIDCBackchannelLogoutSessionRequired {
		claims["sid"] = session.ID
	}
	if faults.tampers(tamperLogoutWrongAudience) {
		claims["aud"] = nearMiss(claims["aud"])
	}
	if faults.tampers(tamperLogoutMissingEvents) {
		delete(claims, "events")
	}
	return a.signLogoutToken(claims, faults.tampers(tamperLogoutAlgNone))
}

// signLogoutToken signs claims as an RS256 compact JWS typed logout+jwt, as
// section 2.4 recommends, or leaves it unsigned with alg none.
func (a *webApp) signLogoutToken(claims map[string]any, unsigned bool) (string, error) {
	header := map[string]any{"typ": "logout+jwt", "alg": "RS256", "kid": "scimtest-dev"}
	if unsigned {
		header = map[string]any{"typ": "logout+jwt", "alg": "none"}
	}
	headerData, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimData, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(headerData) + "." + base64.RawURLEncoding.EncodeToString(claimData)
	if unsigned {
		return signingInput + ".", nil
	}
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, a.signingKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

// postLogoutToken delivers token and records the request and the app's
// response in flow activity and the traffic view. A tampered token should be
// rejected, so the flow event fails when the app accepts one.
func (a *webApp) postLogoutToken(found app, session idpSession, token string, tampers []tamperFault) {
	ctx, cancel := context.WithTimeout(context.Background(), backchannelLogoutTimeout)
	defer cancel()
	body := url.Values{"logout_token": {token}}.Encode()
	description := "Logout token"
	if len(tampers) > 0 {
		names := make([]string, len(tampers))
		for i, fault := range tampers {
			names[i] = string(fault)
		}
		description = "Tampered logout token (" + strings.Join(names, ", ") + ")"
	}
	result := backchannelLogoutResult{Token: description, URI: found.OIDCBackchannelLogoutURI, Outcome: "failed"}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, found.OIDCBackchannelLogoutURI, strings.NewReader(body))
	if err != nil {
		a.recordFlowEvent(found.Slug, "oidc", backchannelLogoutFlowStage, "failed", session.User, "Logout token for session "+session.ID+": "+err.Error())
		result.Response = err.Error()
		a.rememberLogoutResult(session.ID, result)
		return
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := backchannelLogoutClient.Do(request)
	var responseBody []byte
	if err == nil {
		responseBody, err = readAndCloseAPIResponse(response, maxLogoutResponseBytes)
	}
	a.recordLogoutTraffic(request, body, token, response, responseBody, err)

	subject := description + " for session " + session.ID
	if err != nil {
		a.recordFlowEvent(found.Slug, "oidc", backchannelLogoutFlowStage, "failed", session.User, subject+" to "+found.OIDCBackchannelLogoutURI+" failed: "+err.Error())
		result.Response = err.Error()
		a.rememberLogoutResult(session.ID, result)
		return
	}
	outcome, verdict := logoutResponseVerdict(response.StatusCode, len(tampers) > 0)
	result.Outcome = outcome
	result.Response = fmt.Sprintf("HTTP %d %s", response.StatusCode, http.StatusText(response.StatusCode))
	if verdict != "" {
		result.Response += "; " + verdict
	}
	a.rememberLogoutResult(session.ID, result)
	detail := fmt.Sprintf("%s sent to %s: HTTP %d %s", subject, found.OIDCBackchannelLogoutURI, response.StatusCode, http.StatusText(response.StatusCode))
	if verdict != "" {
		detail += "; " + verdict
	}
	if excerpt := strings.TrimSpace(string(responseBody)); outcome == "failed" && excerpt != "" {
		if runes := []rune(excerpt); len(runes) > maxLogoutFlowDetailRunes {
			excerpt = string(runes[:maxLogoutFlowDetailRunes]) + "…"
		}
		detail += ": " + excerpt
	}
	a.recordFlowEvent(found.Slug, "oidc", backchannelLogoutFlowStage, outcome, session.User, detail)
}

// logoutResponseVerdict judges the app's response. An app must accept a
// valid logout token with 200 and reject a tampered one with 400.
func logoutResponseVerdict(status int, tampered bool) (outcome, verdict string) {
	accepted := status >= 200 && status < 300
	rejected := status >= 400 && status < 500
	switch {
	case !tampered && accepted:
		return "ok", ""
	case !tampered:
		return "failed", "the app did not accept it"
	case accepted:
		return "failed", "the app accepted a tampered logout token"
	case rejected:
		return "ok", "the app rejected it"
	}
	return "failed", "the app did not reject it with a 4xx status"
}

// recordLogoutTraffic renders the logout request and the app's response, or
// the delivery error, for --debug and the Traffic view.
func (a *webApp) recordLogoutTraffic(request *http.Request, body, token string, response *http.Response, responseBody []byte, deliveryErr error) {
	stdout := a.debugRPEnabled()
	record := a.trafficRecordEnabled()
	if !stdout && !record {
		return
	}
	secrets := a.debugSecretsEnabled()
	var transcript bytes.Buffer
	writeDebugf(&transcript, "===== Back-channel logout %s =====\n", time.Now().Format(time.RFC3339))
	writeDebugln(&transcript, "----- request to app -----")
	writeDebugf(&transcript, "%s %s %s\n", request.Method, request.URL.String(), request.Proto)
	writeDebugf(&transcript, "Host: %s\n", request.URL.Host)
	writeDebugHeaders(&transcript, request.Header, secrets)
	writeDebugln(&transcript)
	writeDebugln(&transcript, debugBody(request.Header.Get("Content-Type"), []byte(body), secrets))
	if parts := strings.Split(token, "."); len(parts) == 3 {
		writeDebugln(&transcript, "\n----- decoded logout token -----")
		for _, part := range parts[:2] {
			decoded, err := base64.RawURLEncoding.DecodeString(part)
			if err != nil {
				decoded = []byte("unavailable")
			}
			writeDebugln(&transcript, string(decoded))
		}
	}
	if deliveryErr != nil {
		writeDebugf(&transcript, "----- no response: %v -----\n", deliveryErr)
	} else {
		writeDebugln(&transcript, "----- response from app -----")
		writeDebugf(&transcript, "HTTP %d %s\n", response.StatusCode, http.StatusText(response.StatusCode))
		writeDebugHeaders(&transcript, response.Header, secrets)
		if len(responseBody) > 0 {
			writeDebugln(&transcript)
			writeDebugln(&transcript, debugResponseBody(response.Header.Get("Content-Type"), string(responseBody), secrets))
		}
	}
	writeDebugln(&transcript, "===== end back-channel logout =====")

	rpDebugLogMu.Lock()
	defer rpDebugLogMu.Unlock()
	if stdout {
		writeDebugln(os.Stdout)
		writeDebugln(os.Stdout, transcript.String())
	}
	if record {
		a.traffic.add(transcript.String())
	}
}
