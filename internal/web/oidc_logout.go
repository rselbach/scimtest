package web

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

// logoutRequest is a validated end session request.
type logoutRequest struct {
	Hinted      bool   // an id_token_hint was presented and verified
	HintSubject string // the hint's sub
	HintSession string // the hint's sid
	RedirectURI *url.URL
}

// handleOIDCLogout is the end session endpoint from OpenID Connect
// RP-Initiated Logout 1.0. It ends the IdP session named by the
// id_token_hint's sid, or else the browser's session, then redirects to
// post_logout_redirect_uri with state. Unless the hint names the browser's
// own session, it first asks the user to confirm, as the specification
// requires. Invalid requests never redirect.
func (a *webApp) handleOIDCLogout(w http.ResponseWriter, r *http.Request) {
	if !a.allowTunneledChooser(w, r) {
		return
	}
	state, app, ok := appForProtocol(w, r, supportsOIDC)
	if !ok {
		return
	}
	values := r.URL.Query()
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			a.failFlow(w, app, "oidc", "logout", http.StatusBadRequest, err.Error())
			return
		}
		values = r.PostForm
	}
	request, err := a.parseLogoutRequest(r, state, oidcIssuer(a.effectiveIDPBaseURL(r, state), app), app, values)
	if err != nil {
		a.failFlow(w, app, "oidc", "logout", http.StatusBadRequest, err.Error())
		return
	}

	browser, browserLive := a.browserIdPSession(r, app.Slug)
	target, live := browser, browserLive
	if request.HintSession != "" {
		target, live = a.liveIdPSession(app.Slug, request.HintSession)
	}
	ownSession := request.Hinted && browserLive && target.ID == browser.ID &&
		(request.HintSession != "" || request.HintSubject == browser.SignIn.UserID)
	confirmed := r.Method == http.MethodPost && values.Get("confirm") == "1"
	if live && !ownSession && !confirmed {
		action, _, _ := strings.Cut(publicRequestURI(r), "?")
		hidden := url.Values{}
		for key, value := range values {
			if key != "confirm" {
				hidden[key] = value
			}
		}
		renderLogoutPage(w, logoutPage{AppName: app.Name, User: target.User, Action: action, Hidden: hidden, Confirm: true})
		return
	}

	detail := "No live session to end"
	signedOut := ""
	if live {
		a.endAppIdPSessions(app.Slug, target.ID, "RP-initiated logout")
		detail = "Ended session " + target.ID
		signedOut = target.User
	}
	if browserLive && target.ID == browser.ID {
		forgetIdPSession(w, app.Slug)
	}
	if request.RedirectURI == nil {
		a.recordFlowEvent(app.Slug, "oidc", "logout", "ok", signedOut, detail)
		renderLogoutPage(w, logoutPage{AppName: app.Name, User: signedOut})
		return
	}
	query := request.RedirectURI.Query()
	if stateValue := values.Get("state"); stateValue != "" {
		query.Set("state", stateValue)
	}
	request.RedirectURI.RawQuery = query.Encode()
	a.recordFlowEvent(app.Slug, "oidc", "logout", "ok", signedOut, detail+"; redirected to "+values.Get("post_logout_redirect_uri"))
	http.Redirect(w, r, request.RedirectURI.String(), http.StatusFound)
}

// parseLogoutRequest checks client_id, id_token_hint, and
// post_logout_redirect_uri. A redirect needs a hint or client_id to name the
// client, and must go to one of the environment's registered redirect URIs.
func (a *webApp) parseLogoutRequest(r *http.Request, state appState, issuer string, app app, values url.Values) (logoutRequest, error) {
	var request logoutRequest
	clientID := values.Get("client_id")
	if clientID != "" && clientID != app.OIDCClientID {
		return logoutRequest{}, errors.New("client_id is invalid")
	}
	if hint := values.Get("id_token_hint"); hint != "" {
		claims, err := a.verifyIDTokenHint(state, hint, issuer, app.OIDCClientID)
		if err != nil {
			return logoutRequest{}, err
		}
		request.Hinted = true
		request.HintSubject, _ = claims["sub"].(string)
		request.HintSession, _ = claims["sid"].(string)
	}
	raw := values.Get("post_logout_redirect_uri")
	if raw == "" {
		return request, nil
	}
	if !request.Hinted && clientID == "" {
		return logoutRequest{}, errors.New("post_logout_redirect_uri requires id_token_hint or client_id")
	}
	redirectURI, err := parseOIDCRedirectURI(raw)
	if err != nil {
		return logoutRequest{}, fmt.Errorf("post_logout_redirect_uri: %w", err)
	}
	allowAny := app.AllowAnyOIDCRedirect && !isTunneledRequest(r)
	if !allowAny && !slices.Contains(app.OIDCRedirectURIs, raw) {
		return logoutRequest{}, fmt.Errorf("post_logout_redirect_uri %q is not a registered redirect URI; registered: %v", raw, app.OIDCRedirectURIs)
	}
	request.RedirectURI = redirectURI
	return request, nil
}

// verifyIDTokenHint checks that token is an RS256 ID token this IdP signed
// for clientID under issuer, and returns its claims. It accepts an expired
// token, as RP-Initiated Logout allows.
func (a *webApp) verifyIDTokenHint(state appState, token, issuer, clientID string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("id_token_hint is not a signed JWT")
	}
	headerData, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("id_token_hint header: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerData, &header); err != nil {
		return nil, fmt.Errorf("id_token_hint header: %w", err)
	}
	if header.Alg != "RS256" {
		return nil, fmt.Errorf("id_token_hint must be signed with RS256, not %q", header.Alg)
	}
	if header.Typ != idTokenJWT.typ {
		return nil, errors.New("id_token_hint must be an ID token")
	}
	keys, err := a.publishedSigningKeys(state, time.Now())
	if err != nil {
		return nil, err
	}
	var publicKey *rsa.PublicKey
	for _, key := range keys {
		if key.ID == header.Kid {
			publicKey = &key.PrivateKey.PublicKey
			break
		}
	}
	if publicKey == nil {
		return nil, errors.New("id_token_hint signing key is not published by this environment")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("id_token_hint signature: %w", err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest[:], signature); err != nil {
		return nil, errors.New("id_token_hint signature is invalid")
	}
	claimData, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("id_token_hint claims: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(claimData, &claims); err != nil {
		return nil, fmt.Errorf("id_token_hint claims: %w", err)
	}
	if claims["iss"] != issuer {
		return nil, errors.New("id_token_hint was not issued by this environment")
	}
	if !audienceIncludes(claims["aud"], clientID) {
		return nil, errors.New("id_token_hint was not issued to this client")
	}
	return claims, nil
}

// audienceIncludes reports whether a JWT aud claim, a string or an array,
// names clientID.
func audienceIncludes(aud any, clientID string) bool {
	switch value := aud.(type) {
	case string:
		return value == clientID
	case []any:
		return slices.Contains(value, any(clientID))
	}
	return false
}

type logoutPage struct {
	AppName string
	User    string
	Action  string
	Hidden  url.Values
	Confirm bool   // ask before ending the session
	Detail  string // shown under the signed-out message
}

func renderLogoutPage(w http.ResponseWriter, page logoutPage) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := logoutTemplate.Execute(w, page); err != nil {
		log.Printf("render logout page: %v", err)
	}
}

var logoutTemplate = template.Must(template.New("logout").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{if .Confirm}}Sign out{{else}}Signed out{{end}} · {{.AppName}}</title>
  <style>
    body { margin:0; min-height:100vh; display:grid; place-items:center; padding:16px; background:#f4f5f7; color:#1f2328; font:13.5px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Helvetica,Arial,sans-serif; }
    main { width:min(420px, 100%); padding:20px; background:#fff; border:1px solid #d1d5db; border-radius:8px; box-shadow:0 20px 50px rgba(15,23,42,.16); }
    h1 { margin:0; font-size:18px; }
    p { margin:6px 0 0; color:#6b7280; }
    button { margin-top:16px; height:34px; padding:0 14px; border:1px solid #1563ff; background:#1563ff; color:#fff; border-radius:6px; font-weight:600; cursor:pointer; }
  </style>
</head>
<body>
  <main>
    {{if .Confirm}}
    <h1>Sign out of {{.AppName}}?</h1>
    <p>This ends {{.User}}'s session in this environment.</p>
    <form method="post" action="{{.Action}}">
      {{range $key, $values := .Hidden}}{{range $values}}<input type="hidden" name="{{$key}}" value="{{.}}">{{end}}{{end}}
      <button type="submit" name="confirm" value="1">Sign out</button>
    </form>
    {{else}}
    <h1>Signed out</h1>
    <p>{{if .User}}{{.User}} is signed out of {{.AppName}}.{{else}}There is no active session for {{.AppName}}.{{end}}</p>
    {{if .Detail}}<p>{{.Detail}}</p>{{end}}
    {{end}}
  </main>
</body>
</html>`))
