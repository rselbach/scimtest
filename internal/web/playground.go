package web

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const playgroundStateCookie = "scimtest_playground"

func (a *webApp) playgroundCallbackURI(slug string) string {
	if a.adminHost == "" {
		return ""
	}
	return "http://" + a.adminHost + "/inspect/oidc/" + url.PathEscape(slug) + "/playground/callback"
}

// handleOIDCPlayground starts a built-in relying-party flow: it generates
// state, nonce, and (for public clients) a PKCE pair, remembers them in a
// short-lived cookie, and redirects to this IDP's own authorize endpoint with
// the playground callback as the redirect URI.
func (a *webApp) handleOIDCPlayground(w http.ResponseWriter, r *http.Request) {
	state, foundApp, ok := appForProtocol(w, r, supportsOIDC)
	if !ok {
		return
	}
	if oidcSetupStatus(foundApp) != setupStatusConfigured {
		http.Error(w, "configure OIDC for this environment before using the playground", http.StatusBadRequest)
		return
	}
	callback := a.playgroundCallbackURI(foundApp.Slug)
	if callback == "" {
		http.Error(w, "playground is unavailable: admin host is not initialized", http.StatusServiceUnavailable)
		return
	}

	nonce, err := randomSecret(16)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	stateValue, err := randomSecret(16)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	verifier, err := randomSecret(32)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	query := url.Values{
		"response_type": {"code"},
		"client_id":     {foundApp.OIDCClientID},
		"redirect_uri":  {callback},
		"scope":         {"openid profile email groups"},
		"state":         {stateValue},
		"nonce":         {nonce},
	}
	cookie := stateValue + "|" + nonce + "|"
	if foundApp.OIDCPublicClient {
		challenge := sha256.Sum256([]byte(verifier))
		query.Set("code_challenge", base64.RawURLEncoding.EncodeToString(challenge[:]))
		query.Set("code_challenge_method", "S256")
		cookie += verifier
	}
	// carry through any fault_* parameters the caller wants to exercise
	for key, vals := range r.URL.Query() {
		if strings.HasPrefix(key, "fault_") {
			query[key] = vals
		}
	}

	http.SetCookie(w, &http.Cookie{
		Name:     playgroundStateCookie + "_" + foundApp.Slug,
		Value:    cookie,
		Path:     "/inspect/oidc/" + url.PathEscape(foundApp.Slug),
		MaxAge:   600,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	issuer := oidcIssuer(a.effectiveIDPBaseURL(r, state), foundApp)
	http.Redirect(w, r, issuer+"/authorize?"+query.Encode(), http.StatusFound)
}

type playgroundResult struct {
	App           app
	Error         string
	AuthorizeCode string
	State         string
	TokenStatus   string
	TokenBody     string
	IDToken       string
	IDTokenHeader string
	IDTokenClaims string
	UserinfoBody  string
	InspectorURL  string
}

// handleOIDCPlaygroundCallback completes the built-in RP flow: it exchanges the
// authorization code for tokens server-side, then renders the raw token
// response, the decoded ID token, and a userinfo call so the whole exchange is
// visible on one page.
func (a *webApp) handleOIDCPlaygroundCallback(w http.ResponseWriter, r *http.Request) {
	appState, foundApp, ok := appForProtocol(w, r, supportsOIDC)
	if !ok {
		return
	}
	result := playgroundResult{App: foundApp, InspectorURL: "/inspect/oidc/" + url.PathEscape(foundApp.Slug)}

	render := func() {
		if err := pageTemplate.ExecuteTemplate(w, "oidc-playground.html", result); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}

	if oauthErr := r.URL.Query().Get("error"); oauthErr != "" {
		result.Error = oauthErr + ": " + r.URL.Query().Get("error_description")
		render()
		return
	}

	cookie, err := r.Cookie(playgroundStateCookie + "_" + foundApp.Slug)
	if err != nil {
		result.Error = "playground session expired; start the test sign-in again"
		render()
		return
	}
	parts := strings.SplitN(cookie.Value, "|", 3)
	if len(parts) != 3 || parts[0] == "" || parts[0] != r.URL.Query().Get("state") {
		result.Error = "state did not match the playground session"
		render()
		return
	}
	verifier := parts[2]

	code := r.URL.Query().Get("code")
	result.AuthorizeCode = code
	result.State = r.URL.Query().Get("state")
	if code == "" {
		result.Error = "authorization response carried no code"
		render()
		return
	}

	issuer := oidcIssuer(a.effectiveIDPBaseURL(r, appState), foundApp)
	tokenForm := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {a.playgroundCallbackURI(foundApp.Slug)},
	}
	if foundApp.OIDCPublicClient {
		tokenForm.Set("client_id", foundApp.OIDCClientID)
		tokenForm.Set("code_verifier", verifier)
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	tokenReq, err := http.NewRequestWithContext(ctx, http.MethodPost, issuer+"/token", strings.NewReader(tokenForm.Encode()))
	if err != nil {
		result.Error = err.Error()
		render()
		return
	}
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if !foundApp.OIDCPublicClient {
		tokenReq.SetBasicAuth(foundApp.OIDCClientID, foundApp.OIDCClientSecret)
	}
	tokenResp, err := http.DefaultClient.Do(tokenReq)
	if err != nil {
		result.Error = "token request failed: " + err.Error()
		render()
		return
	}
	tokenBytes, _ := io.ReadAll(tokenResp.Body)
	closeBody(tokenResp.Body)
	result.TokenStatus = tokenResp.Status
	result.TokenBody = prettyJSON(string(tokenBytes))
	if tokenResp.StatusCode != http.StatusOK {
		render()
		return
	}

	var tokenPayload struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	if err := json.Unmarshal(tokenBytes, &tokenPayload); err != nil {
		result.Error = "decode token response: " + err.Error()
		render()
		return
	}
	result.IDToken = tokenPayload.IDToken
	result.IDTokenHeader, result.IDTokenClaims = decodeJWTSegments(tokenPayload.IDToken)

	if tokenPayload.AccessToken != "" {
		userinfoReq, err := http.NewRequestWithContext(ctx, http.MethodGet, issuer+"/userinfo", nil)
		if err == nil {
			userinfoReq.Header.Set("Authorization", "Bearer "+tokenPayload.AccessToken)
			if userinfoResp, err := http.DefaultClient.Do(userinfoReq); err == nil {
				userinfoBytes, _ := io.ReadAll(userinfoResp.Body)
				closeBody(userinfoResp.Body)
				result.UserinfoBody = prettyJSON(string(userinfoBytes))
			}
		}
	}
	render()
}

func closeBody(body io.Closer) {
	if err := body.Close(); err != nil {
		return
	}
}

// decodeJWTSegments returns the pretty-printed header and claims of a compact
// JWT for display. It does not verify the signature.
func decodeJWTSegments(token string) (header, claims string) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", ""
	}
	decode := func(segment string) string {
		raw, err := base64.RawURLEncoding.DecodeString(segment)
		if err != nil {
			return ""
		}
		return prettyJSON(string(raw))
	}
	return decode(parts[0]), decode(parts[1])
}
