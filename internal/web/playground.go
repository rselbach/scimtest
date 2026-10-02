package web

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
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
	_, foundApp, ok := appForProtocol(w, r, supportsOIDC)
	if !ok {
		return
	}
	// The playground supplies its own callback, so registered redirect URIs
	// are not required; only credentials the token exchange needs are.
	if strings.TrimSpace(foundApp.OIDCClientID) == "" {
		http.Error(w, "set an OIDC client ID for this environment before using the playground", http.StatusBadRequest)
		return
	}
	if !foundApp.OIDCPublicClient && strings.TrimSpace(foundApp.OIDCClientSecret) == "" {
		http.Error(w, "set an OIDC client secret for this environment before using the playground", http.StatusBadRequest)
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
		"scope":         {"openid profile email groups offline_access"},
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
	http.Redirect(w, r, a.playgroundIssuer(foundApp)+"/authorize?"+query.Encode(), http.StatusFound)
}

// playgroundIssuer returns the loopback issuer for the built-in RP. The
// playground must not use the public tunnel base: its callback is a loopback
// URI, which authorize only accepts on untunneled requests.
func (a *webApp) playgroundIssuer(foundApp app) string {
	return oidcIssuer("http://"+a.adminHost, foundApp)
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
	RefreshToken  string
	UserinfoBody  string
	InspectorURL  string
	GitHubAccount githubAccountView

	// Refreshed marks a page produced by redeeming a refresh token.
	Refreshed             bool
	RequestedScope        string
	PreviousIDTokenClaims string

	// AccessTokenHeader and AccessTokenClaims are set for JWT access tokens.
	AccessTokenHeader string
	AccessTokenClaims string
}

// handleOIDCPlaygroundCallback completes the built-in RP flow: it exchanges the
// authorization code for tokens server-side, then renders the raw token
// response, the decoded ID token, and a userinfo call so the whole exchange is
// visible on one page.
func (a *webApp) handleOIDCPlaygroundCallback(w http.ResponseWriter, r *http.Request) {
	_, foundApp, ok := appForProtocol(w, r, supportsOIDC)
	if !ok {
		return
	}
	result := playgroundResult{
		App:           foundApp,
		InspectorURL:  "/inspect/oidc/" + url.PathEscape(foundApp.Slug),
		GitHubAccount: a.githubAccountView(),
	}

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

	tokenForm := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {a.playgroundCallbackURI(foundApp.Slug)},
	}
	if foundApp.OIDCPublicClient {
		tokenForm.Set("code_verifier", verifier)
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if err := a.redeemPlaygroundTokens(ctx, foundApp, tokenForm, &result); err != nil {
		result.Error = err.Error()
	}
	render()
}

// handleOIDCPlaygroundRefresh redeems the refresh token the playground
// received and renders the new tokens beside the claims they replace.
func (a *webApp) handleOIDCPlaygroundRefresh(w http.ResponseWriter, r *http.Request) {
	_, foundApp, ok := appForProtocol(w, r, supportsOIDC)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	result := playgroundResult{
		App:            foundApp,
		InspectorURL:   "/inspect/oidc/" + url.PathEscape(foundApp.Slug),
		GitHubAccount:  a.githubAccountView(),
		Refreshed:      true,
		RequestedScope: strings.TrimSpace(r.PostFormValue("scope")),
	}
	_, result.PreviousIDTokenClaims = decodeJWTSegments(r.PostFormValue("previous_id_token"))
	tokenForm := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {r.PostFormValue("refresh_token")},
	}
	if result.RequestedScope != "" {
		tokenForm.Set("scope", result.RequestedScope)
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if err := a.redeemPlaygroundTokens(ctx, foundApp, tokenForm, &result); err != nil {
		result.Error = err.Error()
	}
	if err := pageTemplate.ExecuteTemplate(w, "oidc-playground.html", result); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// redeemPlaygroundTokens posts tokenForm to the token endpoint as the
// environment's client. It records the token response, the decoded ID token,
// and a userinfo call made with the new access token. A rejected token
// request is recorded rather than returned, so the page can show it.
func (a *webApp) redeemPlaygroundTokens(ctx context.Context, foundApp app, tokenForm url.Values, result *playgroundResult) error {
	issuer := a.playgroundIssuer(foundApp)
	if foundApp.OIDCPublicClient {
		tokenForm.Set("client_id", foundApp.OIDCClientID)
	}
	tokenReq, err := http.NewRequestWithContext(ctx, http.MethodPost, issuer+"/token", strings.NewReader(tokenForm.Encode()))
	if err != nil {
		return err
	}
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if !foundApp.OIDCPublicClient {
		// OAuth Basic credentials are form-encoded before base64 (RFC 6749).
		tokenReq.SetBasicAuth(url.QueryEscape(foundApp.OIDCClientID), url.QueryEscape(foundApp.OIDCClientSecret))
	}
	tokenResp, err := http.DefaultClient.Do(tokenReq)
	if err != nil {
		return fmt.Errorf("token request failed: %w", err)
	}
	tokenBytes, err := readAndCloseAPIResponse(tokenResp, 1<<20)
	if err != nil {
		return fmt.Errorf("read token response: %w", err)
	}
	result.TokenStatus = tokenResp.Status
	result.TokenBody = prettyJSON(string(tokenBytes))
	if tokenResp.StatusCode != http.StatusOK {
		return nil
	}

	var tokenPayload struct {
		AccessToken  string `json:"access_token"`
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(tokenBytes, &tokenPayload); err != nil {
		return fmt.Errorf("decode token response: %w", err)
	}
	result.IDToken = tokenPayload.IDToken
	result.IDTokenHeader, result.IDTokenClaims = decodeJWTSegments(tokenPayload.IDToken)
	result.AccessTokenHeader, result.AccessTokenClaims = decodeJWTSegments(tokenPayload.AccessToken)
	result.RefreshToken = tokenPayload.RefreshToken
	if tokenPayload.AccessToken == "" {
		return nil
	}

	userinfoReq, err := http.NewRequestWithContext(ctx, http.MethodGet, issuer+"/userinfo", nil)
	if err != nil {
		return err
	}
	userinfoReq.Header.Set("Authorization", "Bearer "+tokenPayload.AccessToken)
	userinfoResp, err := http.DefaultClient.Do(userinfoReq)
	if err != nil {
		return fmt.Errorf("userinfo request failed: %w", err)
	}
	userinfoBytes, err := readAndCloseAPIResponse(userinfoResp, 1<<20)
	if err != nil {
		return fmt.Errorf("read userinfo response: %w", err)
	}
	result.UserinfoBody = prettyJSON(string(userinfoBytes))
	return nil
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
