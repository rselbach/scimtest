package web

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

type authCode struct {
	AppSlug       string
	ClientID      string
	UserID        string
	RedirectURI   string
	Nonce         string
	Scope         string
	CodeChallenge string
	Authn         authnStatement
	SessionID     string // the IdP session the sign-in joined, sent as sid
	ExpiresAt     time.Time
	Faults        faultOptions
	Redeeming     bool
}

// refreshTokenLifetime bounds a refresh token. Each refresh rotates the token
// and starts a new lifetime.
const refreshTokenLifetime = 24 * time.Hour

// refreshToken keeps the grant an offline_access authorization started, so a
// refresh can re-check the user and issue tokens for the original scope and
// sign-in.
type refreshToken struct {
	AppSlug  string
	ClientID string
	UserID   string
	Scope    string
	// RedirectURI and CodeChallenge come from the authorization code, so a
	// refresh inspection shows how the grant started.
	RedirectURI   string
	CodeChallenge string
	Authn         authnStatement
	SessionID     string
	ExpiresAt     time.Time
	Redeeming     bool // an injected delay holds the token
}

type accessToken struct {
	AppSlug   string
	UserID    string
	Scope     string
	ExpiresAt time.Time
	Faults    faultOptions
}

func (a *webApp) handleOIDCDiscovery(w http.ResponseWriter, r *http.Request) {
	state, app, ok := appForProtocol(w, r, supportsOIDC)
	if !ok {
		return
	}
	issuer := oidcIssuer(a.effectiveIDPBaseURL(r, state), app)
	authMethods := []string{"client_secret_basic", "client_secret_post"}
	if app.OIDCPublicClient {
		authMethods = []string{"none"}
	}
	scopes := []string{"openid", "profile", "email", "offline_access"}
	if app.IncludeGroupsClaim {
		scopes = append(scopes, "groups")
	}
	writeJSON(w, map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/authorize",
		"token_endpoint":                        issuer + "/token",
		"userinfo_endpoint":                     issuer + "/userinfo",
		"jwks_uri":                              issuer + "/jwks",
		"end_session_endpoint":                  issuer + "/logout",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      scopes,
		"claims_supported":                      oidcClaimsSupported(app),
		"acr_values_supported":                  supportedAuthnContexts(),
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": authMethods,
	})
}

func (a *webApp) handleOIDCJWKS(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := appForProtocol(w, r, supportsOIDC); !ok {
		return
	}
	pub := a.signingKey.PublicKey
	writeJSON(w, map[string]any{
		"keys": []map[string]string{{
			"kty": "RSA",
			"use": "sig",
			"kid": "scimtest-dev",
			"alg": "RS256",
			"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}},
	})
}

func (a *webApp) handleOIDCAuthorize(w http.ResponseWriter, r *http.Request) {
	a.serveOIDCAuthorize(w, r, false)
}

func (a *webApp) handleOIDCAuthorizePost(w http.ResponseWriter, r *http.Request) {
	a.serveOIDCAuthorize(w, r, true)
}

// serveOIDCAuthorize handles both authorize bindings. The GET without a
// selection renders the chooser, so a bookmarked authorize URL with a
// user_id can iterate hands-free; the chooser's POST always carries a
// selection and goes straight to code issuance.
func (a *webApp) serveOIDCAuthorize(w http.ResponseWriter, r *http.Request, post bool) {
	if !a.allowTunneledChooser(w, r) {
		return
	}
	state, app, ok := appForProtocol(w, r, supportsOIDC)
	if !ok {
		return
	}
	values := r.URL.Query()
	if post {
		if err := r.ParseForm(); err != nil {
			a.failFlow(w, app, "oidc", "authorize", http.StatusBadRequest, err.Error())
			return
		}
		values = r.Form
	}
	tunneled := isTunneledRequest(r)
	if err := validateAuthorizeClient(app, values, tunneled, a.playgroundAllowedRedirect(tunneled, app.Slug)); err != nil {
		a.failFlow(w, app, "oidc", "authorize", http.StatusBadRequest, err.Error())
		return
	}
	request, err := parseAuthorizeRequest(app, values)
	if err != nil {
		a.failAuthorize(w, r, app, values, err)
		return
	}
	if isTruthy(values.Get("deny")) {
		a.failAuthorize(w, r, app, values, &authorizeError{code: "access_denied", description: "the user denied the request"})
		return
	}
	now := time.Now()
	if request.Passive {
		found, session, ok := a.rememberedSignIn(r, state.Users, app.Slug)
		if !ok {
			a.failAuthorize(w, r, app, values, &authorizeError{code: "login_required", description: "prompt=none requires a remembered sign-in"})
			return
		}
		if reason := request.reuseBlocker(session, now); reason != "" {
			a.failAuthorize(w, r, app, values, &authorizeError{code: "login_required", description: "the remembered sign-in does not satisfy " + reason})
			return
		}
		a.issueOIDCCode(w, r, app, values, found, session, request)
		return
	}
	if !post && !chooserSelectionProvided(app, values) {
		data := newChooserData("OIDC sign-in", app, publicRequestURI(r), state.Users, loginHintFromValues(values), hiddenValues(values), "Create an active user before starting an OIDC flow.")
		a.applySignIn(&data, r, state.Users, app.Slug, values, request, now)
		renderChooser(w, data)
		return
	}
	found, session, err := a.chooserSignIn(r, state.Users, app, values, request, now)
	if err != nil {
		a.failFlow(w, app, "oidc", "authorize", http.StatusBadRequest, err.Error())
		return
	}
	a.issueOIDCCode(w, r, app, values, found, session, request)
}

// issueOIDCCode mints an authorization code for a sign-in and redirects to the
// RP. It is shared by the chooser POST, the user_id GET shortcut, and
// prompt=none.
func (a *webApp) issueOIDCCode(w http.ResponseWriter, r *http.Request, app app, values url.Values, user user, session signIn, request authnRequest) {
	redirectURI, err := parseOIDCRedirectURI(values.Get("redirect_uri"))
	if err != nil {
		a.failFlow(w, app, "oidc", "authorize", http.StatusBadRequest, err.Error())
		return
	}
	sessionID, err := a.joinIdPSession(w, r, app.Slug, user, session, "oidc")
	if err != nil {
		a.failFlow(w, app, "oidc", "authorize", http.StatusInternalServerError, err.Error())
		return
	}

	a.oidcMu.Lock()
	defer a.oidcMu.Unlock()
	now := time.Now()
	a.pruneExpiredOIDCCredentials(now)

	code, err := randomSecret(24)
	if err != nil {
		a.failFlow(w, app, "oidc", "authorize", http.StatusInternalServerError, err.Error())
		return
	}
	authCode := authCode{
		AppSlug:       app.Slug,
		ClientID:      values.Get("client_id"),
		UserID:        user.ID,
		RedirectURI:   values.Get("redirect_uri"),
		Nonce:         values.Get("nonce"),
		Scope:         values.Get("scope"),
		CodeChallenge: values.Get("code_challenge"),
		Authn:         session.statement(request.Contexts),
		SessionID:     sessionID,
		ExpiresAt:     now.Add(5 * time.Minute),
		Faults:        a.flowFaults(app.Slug, values),
	}
	a.authCodes[code] = authCode
	if err := a.rememberOIDCInspection(app, user, authCode, "Authorization code issued", nil, "", now); err != nil {
		a.failFlow(w, app, "oidc", "authorize", http.StatusInternalServerError, err.Error())
		return
	}
	a.recordFlowEvent(app.Slug, "oidc", "authorize", "ok", userLabel(user), "Authorization code issued to "+authCode.ClientID)

	query := redirectURI.Query()
	query.Set("code", code)
	if stateValue := values.Get("state"); stateValue != "" {
		query.Set("state", stateValue)
	}
	redirectURI.RawQuery = query.Encode()
	if wantsAPIProtocolResponse(r) {
		writeJSON(w, map[string]string{"code": code, "redirect_uri": redirectURI.String(), "state": values.Get("state")})
		return
	}
	http.Redirect(w, r, redirectURI.String(), http.StatusFound)
}

func (a *webApp) handleOIDCToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	_, app, ok := appForProtocol(w, r, supportsOIDC)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		a.failOAuth(w, app, "token", http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	grantType := r.FormValue("grant_type")
	if grantType != "authorization_code" && grantType != "refresh_token" {
		a.failOAuth(w, app, "token", http.StatusBadRequest, "unsupported_grant_type", "grant_type must be authorization_code or refresh_token")
		return
	}
	if !clientAuthenticated(r, app) {
		// RFC 6749 section 5.2: a 401 for an attempted Basic
		// authentication must carry a WWW-Authenticate challenge.
		if _, _, usedBasic := r.BasicAuth(); usedBasic {
			w.Header().Set("WWW-Authenticate", `Basic realm="scimtest", charset="UTF-8"`)
		}
		a.failOAuth(w, app, "token", http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}
	if grantType == "refresh_token" {
		a.refreshOIDCTokens(w, r, app)
		return
	}

	a.oidcMu.Lock()
	defer a.oidcMu.Unlock()
	a.pruneExpiredOIDCCredentials(time.Now())

	codeValue := r.FormValue("code")
	code, ok := a.authCodes[codeValue]
	if !ok || code.Redeeming {
		a.failOAuth(w, app, "token", http.StatusBadRequest, "invalid_grant", "authorization code is invalid or expired")
		return
	}

	if code.AppSlug != app.Slug || code.ClientID != app.OIDCClientID || code.RedirectURI != r.FormValue("redirect_uri") {
		a.failOAuth(w, app, "token", http.StatusBadRequest, "invalid_grant", "authorization code does not match this request")
		return
	}
	if code.CodeChallenge != "" && !validPKCEVerifier(code.CodeChallenge, r.FormValue("code_verifier")) {
		a.failOAuth(w, app, "token", http.StatusBadRequest, "invalid_grant", "PKCE code verifier is invalid")
		return
	}
	// OAuth 2.0 Security BCP: a verifier for a code issued without a
	// challenge signals a confused or attacked client - reject it.
	if code.CodeChallenge == "" && r.FormValue("code_verifier") != "" {
		a.failOAuth(w, app, "token", http.StatusBadRequest, "invalid_grant", "code_verifier provided but the authorization request used no code_challenge")
		return
	}
	setRedeeming := func(redeeming bool) {
		if current, found := a.authCodes[codeValue]; found {
			current.Redeeming = redeeming
			a.authCodes[codeValue] = current
		}
	}
	if !a.injectTokenFault(w, r, app, grantType, setRedeeming) {
		return
	}
	code, ok = a.authCodes[codeValue]
	if !ok || !code.ExpiresAt.After(time.Now()) {
		delete(a.authCodes, codeValue)
		a.failOAuth(w, app, "token", http.StatusBadRequest, "invalid_grant", "authorization code is invalid or expired")
		return
	}
	delete(a.authCodes, codeValue)
	// Fault injection: fail the exchange on demand before doing any work.
	if code.Faults.TokenError != "" {
		a.failOAuth(w, app, "token", http.StatusBadRequest, code.Faults.TokenError, "injected token error")
		return
	}
	state, err := loadStateForApp(app.ID)
	if err != nil {
		a.failOAuth(w, app, "token", http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	user, ok := userByID(state.Users, code.UserID)
	if !ok || !user.Active || user.Deleted {
		a.failOAuth(w, app, "token", http.StatusBadRequest, "invalid_grant", "user is inactive or missing")
		return
	}

	now := time.Now()
	response, err := a.issueOIDCTokens(r, state, app, user, code, "Tokens issued", now)
	if err != nil {
		a.failOAuth(w, app, "token", http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	tokenDetail := "ID and access tokens issued to " + app.OIDCClientID
	if hasOIDCScope(code.Scope, "offline_access") {
		refresh, err := a.issueRefreshToken(refreshToken{
			AppSlug:       app.Slug,
			ClientID:      code.ClientID,
			UserID:        user.ID,
			RedirectURI:   code.RedirectURI,
			Scope:         code.Scope,
			CodeChallenge: code.CodeChallenge,
			Authn:         code.Authn,
			SessionID:     code.SessionID,
		}, now)
		if err != nil {
			a.failOAuth(w, app, "token", http.StatusInternalServerError, "server_error", err.Error())
			return
		}
		response["refresh_token"] = refresh
		tokenDetail = "ID, access, and refresh tokens issued to " + app.OIDCClientID
	}
	if code.Faults.active() {
		tokenDetail += " (faults injected)"
	}
	a.recordFlowEvent(app.Slug, "oidc", "token", "ok", userLabel(user), tokenDetail)
	writeJSON(w, response)
}

// injectTokenFault delivers an armed token-phase scenario action to a
// grantType request. The caller holds oidcMu and has validated the presented
// grant. A delay releases oidcMu while it runs, and setRedeeming marks the
// grant meanwhile so a concurrent request cannot redeem it. It returns with
// oidcMu held, and false once it has finished the response. On true the
// caller must look the grant up again: it may have expired or been revoked
// during a delay.
func (a *webApp) injectTokenFault(w http.ResponseWriter, r *http.Request, app app, grantType string, setRedeeming func(bool)) bool {
	action, inject := a.reserveResilienceEndpointAction(app.Slug, "token", time.Now())
	if !inject {
		return true
	}
	label := "token (" + grantType + ")"
	completed := false
	if action.Delay > 0 {
		setRedeeming(true)
		a.oidcMu.Unlock()
		delivered := waitForResilienceDelay(r.Context(), action.Delay)
		a.oidcMu.Lock()
		setRedeeming(false)
		if !delivered {
			a.cancelResilienceEndpointAction(app.Slug, label, action, time.Now())
			return false
		}
		completed = a.completeResilienceEndpointAction(app.Slug, label, action, time.Now())
		if completed {
			a.recordFlowEvent(app.Slug, "oidc", "token", "ok", "", "Injected "+action.describe())
		}
	}
	if action.Delay == 0 {
		completed = a.completeResilienceEndpointAction(app.Slug, label, action, time.Now())
	}
	if completed && action.Status != 0 {
		a.writeResilienceEndpointFailure(w, app.Slug, "oidc", "token", action)
		return false
	}
	return true
}

// issueOIDCTokens signs an ID token and stores an access token for grant,
// records the inspection under stage, and returns the token response. The
// caller holds oidcMu.
func (a *webApp) issueOIDCTokens(r *http.Request, state appState, app app, user user, grant authCode, stage string, now time.Time) (map[string]any, error) {
	claims := userClaims(state, app, user, grant.Scope)
	claims["iss"] = oidcIssuer(a.effectiveIDPBaseURL(r, state), app)
	claims["aud"] = app.OIDCClientID
	claims["iat"] = now.Unix()
	grant.Authn.addClaims(claims, grant.Faults.ClockSkew)
	if grant.Nonce != "" {
		claims["nonce"] = grant.Nonce
	}
	if grant.SessionID != "" {
		claims["sid"] = grant.SessionID
	}
	grant.Faults.applyToClaims(claims, now)
	idToken, err := a.signJWT(claims, grant.Faults)
	if err != nil {
		return nil, err
	}
	if grant.Faults.BreakSignature {
		idToken = corruptJWTSignature(idToken)
	}
	access, err := randomSecret(32)
	if err != nil {
		return nil, err
	}
	if err := a.rememberOIDCInspection(app, user, grant, stage, claims, idToken, now); err != nil {
		return nil, err
	}
	a.accessTokens[access] = accessToken{
		AppSlug:   app.Slug,
		UserID:    user.ID,
		Scope:     grant.Scope,
		ExpiresAt: now.Add(time.Hour),
		Faults:    grant.Faults,
	}
	return map[string]any{
		"access_token": access,
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     idToken,
		"scope":        grant.Scope,
	}, nil
}

// issueRefreshToken stores grant under a new refresh token value. The caller
// holds oidcMu.
func (a *webApp) issueRefreshToken(grant refreshToken, now time.Time) (string, error) {
	value, err := randomSecret(32)
	if err != nil {
		return "", err
	}
	grant.ExpiresAt = now.Add(refreshTokenLifetime)
	a.refreshTokens[value] = grant
	return value, nil
}

// refreshOIDCTokens redeems a refresh token (RFC 6749 section 6). The token
// rotates: the presented value stops working and the response carries its
// replacement. A narrower scope applies to the new access and ID tokens
// only; the replacement refresh token keeps the original scope.
func (a *webApp) refreshOIDCTokens(w http.ResponseWriter, r *http.Request, app app) {
	a.oidcMu.Lock()
	defer a.oidcMu.Unlock()
	a.pruneExpiredOIDCCredentials(time.Now())

	presented := r.FormValue("refresh_token")
	grant, ok := a.refreshTokens[presented]
	if !ok || grant.Redeeming || grant.AppSlug != app.Slug || grant.ClientID != app.OIDCClientID {
		a.failOAuth(w, app, "token", http.StatusBadRequest, "invalid_grant", "refresh token is invalid, expired, or revoked")
		return
	}
	scope := grant.Scope
	if requested := r.FormValue("scope"); requested != "" {
		for _, value := range strings.Fields(requested) {
			if !hasOIDCScope(grant.Scope, value) {
				a.failOAuth(w, app, "token", http.StatusBadRequest, "invalid_scope", "scope "+value+" was not granted")
				return
			}
		}
		scope = requested
	}
	setRedeeming := func(redeeming bool) {
		if current, found := a.refreshTokens[presented]; found {
			current.Redeeming = redeeming
			a.refreshTokens[presented] = current
		}
	}
	if !a.injectTokenFault(w, r, app, "refresh_token", setRedeeming) {
		return
	}
	grant, ok = a.refreshTokens[presented]
	if !ok || !grant.ExpiresAt.After(time.Now()) {
		delete(a.refreshTokens, presented)
		a.failOAuth(w, app, "token", http.StatusBadRequest, "invalid_grant", "refresh token is invalid, expired, or revoked")
		return
	}
	state, err := loadStateForApp(app.ID)
	if err != nil {
		a.failOAuth(w, app, "token", http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	user, ok := userByID(state.Users, grant.UserID)
	if !ok || !user.Active || user.Deleted {
		delete(a.refreshTokens, presented)
		a.failOAuth(w, app, "token", http.StatusBadRequest, "invalid_grant", "user is inactive or missing")
		return
	}

	// OIDC Core section 12.2: same iss, sub, and aud, a new iat, the original
	// auth_time, and no nonce.
	now := time.Now()
	response, err := a.issueOIDCTokens(r, state, app, user, authCode{
		ClientID:      grant.ClientID,
		RedirectURI:   grant.RedirectURI,
		Scope:         scope,
		CodeChallenge: grant.CodeChallenge,
		Authn:         grant.Authn,
		SessionID:     grant.SessionID,
	}, "Tokens refreshed", now)
	if err != nil {
		a.failOAuth(w, app, "token", http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	replacement, err := a.issueRefreshToken(grant, now)
	if err != nil {
		a.failOAuth(w, app, "token", http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	delete(a.refreshTokens, presented)
	response["refresh_token"] = replacement
	a.recordFlowEvent(app.Slug, "oidc", "token", "ok", userLabel(user), "Tokens refreshed for "+grant.ClientID+"; refresh token rotated")
	writeJSON(w, response)
}

func (a *webApp) handleOIDCUserinfo(w http.ResponseWriter, r *http.Request) {
	a.oidcMu.Lock()
	defer a.oidcMu.Unlock()

	state, app, ok := appForProtocol(w, r, supportsOIDC)
	if !ok {
		return
	}
	a.pruneExpiredOIDCCredentials(time.Now())
	tokenValue, ok := oidcBearerToken(r.Header.Get("Authorization"))
	if !ok {
		a.failOAuth(w, app, "userinfo", http.StatusUnauthorized, "invalid_token", "access token is invalid or expired")
		return
	}
	token, ok := a.accessTokens[tokenValue]
	if !ok || token.AppSlug != app.Slug {
		a.failOAuth(w, app, "userinfo", http.StatusUnauthorized, "invalid_token", "access token is invalid or expired")
		return
	}
	user, ok := userByID(state.Users, token.UserID)
	if !ok || !user.Active || user.Deleted {
		a.failOAuth(w, app, "userinfo", http.StatusUnauthorized, "invalid_token", "user is inactive or missing")
		return
	}
	claims := userClaims(state, app, user, token.Scope)
	token.Faults.dropClaims(claims)
	a.recordFlowEvent(app.Slug, "oidc", "userinfo", "ok", userLabel(user), "Userinfo claims served")
	writeJSON(w, claims)
}

// oidcTokenHolder counts the live tokens one user holds for an app.
type oidcTokenHolder struct {
	UserID        string `json:"user_id"`
	User          string `json:"user"`
	AccessTokens  int    `json:"access_tokens"`
	RefreshTokens int    `json:"refresh_tokens"`
}

// oidcTokenHolders lists the users holding live tokens for an app, sorted by
// user label.
func (a *webApp) oidcTokenHolders(slug string, users []user) []oidcTokenHolder {
	a.oidcMu.Lock()
	defer a.oidcMu.Unlock()
	a.pruneExpiredOIDCCredentials(time.Now())
	byUser := make(map[string]*oidcTokenHolder)
	holder := func(userID string) *oidcTokenHolder {
		if byUser[userID] == nil {
			byUser[userID] = &oidcTokenHolder{UserID: userID, User: userID}
			if found, ok := userByID(users, userID); ok {
				byUser[userID].User = userLabel(found)
			}
		}
		return byUser[userID]
	}
	for _, token := range a.accessTokens {
		if token.AppSlug == slug {
			holder(token.UserID).AccessTokens++
		}
	}
	for _, token := range a.refreshTokens {
		if token.AppSlug == slug {
			holder(token.UserID).RefreshTokens++
		}
	}
	holders := make([]oidcTokenHolder, 0, len(byUser))
	for _, found := range byUser {
		holders = append(holders, *found)
	}
	slices.SortFunc(holders, func(x, y oidcTokenHolder) int { return strings.Compare(x.User, y.User) })
	return holders
}

// revokeOIDCTokens deletes an app's access and refresh tokens, or only
// userID's when it is set, and reports how many it deleted.
func (a *webApp) revokeOIDCTokens(slug, userID string) int {
	a.oidcMu.Lock()
	defer a.oidcMu.Unlock()
	matches := func(appSlug, tokenUserID string) bool {
		return appSlug == slug && (userID == "" || tokenUserID == userID)
	}
	revoked := 0
	for value, token := range a.accessTokens {
		if matches(token.AppSlug, token.UserID) {
			delete(a.accessTokens, value)
			revoked++
		}
	}
	for value, token := range a.refreshTokens {
		if matches(token.AppSlug, token.UserID) {
			delete(a.refreshTokens, value)
			revoked++
		}
	}
	return revoked
}

func (a *webApp) handleOIDCTokenRevoke(w http.ResponseWriter, r *http.Request) {
	state, foundApp, ok := appForProtocol(w, r, supportsOIDC)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	userID := r.FormValue("user_id")
	revoked := a.revokeOIDCTokens(foundApp.Slug, userID)
	a.recordFlowEvent(foundApp.Slug, "oidc", "revoke", "ok", revokedUserLabel(state.Users, userID), fmt.Sprintf("Revoked %d tokens", revoked))
	http.Redirect(w, r, inspectorReturnPath(r, foundApp), http.StatusSeeOther)
}

// revokedUserLabel names the user whose tokens were revoked, or no one when
// every user's tokens were.
func revokedUserLabel(users []user, userID string) string {
	if found, ok := userByID(users, userID); ok {
		return userLabel(found)
	}
	return userID
}

func oidcBearerToken(value string) (string, bool) {
	scheme, token, found := strings.Cut(strings.TrimSpace(value), " ")
	if !found || !strings.EqualFold(scheme, "Bearer") || token == "" || strings.ContainsAny(token, " \t\r\n") {
		return "", false
	}
	return token, true
}

func (a *webApp) pruneExpiredOIDCCredentials(now time.Time) {
	for value, code := range a.authCodes {
		if !code.ExpiresAt.After(now) {
			delete(a.authCodes, value)
		}
	}
	for value, token := range a.accessTokens {
		if !token.ExpiresAt.After(now) {
			delete(a.accessTokens, value)
		}
	}
	for value, token := range a.refreshTokens {
		if !token.ExpiresAt.After(now) {
			delete(a.refreshTokens, value)
		}
	}
}

// validateAuthorizeClient checks client_id and redirect_uri. Failures here
// must never redirect: an unverified redirect_uri is not a safe target
// (RFC 6749 section 4.1.2.1). When tunneled is true, AllowAnyOIDCRedirect is
// ignored so a public tunnel cannot mint codes to an attacker-chosen URI.
func validateAuthorizeClient(app app, values url.Values, tunneled bool, extraAllowed ...string) error {
	if values.Get("client_id") != app.OIDCClientID {
		return fmt.Errorf("client_id is invalid")
	}
	redirectURI := values.Get("redirect_uri")
	if redirectURI == "" {
		return fmt.Errorf("redirect_uri is required")
	}
	if _, err := parseOIDCRedirectURI(redirectURI); err != nil {
		return err
	}
	allowAny := app.AllowAnyOIDCRedirect && !tunneled
	if !allowAny && !slices.Contains(app.OIDCRedirectURIs, redirectURI) && !slices.Contains(extraAllowed, redirectURI) {
		return fmt.Errorf("redirect_uri %q is not registered for this app; registered: %v", redirectURI, app.OIDCRedirectURIs)
	}
	return nil
}

// playgroundAllowedRedirect returns the built-in RP callback URI that authorize
// should accept in addition to the registered set, but only for loopback
// requests: a tunneled flow must never mint codes to a loopback URI.
func (a *webApp) playgroundAllowedRedirect(tunneled bool, slug string) string {
	if tunneled {
		return ""
	}
	return a.playgroundCallbackURI(slug)
}

type authorizeError struct {
	code        string
	description string
}

func (e *authorizeError) Error() string { return e.description }

// parseAuthorizeRequest checks the authorize parameters whose failures are
// delivered to the already-validated redirect_uri, and returns what the
// request asks of the sign-in.
func parseAuthorizeRequest(app app, values url.Values) (authnRequest, error) {
	if values.Get("response_type") != "code" {
		return authnRequest{}, &authorizeError{code: "unsupported_response_type", description: "response_type must be code"}
	}
	if !strings.Contains(" "+values.Get("scope")+" ", " openid ") {
		return authnRequest{}, &authorizeError{code: "invalid_scope", description: "scope must include openid"}
	}
	challenge := values.Get("code_challenge")
	method := values.Get("code_challenge_method")
	switch {
	case app.OIDCPublicClient && challenge == "":
		return authnRequest{}, &authorizeError{code: "invalid_request", description: "public clients must use PKCE"}
	case challenge != "" && method != "S256":
		return authnRequest{}, &authorizeError{code: "invalid_request", description: "code_challenge_method must be S256"}
	case challenge != "" && len(challenge) != 43:
		return authnRequest{}, &authorizeError{code: "invalid_request", description: "code_challenge must be a valid S256 challenge"}
	case challenge == "" && method != "":
		return authnRequest{}, &authorizeError{code: "invalid_request", description: "code_challenge is required when code_challenge_method is set"}
	}

	request := authnRequest{Contexts: strings.Fields(values.Get("acr_values"))}
	// consent and select_account need nothing extra: the chooser always
	// shows the account list and the Deny button.
	prompts := strings.Fields(values.Get("prompt"))
	switch {
	case slices.Contains(prompts, "none") && len(prompts) > 1:
		return authnRequest{}, &authorizeError{code: "invalid_request", description: "prompt=none cannot be combined with other prompt values"}
	case slices.Contains(prompts, "none"):
		request.Passive = true
	case slices.Contains(prompts, "login"):
		request.FreshReason = "prompt=login"
	}
	if raw := values.Get("max_age"); raw != "" {
		seconds, err := strconv.ParseUint(raw, 10, 32)
		if err != nil {
			return authnRequest{}, &authorizeError{code: "invalid_request", description: "max_age must be a non-negative number of seconds"}
		}
		request.MaxAge = time.Duration(seconds) * time.Second
		// OIDC Core section 3.1.2.1: max_age=0 is equivalent to prompt=login.
		if seconds == 0 && request.FreshReason == "" {
			request.FreshReason = "max_age=0"
		}
	}
	return request, nil
}

// redirectAuthorizeError delivers an authorize failure to the RP on the
// already-validated redirect_uri with error, error_description, and state,
// per RFC 6749 section 4.1.2.1.
func redirectAuthorizeError(w http.ResponseWriter, r *http.Request, values url.Values, failure error) {
	redirectURI, err := parseOIDCRedirectURI(values.Get("redirect_uri"))
	if err != nil {
		http.Error(w, failure.Error(), http.StatusBadRequest)
		return
	}
	code := "invalid_request"
	var authorizeErr *authorizeError
	if errors.As(failure, &authorizeErr) {
		code = authorizeErr.code
	}
	query := redirectURI.Query()
	query.Set("error", code)
	query.Set("error_description", failure.Error())
	if stateValue := values.Get("state"); stateValue != "" {
		query.Set("state", stateValue)
	}
	redirectURI.RawQuery = query.Encode()
	http.Redirect(w, r, redirectURI.String(), http.StatusFound)
}

func parseOIDCRedirectURI(value string) (*url.URL, error) {
	redirectURI, err := url.Parse(value)
	if err != nil {
		return nil, fmt.Errorf("redirect_uri must be a valid absolute HTTP(S) URL: %w", err)
	}
	switch strings.ToLower(redirectURI.Scheme) {
	case "http", "https":
	default:
		return nil, fmt.Errorf("redirect_uri must be a valid absolute HTTP(S) URL")
	}
	if redirectURI.Host == "" || redirectURI.Fragment != "" {
		return nil, fmt.Errorf("redirect_uri must be a valid absolute HTTP(S) URL without a fragment")
	}
	return redirectURI, nil
}

func validPKCEVerifier(challenge string, verifier string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	for _, character := range verifier {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~", character) {
			return false
		}
	}
	digest := sha256.Sum256([]byte(verifier))
	actual := base64.RawURLEncoding.EncodeToString(digest[:])
	return subtle.ConstantTimeCompare([]byte(actual), []byte(challenge)) == 1
}

func clientAuthenticated(r *http.Request, app app) bool {
	if app.OIDCPublicClient {
		return r.FormValue("client_id") == app.OIDCClientID
	}
	clientID, secret, ok := r.BasicAuth()
	if ok {
		// RFC 6749 section 2.3.1: Basic credentials are form-url-encoded
		// before being base64-encoded.
		if decoded, err := url.QueryUnescape(clientID); err == nil {
			clientID = decoded
		}
		if decoded, err := url.QueryUnescape(secret); err == nil {
			secret = decoded
		}
	} else {
		clientID, secret = r.FormValue("client_id"), r.FormValue("client_secret")
	}
	// The token endpoint is reachable through the public tunnel, so the
	// secret comparison must not leak timing.
	return clientID == app.OIDCClientID && subtle.ConstantTimeCompare([]byte(secret), []byte(app.OIDCClientSecret)) == 1
}

func userClaims(state appState, app app, user user, scope string) map[string]any {
	claims := map[string]any{"sub": user.ID}
	mappings := oidcClaimMappingsForApp(app)
	if hasOIDCScope(scope, "profile") {
		claims[mappings.Name] = userLabel(user)
		claims[mappings.GivenName] = user.GivenName
		claims[mappings.FamilyName] = user.FamilyName
		claims[mappings.Username] = user.Username
	}
	if hasOIDCScope(scope, "email") {
		claims[mappings.Email] = user.Email
		claims["email_verified"] = true
	}
	if app.IncludeGroupsClaim && hasOIDCScope(scope, "groups") {
		claims[mappings.Groups] = userGroups(state, user.ID)
	}
	return claims
}

func oidcClaimsSupported(app app) []string {
	mappings := oidcClaimMappingsForApp(app)
	return []string{
		"sub", mappings.Name, mappings.GivenName, mappings.FamilyName,
		mappings.Username, mappings.Email, "email_verified", mappings.Groups,
		"auth_time", "acr", "amr", "sid",
	}
}

func hasOIDCScope(scope string, target string) bool {
	return slices.Contains(strings.Fields(scope), target)
}

// signJWT signs claims as an RS256 compact JWS. Tamper faults can name a key
// the JWKS does not publish or emit an unsecured alg none token.
func (a *webApp) signJWT(claims map[string]any, faults faultOptions) (string, error) {
	header := map[string]any{"typ": "JWT", "alg": "RS256", "kid": "scimtest-dev"}
	if faults.tampers(tamperUnknownKeyID) {
		header["kid"] = "scimtest-unknown"
	}
	if faults.tampers(tamperAlgNone) {
		header = map[string]any{"typ": "JWT", "alg": "none"}
	}
	headerData, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimData, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	a.writeDebugOIDCTokenPayload(os.Stdout, claimData)
	unsigned := base64.RawURLEncoding.EncodeToString(headerData) + "." + base64.RawURLEncoding.EncodeToString(claimData)
	if faults.tampers(tamperAlgNone) {
		return unsigned + ".", nil
	}
	digest := sha256.Sum256([]byte(unsigned))
	sig, err := rsa.SignPKCS1v15(rand.Reader, a.signingKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func writeJSON(w http.ResponseWriter, value any) {
	writeJSONStatus(w, http.StatusOK, value)
}

func writeJSONStatus(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf("write JSON response: %v", err)
	}
}

func writeOAuthError(w http.ResponseWriter, status int, code string, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": description}); err != nil {
		log.Printf("write OAuth error response: %v", err)
	}
}
