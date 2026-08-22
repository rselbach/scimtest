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
	ExpiresAt     time.Time
	Faults        faultOptions
	Redeeming     bool
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
	scopes := []string{"openid", "profile", "email"}
	if app.IncludeGroupsClaim {
		scopes = append(scopes, "groups")
	}
	writeJSON(w, map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/authorize",
		"token_endpoint":                        issuer + "/token",
		"userinfo_endpoint":                     issuer + "/userinfo",
		"jwks_uri":                              issuer + "/jwks",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      scopes,
		"claims_supported":                      oidcClaimsSupported(app),
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
	if err := validateAuthorizeRequest(app, values); err != nil {
		a.failAuthorize(w, r, app, values, err)
		return
	}
	if isTruthy(values.Get("deny")) {
		a.failAuthorize(w, r, app, values, &authorizeError{code: "access_denied", description: "the user denied the request"})
		return
	}
	if !post && !chooserSelectionProvided(app, values) {
		data := newChooserData("OIDC sign-in", app, publicRequestURI(r), state.Users, loginHintFromValues(values), hiddenValues(values), "Create an active user before starting an OIDC flow.")
		a.applyRememberedChooserUser(&data, r, state, app)
		renderChooser(w, data)
		return
	}
	a.issueOIDCCode(w, r, state, app, values)
}

// issueOIDCCode mints an authorization code for the selected user and redirects
// to the RP. It is shared by the chooser POST and the user_id GET shortcut.
func (a *webApp) issueOIDCCode(w http.ResponseWriter, r *http.Request, state appState, app app, values url.Values) {
	redirectURI, err := parseOIDCRedirectURI(values.Get("redirect_uri"))
	if err != nil {
		a.failFlow(w, app, "oidc", "authorize", http.StatusBadRequest, err.Error())
		return
	}
	user, ok := chooserUser(state.Users, app, values)
	if !ok || !user.Active || user.Deleted {
		a.failFlow(w, app, "oidc", "authorize", http.StatusBadRequest, "active user is required")
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
		ExpiresAt:     now.Add(5 * time.Minute),
		Faults:        a.flowFaults(app.Slug, values),
	}
	a.authCodes[code] = authCode
	if err := a.rememberOIDCInspection(app, user, authCode, "Authorization code issued", nil, "", now); err != nil {
		a.failFlow(w, app, "oidc", "authorize", http.StatusInternalServerError, err.Error())
		return
	}
	a.recordFlowEvent(app.Slug, "oidc", "authorize", "ok", userLabel(user), "Authorization code issued to "+authCode.ClientID)
	rememberChooserUser(w, app.Slug, user.ID)

	query := redirectURI.Query()
	query.Set("code", code)
	if stateValue := values.Get("state"); stateValue != "" {
		query.Set("state", stateValue)
	}
	redirectURI.RawQuery = query.Encode()
	http.Redirect(w, r, redirectURI.String(), http.StatusFound)
}

func (a *webApp) handleOIDCToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	state, app, ok := appForProtocol(w, r, supportsOIDC)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		a.failOAuth(w, app, "token", http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if r.FormValue("grant_type") != "authorization_code" {
		a.failOAuth(w, app, "token", http.StatusBadRequest, "unsupported_grant_type", "only authorization_code is supported")
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

	a.oidcMu.Lock()
	now := time.Now()
	a.pruneExpiredOIDCCredentials(now)

	codeValue := r.FormValue("code")
	code, ok := a.authCodes[codeValue]
	if !ok || code.Redeeming {
		a.oidcMu.Unlock()
		a.failOAuth(w, app, "token", http.StatusBadRequest, "invalid_grant", "authorization code is invalid or expired")
		return
	}

	if code.AppSlug != app.Slug || code.ClientID != app.OIDCClientID || code.RedirectURI != r.FormValue("redirect_uri") {
		a.oidcMu.Unlock()
		a.failOAuth(w, app, "token", http.StatusBadRequest, "invalid_grant", "authorization code does not match this request")
		return
	}
	if code.CodeChallenge != "" && !validPKCEVerifier(code.CodeChallenge, r.FormValue("code_verifier")) {
		a.oidcMu.Unlock()
		a.failOAuth(w, app, "token", http.StatusBadRequest, "invalid_grant", "PKCE code verifier is invalid")
		return
	}
	// OAuth 2.0 Security BCP: a verifier for a code issued without a
	// challenge signals a confused or attacked client - reject it.
	if code.CodeChallenge == "" && r.FormValue("code_verifier") != "" {
		a.oidcMu.Unlock()
		a.failOAuth(w, app, "token", http.StatusBadRequest, "invalid_grant", "code_verifier provided but the authorization request used no code_challenge")
		return
	}
	action, inject := a.reserveResilienceEndpointAction(app.Slug, "token", time.Now())
	injectionCompleted := false
	if inject && action.Delay > 0 {
		code.Redeeming = true
		a.authCodes[codeValue] = code
		a.oidcMu.Unlock()
		if !waitForResilienceDelay(r.Context(), action.Delay) {
			a.oidcMu.Lock()
			if current, found := a.authCodes[codeValue]; found && current.Redeeming {
				current.Redeeming = false
				a.authCodes[codeValue] = current
			}
			a.oidcMu.Unlock()
			a.cancelResilienceEndpointAction(app.Slug, "token", action, time.Now())
			return
		}
		injectionCompleted = a.completeResilienceEndpointAction(app.Slug, "token", action, time.Now())
		if injectionCompleted {
			a.recordFlowEvent(app.Slug, "oidc", "token", "ok", "", "Injected "+action.describe())
		}
		a.oidcMu.Lock()
		current, found := a.authCodes[codeValue]
		if !found || !current.Redeeming {
			a.oidcMu.Unlock()
			a.failOAuth(w, app, "token", http.StatusBadRequest, "invalid_grant", "authorization code is invalid or expired")
			return
		}
		code = current
	}
	if inject && action.Delay == 0 {
		injectionCompleted = a.completeResilienceEndpointAction(app.Slug, "token", action, time.Now())
	}
	if injectionCompleted && action.Status != 0 {
		a.oidcMu.Unlock()
		a.writeResilienceEndpointFailure(w, app.Slug, "oidc", "token", action)
		return
	}
	delete(a.authCodes, codeValue)
	defer a.oidcMu.Unlock()
	// Fault injection: fail the exchange on demand before doing any work.
	if code.Faults.TokenError != "" {
		a.failOAuth(w, app, "token", http.StatusBadRequest, code.Faults.TokenError, "injected token error")
		return
	}
	user, ok := userByID(state.Users, code.UserID)
	if !ok || !user.Active || user.Deleted {
		a.failOAuth(w, app, "token", http.StatusBadRequest, "invalid_grant", "user is inactive or missing")
		return
	}

	claims := userClaims(state, app, user, code.Scope)
	claims["iss"] = oidcIssuer(a.effectiveIDPBaseURL(r, state), app)
	claims["aud"] = app.OIDCClientID
	claims["iat"] = now.Unix()
	claims["exp"] = now.Add(time.Hour).Unix()
	if code.Nonce != "" {
		claims["nonce"] = code.Nonce
	}
	code.Faults.applyToClaims(claims, now)
	idToken, err := a.signJWT(claims)
	if err != nil {
		a.failOAuth(w, app, "token", http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	if code.Faults.BreakSignature {
		idToken = corruptJWTSignature(idToken)
	}
	access, err := randomSecret(32)
	if err != nil {
		a.failOAuth(w, app, "token", http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	if err := a.rememberOIDCInspection(app, user, code, "Tokens issued", claims, idToken, now); err != nil {
		a.failOAuth(w, app, "token", http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	a.accessTokens[access] = accessToken{
		AppSlug:   app.Slug,
		UserID:    user.ID,
		Scope:     code.Scope,
		ExpiresAt: now.Add(time.Hour),
		Faults:    code.Faults,
	}
	tokenDetail := "ID and access tokens issued to " + app.OIDCClientID
	if code.Faults.active() {
		tokenDetail += " (faults injected)"
	}
	a.recordFlowEvent(app.Slug, "oidc", "token", "ok", userLabel(user), tokenDetail)
	writeJSON(w, map[string]any{
		"access_token": access,
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     idToken,
		"scope":        code.Scope,
	})
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
	if !allowAny && !stringIn(app.OIDCRedirectURIs, redirectURI) && !stringIn(extraAllowed, redirectURI) {
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

// validateAuthorizeRequest checks the authorize parameters whose failures
// are delivered to the already-validated redirect_uri.
func validateAuthorizeRequest(app app, values url.Values) error {
	if values.Get("response_type") != "code" {
		return &authorizeError{code: "unsupported_response_type", description: "response_type must be code"}
	}
	if !strings.Contains(" "+values.Get("scope")+" ", " openid ") {
		return &authorizeError{code: "invalid_scope", description: "scope must include openid"}
	}
	challenge := values.Get("code_challenge")
	method := values.Get("code_challenge_method")
	switch {
	case app.OIDCPublicClient && challenge == "":
		return &authorizeError{code: "invalid_request", description: "public clients must use PKCE"}
	case challenge != "" && method != "S256":
		return &authorizeError{code: "invalid_request", description: "code_challenge_method must be S256"}
	case challenge != "" && len(challenge) != 43:
		return &authorizeError{code: "invalid_request", description: "code_challenge must be a valid S256 challenge"}
	case challenge == "" && method != "":
		return &authorizeError{code: "invalid_request", description: "code_challenge is required when code_challenge_method is set"}
	}
	return nil
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
	}
}

func hasOIDCScope(scope string, target string) bool {
	return stringIn(strings.Fields(scope), target)
}

func (a *webApp) signJWT(claims map[string]any) (string, error) {
	header := map[string]any{"typ": "JWT", "alg": "RS256", "kid": "scimtest-dev"}
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

func stringIn(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
