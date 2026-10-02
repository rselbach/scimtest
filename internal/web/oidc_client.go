package web

import (
	"fmt"
	"net/http"
	"time"
)

// authenticateOAuthClient checks the client authentication of a token,
// introspection, or revocation request, and answers a failure with
// invalid_client.
func (a *webApp) authenticateOAuthClient(w http.ResponseWriter, r *http.Request, app app, stage string) bool {
	if clientAuthenticated(r, app) {
		return true
	}
	// RFC 6749 section 5.2: a 401 for an attempted Basic authentication must
	// carry a WWW-Authenticate challenge.
	if _, _, usedBasic := r.BasicAuth(); usedBasic {
		w.Header().Set("WWW-Authenticate", `Basic realm="scimtest", charset="UTF-8"`)
	}
	a.failOAuth(w, app, stage, http.StatusUnauthorized, "invalid_client", "client authentication failed")
	return false
}

// issueClientCredentialsToken answers grant_type=client_credentials (RFC 6749
// section 4.4) with an access token the client holds for itself. There is no
// user, so the response has no ID token and no refresh token. The requested
// scope is granted as asked.
func (a *webApp) issueClientCredentialsToken(w http.ResponseWriter, r *http.Request, app app) {
	if app.OIDCPublicClient {
		a.failOAuth(w, app, "token", http.StatusBadRequest, "unauthorized_client", "client_credentials requires a confidential client")
		return
	}
	a.oidcMu.Lock()
	defer a.oidcMu.Unlock()
	a.pruneExpiredOIDCCredentials(time.Now())
	// No stored grant can be redeemed twice during a delay, so there is
	// nothing to mark.
	if !a.injectTokenFault(w, r, app, "client_credentials", func(bool) {}) {
		return
	}
	state, err := loadStateForApp(app.ID)
	if err != nil {
		a.failOAuth(w, app, "token", http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	now := time.Now()
	scope := r.FormValue("scope")
	issuer := oidcIssuer(a.effectiveIDPBaseURL(r, state), app)
	access, err := a.mintAccessToken(issuer, app, "", authCode{ClientID: app.OIDCClientID, Scope: scope}, now)
	if err != nil {
		a.failOAuth(w, app, "token", http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	response := map[string]any{
		"access_token": access,
		"token_type":   "Bearer",
		"expires_in":   int(accessTokenLifetime.Seconds()),
	}
	if scope != "" {
		response["scope"] = scope
	}
	a.recordFlowEvent(app.Slug, "oidc", "token", "ok", "", "Access token issued to "+app.OIDCClientID+" (client_credentials)")
	writeJSON(w, response)
}

// handleOIDCIntrospect answers token introspection (RFC 7662) for the
// environment's client. A token is active when this environment issued it,
// it has not expired or been revoked, and its user can still sign in.
func (a *webApp) handleOIDCIntrospect(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	value, state, app, ok := a.clientTokenRequest(w, r, "introspect")
	if !ok {
		return
	}
	a.oidcMu.Lock()
	defer a.oidcMu.Unlock()
	a.pruneExpiredOIDCCredentials(time.Now())

	response, holder, detail := a.introspectToken(r, state, app, value)
	a.recordFlowEvent(app.Slug, "oidc", "introspect", "ok", holder, detail)
	writeJSON(w, response)
}

// introspectToken describes value as RFC 7662 section 2.2 does, and returns
// its holder and a flow log detail. The caller holds oidcMu.
func (a *webApp) introspectToken(r *http.Request, state appState, app app, value string) (map[string]any, string, string) {
	inactive := map[string]any{"active": false}
	response := map[string]any{"active": true, "iss": oidcIssuer(a.effectiveIDPBaseURL(r, state), app)}
	access, isAccess := a.accessTokens[value]
	refresh, isRefresh := a.refreshTokens[value]
	userID, kind := "", ""
	switch {
	case isAccess && access.AppSlug == app.Slug:
		userID, kind = access.UserID, "Access token"
		response["token_type"] = "Bearer"
		response["client_id"] = access.ClientID
		response["scope"] = access.Scope
		response["iat"] = access.IssuedAt.Unix()
		response["exp"] = access.ExpiresAt.Unix()
		response["sub"] = access.ClientID
		if access.Audience != "" {
			response["aud"] = access.Audience
		}
	case isRefresh && refresh.AppSlug == app.Slug && refresh.ClientID == app.OIDCClientID:
		userID, kind = refresh.UserID, "Refresh token"
		response["client_id"] = refresh.ClientID
		response["scope"] = refresh.Scope
		response["iat"] = refresh.IssuedAt.Unix()
		response["exp"] = refresh.ExpiresAt.Unix()
	default:
		return inactive, "", "Token introspected: inactive (unknown, expired, or revoked)"
	}
	if userID == "" {
		return response, access.ClientID, kind + " introspected: active (client_credentials)"
	}
	user, ok := userByID(state.Users, userID)
	if !ok || !user.Active || user.Deleted {
		return inactive, userID, kind + " introspected: inactive, user is inactive or missing"
	}
	response["sub"] = user.ID
	response["username"] = user.Username
	return response, userLabel(user), kind + " introspected: active"
}

// handleOIDCRevoke revokes a token at the client's request (RFC 7009).
// Revoking a refresh token also revokes the access tokens its grant issued.
// The response is 200 for unknown tokens too, as section 2.2 requires.
func (a *webApp) handleOIDCRevoke(w http.ResponseWriter, r *http.Request) {
	value, state, app, ok := a.clientTokenRequest(w, r, "revoke")
	if !ok {
		return
	}
	a.oidcMu.Lock()
	defer a.oidcMu.Unlock()
	a.pruneExpiredOIDCCredentials(time.Now())

	detail, userID := a.revokeClientToken(app, value)
	a.recordFlowEvent(app.Slug, "oidc", "revoke", "ok", revokedUserLabel(state.Users, userID), detail)
	w.WriteHeader(http.StatusOK)
}

// revokeClientToken deletes value and, for a refresh token, every token of
// its grant. It returns a flow log detail and the token's user. The caller
// holds oidcMu.
func (a *webApp) revokeClientToken(app app, value string) (string, string) {
	if token, ok := a.accessTokens[value]; ok && token.AppSlug == app.Slug {
		delete(a.accessTokens, value)
		return "Client revoked an access token", token.UserID
	}
	refresh, ok := a.refreshTokens[value]
	if !ok || refresh.AppSlug != app.Slug || refresh.ClientID != app.OIDCClientID {
		return "Client revoked an unknown token; nothing changed", ""
	}
	delete(a.refreshTokens, value)
	if refresh.GrantID == "" {
		return "Client revoked a refresh token", refresh.UserID
	}
	revokedAccess := 0
	for other, token := range a.accessTokens {
		if token.AppSlug == app.Slug && token.GrantID == refresh.GrantID {
			delete(a.accessTokens, other)
			revokedAccess++
		}
	}
	for other, token := range a.refreshTokens {
		if token.AppSlug == app.Slug && token.GrantID == refresh.GrantID {
			delete(a.refreshTokens, other)
		}
	}
	return fmt.Sprintf("Client revoked a refresh token and %d access tokens from its grant", revokedAccess), refresh.UserID
}

// clientTokenRequest parses an introspection or revocation request,
// authenticates the client, and returns the presented token. It answers
// every failure itself.
func (a *webApp) clientTokenRequest(w http.ResponseWriter, r *http.Request, stage string) (string, appState, app, bool) {
	state, app, ok := appForProtocol(w, r, supportsOIDC)
	if !ok {
		return "", appState{}, app, false
	}
	if err := r.ParseForm(); err != nil {
		a.failOAuth(w, app, stage, http.StatusBadRequest, "invalid_request", err.Error())
		return "", appState{}, app, false
	}
	if !a.authenticateOAuthClient(w, r, app, stage) {
		return "", appState{}, app, false
	}
	// token_type_hint is optional and only speeds up a lookup, so it is
	// ignored: both kinds are checked.
	value := r.PostFormValue("token")
	if value == "" {
		a.failOAuth(w, app, stage, http.StatusBadRequest, "invalid_request", "token is required")
		return "", appState{}, app, false
	}
	return value, state, app, true
}
