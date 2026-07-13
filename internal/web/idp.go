package web

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
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
}

type accessToken struct {
	AppSlug   string
	UserID    string
	Scope     string
	ExpiresAt time.Time
}

const (
	samlHTTPPostBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
	maxSAMLRequestBytes = 1 << 20
)

var errSAMLRequestTooLarge = fmt.Errorf("inflated SAMLRequest exceeds %d bytes", maxSAMLRequestBytes)

type samlAuthnRequest struct {
	ID              string
	Issuer          string
	Destination     string
	ACSURL          string
	ProtocolBinding string
}

type samlResponseContext struct {
	ACSURL       string
	InResponseTo string
}

func (a *webApp) handleAppSave(w http.ResponseWriter, r *http.Request) {
	tab := normalizedTab(r.FormValue("tab"))
	a.mu.Lock()
	defer a.mu.Unlock()

	state, err := loadRequestState(r)
	if err != nil {
		a.redirectError(w, r, tab, err)
		return
	}
	id := strings.TrimSpace(r.FormValue("id"))
	oidcClientSecret := strings.TrimSpace(r.FormValue("oidc_client_secret"))
	scimBearerToken := strings.TrimSpace(r.FormValue("scim_bearer_token"))
	existingIndex, appExists := appIndexByID(state.Apps, id)
	wasSCIMEnabled := false
	previousSCIMBaseURL := ""
	scimCapabilitiesKnown := false
	scimPatchSupported := false
	if appExists {
		wasSCIMEnabled = state.Apps[existingIndex].SCIMEnabled
		previousSCIMBaseURL = strings.TrimRight(strings.TrimSpace(state.Apps[existingIndex].SCIMBaseURL), "/")
		scimCapabilitiesKnown = state.Apps[existingIndex].SCIMCapabilitiesKnown
		scimPatchSupported = state.Apps[existingIndex].SCIMPatchSupported
		if oidcClientSecret == "" && r.FormValue("regenerate_oidc_secret") != "on" {
			oidcClientSecret = state.Apps[existingIndex].OIDCClientSecret
		}
		if scimBearerToken == "" {
			scimBearerToken = state.Apps[existingIndex].SCIMBearerToken
		}
	}
	app := app{
		ID:                     id,
		Name:                   strings.TrimSpace(r.FormValue("name")),
		Slug:                   slugify(r.FormValue("slug")),
		Protocol:               strings.TrimSpace(r.FormValue("protocol")),
		OIDCClientID:           strings.TrimSpace(r.FormValue("oidc_client_id")),
		OIDCClientSecret:       oidcClientSecret,
		OIDCPublicClient:       r.FormValue("oidc_public_client") == "on",
		OIDCRedirectURIs:       lines(r.FormValue("oidc_redirect_uris")),
		AllowAnyOIDCRedirect:   r.FormValue("allow_any_oidc_redirect") == "on",
		SAMLEntityID:           strings.TrimSpace(r.FormValue("saml_entity_id")),
		SAMLACSURL:             strings.TrimSpace(r.FormValue("saml_acs_url")),
		SAMLAudience:           strings.TrimSpace(r.FormValue("saml_audience")),
		SAMLNameIDField:        normalizeSAMLNameIDField(r.FormValue("saml_name_id_field")),
		SAMLEmailAttributeName: strings.TrimSpace(r.FormValue("saml_email_attribute_name")),
		IncludeGroupsClaim:     r.FormValue("include_groups_claim") == "on",
		SCIMEnabled:            r.FormValue("scim_enabled") == "on",
		SCIMBaseURL:            strings.TrimSpace(r.FormValue("scim_base_url")),
		SCIMBearerToken:        scimBearerToken,
		SCIMAutoOpenTrace:      r.FormValue("scim_auto_open_trace") == "on",
		SCIMCapabilitiesKnown:  scimCapabilitiesKnown,
		SCIMPatchSupported:     scimPatchSupported,
	}
	if app.Slug == "" {
		app.Slug = slugify(app.Name)
	}
	if app.Protocol == "" {
		app.Protocol = "oidc"
	}
	if app.Protocol == "scim" {
		app.SCIMEnabled = true
	}
	if supportsOIDC(app) {
		if app.OIDCClientID == "" {
			app.OIDCClientID = app.Slug
		}
		if r.FormValue("regenerate_oidc_secret") == "on" {
			app.OIDCClientSecret = ""
		}
		if app.OIDCPublicClient {
			app.OIDCClientSecret = ""
		} else if app.OIDCClientSecret == "" {
			app.OIDCClientSecret, err = randomSecret(24)
			if err != nil {
				a.redirectError(w, r, tab, err)
				return
			}
		}
	} else {
		app.OIDCClientID = ""
		app.OIDCClientSecret = ""
		app.OIDCRedirectURIs = nil
	}
	if supportsSAML(app) {
		if app.SAMLNameIDField == "" {
			app.SAMLNameIDField = defaultSAMLNameIDField
		}
		app.SAMLNameIDFormat = samlNameIDFormatForField(app.SAMLNameIDField)
		if app.SAMLEmailAttributeName == "" {
			app.SAMLEmailAttributeName = defaultSAMLEmailAttributeName
		}
	} else {
		app.SAMLEntityID = ""
		app.SAMLACSURL = ""
		app.SAMLAudience = ""
		app.SAMLNameIDField = ""
		app.SAMLNameIDFormat = ""
		app.SAMLEmailAttributeName = ""
	}
	if err := validateHTTPBaseURL("SCIM base URL", app.SCIMBaseURL, app.SCIMEnabled); err != nil {
		a.redirectFormError(w, r, tab, "app", err)
		return
	}
	if app.SCIMEnabled && app.SCIMBearerToken == "" {
		a.redirectFormError(w, r, tab, "app", fmt.Errorf("SCIM bearer token is required"))
		return
	}
	allApps, err := loadAllApps()
	if err != nil {
		a.redirectError(w, r, tab, err)
		return
	}
	if err := validateApp(app, allApps); err != nil {
		a.redirectFormError(w, r, tab, "app", err)
		return
	}

	status := "environment updated"
	created := id == ""
	if id == "" {
		app.ID, err = newAppID()
		if err != nil {
			a.redirectError(w, r, tab, err)
			return
		}
		state.Apps = append(state.Apps, app)
		status = "environment added"
	} else if index, ok := appIndexByID(state.Apps, id); ok {
		state.Apps[index] = app
	} else {
		a.redirectError(w, r, tab, fmt.Errorf("environment %s not found", id))
		return
	}
	scimEndpointChanged := previousSCIMBaseURL != strings.TrimRight(app.SCIMBaseURL, "/")
	if scimEndpointChanged {
		app.SCIMCapabilitiesKnown = false
		app.SCIMPatchSupported = false
	}
	if app.SCIMEnabled && (!wasSCIMEnabled || scimEndpointChanged) {
		initializeAppSync(&state, app.ID)
	}
	if err := saveState(state); err != nil {
		a.redirectError(w, r, tab, err)
		return
	}
	location := dashboardURL("apps", nil)
	if created {
		location = addEnvironmentToURL(location, app.ID)
	}
	redirectWithFlash(w, r, location, flashMessage{Kind: "success", Message: status})
}

func (a *webApp) handleAppDiscoverSCIM(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	state, err := loadRequestState(r)
	if err != nil {
		a.redirectError(w, r, "apps", err)
		return
	}
	index, ok := appIndexByID(state.Apps, r.PathValue("id"))
	if !ok || !state.Apps[index].SCIMEnabled {
		a.redirectError(w, r, "apps", fmt.Errorf("SCIM-enabled environment not found"))
		return
	}
	projected, err := stateForApp(state, state.Apps[index].ID)
	if err != nil {
		a.redirectError(w, r, "apps", err)
		return
	}
	capabilities, err := discoverSCIMCapabilities(projected.Config)
	a.rememberTrace(state.Apps[index].ID, capabilities.Traces)
	if err != nil {
		a.redirectError(w, r, "apps", err)
		return
	}
	state.Apps[index].SCIMCapabilitiesKnown = true
	state.Apps[index].SCIMPatchSupported = capabilities.PatchSupported
	if err := saveState(state); err != nil {
		a.redirectError(w, r, "apps", err)
		return
	}
	message := "SCIM capabilities discovered: PATCH is not supported"
	if capabilities.PatchSupported {
		message = "SCIM capabilities discovered: PATCH is supported"
	}
	redirectWithFlash(w, r, dashboardURL("apps", map[string]string{"modal": "app", "id": state.Apps[index].ID}), flashMessage{Kind: "success", Message: message})
}

func (a *webApp) handleAppTestSCIM(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := r.ParseMultipartForm(1 << 20); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	token := strings.TrimSpace(r.FormValue("scim_bearer_token"))
	if token == "" && strings.TrimSpace(r.FormValue("id")) != "" {
		state, err := loadRequestState(r)
		if err != nil {
			writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if index, ok := appIndexByID(state.Apps, r.FormValue("id")); ok {
			token = state.Apps[index].SCIMBearerToken
		}
	}
	capabilities, err := discoverSCIMCapabilities(config{
		BaseURL:     strings.TrimSpace(r.FormValue("scim_base_url")),
		BearerToken: token,
	})
	if err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	patch := "not supported"
	if capabilities.PatchSupported {
		patch = "supported"
	}
	writeJSON(w, map[string]string{"message": "Connection successful. PATCH is " + patch + "."})
}

func (a *webApp) handleAppDelete(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()

	state, err := loadRequestState(r)
	if err != nil {
		a.redirectError(w, r, "apps", err)
		return
	}
	index, ok := appIndexByID(state.Apps, r.PathValue("id"))
	if !ok {
		a.redirectError(w, r, "apps", fmt.Errorf("environment not found"))
		return
	}
	appID := state.Apps[index].ID
	state.Apps = append(state.Apps[:index], state.Apps[index+1:]...)
	delete(state.UserSync, appID)
	delete(state.GroupSync, appID)
	dropAppOperationLogs(&state, appID)
	if err := saveState(state); err != nil {
		a.redirectError(w, r, "apps", err)
		return
	}
	location := dashboardURL("apps", nil)
	if strings.TrimSpace(r.FormValue("environment")) == appID {
		if len(state.Apps) == 0 {
			http.SetCookie(w, &http.Cookie{Name: environmentCookieName, Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
			setFlashCookie(w, flashMessage{Kind: "success", Message: "environment deleted"})
			http.Redirect(w, r, location, http.StatusSeeOther)
			return
		}
		location = addEnvironmentToURL(location, state.Apps[0].ID)
	}
	redirectWithFlash(w, r, location, flashMessage{Kind: "success", Message: "environment deleted"})
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
		"scopes_supported":                      []string{"openid", "profile", "email", "groups"},
		"claims_supported":                      []string{"sub", "name", "given_name", "family_name", "preferred_username", "email", "email_verified", "groups"},
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
	state, app, ok := appForProtocol(w, r, supportsOIDC)
	if !ok {
		return
	}
	if err := validateAuthorizeRequest(app, r.URL.Query()); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	loginHint := loginHintFromRequest(r)
	selectedUserID := selectedLoginHintUserID(state.Users, loginHint)
	renderChooser(w, chooserData{
		Title:          "OIDC sign-in",
		AppName:        app.Name,
		Action:         r.URL.RequestURI(),
		Users:          activeUsersWithLoginHint(state.Users, loginHint),
		SelectedUserID: selectedUserID,
		Hidden:         hiddenValues(r.URL.Query()),
		NoUsersHint:    "Create an active user before starting an OIDC flow.",
	})
}

func (a *webApp) handleOIDCAuthorizePost(w http.ResponseWriter, r *http.Request) {
	a.oidcMu.Lock()
	defer a.oidcMu.Unlock()

	state, app, ok := appForProtocol(w, r, supportsOIDC)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := validateAuthorizeRequest(app, r.Form); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	redirectURI, err := parseOIDCRedirectURI(r.FormValue("redirect_uri"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	user, ok := userByID(state.Users, r.FormValue("user_id"))
	if !ok || !user.Active || user.Deleted {
		http.Error(w, "active user is required", http.StatusBadRequest)
		return
	}
	now := time.Now()
	a.pruneExpiredOIDCCredentials(now)

	code, err := randomSecret(24)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	a.authCodes[code] = authCode{
		AppSlug:       app.Slug,
		ClientID:      r.FormValue("client_id"),
		UserID:        user.ID,
		RedirectURI:   r.FormValue("redirect_uri"),
		Nonce:         r.FormValue("nonce"),
		Scope:         r.FormValue("scope"),
		CodeChallenge: r.FormValue("code_challenge"),
		ExpiresAt:     now.Add(5 * time.Minute),
	}

	query := redirectURI.Query()
	query.Set("code", code)
	if stateValue := r.FormValue("state"); stateValue != "" {
		query.Set("state", stateValue)
	}
	redirectURI.RawQuery = query.Encode()
	http.Redirect(w, r, redirectURI.String(), http.StatusFound)
}

func (a *webApp) handleOIDCToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	a.oidcMu.Lock()
	defer a.oidcMu.Unlock()

	state, app, ok := appForProtocol(w, r, supportsOIDC)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if r.FormValue("grant_type") != "authorization_code" {
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "only authorization_code is supported")
		return
	}
	if !clientAuthenticated(r, app) {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}
	now := time.Now()
	a.pruneExpiredOIDCCredentials(now)

	codeValue := r.FormValue("code")
	code, ok := a.authCodes[codeValue]
	if !ok {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "authorization code is invalid or expired")
		return
	}
	delete(a.authCodes, codeValue)

	if code.AppSlug != app.Slug || code.ClientID != app.OIDCClientID || code.RedirectURI != r.FormValue("redirect_uri") {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "authorization code does not match this request")
		return
	}
	if code.CodeChallenge != "" && !validPKCEVerifier(code.CodeChallenge, r.FormValue("code_verifier")) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "PKCE code verifier is invalid")
		return
	}
	user, ok := userByID(state.Users, code.UserID)
	if !ok || !user.Active || user.Deleted {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "user is inactive or missing")
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
	idToken, err := a.signJWT(claims)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	access, err := randomSecret(32)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	a.accessTokens[access] = accessToken{
		AppSlug:   app.Slug,
		UserID:    user.ID,
		Scope:     code.Scope,
		ExpiresAt: now.Add(time.Hour),
	}
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
	tokenValue := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	token, ok := a.accessTokens[tokenValue]
	if !ok || token.AppSlug != app.Slug {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "access token is invalid or expired")
		return
	}
	user, ok := userByID(state.Users, token.UserID)
	if !ok || !user.Active || user.Deleted {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "user is inactive or missing")
		return
	}
	writeJSON(w, userClaims(state, app, user, token.Scope))
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

func (a *webApp) handleSAMLMetadata(w http.ResponseWriter, r *http.Request) {
	state, app, ok := appForProtocol(w, r, supportsSAML)
	if !ok {
		return
	}
	baseURL := a.effectiveIDPBaseURL(r, state)
	entityID := baseURL + "/saml/" + app.Slug + "/metadata"
	nameIDFormat := app.SAMLNameIDFormat
	if nameIDFormat == "" {
		nameIDFormat = samlNameIDFormatForField(app.SAMLNameIDField)
	}
	cert := base64.StdEncoding.EncodeToString(a.certDER)
	metadata := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%s">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>%s</X509Certificate></X509Data></KeyInfo></KeyDescriptor>
    <NameIDFormat>%s</NameIDFormat>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="%s/saml/%s/sso"/>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="%s/saml/%s/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`, xmlEscape(entityID), cert, xmlEscape(nameIDFormat), xmlEscape(baseURL), xmlEscape(app.Slug), xmlEscape(baseURL), xmlEscape(app.Slug))
	w.Header().Set("Content-Type", "application/samlmetadata+xml; charset=utf-8")
	if _, err := w.Write([]byte(metadata)); err != nil {
		log.Printf("write SAML metadata response: %v", err)
	}
}

func (a *webApp) handleSAMLSSO(w http.ResponseWriter, r *http.Request) {
	state, app, ok := appForProtocol(w, r, supportsSAML)
	if !ok {
		return
	}
	baseURL := a.effectiveIDPBaseURL(r, state)
	if _, err := resolveSAMLResponseContext(r.URL.Query(), app, baseURL, false); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	loginHint := loginHintFromRequest(r)
	selectedUserID := selectedLoginHintUserID(state.Users, loginHint)
	renderChooser(w, chooserData{
		Title:          "SAML sign-in",
		AppName:        app.Name,
		Action:         r.URL.RequestURI(),
		Users:          activeUsersWithLoginHint(state.Users, loginHint),
		SelectedUserID: selectedUserID,
		Hidden:         hiddenValues(r.URL.Query()),
		NoUsersHint:    "Create an active user before starting a SAML flow.",
	})
}

func (a *webApp) handleSAMLSSOPost(w http.ResponseWriter, r *http.Request) {
	state, app, ok := appForProtocol(w, r, supportsSAML)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	baseURL := a.effectiveIDPBaseURL(r, state)
	responseContext, err := resolveSAMLResponseContext(r.Form, app, baseURL, r.FormValue("user_id") != "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if r.FormValue("user_id") == "" && (r.FormValue("SAMLRequest") != "" || r.FormValue("login_hint") != "" || r.FormValue("RelayState") != "") {
		loginHint := loginHintFromValues(r.Form)
		selectedUserID := selectedLoginHintUserID(state.Users, loginHint)
		renderChooser(w, chooserData{
			Title:          "SAML sign-in",
			AppName:        app.Name,
			Action:         r.URL.RequestURI(),
			Users:          activeUsersWithLoginHint(state.Users, loginHint),
			SelectedUserID: selectedUserID,
			Hidden:         hiddenValues(r.Form),
			NoUsersHint:    "Create an active user before starting a SAML flow.",
		})
		return
	}
	user, ok := userByID(state.Users, r.FormValue("user_id"))
	if !ok || !user.Active || user.Deleted {
		http.Error(w, "active user is required", http.StatusBadRequest)
		return
	}
	response, err := a.buildSignedSAMLResponse(state, baseURL, app, user, responseContext)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	renderPostBack(w, responseContext.ACSURL, map[string]string{
		"SAMLResponse": base64.StdEncoding.EncodeToString([]byte(response)),
		"RelayState":   r.FormValue("RelayState"),
	})
}

func appForProtocol(w http.ResponseWriter, r *http.Request, supports func(app) bool) (appState, app, bool) {
	state, err := loadStateForAppSlug(r.PathValue("slug"))
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			http.NotFound(w, r)
			return appState{}, app{}, false
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return appState{}, app{}, false
	}
	found, ok := appBySlug(state.Apps, r.PathValue("slug"))
	if !ok || !supports(found) {
		http.NotFound(w, r)
		return appState{}, app{}, false
	}
	return state, found, true
}

func effectiveIDPBaseURL(r *http.Request, state appState) string {
	configured := strings.TrimRight(strings.TrimSpace(state.Config.IDPBaseURL), "/")
	if configured != "" {
		return configured
	}
	proto := "http"
	if r.TLS != nil {
		proto = "https"
	}
	if state.Config.TrustForwardedHeaders {
		if forwardedProto := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0]); forwardedProto == "http" || forwardedProto == "https" {
			proto = forwardedProto
		}
	}
	host := r.Host
	if host == "" {
		return "http://localhost:8080"
	}
	return proto + "://" + host
}

func oidcIssuer(baseURL string, app app) string {
	return baseURL + "/oidc/" + app.Slug
}

func resolveSAMLResponseContext(values url.Values, app app, baseURL string, requireACS bool) (samlResponseContext, error) {
	configuredACS := strings.TrimSpace(app.SAMLACSURL)
	requestedACS := strings.TrimSpace(values.Get("acs_url"))
	if requestedACS != "" {
		if configuredACS == "" {
			return samlResponseContext{}, fmt.Errorf("SAML ACS URL must be configured on the app")
		}
		if requestedACS != configuredACS {
			return samlResponseContext{}, fmt.Errorf("SAML ACS URL does not match the configured app")
		}
	}

	context := samlResponseContext{ACSURL: configuredACS}
	encodedRequest := strings.TrimSpace(values.Get("SAMLRequest"))
	if encodedRequest != "" {
		// This test IDP has no SP certificates, so request signatures are accepted
		// as opaque input while the request's configured endpoints are validated.
		request, err := parseSAMLAuthnRequest(encodedRequest)
		if err != nil {
			return samlResponseContext{}, err
		}
		if request.ID == "" {
			return samlResponseContext{}, fmt.Errorf("SAML AuthnRequest ID is required")
		}
		if expectedIssuer := strings.TrimSpace(app.SAMLEntityID); expectedIssuer != "" && request.Issuer != expectedIssuer {
			return samlResponseContext{}, fmt.Errorf("SAML AuthnRequest issuer does not match the configured app")
		}
		expectedDestination := strings.TrimRight(baseURL, "/") + "/saml/" + app.Slug + "/sso"
		if request.Destination != "" && request.Destination != expectedDestination {
			return samlResponseContext{}, fmt.Errorf("SAML AuthnRequest destination does not match this IDP")
		}
		if request.ACSURL != "" && configuredACS != "" && request.ACSURL != configuredACS {
			return samlResponseContext{}, fmt.Errorf("SAML AuthnRequest ACS URL does not match the configured app")
		}
		if request.ProtocolBinding != "" && request.ProtocolBinding != samlHTTPPostBinding {
			return samlResponseContext{}, fmt.Errorf("SAML AuthnRequest must request the HTTP-POST response binding")
		}
		context.InResponseTo = request.ID
	}
	if requireACS && configuredACS == "" {
		return samlResponseContext{}, fmt.Errorf("SAML ACS URL must be configured on the app")
	}
	return context, nil
}

func parseSAMLAuthnRequest(encodedRequest string) (samlAuthnRequest, error) {
	doc, err := parseSAMLRequestDocument(encodedRequest)
	if err != nil {
		return samlAuthnRequest{}, err
	}
	root := doc.Root()
	if elementLocalName(root) != "AuthnRequest" {
		return samlAuthnRequest{}, fmt.Errorf("SAMLRequest must contain an AuthnRequest")
	}
	return samlAuthnRequest{
		ID:              strings.TrimSpace(root.SelectAttrValue("ID", "")),
		Issuer:          childElementTextByLocalName(root, "Issuer"),
		Destination:     strings.TrimSpace(root.SelectAttrValue("Destination", "")),
		ACSURL:          strings.TrimSpace(root.SelectAttrValue("AssertionConsumerServiceURL", "")),
		ProtocolBinding: strings.TrimSpace(root.SelectAttrValue("ProtocolBinding", "")),
	}, nil
}

func childElementTextByLocalName(parent *etree.Element, localName string) string {
	for _, child := range parent.ChildElements() {
		if elementLocalName(child) == localName {
			return strings.TrimSpace(child.Text())
		}
	}
	return ""
}

func validateAuthorizeRequest(app app, values url.Values) error {
	if values.Get("response_type") != "code" {
		return fmt.Errorf("response_type must be code")
	}
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
	if !app.AllowAnyOIDCRedirect && !stringIn(app.OIDCRedirectURIs, redirectURI) {
		return fmt.Errorf("redirect_uri is not registered for this app")
	}
	if !strings.Contains(" "+values.Get("scope")+" ", " openid ") {
		return fmt.Errorf("scope must include openid")
	}
	challenge := values.Get("code_challenge")
	method := values.Get("code_challenge_method")
	if app.OIDCPublicClient && challenge == "" {
		return fmt.Errorf("public clients must use PKCE")
	}
	if challenge != "" && method != "S256" {
		return fmt.Errorf("code_challenge_method must be S256")
	}
	if challenge != "" && len(challenge) != 43 {
		return fmt.Errorf("code_challenge must be a valid S256 challenge")
	}
	if challenge == "" && method != "" {
		return fmt.Errorf("code_challenge is required when code_challenge_method is set")
	}
	return nil
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
		return clientID == app.OIDCClientID && secret == app.OIDCClientSecret
	}
	return r.FormValue("client_id") == app.OIDCClientID && r.FormValue("client_secret") == app.OIDCClientSecret
}

func userClaims(state appState, app app, user user, scope string) map[string]any {
	claims := map[string]any{"sub": user.ID}
	if hasOIDCScope(scope, "profile") {
		claims["name"] = userLabel(user)
		claims["given_name"] = user.GivenName
		claims["family_name"] = user.FamilyName
		claims["preferred_username"] = user.Username
	}
	if hasOIDCScope(scope, "email") {
		claims["email"] = user.Email
		claims["email_verified"] = true
	}
	if app.IncludeGroupsClaim && hasOIDCScope(scope, "groups") {
		claims["groups"] = userGroups(state, user.ID)
	}
	return claims
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

type chooserData struct {
	Title          string
	AppName        string
	Action         string
	Users          []user
	SelectedUserID string
	Hidden         map[string][]string
	NoUsersHint    string
}

func activeUsers(users []user) []user {
	var active []user
	for _, user := range users {
		if user.Active && !user.Deleted {
			active = append(active, user)
		}
	}
	sort.Slice(active, func(i, j int) bool {
		return userLabel(active[i]) < userLabel(active[j])
	})
	return active
}

func activeUsersWithLoginHint(users []user, loginHint string) []user {
	active := activeUsers(users)
	selectedID := selectedLoginHintUserID(active, loginHint)
	if selectedID == "" {
		return active
	}
	for i, user := range active {
		if user.ID != selectedID {
			continue
		}
		selected := active[i]
		copy(active[1:i+1], active[0:i])
		active[0] = selected
		return active
	}
	return active
}

func selectedLoginHintUserID(users []user, loginHint string) string {
	loginHint = strings.TrimSpace(loginHint)
	if loginHint == "" {
		return ""
	}

	selectedID := ""
	for _, user := range users {
		if !user.Active || user.Deleted {
			continue
		}
		if !loginHintMatchesUser(loginHint, user) {
			continue
		}
		if selectedID != "" && selectedID != user.ID {
			return ""
		}
		selectedID = user.ID
	}
	return selectedID
}

func loginHintMatchesUser(loginHint string, user user) bool {
	username := strings.TrimSpace(user.Username)
	email := strings.TrimSpace(user.Email)
	return (username != "" && strings.EqualFold(loginHint, username)) ||
		(email != "" && strings.EqualFold(loginHint, email))
}

func loginHintFromRequest(r *http.Request) string {
	return loginHintFromValues(r.URL.Query())
}

func loginHintFromValues(values url.Values) string {
	if loginHint, _ := firstQueryValue(values, "login_hint", "LoginHint", "loginHint"); loginHint != "" {
		return loginHint
	}
	if loginHint := loginHintFromSAMLRequest(values.Get("SAMLRequest")); loginHint != "" {
		return loginHint
	}
	if loginHint := loginHintFromRelayState(values.Get("RelayState")); loginHint != "" {
		return loginHint
	}
	return ""
}

func firstQueryValue(values url.Values, keys ...string) (string, string) {
	for _, key := range keys {
		if value := strings.TrimSpace(values.Get(key)); value != "" {
			return value, key
		}
	}
	return "", ""
}

func loginHintFromSAMLRequest(encodedRequest string) string {
	doc, err := parseSAMLRequestDocument(encodedRequest)
	if err != nil {
		return ""
	}
	for _, localName := range []string{"NameID", "LoginHint", "login_hint"} {
		if text := firstElementTextByLocalName(doc.Root(), localName); text != "" {
			return text
		}
	}
	return ""
}

func parseSAMLRequestDocument(encodedRequest string) (*etree.Document, error) {
	encodedRequest = strings.TrimSpace(encodedRequest)
	if encodedRequest == "" {
		return nil, fmt.Errorf("SAMLRequest is required")
	}
	decoded, err := base64.StdEncoding.DecodeString(encodedRequest)
	if err != nil {
		decoded, err = base64.StdEncoding.DecodeString(strings.ReplaceAll(encodedRequest, " ", "+"))
		if err != nil {
			return nil, fmt.Errorf("decode SAMLRequest: %w", err)
		}
	}
	requestXML, inflateErr := inflateRawDeflate(decoded)
	if errors.Is(inflateErr, errSAMLRequestTooLarge) {
		return nil, inflateErr
	}
	if inflateErr != nil || len(requestXML) == 0 {
		requestXML = decoded
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromString(string(requestXML)); err != nil {
		return nil, fmt.Errorf("parse SAMLRequest XML: %w", err)
	}
	if doc.Root() == nil {
		return nil, fmt.Errorf("parse SAMLRequest XML: root element is required")
	}
	return doc, nil
}

func loginHintFromRelayState(relayState string) string {
	relayState = strings.TrimSpace(relayState)
	if relayState == "" {
		return ""
	}
	candidates := []string{relayState}
	if decoded, err := url.QueryUnescape(relayState); err == nil && decoded != relayState {
		candidates = append(candidates, decoded)
	}
	for _, candidate := range candidates {
		if loginHint := loginHintFromURLOrQuery(candidate); loginHint != "" {
			return loginHint
		}
	}
	return ""
}

func loginHintFromURLOrQuery(value string) string {
	if parsed, err := url.Parse(value); err == nil && parsed.RawQuery != "" {
		if loginHint, _ := firstQueryValue(parsed.Query(), "login_hint", "LoginHint", "loginHint"); loginHint != "" {
			return loginHint
		}
	}
	if parsedValues, err := url.ParseQuery(value); err == nil {
		loginHint, _ := firstQueryValue(parsedValues, "login_hint", "LoginHint", "loginHint")
		return loginHint
	}
	return ""
}

func inflateRawDeflate(data []byte) ([]byte, error) {
	reader := flate.NewReader(bytes.NewReader(data))
	out, readErr := io.ReadAll(io.LimitReader(reader, maxSAMLRequestBytes+1))
	closeErr := reader.Close()
	if readErr != nil {
		if closeErr != nil {
			return nil, fmt.Errorf("read raw deflate: %w (close: %v)", readErr, closeErr)
		}
		return nil, fmt.Errorf("read raw deflate: %w", readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close raw deflate reader: %w", closeErr)
	}
	if len(out) > maxSAMLRequestBytes {
		return nil, errSAMLRequestTooLarge
	}
	return out, nil
}

func firstElementTextByLocalName(el *etree.Element, localName string) string {
	if el == nil {
		return ""
	}
	if elementLocalName(el) == localName {
		if text := strings.TrimSpace(el.Text()); text != "" {
			return text
		}
	}
	for _, child := range el.ChildElements() {
		if text := firstElementTextByLocalName(child, localName); text != "" {
			return text
		}
	}
	return ""
}

func hiddenValues(values url.Values) map[string][]string {
	out := make(map[string][]string)
	for key, value := range values {
		if key == "user_id" {
			continue
		}
		out[key] = value
	}
	return out
}

func renderChooser(w http.ResponseWriter, data chooserData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := chooserTemplate.Execute(w, data); err != nil {
		log.Printf("render login chooser: %v", err)
	}
}

var chooserTemplate = template.Must(template.New("chooser").Funcs(template.FuncMap{
	"userDisplayName": userLabel,
}).Parse(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{.Title}} · {{.AppName}}</title>
  <style>
    :root { --bg:#f4f5f7; --card:#fff; --line:#d1d5db; --text:#1f2328; --muted:#6b7280; --accent:#1563ff; --accent-strong:#1051d8; --radius:8px; }
    * { box-sizing: border-box; }
    body { margin:0; min-height:100vh; min-height:100dvh; display:grid; place-items:center; padding:16px; background:var(--bg); color:var(--text); font:13.5px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Helvetica,Arial,sans-serif; }
    main { width:min(460px, 100%); max-height:calc(100vh - 32px); max-height:calc(100dvh - 32px); display:grid; grid-template-rows:auto minmax(0, 1fr); background:var(--card); border:1px solid var(--line); border-radius:var(--radius); box-shadow:0 20px 50px rgba(15,23,42,.16); overflow:hidden; }
    header { padding:18px 20px; border-bottom:1px solid #e5e7eb; }
    h1 { margin:0; font-size:18px; line-height:1.2; }
    p { margin:4px 0 0; color:var(--muted); }
    form { min-height:0; padding:18px 20px 20px; display:grid; grid-template-rows:auto minmax(0, 1fr) auto; gap:12px; overflow:hidden; }
    .search-row { display:grid; grid-template-columns:minmax(0, 1fr) auto; align-items:center; gap:10px; }
    .search-row input { width:100%; height:36px; padding:0 11px; border:1px solid var(--line); border-radius:6px; color:var(--text); font:inherit; }
    .search-row input:focus { outline:none; border-color:var(--accent); box-shadow:0 0 0 3px rgba(21,99,255,.15); }
    .match-count { color:var(--muted); font-size:12px; white-space:nowrap; }
    .user-list { min-height:0; max-height:520px; overflow-y:auto; display:grid; align-content:start; gap:8px; padding-right:4px; scrollbar-gutter:stable; }
    .user-option { display:flex; align-items:center; gap:10px; padding:10px 12px; border:1px solid #e5e7eb; border-radius:6px; cursor:pointer; }
    .user-option:hover { border-color:var(--line); background:#f9fafb; }
    .user-option:has(input:checked) { border-color:var(--accent); background:#f5f8ff; }
    strong { display:block; font-weight:600; }
    .user-meta { color:var(--muted); font-size:12.5px; }
    .no-matches { padding:24px 12px; text-align:center; color:var(--muted); }
    [hidden] { display:none !important; }
    button { height:34px; border:1px solid var(--accent); background:var(--accent); color:#fff; border-radius:6px; font-weight:600; cursor:pointer; }
    button:hover { background:var(--accent-strong); border-color:var(--accent-strong); }
    button:disabled { opacity:.5; cursor:not-allowed; }
    .empty { color:var(--muted); padding:18px 20px 20px; }
  </style>
</head>
<body>
  <main>
    <header>
      <h1>{{.Title}}</h1>
      <p>{{.AppName}}</p>
    </header>
    {{if .Users}}
    <form method="post" action="{{.Action}}">
      {{range $key, $values := .Hidden}}{{range $values}}<input type="hidden" name="{{$key}}" value="{{.}}">{{end}}{{end}}
      <div class="search-row">
        <input type="search" placeholder="Search name, username, or email" aria-label="Search users" aria-controls="user-list" autocomplete="off" autofocus data-user-search>
        <span class="match-count" aria-live="polite" data-match-count></span>
      </div>
      <div class="user-list" id="user-list" role="radiogroup" aria-label="Users" data-user-list>
        {{range .Users}}
        <label class="user-option" data-user-option data-search="{{userDisplayName .}} {{.Username}} {{.Email}}">
          <input type="radio" name="user_id" value="{{.ID}}" required {{if eq .ID $.SelectedUserID}}checked{{end}}>
          <div><strong>{{userDisplayName .}}</strong><span class="user-meta">{{.Email}}</span></div>
        </label>
        {{end}}
        <div class="no-matches" hidden data-no-matches>No users match your search.</div>
      </div>
      <button type="submit" data-continue>Continue</button>
    </form>
    {{else}}
    <div class="empty">{{.NoUsersHint}}</div>
    {{end}}
  </main>
  {{if .Users}}
  <script>
    const search = document.querySelector('[data-user-search]');
    const options = Array.from(document.querySelectorAll('[data-user-option]'));
    const matchCount = document.querySelector('[data-match-count]');
    const noMatches = document.querySelector('[data-no-matches]');
    const continueButton = document.querySelector('[data-continue]');
    function filterUsers() {
      const terms = search.value.toLocaleLowerCase().trim().split(/\s+/).filter(Boolean);
      let visible = 0;
      for (const option of options) {
        const value = option.dataset.search.toLocaleLowerCase();
        const matches = terms.every(function (term) { return value.includes(term); });
        option.hidden = !matches;
        const radio = option.querySelector('input[type="radio"]');
        if (radio) radio.disabled = !matches;
        if (matches) {
          visible++;
        } else {
          if (radio) radio.checked = false;
        }
      }
      matchCount.textContent = String(visible) + (visible === 1 ? ' user' : ' users');
      noMatches.hidden = visible !== 0;
      continueButton.disabled = visible === 0;
    }
    search.addEventListener('input', filterUsers);
    filterUsers();
  </script>
  {{end}}
</body>
</html>`))

func (a *webApp) buildSignedSAMLResponse(state appState, baseURL string, app app, user user, responseContext samlResponseContext) (string, error) {
	response, err := buildSAMLResponse(state, baseURL, app, user, responseContext)
	if err != nil {
		return "", err
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromString(response); err != nil {
		return "", fmt.Errorf("parse SAML response for signing: %w", err)
	}
	assertion := findElementByLocalName(doc.Root(), "Assertion")
	if assertion == nil {
		return "", fmt.Errorf("SAML assertion not found")
	}
	ctx, err := dsig.NewSigningContext(a.signingKey, [][]byte{a.certDER})
	if err != nil {
		return "", fmt.Errorf("create SAML signing context: %w", err)
	}
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	signature, err := ctx.ConstructSignature(assertion, true)
	if err != nil {
		return "", fmt.Errorf("sign SAML assertion: %w", err)
	}
	signedAssertion := assertion.Copy()
	if err := placeSAMLAssertionSignature(signedAssertion, signature); err != nil {
		return "", err
	}
	parent := assertion.Parent()
	if parent == nil {
		return "", fmt.Errorf("SAML assertion has no parent")
	}
	parent.RemoveChild(assertion)
	parent.AddChild(signedAssertion)
	signed, err := doc.WriteToString()
	if err != nil {
		return "", fmt.Errorf("serialize signed SAML response: %w", err)
	}
	return signed, nil
}

func placeSAMLAssertionSignature(assertion *etree.Element, signature *etree.Element) error {
	issuerIndex := -1
	for index, child := range assertion.Child {
		element, ok := child.(*etree.Element)
		if !ok {
			continue
		}
		if elementLocalName(element) == "Issuer" {
			issuerIndex = index
		}
	}
	if issuerIndex < 0 {
		return fmt.Errorf("signed SAML assertion issuer not found")
	}
	assertion.InsertChildAt(issuerIndex+1, signature)
	return nil
}

func findElementByLocalName(el *etree.Element, localName string) *etree.Element {
	if el == nil {
		return nil
	}
	if elementLocalName(el) == localName {
		return el
	}
	for _, child := range el.ChildElements() {
		if found := findElementByLocalName(child, localName); found != nil {
			return found
		}
	}
	return nil
}

func elementLocalName(el *etree.Element) string {
	if el == nil {
		return ""
	}
	if index := strings.LastIndex(el.Tag, ":"); index >= 0 {
		return el.Tag[index+1:]
	}
	return el.Tag
}

func buildSAMLResponse(state appState, baseURL string, app app, user user, responseContext samlResponseContext) (string, error) {
	now := time.Now().UTC()
	responseID, err := newID("saml-response")
	if err != nil {
		return "", fmt.Errorf("generate SAML response ID: %w", err)
	}
	assertionID, err := newID("saml-assertion")
	if err != nil {
		return "", fmt.Errorf("generate SAML assertion ID: %w", err)
	}
	issuer := baseURL + "/saml/" + app.Slug + "/metadata"
	audience := app.SAMLAudience
	if audience == "" {
		audience = app.SAMLEntityID
	}
	if audience == "" {
		audience = responseContext.ACSURL
	}
	groups := userGroups(state, user.ID)
	var groupAttribute string
	if app.IncludeGroupsClaim {
		var groupAttrs strings.Builder
		for _, group := range groups {
			groupAttrs.WriteString("<saml:AttributeValue>")
			groupAttrs.WriteString(xmlEscape(group))
			groupAttrs.WriteString("</saml:AttributeValue>")
		}
		groupAttribute = "<saml:Attribute Name=\"groups\">" + groupAttrs.String() + "</saml:Attribute>"
	}
	nameIDValue := samlNameIDValue(app, user)
	nameIDFormat := app.SAMLNameIDFormat
	if nameIDFormat == "" {
		nameIDFormat = samlNameIDFormatForField(app.SAMLNameIDField)
	}
	responseInResponseTo := ""
	subjectInResponseTo := ""
	if responseContext.InResponseTo != "" {
		responseInResponseTo = ` InResponseTo="` + xmlEscape(responseContext.InResponseTo) + `"`
		subjectInResponseTo = ` InResponseTo="` + xmlEscape(responseContext.InResponseTo) + `"`
	}
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="%s" Version="2.0" IssueInstant="%s" Destination="%s"%s>
  <saml:Issuer>%s</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="%s" Version="2.0" IssueInstant="%s">
    <saml:Issuer>%s</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="%s">%s</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData%s NotOnOrAfter="%s" Recipient="%s"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="%s" NotOnOrAfter="%s"><saml:AudienceRestriction><saml:Audience>%s</saml:Audience></saml:AudienceRestriction></saml:Conditions>
    <saml:AuthnStatement AuthnInstant="%s"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="%s"><saml:AttributeValue>%s</saml:AttributeValue></saml:Attribute>
      <saml:Attribute Name="username"><saml:AttributeValue>%s</saml:AttributeValue></saml:Attribute>
      <saml:Attribute Name="firstName"><saml:AttributeValue>%s</saml:AttributeValue></saml:Attribute>
      <saml:Attribute Name="lastName"><saml:AttributeValue>%s</saml:AttributeValue></saml:Attribute>
      %s
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>`,
		xmlEscape(responseID), now.Format(time.RFC3339), xmlEscape(responseContext.ACSURL), responseInResponseTo, xmlEscape(issuer),
		xmlEscape(assertionID), now.Format(time.RFC3339), xmlEscape(issuer),
		xmlEscape(nameIDFormat), xmlEscape(nameIDValue), subjectInResponseTo, now.Add(5*time.Minute).Format(time.RFC3339), xmlEscape(responseContext.ACSURL),
		now.Add(-time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339), xmlEscape(audience),
		now.Format(time.RFC3339), xmlEscape(app.SAMLEmailAttributeName), xmlEscape(user.Email), xmlEscape(user.Username), xmlEscape(user.GivenName), xmlEscape(user.FamilyName), groupAttribute), nil
}

func renderPostBack(w http.ResponseWriter, target string, values map[string]string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := postBackTemplate.Execute(w, struct {
		Target string
		Values map[string]string
	}{Target: target, Values: values}); err != nil {
		log.Printf("render SAML postback: %v", err)
	}
}

var postBackTemplate = template.Must(template.New("postback").Parse(`<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Continue</title></head>
<body>
  <form method="post" action="{{.Target}}">
    {{range $key, $value := .Values}}{{if $value}}<input type="hidden" name="{{$key}}" value="{{$value}}">{{end}}{{end}}
    <noscript><button type="submit">Continue</button></noscript>
  </form>
  <script>document.forms[0].submit()</script>
</body>
</html>`))

func xmlEscape(value string) string {
	var b strings.Builder
	if err := xml.EscapeText(&b, []byte(value)); err != nil {
		log.Printf("escape XML text: %v", err)
		return ""
	}
	return b.String()
}

func selfSignedCert(key *rsa.PrivateKey) ([]byte, error) {
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: "scimtest local signing"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	return x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
}

func loadOrCreateSigningMaterial() (*rsa.PrivateKey, []byte, error) {
	state, err := loadState()
	if err != nil {
		return nil, nil, err
	}
	if strings.TrimSpace(state.Config.SigningPrivateKeyPEM) != "" && strings.TrimSpace(state.Config.SigningCertificatePEM) != "" {
		key, err := parseRSAPrivateKeyPEM(state.Config.SigningPrivateKeyPEM)
		if err != nil {
			return nil, nil, fmt.Errorf("parse saved signing key: %w", err)
		}
		certDER, err := parseCertificatePEM(state.Config.SigningCertificatePEM)
		if err != nil {
			return nil, nil, fmt.Errorf("parse saved signing certificate: %w", err)
		}
		return key, certDER, nil
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("generate signing key: %w", err)
	}
	certDER, err := selfSignedCert(key)
	if err != nil {
		return nil, nil, fmt.Errorf("generate signing certificate: %w", err)
	}
	state.Config.SigningPrivateKeyPEM = privateKeyPEM(key)
	state.Config.SigningCertificatePEM = certificatePEM(certDER)
	if err := saveState(state); err != nil {
		return nil, nil, err
	}
	return key, certDER, nil
}

func privateKeyPEM(key *rsa.PrivateKey) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
}

func certificatePEM(certDER []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
}

func parseRSAPrivateKeyPEM(value string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(value))
	if block == nil {
		return nil, fmt.Errorf("missing PEM block")
	}
	if block.Type == "RSA PRIVATE KEY" {
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is %T, not RSA", key)
	}
	return rsaKey, nil
}

func parseCertificatePEM(value string) ([]byte, error) {
	block, _ := pem.Decode([]byte(value))
	if block == nil {
		return nil, fmt.Errorf("missing PEM block")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("PEM block is %q, not CERTIFICATE", block.Type)
	}
	return block.Bytes, nil
}
