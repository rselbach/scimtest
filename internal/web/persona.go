package web

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"
)

// oktaEveryoneGroup is the group Okta puts every user in.
const oktaEveryoneGroup = "Everyone"

// googleConsumerDomains host personal Google accounts, whose ID tokens carry
// no hd claim.
var googleConsumerDomains = map[string]bool{"gmail.com": true, "googlemail.com": true}

// addPersonaClaims reshapes OIDC claims the way the app's provider persona
// issues them. A claim name that a renamed claim mapping produces keeps the
// mapped value.
func addPersonaClaims(claims map[string]any, state appState, app app, user user, scope string, issuer string) {
	renamed := renamedOIDCClaims(app)
	set := func(name string, value any) {
		if !renamed[name] {
			claims[name] = value
		}
	}
	groupsClaim := oidcClaimMappingsForApp(app).Groups
	groups, hasGroups := claims[groupsClaim].([]string)
	switch normalizePersona(app.Persona) {
	case personaEntra:
		set("tid", entraTenantID(app))
		if hasOIDCScope(scope, "profile") {
			set("oid", entraObjectID(app, user))
			set("preferred_username", entraUPN(user))
			set("upn", entraUPN(user))
		}
		if !renamed["email_verified"] {
			delete(claims, "email_verified")
		}
		if hasGroups && len(groups) > groupsOverageThresholdForApp(app) {
			delete(claims, groupsClaim)
			claims["_claim_names"] = map[string]string{groupsClaim: "src1"}
			claims["_claim_sources"] = map[string]any{
				"src1": map[string]string{"endpoint": entraMemberObjectsURL(issuer, app, user)},
			}
		}
	case personaOkta:
		set("ver", 1)
		if hasGroups && !slices.Contains(groups, oktaEveryoneGroup) {
			claims[groupsClaim] = append([]string{oktaEveryoneGroup}, groups...)
		}
	case personaGoogle:
		if domain := emailDomain(user.Email); domain != "" && !googleConsumerDomains[domain] {
			set("hd", domain)
		}
	}
}

// personaClaimsSupported adjusts the discovery claim list for the app's
// persona.
func personaClaimsSupported(app app, claims []string) []string {
	switch normalizePersona(app.Persona) {
	case personaEntra:
		claims = slices.DeleteFunc(claims, func(name string) bool { return name == "email_verified" })
		return append(claims, "tid", "oid", "upn")
	case personaOkta:
		return append(claims, "ver")
	case personaGoogle:
		return append(claims, "hd")
	default:
		return claims
	}
}

// renamedOIDCClaims returns the claim names that the app's claim mappings
// use in place of the defaults.
func renamedOIDCClaims(app app) map[string]bool {
	mappings, defaults := oidcClaimMappingsForApp(app), defaultOIDCClaimMappings()
	renamed := make(map[string]bool)
	for _, pair := range [][2]string{
		{mappings.Name, defaults.Name},
		{mappings.GivenName, defaults.GivenName},
		{mappings.FamilyName, defaults.FamilyName},
		{mappings.Username, defaults.Username},
		{mappings.Email, defaults.Email},
		{mappings.Groups, defaults.Groups},
	} {
		if pair[0] != pair[1] {
			renamed[pair[0]] = true
		}
	}
	return renamed
}

// entraTenantID is the environment's stable Entra ID tenant GUID.
func entraTenantID(app app) string {
	return personaGUID("tid", app.ID)
}

// entraObjectID is the user's stable Entra ID object GUID in the
// environment.
func entraObjectID(app app, user user) string {
	return personaGUID("oid", app.ID, user.ID)
}

// personaGUID derives a version 8 (RFC 9562) GUID from parts, so the same
// environment and user always get the same identifier.
func personaGUID(parts ...string) string {
	sum := sha256.Sum256([]byte("scimtest-persona\x00" + strings.Join(parts, "\x00")))
	sum[6] = sum[6]&0x0f | 0x80
	sum[8] = sum[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", sum[0:4], sum[4:6], sum[6:8], sum[8:10], sum[10:16])
}

// entraUPN returns the user principal name: the username when it is an
// address already, otherwise the username at the email's domain.
func entraUPN(user user) string {
	username := strings.TrimSpace(user.Username)
	domain := emailDomain(user.Email)
	switch {
	case username == "":
		return strings.TrimSpace(user.Email)
	case strings.Contains(username, "@") || domain == "":
		return username
	default:
		return username + "@" + domain
	}
}

func emailDomain(email string) string {
	_, domain, found := strings.Cut(strings.TrimSpace(email), "@")
	if !found {
		return ""
	}
	return strings.ToLower(domain)
}

func entraMemberObjectsURL(issuer string, app app, user user) string {
	return issuer + "/users/" + entraObjectID(app, user) + "/getMemberObjects"
}

func supportsEntraPersona(app app) bool {
	return supportsOIDC(app) && normalizePersona(app.Persona) == personaEntra
}

// handleEntraMemberObjects serves the group list that an Entra ID groups
// overage claim points to, shaped like Microsoft Graph's getMemberObjects.
// The caller presents an access token issued to the same user, with the
// groups scope.
func (a *webApp) handleEntraMemberObjects(w http.ResponseWriter, r *http.Request) {
	a.oidcMu.Lock()
	defer a.oidcMu.Unlock()

	state, app, ok := appForProtocol(w, r, supportsEntraPersona)
	if !ok {
		return
	}
	a.pruneExpiredOIDCCredentials(time.Now())
	tokenValue, ok := oidcBearerToken(r.Header.Get("Authorization"))
	if !ok {
		a.failGraph(w, app, http.StatusUnauthorized, "InvalidAuthenticationToken", "Access token is empty.")
		return
	}
	token, ok := a.accessTokens[tokenValue]
	if !ok || token.AppSlug != app.Slug {
		a.failGraph(w, app, http.StatusUnauthorized, "InvalidAuthenticationToken", "Access token is invalid or expired.")
		return
	}
	user, ok := userByID(state.Users, token.UserID)
	if !ok || !user.Active || user.Deleted {
		a.failGraph(w, app, http.StatusUnauthorized, "InvalidAuthenticationToken", "User is inactive or missing.")
		return
	}
	if r.PathValue("oid") != entraObjectID(app, user) || !app.IncludeGroupsClaim || !hasOIDCScope(token.Scope, "groups") {
		a.failGraph(w, app, http.StatusForbidden, "Authorization_RequestDenied", "Insufficient privileges to complete the operation.")
		return
	}
	var body struct {
		SecurityEnabledOnly *bool `json:"securityEnabledOnly"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil || body.SecurityEnabledOnly == nil {
		a.failGraph(w, app, http.StatusBadRequest, "Request_BadRequest", "The request body must set securityEnabledOnly.")
		return
	}
	groups := userGroups(state, user.ID)
	if groups == nil {
		groups = []string{}
	}
	a.recordFlowEvent(app.Slug, "oidc", "groups overage", "ok", userLabel(user), fmt.Sprintf("Served %d groups through getMemberObjects", len(groups)))
	a.noteIssuedGroups(app, user.ID, "oidc", "group source response", app.OIDCClientID, lifecycleGroupClaims{Groups: groups, Carried: true})
	writeJSON(w, map[string]any{
		"@odata.context": "https://graph.microsoft.com/v1.0/$metadata#Collection(Edm.String)",
		"value":          groups,
	})
}

// failGraph records a failed overage request and writes a Microsoft Graph
// error response.
func (a *webApp) failGraph(w http.ResponseWriter, app app, status int, code string, message string) {
	a.recordFlowEvent(app.Slug, "oidc", "groups overage", "failed", "", code+": "+message)
	writeJSONStatus(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}
