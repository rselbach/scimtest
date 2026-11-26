package web

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
)

func (a *webApp) handleAppSave(w http.ResponseWriter, r *http.Request) {
	tab := normalizedTab(r.FormValue("tab"))
	a.mu.Lock()
	defer a.mu.Unlock()

	apiRequest, isAPI := apiEnvironmentRequestFrom(r)
	if isAPI {
		current := app{}
		id := r.PathValue("environment_id")
		if id != "" {
			state, err := loadStateForApp(id)
			if err != nil {
				apiError(w, http.StatusNotFound, err.Error())
				return
			}
			current, err = apiAppByID(state, id)
			if err != nil {
				apiError(w, http.StatusNotFound, err.Error())
				return
			}
		}
		r.Form = apiEnvironmentForm(current, apiRequest)
	}

	id := strings.TrimSpace(r.FormValue("id"))
	globalState, err := loadState()
	if err != nil {
		a.redirectError(w, r, tab, err)
		return
	}
	state := appState{Config: globalState.Config}
	if id != "" {
		state, err = loadStateForApp(id)
		if err != nil {
			a.redirectError(w, r, tab, err)
			return
		}
	}
	removedProtocol := strings.TrimSpace(r.FormValue("remove_protocol"))
	protocolSwitchesPresent := r.FormValue("protocol_switches_present") == "true"
	protocolEnabled := map[string]bool{
		"oidc": !protocolSwitchesPresent || r.FormValue("oidc_enabled") == "on",
		"saml": !protocolSwitchesPresent || r.FormValue("saml_enabled") == "on",
		"scim": !protocolSwitchesPresent || r.FormValue("scim_enabled") == "on",
	}
	if removedProtocol != "" {
		protocolEnabled[removedProtocol] = false
	}
	oidcClientSecret := strings.TrimSpace(r.FormValue("oidc_client_secret"))
	scimBearerToken := strings.TrimSpace(r.FormValue("scim_bearer_token"))
	existingIndex, appExists := appIndexByID(state.Apps, id)
	existingProtocol := "none"
	previousSlug := ""
	wasSCIMEnabled := false
	previousSCIMBaseURL := ""
	scimCapabilitiesKnown := false
	scimPatchSupported := false
	scimFilterSupported := false
	if appExists {
		existingProtocol = state.Apps[existingIndex].Protocol
		previousSlug = state.Apps[existingIndex].Slug
		wasSCIMEnabled = state.Apps[existingIndex].SCIMEnabled
		previousSCIMBaseURL = strings.TrimRight(strings.TrimSpace(state.Apps[existingIndex].SCIMBaseURL), "/")
		scimCapabilitiesKnown = state.Apps[existingIndex].SCIMCapabilitiesKnown
		scimPatchSupported = state.Apps[existingIndex].SCIMPatchSupported
		scimFilterSupported = state.Apps[existingIndex].SCIMFilterSupported
		if protocolEnabled["oidc"] && oidcClientSecret == "" && r.FormValue("regenerate_oidc_secret") != "on" {
			oidcClientSecret = state.Apps[existingIndex].OIDCClientSecret
		}
		if protocolEnabled["scim"] && scimBearerToken == "" && (!isAPI || apiRequest.SCIMBearerToken == nil) {
			scimBearerToken = state.Apps[existingIndex].SCIMBearerToken
		}
	}
	for _, protocol := range []string{"oidc", "saml", "scim"} {
		if !protocolEnabled[protocol] {
			existingProtocol = protocolWithout(existingProtocol, protocol)
		}
	}
	groupsOverageThreshold := 0
	if raw := strings.TrimSpace(r.FormValue("groups_overage_threshold")); raw != "" {
		groupsOverageThreshold, err = strconv.Atoi(raw)
		if err != nil {
			a.redirectFormError(w, r, tab, "app", fmt.Errorf("groups overage threshold must be a whole number"))
			return
		}
	}
	persona := strings.TrimSpace(r.FormValue("persona"))
	if persona == "" {
		persona = personaGeneric
	}
	app := app{
		ID:                      id,
		Name:                    strings.TrimSpace(r.FormValue("name")),
		Slug:                    slugify(r.FormValue("slug")),
		Protocol:                existingProtocol,
		OIDCClientID:            strings.TrimSpace(r.FormValue("oidc_client_id")),
		OIDCClientSecret:        oidcClientSecret,
		OIDCPublicClient:        r.FormValue("oidc_public_client") == "on",
		OIDCRedirectURIs:        lines(r.FormValue("oidc_redirect_uris")),
		AllowAnyOIDCRedirect:    r.FormValue("allow_any_oidc_redirect") == "on",
		OIDCJWTAccessTokens:     r.FormValue("oidc_jwt_access_tokens") == "on",
		OIDCAccessTokenAudience: strings.TrimSpace(r.FormValue("oidc_access_token_audience")),
		SAMLEntityID:            strings.TrimSpace(r.FormValue("saml_entity_id")),
		SAMLACSURL:              strings.TrimSpace(r.FormValue("saml_acs_url")),
		SAMLSLOURL:              strings.TrimSpace(r.FormValue("saml_slo_url")),
		SAMLAudience:            strings.TrimSpace(r.FormValue("saml_audience")),
		SAMLNameIDField:         normalizeSAMLNameIDField(r.FormValue("saml_name_id_field")),
		SAMLEmailAttributeName:  strings.TrimSpace(r.FormValue("saml_email_attribute_name")),
		SAMLRequestCertPEM:      strings.TrimSpace(r.FormValue("saml_request_certificate_pem")),
		SAMLEncryptionCertPEM:   strings.TrimSpace(r.FormValue("saml_encryption_certificate_pem")),
		SAMLEncryptionAlgorithm: strings.TrimSpace(r.FormValue("saml_encryption_algorithm")),
		SAMLSigningMode:         strings.TrimSpace(r.FormValue("saml_signing_mode")),
		IncludeGroupsClaim:      r.FormValue("include_groups_claim") == "on",
		ChooserMode:             normalizeChooserMode(r.FormValue("chooser_mode")),
		Persona:                 persona,
		GroupsOverageThreshold:  groupsOverageThreshold,
		OIDCClaimMappings: oidcClaimMappings{
			Name: strings.TrimSpace(r.FormValue("oidc_claim_name")), GivenName: strings.TrimSpace(r.FormValue("oidc_claim_given_name")),
			FamilyName: strings.TrimSpace(r.FormValue("oidc_claim_family_name")), Username: strings.TrimSpace(r.FormValue("oidc_claim_username")),
			Email: strings.TrimSpace(r.FormValue("oidc_claim_email")), Groups: strings.TrimSpace(r.FormValue("oidc_claim_groups")),
		},
		OIDCBackchannelLogoutURI:             strings.TrimSpace(r.FormValue("oidc_backchannel_logout_uri")),
		OIDCBackchannelLogoutSessionRequired: r.FormValue("oidc_backchannel_logout_session_required") == "on",
		SAMLAttributeMappings: samlAttributeMappings{
			GivenName: strings.TrimSpace(r.FormValue("saml_attribute_given_name")), FamilyName: strings.TrimSpace(r.FormValue("saml_attribute_family_name")),
			Username: strings.TrimSpace(r.FormValue("saml_attribute_username")), Email: strings.TrimSpace(r.FormValue("saml_email_attribute_name")),
			Groups: strings.TrimSpace(r.FormValue("saml_attribute_groups")),
		},
		SCIMBaseURL:           strings.TrimSpace(r.FormValue("scim_base_url")),
		SCIMBearerToken:       scimBearerToken,
		SCIMAutoOpenTrace:     r.FormValue("scim_auto_open_trace") == "on",
		SCIMCapabilitiesKnown: scimCapabilitiesKnown,
		SCIMPatchSupported:    scimPatchSupported,
		SCIMFilterSupported:   scimFilterSupported,
	}
	if app.Slug == "" {
		app.Slug = slugify(app.Name)
	}
	for _, protocol := range []string{"oidc", "saml", "scim"} {
		if !protocolEnabled[protocol] {
			clearAppProtocol(&app, protocol)
		}
	}
	app.OIDCClaimMappings = oidcClaimMappingsForApp(app)
	app.SAMLAttributeMappings = samlAttributeMappingsForApp(app)
	app.SAMLEmailAttributeName = app.SAMLAttributeMappings.Email
	app.Protocol = inferAppProtocol(app)
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
	}
	if supportsSAML(app) {
		if app.SAMLNameIDField == "" {
			app.SAMLNameIDField = defaultSAMLNameIDField
		}
		app.SAMLNameIDFormat = samlNameIDFormatForField(app.SAMLNameIDField)
		if app.SAMLEmailAttributeName == "" {
			app.SAMLEmailAttributeName = defaultSAMLEmailAttributeName
		}
		app.SAMLEncryptionAlgorithm = normalizeSAMLEncryptionAlgorithm(app.SAMLEncryptionAlgorithm)
		app.SAMLSigningMode = normalizeSAMLSigningMode(app.SAMLSigningMode)
	}
	if err := validateHTTPBaseURL("SCIM base URL", app.SCIMBaseURL, false); err != nil {
		a.redirectFormError(w, r, tab, "app", err)
		return
	}
	app.SCIMEnabled = scimSetupStatus(app) == setupStatusConfigured
	if err := validateApp(app, globalState.Apps); err != nil {
		a.redirectFormError(w, r, tab, "app", err)
		return
	}

	status := "environment updated"
	if removedProtocol != "" {
		status = strings.ToUpper(removedProtocol) + " setup removed"
	}
	created := id == ""
	if id == "" {
		app.ID, err = newAppID()
		if err != nil {
			a.redirectError(w, r, tab, err)
			return
		}
		state.Environment = environment{ID: app.ID, Name: app.Name, Slug: app.Slug}
		state.Apps = append(state.Apps, app)
		status = "environment added"
	} else if index, ok := appIndexByID(state.Apps, id); ok {
		state.Apps[index] = app
	} else {
		a.redirectError(w, r, tab, fmt.Errorf("environment %s not found", id))
		return
	}
	scimEndpointChanged := previousSCIMBaseURL != strings.TrimRight(app.SCIMBaseURL, "/")
	if appExists && scimEndpointChanged {
		app.SCIMCapabilitiesKnown = false
		app.SCIMPatchSupported = false
		app.SCIMFilterSupported = false
		state.Apps[existingIndex] = app
	}
	// First enable or SCIM base URL change rebuilds sync rows. Re-enabling
	// after a pause resumes remembered remote IDs instead of recreating.
	if app.SCIMEnabled && scimEndpointChanged {
		initializeAppSync(&state, app.ID)
	} else if app.SCIMEnabled && !wasSCIMEnabled && !appHasSyncState(state, app.ID) {
		initializeAppSync(&state, app.ID)
	}
	if err := saveEnvironmentState(state); err != nil {
		a.redirectError(w, r, tab, err)
		return
	}
	if appExists && previousSlug != "" && previousSlug != app.Slug {
		a.purgeEnvironmentRuntimeState("", previousSlug)
	}
	if _, ok := apiEnvironmentRequestFrom(r); ok {
		status := http.StatusOK
		if created {
			status = http.StatusCreated
		}
		writeJSONStatus(w, status, app)
		return
	}
	location := dashboardURL("apps", nil)
	if created {
		location = addEnvironmentToURL(location, app.ID)
	}
	redirectWithFlash(w, r, location, flashMessage{Kind: "success", Message: status})
}

func clearAppProtocol(app *app, protocol string) {
	switch protocol {
	case "oidc":
		app.OIDCClientID = ""
		app.OIDCClientSecret = ""
		app.OIDCPublicClient = false
		app.OIDCRedirectURIs = nil
		app.AllowAnyOIDCRedirect = false
		app.OIDCBackchannelLogoutURI = ""
		app.OIDCBackchannelLogoutSessionRequired = false
		app.OIDCJWTAccessTokens = false
		app.OIDCAccessTokenAudience = ""
	case "saml":
		app.SAMLEntityID = ""
		app.SAMLACSURL = ""
		app.SAMLSLOURL = ""
		app.SAMLAudience = ""
		app.SAMLRequestCertPEM = ""
		app.SAMLEncryptionCertPEM = ""
		app.SAMLEncryptionAlgorithm = ""
		app.SAMLSigningMode = ""
	case "scim":
		app.SCIMBaseURL = ""
		app.SCIMBearerToken = ""
		app.SCIMAutoOpenTrace = false
		app.SCIMCapabilitiesKnown = false
		app.SCIMPatchSupported = false
		app.SCIMFilterSupported = false
	}
}

func protocolWithout(protocol string, removed string) string {
	switch removed {
	case "oidc":
		if protocol == "both" {
			return "saml"
		}
		if protocol == "oidc" {
			return "none"
		}
	case "saml":
		if protocol == "both" {
			return "oidc"
		}
		if protocol == "saml" {
			return "none"
		}
	case "scim":
		if protocol == "scim" {
			return "none"
		}
	}
	return protocol
}

func (a *webApp) handleAppDiscoverSCIM(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	state, err := loadStateForApp(id)
	if err != nil {
		a.redirectError(w, r, "apps", err)
		return
	}
	index, ok := appIndexByID(state.Apps, id)
	if !ok || !state.Apps[index].SCIMEnabled {
		a.redirectError(w, r, "apps", fmt.Errorf("SCIM-enabled environment not found"))
		return
	}
	origBaseURL := strings.TrimRight(strings.TrimSpace(state.Apps[index].SCIMBaseURL), "/")
	origToken := state.Apps[index].SCIMBearerToken
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
	a.syncMutationMu.Lock()
	defer a.syncMutationMu.Unlock()
	if a.anySyncRunning() {
		a.redirectError(w, r, "apps", fmt.Errorf("sync is running; wait for it to finish"))
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	fresh, err := loadStateForApp(id)
	if err != nil {
		a.redirectError(w, r, "apps", err)
		return
	}
	index, ok = appIndexByID(fresh.Apps, id)
	if !ok || !fresh.Apps[index].SCIMEnabled ||
		strings.TrimRight(strings.TrimSpace(fresh.Apps[index].SCIMBaseURL), "/") != origBaseURL ||
		fresh.Apps[index].SCIMBearerToken != origToken {
		a.redirectError(w, r, "apps", fmt.Errorf("SCIM configuration changed during discovery"))
		return
	}
	fresh.Apps[index].SCIMCapabilitiesKnown = true
	fresh.Apps[index].SCIMPatchSupported = capabilities.PatchSupported
	fresh.Apps[index].SCIMFilterSupported = capabilities.FilterSupported
	if err := saveEnvironmentState(fresh); err != nil {
		a.redirectError(w, r, "apps", err)
		return
	}
	message := fmt.Sprintf("SCIM capabilities discovered: PATCH %s; filtering %s", supportedLabel(capabilities.PatchSupported), supportedLabel(capabilities.FilterSupported))
	redirectWithFlash(w, r, dashboardURL("apps", map[string]string{"modal": "app", "id": fresh.Apps[index].ID}), flashMessage{Kind: "success", Message: message})
}

func supportedLabel(supported bool) string {
	if supported {
		return "supported"
	}
	return "not supported"
}

func (a *webApp) handleAppTestSCIM(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseMultipartForm(1 << 20); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if r.MultipartForm != nil {
		defer func() {
			if err := r.MultipartForm.RemoveAll(); err != nil {
				log.Printf("remove test-scim temporary files: %v", err)
			}
		}()
	}
	token := strings.TrimSpace(r.FormValue("scim_bearer_token"))
	if token == "" && strings.TrimSpace(r.FormValue("id")) != "" {
		state, err := loadStateForApp(strings.TrimSpace(r.FormValue("id")))
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

	state, err := loadState()
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
	appSlug := state.Apps[index].Slug
	state.Apps = append(state.Apps[:index], state.Apps[index+1:]...)
	if err := deleteEnvironment(appID); err != nil {
		a.redirectError(w, r, "apps", err)
		return
	}
	a.purgeEnvironmentRuntimeState(appID, appSlug)
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

// purgeEnvironmentRuntimeState clears in-memory credentials, sessions,
// inspections, faults, logs, and cached traces associated with an environment
// when it is deleted or its slug is renamed.
func (a *webApp) purgeEnvironmentRuntimeState(appID string, slug string) {
	if slug != "" {
		a.oidcMu.Lock()
		for k, v := range a.authCodes {
			if v.AppSlug == slug {
				delete(a.authCodes, k)
			}
		}
		for k, v := range a.accessTokens {
			if v.AppSlug == slug {
				delete(a.accessTokens, k)
			}
		}
		for k, v := range a.refreshTokens {
			if v.AppSlug == slug {
				delete(a.refreshTokens, k)
			}
		}
		a.oidcMu.Unlock()

		a.sessionMu.Lock()
		var removedSessionIDs []string
		for k, v := range a.idpSessions {
			if v.AppSlug == slug {
				delete(a.idpSessions, k)
				removedSessionIDs = append(removedSessionIDs, k)
			}
		}
		for k, v := range a.logoutConfirmTokens {
			if v.AppSlug == slug {
				delete(a.logoutConfirmTokens, k)
			}
		}
		a.sessionMu.Unlock()

		if len(removedSessionIDs) > 0 {
			a.logoutResultMu.Lock()
			for _, id := range removedSessionIDs {
				delete(a.logoutResults, id)
			}
			a.logoutResultMu.Unlock()
		}

		a.faultMu.Lock()
		delete(a.armedFaults, slug)
		a.faultMu.Unlock()

		a.resilienceMu.Lock()
		delete(a.resilienceRuns, slug)
		a.resilienceMu.Unlock()

		a.lifecycleMu.Lock()
		delete(a.lifecycleRuns, slug)
		a.lifecycleMu.Unlock()

		a.oidcInspectorMu.Lock()
		delete(a.oidcInspections, slug)
		a.oidcInspectorMu.Unlock()

		a.samlInspectorMu.Lock()
		delete(a.samlInspections, slug)
		a.samlInspectorMu.Unlock()

		a.samlLogoutMu.Lock()
		delete(a.samlLogoutLog, slug)
		a.samlLogoutMu.Unlock()

		a.flowLogMu.Lock()
		delete(a.flowLog, slug)
		a.flowLogMu.Unlock()
	}

	if appID != "" {
		a.traceMu.Lock()
		delete(a.lastTraces, appID)
		delete(a.lastTraceContent, appID)
		a.traceMu.Unlock()

		a.importPreviewMu.Lock()
		delete(a.importPreviews, appID)
		a.importPreviewMu.Unlock()

		a.syncJobMu.Lock()
		delete(a.syncJobs, appID)
		a.syncJobMu.Unlock()
	}
}
