package web

import (
	"fmt"
	"net/http"
	"strings"
)

func (a *webApp) handleAppSave(w http.ResponseWriter, r *http.Request) {
	tab := normalizedTab(r.FormValue("tab"))
	a.mu.Lock()
	defer a.mu.Unlock()

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
	wasSCIMEnabled := false
	previousSCIMBaseURL := ""
	scimCapabilitiesKnown := false
	scimPatchSupported := false
	scimFilterSupported := false
	if appExists {
		existingProtocol = state.Apps[existingIndex].Protocol
		wasSCIMEnabled = state.Apps[existingIndex].SCIMEnabled
		previousSCIMBaseURL = strings.TrimRight(strings.TrimSpace(state.Apps[existingIndex].SCIMBaseURL), "/")
		scimCapabilitiesKnown = state.Apps[existingIndex].SCIMCapabilitiesKnown
		scimPatchSupported = state.Apps[existingIndex].SCIMPatchSupported
		scimFilterSupported = state.Apps[existingIndex].SCIMFilterSupported
		if protocolEnabled["oidc"] && oidcClientSecret == "" && r.FormValue("regenerate_oidc_secret") != "on" {
			oidcClientSecret = state.Apps[existingIndex].OIDCClientSecret
		}
		if protocolEnabled["scim"] && scimBearerToken == "" {
			scimBearerToken = state.Apps[existingIndex].SCIMBearerToken
		}
	}
	for _, protocol := range []string{"oidc", "saml", "scim"} {
		if !protocolEnabled[protocol] {
			existingProtocol = protocolWithout(existingProtocol, protocol)
		}
	}
	app := app{
		ID:                     id,
		Name:                   strings.TrimSpace(r.FormValue("name")),
		Slug:                   slugify(r.FormValue("slug")),
		Protocol:               existingProtocol,
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
		ChooserMode:            normalizeChooserMode(r.FormValue("chooser_mode")),
		OIDCClaimMappings: oidcClaimMappings{
			Name: strings.TrimSpace(r.FormValue("oidc_claim_name")), GivenName: strings.TrimSpace(r.FormValue("oidc_claim_given_name")),
			FamilyName: strings.TrimSpace(r.FormValue("oidc_claim_family_name")), Username: strings.TrimSpace(r.FormValue("oidc_claim_username")),
			Email: strings.TrimSpace(r.FormValue("oidc_claim_email")), Groups: strings.TrimSpace(r.FormValue("oidc_claim_groups")),
		},
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
	case "saml":
		app.SAMLEntityID = ""
		app.SAMLACSURL = ""
		app.SAMLAudience = ""
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
	a.mu.Lock()
	defer a.mu.Unlock()
	state, err := loadStateForApp(r.PathValue("id"))
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
	state.Apps[index].SCIMFilterSupported = capabilities.FilterSupported
	if err := saveEnvironmentState(state); err != nil {
		a.redirectError(w, r, "apps", err)
		return
	}
	message := fmt.Sprintf("SCIM capabilities discovered: PATCH %s; filtering %s", supportedLabel(capabilities.PatchSupported), supportedLabel(capabilities.FilterSupported))
	redirectWithFlash(w, r, dashboardURL("apps", map[string]string{"modal": "app", "id": state.Apps[index].ID}), flashMessage{Kind: "success", Message: message})
}

func supportedLabel(supported bool) string {
	if supported {
		return "supported"
	}
	return "not supported"
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
	state.Apps = append(state.Apps[:index], state.Apps[index+1:]...)
	if err := deleteEnvironment(appID); err != nil {
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
