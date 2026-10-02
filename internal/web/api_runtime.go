package web

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func (a *webApp) handleAPITraffic(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{"record": a.trafficRecord.Load(), "record_secrets": a.debugSecrets.Load(), "entries": a.traffic.snapshot()})
}
func (a *webApp) handleAPITrafficSettings(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Record        *bool `json:"record"`
		RecordSecrets *bool `json:"record_secrets"`
	}
	if decodeAPIJSON(w, r, &request) != nil {
		return
	}
	if request.Record != nil {
		a.trafficRecord.Store(*request.Record)
	}
	if request.RecordSecrets != nil {
		a.debugSecrets.Store(*request.RecordSecrets && a.trafficRecord.Load())
	}
	if !a.trafficRecord.Load() {
		a.debugSecrets.Store(false)
	}
	a.handleAPITraffic(w, r)
}
func (a *webApp) handleAPITrafficClear(w http.ResponseWriter, _ *http.Request) {
	a.traffic.clear()
	w.WriteHeader(http.StatusNoContent)
}

func (a *webApp) apiEnvironmentApp(w http.ResponseWriter, r *http.Request) (app, bool) {
	state, err := a.loadAPIEnvironment(r.PathValue("environment_id"))
	if err != nil {
		apiError(w, http.StatusNotFound, err.Error())
		return app{}, false
	}
	found, _ := apiAppByID(state, r.PathValue("environment_id"))
	return found, true
}

// apiOIDCEnvironment loads an environment that must have OIDC enabled.
func (a *webApp) apiOIDCEnvironment(w http.ResponseWriter, r *http.Request) (appState, app, bool) {
	state, err := a.loadAPIEnvironment(r.PathValue("environment_id"))
	if err != nil {
		apiError(w, http.StatusNotFound, err.Error())
		return appState{}, app{}, false
	}
	found, _ := apiAppByID(state, r.PathValue("environment_id"))
	if !supportsOIDC(found) {
		apiError(w, http.StatusBadRequest, "OIDC is not enabled")
		return appState{}, app{}, false
	}
	return state, found, true
}

func (a *webApp) handleAPIOIDCTokens(w http.ResponseWriter, r *http.Request) {
	state, found, ok := a.apiOIDCEnvironment(w, r)
	if !ok {
		return
	}
	writeJSON(w, map[string]any{"holders": a.oidcTokenHolders(found.Slug, state.Users)})
}

// handleAPIOIDCTokensRevoke revokes every token for the environment, or only
// the user named by the user_id query parameter.
func (a *webApp) handleAPIOIDCTokensRevoke(w http.ResponseWriter, r *http.Request) {
	state, found, ok := a.apiOIDCEnvironment(w, r)
	if !ok {
		return
	}
	userID := r.URL.Query().Get("user_id")
	if _, known := userByID(state.Users, userID); userID != "" && !known {
		apiError(w, http.StatusNotFound, fmt.Sprintf("user %q not found", userID))
		return
	}
	revoked := a.revokeOIDCTokens(found.Slug, userID)
	a.recordFlowEvent(found.Slug, "oidc", "revoke", "ok", revokedUserLabel(state.Users, userID), fmt.Sprintf("Revoked %d tokens", revoked))
	writeJSON(w, map[string]int{"revoked": revoked})
}

func (a *webApp) handleAPIFaultGet(w http.ResponseWriter, r *http.Request) {
	found, ok := a.apiEnvironmentApp(w, r)
	if !ok {
		return
	}
	if !supportsAnyIDP(found) {
		apiError(w, http.StatusBadRequest, "environment has no OIDC or SAML configuration")
		return
	}
	writeJSON(w, apiFaultResponse(a.peekArmedFaults(found.Slug)))
}
func (a *webApp) handleAPIFaultPut(w http.ResponseWriter, r *http.Request) {
	found, ok := a.apiEnvironmentApp(w, r)
	if !ok {
		return
	}
	if !supportsAnyIDP(found) {
		apiError(w, http.StatusBadRequest, "environment has no OIDC or SAML configuration")
		return
	}
	var request apiFaultRequest
	if decodeAPIJSON(w, r, &request) != nil {
		return
	}
	values, err := apiFaultValues(request)
	if err != nil {
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	faults, warnings := parseFaultOptionsWithWarnings(values)
	if len(warnings) != 0 {
		apiError(w, http.StatusBadRequest, strings.Join(warnings, "; "))
		return
	}
	a.armFaults(found.Slug, faults)
	writeJSON(w, apiFaultResponse(faults))
}
func (a *webApp) handleAPIFaultDelete(w http.ResponseWriter, r *http.Request) {
	found, ok := a.apiEnvironmentApp(w, r)
	if !ok {
		return
	}
	a.disarmFaults(found.Slug)
	w.WriteHeader(http.StatusNoContent)
}

func (a *webApp) handleAPIScenarios(w http.ResponseWriter, r *http.Request) {
	found, ok := a.apiEnvironmentApp(w, r)
	if !ok {
		return
	}
	run, active := a.resilienceRun(found.Slug, time.Now())
	writeJSON(w, map[string]any{"presets": resiliencePresetsForApp(found), "run": func() any {
		if active {
			return run
		}
		return nil
	}()})
}
func (a *webApp) handleAPIScenarioArm(w http.ResponseWriter, r *http.Request) {
	found, ok := a.apiEnvironmentApp(w, r)
	if !ok {
		return
	}
	var request struct {
		PresetID string `json:"preset_id"`
		Count    any    `json:"count"`
	}
	if decodeAPIJSON(w, r, &request) != nil {
		return
	}
	count, err := apiParseCount(request.Count)
	if err != nil {
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !resiliencePresetAvailable(found, request.PresetID) {
		apiError(w, http.StatusBadRequest, "scenario is not available for this environment")
		return
	}
	run, err := a.armResilienceRun(found.Slug, request.PresetID, count, time.Now())
	if err != nil {
		apiError(w, http.StatusConflict, err.Error())
		return
	}
	a.disarmFaults(found.Slug)
	writeJSONStatus(w, http.StatusCreated, run)
}
func (a *webApp) handleAPIScenarioDisarm(w http.ResponseWriter, r *http.Request) {
	found, ok := a.apiEnvironmentApp(w, r)
	if !ok {
		return
	}
	if !a.disarmResilienceRun(found.Slug, time.Now()) {
		apiError(w, http.StatusConflict, "no fault injection scenario is active")
		return
	}
	run, _ := a.resilienceRun(found.Slug, time.Now())
	writeJSON(w, run)
}

func (a *webApp) handleAPIConnection(w http.ResponseWriter, r *http.Request) {
	state, err := a.loadAPIEnvironment(r.PathValue("environment_id"))
	if err != nil {
		apiError(w, http.StatusNotFound, "environment not found")
		return
	}
	found, _ := apiAppByID(state, r.PathValue("environment_id"))
	export, err := a.appConfigExport(r, state, found)
	if err != nil {
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, export)
}

func (a *webApp) handleAPISCIMDiscover(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("environment_id")
	state, err := a.loadAPIEnvironment(id)
	if err != nil {
		apiError(w, http.StatusNotFound, err.Error())
		return
	}
	index, ok := appIndexByID(state.Apps, id)
	if !ok || !state.Apps[index].SCIMEnabled {
		apiError(w, http.StatusBadRequest, "SCIM-enabled environment not found")
		return
	}
	projected, err := stateForApp(state, id)
	if err != nil {
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	capabilities, err := discoverSCIMCapabilities(projected.Config)
	a.rememberTrace(id, capabilities.Traces)
	if err != nil {
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	fresh, err := a.loadAPIEnvironment(id)
	if err != nil {
		apiError(w, http.StatusNotFound, err.Error())
		return
	}
	index, ok = appIndexByID(fresh.Apps, id)
	if !ok || !fresh.Apps[index].SCIMEnabled {
		apiError(w, http.StatusConflict, "SCIM configuration changed during discovery")
		return
	}
	if strings.TrimRight(strings.TrimSpace(fresh.Apps[index].SCIMBaseURL), "/") != strings.TrimRight(strings.TrimSpace(state.Apps[index].SCIMBaseURL), "/") || fresh.Apps[index].SCIMBearerToken != state.Apps[index].SCIMBearerToken {
		apiError(w, http.StatusConflict, "SCIM configuration changed during discovery")
		return
	}
	fresh.Apps[index].SCIMCapabilitiesKnown = true
	fresh.Apps[index].SCIMPatchSupported = capabilities.PatchSupported
	fresh.Apps[index].SCIMFilterSupported = capabilities.FilterSupported
	if err := saveEnvironmentState(fresh); err != nil {
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, map[string]bool{"patch_supported": capabilities.PatchSupported, "filter_supported": capabilities.FilterSupported})
}

func (a *webApp) handleAPISCIMTest(w http.ResponseWriter, r *http.Request) {
	state, err := a.loadAPIEnvironment(r.PathValue("environment_id"))
	if err != nil {
		apiError(w, http.StatusNotFound, err.Error())
		return
	}
	projected, err := stateForApp(state, r.PathValue("environment_id"))
	if err != nil {
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	capabilities, err := discoverSCIMCapabilities(projected.Config)
	a.rememberTrace(r.PathValue("environment_id"), capabilities.Traces)
	if err != nil {
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, map[string]any{"connected": true, "patch_supported": capabilities.PatchSupported, "filter_supported": capabilities.FilterSupported})
}

func (a *webApp) handleAPIImportPreview(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("environment_id")
	state, err := a.loadAPIEnvironment(id)
	if err != nil {
		apiError(w, http.StatusNotFound, err.Error())
		return
	}
	projected, err := stateForApp(state, id)
	if err != nil {
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	digest, err := importPreviewBaselineDigest(projected, id)
	if err != nil {
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}
	result := importStateFromSCIM(projected)
	a.rememberTrace(id, result.Traces)
	if result.Fatal != nil {
		apiError(w, http.StatusBadRequest, result.Fatal.Error())
		return
	}
	added, updated, removed := importChangeCounts(projected, result.State)
	preview := importPreview{State: result.State, Traces: result.Traces, Status: result.Status, Added: added, Updated: updated, Removed: removed, BaselineDigest: digest, CreatedAt: time.Now()}
	a.storeImportPreview(id, preview)
	writeJSON(w, map[string]any{"added": added, "updated": updated, "removed": removed, "digest": fmt.Sprintf("%x", digest), "status": result.Status})
}

func (a *webApp) handleAPIImportPreviewGet(w http.ResponseWriter, r *http.Request) {
	preview := a.cachedImportPreview(r.PathValue("environment_id"))
	if preview == nil {
		apiError(w, http.StatusNotFound, "import preview not found or expired")
		return
	}
	writeJSON(w, map[string]any{"added": preview.Added, "updated": preview.Updated, "removed": preview.Removed, "digest": fmt.Sprintf("%x", preview.BaselineDigest), "status": preview.Status, "created_at": preview.CreatedAt})
}

func (a *webApp) handleAPIImportApply(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("environment_id")
	a.mu.Lock()
	defer a.mu.Unlock()
	state, err := a.loadAPIEnvironment(id)
	if err != nil {
		apiError(w, http.StatusNotFound, err.Error())
		return
	}
	preview := a.cachedImportPreview(id)
	if preview == nil {
		apiError(w, http.StatusConflict, "import preview expired; preview the directory again")
		return
	}
	projected, err := stateForApp(state, id)
	if err != nil {
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	digest, err := importPreviewBaselineDigest(projected, id)
	if err != nil {
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if digest != preview.BaselineDigest {
		a.deleteImportPreview(id)
		apiError(w, http.StatusConflict, "directory changed since the import preview; preview it again")
		return
	}
	if _, err := writeSafetyBackup(state); err != nil {
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}
	mergeAppImportState(&state, id, preview.State)
	appendOperationLogs(&state, id, preview.Traces)
	purgeFullySyncedDeletions(&state)
	if err := saveRequestState(state); err != nil {
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.deleteImportPreview(id)
	writeJSON(w, map[string]string{"message": preview.Status})
}

func (a *webApp) handleAPIBackup(w http.ResponseWriter, r *http.Request) {
	state, err := a.loadAPIEnvironment(r.PathValue("environment_id"))
	if err != nil {
		apiError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, newStateBackup(state))
}
func (a *webApp) handleAPIRestore(w http.ResponseWriter, r *http.Request) {
	var backup stateBackup
	if decodeAPIJSONWithNulls(w, r, &backup, true) != nil {
		return
	}
	restored, err := backup.RestoredState()
	if err != nil {
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	environmentID := r.PathValue("environment_id")
	if restored.Environment.ID != environmentID {
		apiError(w, http.StatusBadRequest, "backup belongs to a different environment")
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	current, err := a.loadAPIEnvironment(environmentID)
	if err != nil {
		apiError(w, http.StatusNotFound, err.Error())
		return
	}
	safetyPath, err := writeSafetyBackup(current)
	if err != nil {
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := saveRequestState(restored); err != nil {
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, map[string]string{"message": "backup restored", "safety_backup": safetyPath})
}

func (a *webApp) handleAPIInspections(w http.ResponseWriter, r *http.Request) {
	found, ok := a.apiEnvironmentApp(w, r)
	if !ok {
		return
	}
	switch r.PathValue("protocol") {
	case "oidc":
		if !supportsOIDC(found) {
			apiError(w, http.StatusBadRequest, "OIDC is not enabled")
			return
		}
		a.oidcInspectorMu.Lock()
		entries := append([]oidcInspection{}, a.oidcInspections[found.Slug]...)
		a.oidcInspectorMu.Unlock()
		writeJSON(w, entries)
	case "saml":
		if !supportsSAML(found) {
			apiError(w, http.StatusBadRequest, "SAML is not enabled")
			return
		}
		a.samlInspectorMu.Lock()
		entries := append([]samlInspection{}, a.samlInspections[found.Slug]...)
		a.samlInspectorMu.Unlock()
		writeJSON(w, entries)
	default:
		apiError(w, http.StatusNotFound, "protocol must be oidc or saml")
	}
}
func (a *webApp) handleAPIFlows(w http.ResponseWriter, r *http.Request) {
	found, ok := a.apiEnvironmentApp(w, r)
	if !ok {
		return
	}
	writeJSON(w, a.flowEvents(found.Slug))
}

type apiOIDCAuthorizeRequest struct {
	UserID              string `json:"user_id"`
	LoginIdentifier     string `json:"login_identifier"`
	ResponseType        string `json:"response_type"`
	ClientID            string `json:"client_id"`
	RedirectURI         string `json:"redirect_uri"`
	State               string `json:"state"`
	Scope               string `json:"scope"`
	Nonce               string `json:"nonce"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	ACRValues           string `json:"acr_values"`
	AuthnStrength       string `json:"authn_strength"`
}

func (a *webApp) handleAPIOIDCAuthorize(w http.ResponseWriter, r *http.Request) {
	var request apiOIDCAuthorizeRequest
	if decodeAPIJSON(w, r, &request) != nil {
		return
	}
	state, err := a.loadAPIEnvironment(r.PathValue("environment_id"))
	if err != nil {
		apiError(w, http.StatusNotFound, err.Error())
		return
	}
	found, _ := apiAppByID(state, r.PathValue("environment_id"))
	if !supportsOIDC(found) {
		apiError(w, http.StatusBadRequest, "OIDC is not enabled")
		return
	}
	values := url.Values{"client_id": {request.ClientID}, "redirect_uri": {request.RedirectURI}, "response_type": {request.ResponseType}, "user_id": {request.UserID}, "login_identifier": {request.LoginIdentifier}, "state": {request.State}, "scope": {request.Scope}, "nonce": {request.Nonce}, "code_challenge": {request.CodeChallenge}, "code_challenge_method": {request.CodeChallengeMethod}, "acr_values": {request.ACRValues}, "authn_strength": {request.AuthnStrength}}
	if values.Get("client_id") == "" {
		values.Set("client_id", found.OIDCClientID)
	}
	if values.Get("response_type") == "" {
		values.Set("response_type", "code")
	}
	if err := validateAuthorizeClient(found, values, false, ""); err != nil {
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	authn, err := parseAuthorizeRequest(found, values)
	if err != nil {
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	selected, session, err := chooserSignIn(r, state.Users, found, values, authn, time.Now())
	if err != nil {
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	a.issueOIDCCode(w, r.WithContext(withAPIProtocolResponse(r.Context())), found, values, selected, session, authn)
}

type apiSAMLSignInRequest struct {
	UserID          string `json:"user_id"`
	LoginIdentifier string `json:"login_identifier"`
	RelayState      string `json:"relay_state"`
	SAMLRequest     string `json:"saml_request"`
	SigAlg          string `json:"sig_alg"`
	Signature       string `json:"signature"`
	RedirectQuery   string `json:"redirect_query"`
	AuthnStrength   string `json:"authn_strength"`
}

func (a *webApp) handleAPISAMLSignIn(w http.ResponseWriter, r *http.Request) {
	var request apiSAMLSignInRequest
	if decodeAPIJSON(w, r, &request) != nil {
		return
	}
	state, err := a.loadAPIEnvironment(r.PathValue("environment_id"))
	if err != nil {
		apiError(w, http.StatusNotFound, err.Error())
		return
	}
	found, _ := apiAppByID(state, r.PathValue("environment_id"))
	if !supportsSAML(found) {
		apiError(w, http.StatusBadRequest, "SAML is not enabled")
		return
	}
	values := url.Values{"user_id": {request.UserID}, "login_identifier": {request.LoginIdentifier}, "RelayState": {request.RelayState}}
	protocolRequest := r.Clone(r.Context())
	protocolRequest.URL.RawQuery = ""
	if request.RedirectQuery != "" {
		if request.SAMLRequest != "" || request.SigAlg != "" || request.Signature != "" || request.RelayState != "" {
			apiError(w, http.StatusBadRequest, "redirect_query cannot be combined with saml_request, sig_alg, signature, or relay_state")
			return
		}
		parsed, err := url.ParseQuery(request.RedirectQuery)
		if err != nil {
			apiError(w, http.StatusBadRequest, "invalid redirect_query: "+err.Error())
			return
		}
		if parsed.Get("SAMLRequest") == "" {
			apiError(w, http.StatusBadRequest, "redirect_query must contain SAMLRequest")
			return
		}
		parsed.Set("user_id", request.UserID)
		parsed.Set("login_identifier", request.LoginIdentifier)
		values = parsed
		protocolRequest.URL.RawQuery = request.RedirectQuery
	}
	if request.SAMLRequest != "" {
		values.Set("SAMLRequest", request.SAMLRequest)
	}
	if request.SigAlg != "" {
		values.Set("SigAlg", request.SigAlg)
	}
	if request.Signature != "" {
		values.Set("Signature", request.Signature)
	}
	values.Set("authn_strength", request.AuthnStrength)
	if _, err := samlAssertionEncryptionForApp(found); err != nil {
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	baseURL := a.effectiveIDPBaseURL(r, state)
	responseContext, err := resolveSAMLResponseContext(protocolRequest, values, found, baseURL)
	if err != nil {
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	selected, session, err := chooserSignIn(r, state.Users, found, values, responseContext.Requested, time.Now())
	if err != nil {
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	a.completeSAMLSSO(w, protocolRequest.WithContext(withAPIProtocolResponse(protocolRequest.Context())), state, found, baseURL, responseContext, values, selected, session)
}

type apiToolRequest struct {
	Count       *int    `json:"count"`
	EmailDomain *string `json:"email_domain"`
}

func (a *webApp) handleAPIToolAction(w http.ResponseWriter, r *http.Request) {
	var request apiToolRequest
	id := r.PathValue("environment_id")
	action := r.PathValue("action")
	if action == "create-users" {
		if decodeAPIJSON(w, r, &request) != nil {
			return
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	state, err := a.loadAPIEnvironment(id)
	if err != nil {
		apiError(w, http.StatusNotFound, err.Error())
		return
	}
	changedUsers, changedGroups := 0, 0
	switch action {
	case "seed-sample":
		firstUser, firstGroup := len(state.Users), len(state.Groups)
		changedUsers, changedGroups, err = appendSampleDirectory(&state)
		if err == nil {
			for _, found := range state.Users[firstUser:] {
				markUserDirty(&state, found.ID, false)
			}
			for _, found := range state.Groups[firstGroup:] {
				markGroupDirty(&state, found.ID, false)
			}
		}
	case "create-users":
		count := 10
		if request.Count != nil {
			count = *request.Count
		}
		domain := "greendale.edu"
		if request.EmailDomain != nil {
			domain = *request.EmailDomain
		}
		if _, err = toolUserCount(strconv.Itoa(count)); err == nil {
			domain, err = toolEmailDomain(domain)
		}
		if err == nil {
			first := len(state.Users)
			changedUsers, err = appendToolUsers(&state, count, domain)
			for _, found := range state.Users[first:] {
				markUserDirty(&state, found.ID, false)
			}
		}
	case "activate-all", "deactivate-all":
		active := action == "activate-all"
		for i := range state.Users {
			if !state.Users[i].Deleted && state.Users[i].Active != active {
				state.Users[i].Active = active
				state.Users[i].Dirty = true
				state.Users[i].LastError = ""
				markUserDirty(&state, state.Users[i].ID, false)
				appendLocalOperationLog(&state, "user", state.Users[i].ID, summarizeActiveToggle(active))
				changedUsers++
			}
		}
	case "delete-all":
		if scimTracksDirectory(state) {
			for i := range state.Users {
				if !state.Users[i].Deleted {
					state.Users[i].Deleted = true
					state.Users[i].Dirty = true
					markUserDirty(&state, state.Users[i].ID, true)
					appendLocalOperationLog(&state, "user", state.Users[i].ID, "Marked for deletion by tools")
					changedUsers++
				}
			}
		} else {
			changedUsers = len(state.Users)
			state.Users = nil
			for i := range state.Groups {
				state.Groups[i].MemberIDs = nil
			}
		}
	case "clear-local":
		changedUsers, changedGroups = len(state.Users), len(state.Groups)
		state.Users, state.Groups = nil, nil
		state.UserOperations = make(map[string][]operationLog)
		state.GroupOperations = make(map[string][]operationLog)
		state.UserSync, state.GroupSync = nil, nil
	default:
		apiError(w, http.StatusNotFound, "unknown tool action")
		return
	}
	if err != nil {
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := saveRequestState(state); err != nil {
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, map[string]int{"users_changed": changedUsers, "groups_changed": changedGroups})
}

func (a *webApp) handleAPITunnel(w http.ResponseWriter, _ *http.Request) {
	a.tunnelMu.Lock()
	defer a.tunnelMu.Unlock()
	result := map[string]any{"supported": a.tunnelSupported, "starting": a.tunnelStarting != nil, "retry_available": a.tunnelLastError != "", "error": a.tunnelLastError}
	result["enrollment_url"] = desktopEnrollmentURL(a.tunnelEnrollmentURL)
	result["enrollment_code"] = a.tunnelEnrollmentCode
	if a.tunnel != nil {
		result["connected"] = true
		result["public_url"] = a.tunnel.PublicURL
		result["client_ip"] = a.tunnel.ClientIP
	} else {
		result["connected"] = false
	}
	writeJSON(w, result)
}
func (a *webApp) handleAPITunnelRetry(w http.ResponseWriter, _ *http.Request) {
	a.retryAutomaticTunnel()
	a.handleAPITunnel(w, nil)
}
func (a *webApp) handleAPIAccount(w http.ResponseWriter, _ *http.Request) {
	view := a.desktopAuthView()
	a.tunnelMu.Lock()
	enrollmentURL, enrollmentCode := desktopEnrollmentURL(a.tunnelEnrollmentURL), a.tunnelEnrollmentCode
	a.tunnelMu.Unlock()
	account := a.githubAccountView()
	writeJSON(w, map[string]any{"required": a.requireGitHubAccount, "state": view.State, "error": view.Error, "linked": account.Linked, "login": account.Login, "enrollment_url": enrollmentURL, "enrollment_code": enrollmentCode})
}
func (a *webApp) handleAPIAccountRetry(w http.ResponseWriter, _ *http.Request) {
	a.retryAutomaticTunnel()
	a.handleAPIAccount(w, nil)
}

func (a *webApp) handleAPIAccountStart(w http.ResponseWriter, _ *http.Request) {
	if !a.requireGitHubAccount {
		apiError(w, http.StatusNotFound, "account sign-in is not enabled")
		return
	}
	a.handleAPIAccount(w, nil)
}
func (a *webApp) handleAPIAccountLogout(w http.ResponseWriter, _ *http.Request) {
	if !a.requireGitHubAccount {
		apiError(w, http.StatusNotFound, "account sign-in is not enabled")
		return
	}
	identity, err := loadTunnelApplicationIdentity()
	if err != nil {
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if identity == nil {
		apiError(w, http.StatusServiceUnavailable, "account sign-in is unavailable")
		return
	}
	if err := a.logoutGitHubAccount(*identity); err != nil {
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.handleAPIAccount(w, nil)
}
