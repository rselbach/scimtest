package web

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const maxAPIJSONBytes = 25 << 20

type apiProtocolResponseContextKey struct{}
type apiEnvironmentRequestContextKey struct{}

func withAPIProtocolResponse(ctx context.Context) context.Context {
	return context.WithValue(ctx, apiProtocolResponseContextKey{}, true)
}

func wantsAPIProtocolResponse(r *http.Request) bool {
	value, _ := r.Context().Value(apiProtocolResponseContextKey{}).(bool)
	return value
}

func withAPIEnvironmentRequest(r *http.Request, request apiEnvironmentRequest) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), apiEnvironmentRequestContextKey{}, request))
}

func apiEnvironmentRequestFrom(r *http.Request) (apiEnvironmentRequest, bool) {
	request, ok := r.Context().Value(apiEnvironmentRequestContextKey{}).(apiEnvironmentRequest)
	return request, ok
}

type apiRoute struct {
	Method       string   `json:"method"`
	Path         string   `json:"path"`
	Fields       []string `json:"fields,omitempty"`
	handler      func(*webApp, http.ResponseWriter, *http.Request)
	mutatesState bool
}

func apiRoutes() []apiRoute {
	return []apiRoute{
		{http.MethodGet, "/api/v1", nil, (*webApp).serveAPI, false},
		{http.MethodGet, "/api/v1/status", nil, (*webApp).handleAPIStatus, false},
		{http.MethodGet, "/api/v1/config", nil, (*webApp).handleAPIConfigGet, false},
		{http.MethodPatch, "/api/v1/config", []string{"idp_base_url", "trust_forwarded_headers", "debug", "record_traffic", "record_secrets"}, (*webApp).handleAPIConfigPatch, true},
		{http.MethodGet, "/api/v1/environments", nil, (*webApp).handleAPIEnvironmentsList, false},
		{http.MethodPost, "/api/v1/environments", environmentAPIFields, (*webApp).handleAPIEnvironmentCreate, true},
		{http.MethodGet, "/api/v1/environments/{environment_id}", nil, (*webApp).handleAPIEnvironmentGet, false},
		{http.MethodPatch, "/api/v1/environments/{environment_id}", environmentAPIFields, (*webApp).handleAPIEnvironmentPatch, true},
		{http.MethodDelete, "/api/v1/environments/{environment_id}", nil, (*webApp).handleAPIEnvironmentDelete, true},
		{http.MethodGet, "/api/v1/environments/{environment_id}/users", nil, (*webApp).handleAPIUsersList, false},
		{http.MethodPost, "/api/v1/environments/{environment_id}/users", userAPIFields, (*webApp).handleAPIUserCreate, true},
		{http.MethodGet, "/api/v1/environments/{environment_id}/users/{user_id}", nil, (*webApp).handleAPIUserGet, false},
		{http.MethodPatch, "/api/v1/environments/{environment_id}/users/{user_id}", userAPIFields, (*webApp).handleAPIUserPatch, true},
		{http.MethodDelete, "/api/v1/environments/{environment_id}/users/{user_id}", nil, (*webApp).handleAPIUserDelete, true},
		{http.MethodPost, "/api/v1/environments/{environment_id}/users/{user_id}/restore", nil, (*webApp).handleAPIUserRestore, true},
		{http.MethodPost, "/api/v1/environments/{environment_id}/users/{user_id}/push", nil, (*webApp).handleAPIUserPush, false},
		{http.MethodGet, "/api/v1/environments/{environment_id}/users/{user_id}/operations", nil, (*webApp).handleAPIUserOperations, false},
		{http.MethodPost, "/api/v1/environments/{environment_id}/users/bulk-delete", []string{"ids"}, (*webApp).handleAPIUsersBulkDelete, true},
		{http.MethodGet, "/api/v1/environments/{environment_id}/groups", nil, (*webApp).handleAPIGroupsList, false},
		{http.MethodPost, "/api/v1/environments/{environment_id}/groups", groupAPIFields, (*webApp).handleAPIGroupCreate, true},
		{http.MethodGet, "/api/v1/environments/{environment_id}/groups/{group_id}", nil, (*webApp).handleAPIGroupGet, false},
		{http.MethodPatch, "/api/v1/environments/{environment_id}/groups/{group_id}", groupAPIFields, (*webApp).handleAPIGroupPatch, true},
		{http.MethodDelete, "/api/v1/environments/{environment_id}/groups/{group_id}", nil, (*webApp).handleAPIGroupDelete, true},
		{http.MethodPost, "/api/v1/environments/{environment_id}/groups/{group_id}/restore", nil, (*webApp).handleAPIGroupRestore, true},
		{http.MethodPost, "/api/v1/environments/{environment_id}/groups/{group_id}/push", nil, (*webApp).handleAPIGroupPush, false},
		{http.MethodGet, "/api/v1/environments/{environment_id}/groups/{group_id}/operations", nil, (*webApp).handleAPIGroupOperations, false},
		{http.MethodPost, "/api/v1/environments/{environment_id}/groups/bulk-delete", []string{"ids"}, (*webApp).handleAPIGroupsBulkDelete, true},
		{http.MethodGet, "/api/v1/environments/{environment_id}/connection", nil, (*webApp).handleAPIConnection, false},
		{http.MethodPost, "/api/v1/environments/{environment_id}/scim/discover", nil, (*webApp).handleAPISCIMDiscover, true},
		{http.MethodPost, "/api/v1/environments/{environment_id}/scim/test", nil, (*webApp).handleAPISCIMTest, true},
		{http.MethodPost, "/api/v1/environments/{environment_id}/tools/seed-sample", nil, (*webApp).handleAPIToolAction, true},
		{http.MethodPost, "/api/v1/environments/{environment_id}/tools/create-users", []string{"count", "email_domain"}, (*webApp).handleAPIToolAction, true},
		{http.MethodPost, "/api/v1/environments/{environment_id}/tools/activate-all", nil, (*webApp).handleAPIToolAction, true},
		{http.MethodPost, "/api/v1/environments/{environment_id}/tools/deactivate-all", nil, (*webApp).handleAPIToolAction, true},
		{http.MethodPost, "/api/v1/environments/{environment_id}/tools/delete-all", nil, (*webApp).handleAPIToolAction, true},
		{http.MethodPost, "/api/v1/environments/{environment_id}/tools/clear-local", nil, (*webApp).handleAPIToolAction, true},
		{http.MethodGet, "/api/v1/environments/{environment_id}/sync/plan", nil, (*webApp).handleAPISyncPlan, false},
		{http.MethodGet, "/api/v1/environments/{environment_id}/sync/status", nil, (*webApp).handleAPISyncStatus, false},
		{http.MethodPost, "/api/v1/environments/{environment_id}/sync/start", nil, (*webApp).handleAPISyncStart, false},
		{http.MethodPost, "/api/v1/environments/{environment_id}/sync/cancel", nil, (*webApp).handleAPISyncCancel, false},
		{http.MethodPost, "/api/v1/environments/{environment_id}/sync/reconcile", nil, (*webApp).handleAPIReconcile, false},
		{http.MethodPost, "/api/v1/environments/{environment_id}/sync/reset", nil, (*webApp).handleAPIReset, true},
		{http.MethodGet, "/api/v1/environments/{environment_id}/sync/trace", nil, (*webApp).handleAPITrace, false},
		{http.MethodPost, "/api/v1/environments/{environment_id}/import/preview", nil, (*webApp).handleAPIImportPreview, true},
		{http.MethodGet, "/api/v1/environments/{environment_id}/import/preview", nil, (*webApp).handleAPIImportPreviewGet, false},
		{http.MethodPost, "/api/v1/environments/{environment_id}/import/apply", nil, (*webApp).handleAPIImportApply, true},
		{http.MethodGet, "/api/v1/environments/{environment_id}/backup", nil, (*webApp).handleAPIBackup, false},
		{http.MethodPost, "/api/v1/environments/{environment_id}/restore", []string{"version", "exported_at", "state", "user_operations", "group_operations", "user_sync", "group_sync"}, (*webApp).handleAPIRestore, true},
		{http.MethodPost, "/api/v1/environments/{environment_id}/oidc/authorize", []string{"user_id", "login_identifier", "response_type", "client_id", "redirect_uri", "scope", "state", "nonce", "code_challenge", "code_challenge_method", "acr_values", "authn_strength"}, (*webApp).handleAPIOIDCAuthorize, false},
		{http.MethodPost, "/api/v1/environments/{environment_id}/oidc/playground", []string{"user_id", "login_identifier", "faults", "refresh"}, (*webApp).handleAPIOIDCPlayground, false},
		{http.MethodGet, "/api/v1/environments/{environment_id}/oidc/tokens", nil, (*webApp).handleAPIOIDCTokens, false},
		{http.MethodDelete, "/api/v1/environments/{environment_id}/oidc/tokens", nil, (*webApp).handleAPIOIDCTokensRevoke, false},
		{http.MethodGet, "/api/v1/environments/{environment_id}/signing-keys", nil, (*webApp).handleAPISigningKeys, false},
		{http.MethodPost, "/api/v1/environments/{environment_id}/signing-keys/rotate", []string{"grace_period"}, (*webApp).handleAPISigningKeyRotate, true},
		{http.MethodPost, "/api/v1/environments/{environment_id}/saml/sign-in", []string{"user_id", "login_identifier", "relay_state", "saml_request", "sig_alg", "signature", "redirect_query", "authn_strength"}, (*webApp).handleAPISAMLSignIn, false},
		{http.MethodGet, "/api/v1/traffic", nil, (*webApp).handleAPITraffic, false},
		{http.MethodPatch, "/api/v1/traffic/settings", []string{"record", "record_secrets"}, (*webApp).handleAPITrafficSettings, false},
		{http.MethodDelete, "/api/v1/traffic", nil, (*webApp).handleAPITrafficClear, false},
		{http.MethodGet, "/api/v1/environments/{environment_id}/inspections/{protocol}", nil, (*webApp).handleAPIInspections, false},
		{http.MethodGet, "/api/v1/environments/{environment_id}/flows", nil, (*webApp).handleAPIFlows, false},
		{http.MethodGet, "/api/v1/environments/{environment_id}/faults", nil, (*webApp).handleAPIFaultGet, false},
		{http.MethodPut, "/api/v1/environments/{environment_id}/faults", faultAPIFields, (*webApp).handleAPIFaultPut, false},
		{http.MethodDelete, "/api/v1/environments/{environment_id}/faults", nil, (*webApp).handleAPIFaultDelete, false},
		{http.MethodGet, "/api/v1/environments/{environment_id}/scenarios", nil, (*webApp).handleAPIScenarios, false},
		{http.MethodPost, "/api/v1/environments/{environment_id}/scenarios/arm", []string{"preset_id", "count"}, (*webApp).handleAPIScenarioArm, false},
		{http.MethodPost, "/api/v1/environments/{environment_id}/scenarios/disarm", nil, (*webApp).handleAPIScenarioDisarm, false},
		{http.MethodGet, "/api/v1/tunnel", nil, (*webApp).handleAPITunnel, false},
		{http.MethodPost, "/api/v1/tunnel/retry", nil, (*webApp).handleAPITunnelRetry, false},
		{http.MethodGet, "/api/v1/account", nil, (*webApp).handleAPIAccount, false},
		{http.MethodPost, "/api/v1/account/start", nil, (*webApp).handleAPIAccountStart, false},
		{http.MethodPost, "/api/v1/account/retry", nil, (*webApp).handleAPIAccountRetry, false},
		{http.MethodPost, "/api/v1/account/logout", nil, (*webApp).handleAPIAccountLogout, false},
	}
}

var environmentAPIFields = []string{
	"name", "slug", "oidc_enabled", "saml_enabled", "scim_enabled", "oidc_client_id",
	"oidc_client_secret", "oidc_public_client", "oidc_redirect_uris", "allow_any_oidc_redirect",
	"saml_entity_id", "saml_acs_url", "saml_audience", "saml_name_id_field",
	"saml_email_attribute_name", "saml_request_certificate_pem", "saml_encryption_certificate_pem",
	"saml_encryption_algorithm", "saml_signing_mode", "include_groups_claim", "chooser_mode",
	"oidc_claim_mappings", "saml_attribute_mappings", "scim_base_url", "scim_bearer_token",
	"scim_auto_open_trace", "regenerate_oidc_secret",
}

var userAPIFields = []string{"given_name", "family_name", "email", "username", "active"}
var groupAPIFields = []string{"display_name", "member_ids"}
var faultAPIFields = []string{"id_token_ttl", "assertion_ttl", "clock_skew", "break_signature", "drop_claims", "token_error", "saml_status", "tamper"}

type apiEnvironmentRequest struct {
	Name                    *string                `json:"name"`
	Slug                    *string                `json:"slug"`
	OIDCEnabled             *bool                  `json:"oidc_enabled"`
	SAMLEnabled             *bool                  `json:"saml_enabled"`
	SCIMEnabled             *bool                  `json:"scim_enabled"`
	OIDCClientID            *string                `json:"oidc_client_id"`
	OIDCClientSecret        *string                `json:"oidc_client_secret"`
	OIDCPublicClient        *bool                  `json:"oidc_public_client"`
	OIDCRedirectURIs        *[]string              `json:"oidc_redirect_uris"`
	AllowAnyOIDCRedirect    *bool                  `json:"allow_any_oidc_redirect"`
	SAMLEntityID            *string                `json:"saml_entity_id"`
	SAMLACSURL              *string                `json:"saml_acs_url"`
	SAMLAudience            *string                `json:"saml_audience"`
	SAMLNameIDField         *string                `json:"saml_name_id_field"`
	SAMLEmailAttributeName  *string                `json:"saml_email_attribute_name"`
	SAMLRequestCertPEM      *string                `json:"saml_request_certificate_pem"`
	SAMLEncryptionCertPEM   *string                `json:"saml_encryption_certificate_pem"`
	SAMLEncryptionAlgorithm *string                `json:"saml_encryption_algorithm"`
	SAMLSigningMode         *string                `json:"saml_signing_mode"`
	IncludeGroupsClaim      *bool                  `json:"include_groups_claim"`
	ChooserMode             *string                `json:"chooser_mode"`
	OIDCClaimMappings       *oidcClaimMappings     `json:"oidc_claim_mappings"`
	SAMLAttributeMappings   *samlAttributeMappings `json:"saml_attribute_mappings"`
	SCIMBaseURL             *string                `json:"scim_base_url"`
	SCIMBearerToken         *string                `json:"scim_bearer_token"`
	SCIMAutoOpenTrace       *bool                  `json:"scim_auto_open_trace"`
	RegenerateOIDCSecret    *bool                  `json:"regenerate_oidc_secret"`
}

type apiUserRequest struct {
	GivenName  *string `json:"given_name"`
	FamilyName *string `json:"family_name"`
	Email      *string `json:"email"`
	Username   *string `json:"username"`
	Active     *bool   `json:"active"`
}

type apiGroupRequest struct {
	DisplayName *string   `json:"display_name"`
	MemberIDs   *[]string `json:"member_ids"`
}

type apiConfigRequest struct {
	IDPBaseURL            *string `json:"idp_base_url"`
	TrustForwardedHeaders *bool   `json:"trust_forwarded_headers"`
	Debug                 *bool   `json:"debug"`
	RecordTraffic         *bool   `json:"record_traffic"`
	RecordSecrets         *bool   `json:"record_secrets"`
}

type apiFaultRequest struct {
	IDTokenTTL     *string  `json:"id_token_ttl"`
	AssertionTTL   *string  `json:"assertion_ttl"`
	ClockSkew      *string  `json:"clock_skew"`
	BreakSignature *bool    `json:"break_signature"`
	DropClaims     []string `json:"drop_claims"`
	TokenError     *string  `json:"token_error"`
	SAMLStatus     *string  `json:"saml_status"`
	Tamper         []string `json:"tamper"`
}

func isAPIRequest(r *http.Request) bool {
	return r.URL.Path == "/api/v1" || strings.HasPrefix(r.URL.Path, "/api/v1/")
}

func (a *webApp) apiHandler() http.Handler {
	mux := http.NewServeMux()
	paths := make(map[string][]apiRoute)
	for _, route := range apiRoutes() {
		paths[route.Path] = append(paths[route.Path], route)
	}
	for pattern, routes := range paths {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			for _, route := range routes {
				if route.Method != r.Method {
					continue
				}
				if route.mutatesState {
					a.syncMutationMu.Lock()
					defer a.syncMutationMu.Unlock()
					if a.anySyncRunning() {
						apiError(w, http.StatusConflict, "sync is running; wait for it to finish before changing state")
						return
					}
				}
				if len(route.Fields) == 0 && r.Method != http.MethodGet && r.Body != nil && r.ContentLength != 0 {
					var empty struct{}
					if decodeAPIJSON(w, r, &empty) != nil {
						return
					}
				}
				if strings.Contains(route.Path, "/tools/") {
					r.SetPathValue("action", route.Path[strings.LastIndex(route.Path, "/")+1:])
				}
				route.handler(a, w, r)
				return
			}
			methods := make([]string, 0, len(routes))
			for _, route := range routes {
				methods = append(methods, route.Method)
			}
			w.Header().Set("Allow", strings.Join(methods, ", "))
			apiError(w, http.StatusMethodNotAllowed, "method not allowed")
		})
	}
	mux.HandleFunc("/api/v1/{$}", a.serveAPI)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		apiError(w, http.StatusNotFound, "API route not found")
	})
	return a.apiAuth(mux)
}

func (a *webApp) apiAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		provided := r.Header.Get(instanceTokenHeader)
		if a.instanceToken == "" || subtle.ConstantTimeCompare([]byte(provided), []byte(a.instanceToken)) != 1 {
			apiError(w, http.StatusUnauthorized, "valid instance token required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *webApp) serveAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		apiError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, map[string]any{"version": "v1", "routes": apiRoutes()})
}

func decodeAPIJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	return decodeAPIJSONWithNulls(w, r, dst, false)
}

func decodeAPIJSONWithNulls(w http.ResponseWriter, r *http.Request, dst any, allowNulls bool) error {
	contentType := strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0])
	if contentType != "application/json" {
		apiError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return errors.New("unsupported content type")
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAPIJSONBytes)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		status := http.StatusBadRequest
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			status = http.StatusRequestEntityTooLarge
		}
		apiError(w, status, "invalid JSON: "+err.Error())
		return err
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) < 2 || trimmed[0] != '{' {
		apiError(w, http.StatusBadRequest, "request body must be a JSON object")
		return errors.New("JSON object required")
	}
	var object map[string]any
	if err := json.Unmarshal(trimmed, &object); err != nil {
		apiError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return err
	}
	if path, ok := apiNullField(object, ""); ok && !allowNulls {
		apiError(w, http.StatusBadRequest, path+" must not be null")
		return errors.New("null field")
	}
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		status := http.StatusBadRequest
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			status = http.StatusRequestEntityTooLarge
		}
		apiError(w, status, "invalid JSON: "+err.Error())
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		apiError(w, http.StatusBadRequest, "request body must contain one JSON object")
		return errors.New("trailing JSON")
	}
	return nil
}

func apiNullField(value any, path string) (string, bool) {
	switch typed := value.(type) {
	case nil:
		return path, true
	case map[string]any:
		for key, item := range typed {
			child := key
			if path != "" {
				child = path + "." + key
			}
			if found, ok := apiNullField(item, child); ok {
				return found, true
			}
		}
	case []any:
		for index, item := range typed {
			if found, ok := apiNullField(item, fmt.Sprintf("%s[%d]", path, index)); ok {
				return found, true
			}
		}
	}
	return "", false
}

func apiError(w http.ResponseWriter, status int, message string) {
	writeJSONStatus(w, status, map[string]string{"error": message})
}

func (a *webApp) handleAPIStatus(w http.ResponseWriter, _ *http.Request) {
	state, err := loadState()
	if err != nil {
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.tunnelMu.Lock()
	tunnel := map[string]any{
		"supported": a.tunnelSupported,
		"starting":  a.tunnelStarting != nil,
		"error":     a.tunnelLastError,
	}
	if a.tunnel != nil {
		tunnel["connected"] = true
		tunnel["public_url"] = a.tunnel.PublicURL
	} else {
		tunnel["connected"] = false
	}
	a.tunnelMu.Unlock()
	writeJSON(w, map[string]any{
		"ready":        true,
		"locked":       a.requireGitHubAccount && !a.githubAccountConnected(),
		"environments": len(state.Apps),
		"debug":        a.debugRP.Load(),
		"traffic":      map[string]any{"record": a.trafficRecord.Load(), "record_secrets": a.debugSecrets.Load()},
		"tunnel":       tunnel,
	})
}

func (a *webApp) handleAPIConfigGet(w http.ResponseWriter, _ *http.Request) {
	state, err := loadState()
	if err != nil {
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, map[string]any{"idp_base_url": state.Config.IDPBaseURL, "trust_forwarded_headers": state.Config.TrustForwardedHeaders, "debug": a.debugRP.Load(), "record_traffic": a.trafficRecord.Load(), "record_secrets": a.debugSecrets.Load()})
}

func (a *webApp) handleAPIConfigPatch(w http.ResponseWriter, r *http.Request) {
	var request apiConfigRequest
	if decodeAPIJSON(w, r, &request) != nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	state, err := loadState()
	if err != nil {
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if request.IDPBaseURL != nil {
		if err := validateHTTPBaseURL("IDP base URL", *request.IDPBaseURL, false); err != nil {
			apiError(w, http.StatusBadRequest, err.Error())
			return
		}
		state.Config.IDPBaseURL = strings.TrimSpace(*request.IDPBaseURL)
	}
	if request.TrustForwardedHeaders != nil {
		state.Config.TrustForwardedHeaders = *request.TrustForwardedHeaders
	}
	if err := saveGlobalConfig(state.Config); err != nil {
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if request.Debug != nil {
		a.debugRP.Store(*request.Debug)
	}
	if request.RecordTraffic != nil {
		a.trafficRecord.Store(*request.RecordTraffic)
	}
	if request.RecordSecrets != nil {
		a.debugSecrets.Store(*request.RecordSecrets && a.trafficRecord.Load())
	}
	if !a.trafficRecord.Load() {
		a.debugSecrets.Store(false)
	}
	a.handleAPIConfigGet(w, r)
}

func apiEnvironmentForm(current app, request apiEnvironmentRequest) url.Values {
	values := make(url.Values)
	values.Set("id", current.ID)
	values.Set("name", current.Name)
	values.Set("slug", current.Slug)
	values.Set("protocol_switches_present", "true")
	setFormBool(values, "oidc_enabled", supportsOIDC(current))
	setFormBool(values, "saml_enabled", supportsSAML(current))
	setFormBool(values, "scim_enabled", scimSetupStatus(current) != setupStatusNotSetUp)
	values.Set("oidc_client_id", current.OIDCClientID)
	values.Set("oidc_client_secret", current.OIDCClientSecret)
	setFormBool(values, "oidc_public_client", current.OIDCPublicClient)
	values.Set("oidc_redirect_uris", strings.Join(current.OIDCRedirectURIs, "\n"))
	setFormBool(values, "allow_any_oidc_redirect", current.AllowAnyOIDCRedirect)
	values.Set("saml_entity_id", current.SAMLEntityID)
	values.Set("saml_acs_url", current.SAMLACSURL)
	values.Set("saml_audience", current.SAMLAudience)
	values.Set("saml_name_id_field", current.SAMLNameIDField)
	values.Set("saml_email_attribute_name", current.SAMLEmailAttributeName)
	values.Set("saml_request_certificate_pem", current.SAMLRequestCertPEM)
	values.Set("saml_encryption_certificate_pem", current.SAMLEncryptionCertPEM)
	values.Set("saml_encryption_algorithm", current.SAMLEncryptionAlgorithm)
	values.Set("saml_signing_mode", current.SAMLSigningMode)
	setFormBool(values, "include_groups_claim", current.IncludeGroupsClaim)
	values.Set("chooser_mode", current.ChooserMode)
	values.Set("oidc_claim_name", current.OIDCClaimMappings.Name)
	values.Set("oidc_claim_given_name", current.OIDCClaimMappings.GivenName)
	values.Set("oidc_claim_family_name", current.OIDCClaimMappings.FamilyName)
	values.Set("oidc_claim_username", current.OIDCClaimMappings.Username)
	values.Set("oidc_claim_email", current.OIDCClaimMappings.Email)
	values.Set("oidc_claim_groups", current.OIDCClaimMappings.Groups)
	values.Set("saml_attribute_given_name", current.SAMLAttributeMappings.GivenName)
	values.Set("saml_attribute_family_name", current.SAMLAttributeMappings.FamilyName)
	values.Set("saml_attribute_username", current.SAMLAttributeMappings.Username)
	values.Set("saml_attribute_groups", current.SAMLAttributeMappings.Groups)
	values.Set("scim_base_url", current.SCIMBaseURL)
	values.Set("scim_bearer_token", current.SCIMBearerToken)
	setFormBool(values, "scim_auto_open_trace", current.SCIMAutoOpenTrace)
	applyString(values, "name", request.Name)
	applyString(values, "slug", request.Slug)
	applyBool(values, "oidc_enabled", request.OIDCEnabled)
	applyBool(values, "saml_enabled", request.SAMLEnabled)
	applyBool(values, "scim_enabled", request.SCIMEnabled)
	applyString(values, "oidc_client_id", request.OIDCClientID)
	applyString(values, "oidc_client_secret", request.OIDCClientSecret)
	applyBool(values, "oidc_public_client", request.OIDCPublicClient)
	if request.OIDCRedirectURIs != nil {
		values.Set("oidc_redirect_uris", strings.Join(*request.OIDCRedirectURIs, "\n"))
	}
	applyBool(values, "allow_any_oidc_redirect", request.AllowAnyOIDCRedirect)
	applyString(values, "saml_entity_id", request.SAMLEntityID)
	applyString(values, "saml_acs_url", request.SAMLACSURL)
	applyString(values, "saml_audience", request.SAMLAudience)
	applyString(values, "saml_name_id_field", request.SAMLNameIDField)
	applyString(values, "saml_email_attribute_name", request.SAMLEmailAttributeName)
	applyString(values, "saml_request_certificate_pem", request.SAMLRequestCertPEM)
	applyString(values, "saml_encryption_certificate_pem", request.SAMLEncryptionCertPEM)
	applyString(values, "saml_encryption_algorithm", request.SAMLEncryptionAlgorithm)
	applyString(values, "saml_signing_mode", request.SAMLSigningMode)
	applyBool(values, "include_groups_claim", request.IncludeGroupsClaim)
	applyString(values, "chooser_mode", request.ChooserMode)
	if request.OIDCClaimMappings != nil {
		values.Set("oidc_claim_name", request.OIDCClaimMappings.Name)
		values.Set("oidc_claim_given_name", request.OIDCClaimMappings.GivenName)
		values.Set("oidc_claim_family_name", request.OIDCClaimMappings.FamilyName)
		values.Set("oidc_claim_username", request.OIDCClaimMappings.Username)
		values.Set("oidc_claim_email", request.OIDCClaimMappings.Email)
		values.Set("oidc_claim_groups", request.OIDCClaimMappings.Groups)
	}
	if request.SAMLAttributeMappings != nil {
		values.Set("saml_attribute_given_name", request.SAMLAttributeMappings.GivenName)
		values.Set("saml_attribute_family_name", request.SAMLAttributeMappings.FamilyName)
		values.Set("saml_attribute_username", request.SAMLAttributeMappings.Username)
		values.Set("saml_email_attribute_name", request.SAMLAttributeMappings.Email)
		values.Set("saml_attribute_groups", request.SAMLAttributeMappings.Groups)
	}
	applyString(values, "scim_base_url", request.SCIMBaseURL)
	applyString(values, "scim_bearer_token", request.SCIMBearerToken)
	applyBool(values, "scim_auto_open_trace", request.SCIMAutoOpenTrace)
	applyBool(values, "regenerate_oidc_secret", request.RegenerateOIDCSecret)
	return values
}

func setFormBool(values url.Values, key string, value bool) {
	if value {
		values.Set(key, "on")
	} else {
		values.Del(key)
	}
}
func applyString(values url.Values, key string, value *string) {
	if value != nil {
		values.Set(key, *value)
	}
}
func applyBool(values url.Values, key string, value *bool) {
	if value != nil {
		setFormBool(values, key, *value)
	}
}

func apiAppByID(state appState, id string) (app, error) {
	found, ok := appByID(state.Apps, id)
	if !ok {
		return app{}, fmt.Errorf("environment %q not found", id)
	}
	return found, nil
}

func apiOperations(state appState, resourceType, id string) []operationLog {
	if resourceType == "user" {
		return append([]operationLog{}, state.UserOperations[id]...)
	}
	return append([]operationLog{}, state.GroupOperations[id]...)
}

func apiFaultValues(request apiFaultRequest) (url.Values, error) {
	values := make(url.Values)
	if request.IDTokenTTL != nil {
		values.Set("fault_id_token_ttl", *request.IDTokenTTL)
	}
	if request.AssertionTTL != nil {
		values.Set("fault_assertion_ttl", *request.AssertionTTL)
	}
	if request.ClockSkew != nil {
		values.Set("fault_clock_skew", *request.ClockSkew)
	}
	if request.BreakSignature != nil && *request.BreakSignature {
		values.Set("fault_break_signature", "true")
	}
	values.Set("fault_drop_claims", strings.Join(request.DropClaims, ","))
	if request.TokenError != nil {
		values.Set("fault_token_error", *request.TokenError)
	}
	if request.SAMLStatus != nil {
		values.Set("fault_saml_status", *request.SAMLStatus)
	}
	values.Set("fault_tamper", strings.Join(request.Tamper, ","))
	faults, warnings := parseFaultOptionsWithWarnings(values)
	if len(warnings) > 0 {
		return nil, errors.New(strings.Join(warnings, "; "))
	}
	if !faults.active() {
		return nil, errors.New("at least one fault is required")
	}
	return values, nil
}

func apiFaultResponse(f faultOptions) map[string]any {
	return map[string]any{"active": f.active(), "id_token_ttl": f.IDTokenTTL.String(), "id_token_ttl_set": f.IDTokenTTLSet, "assertion_ttl": f.AssertionTTL.String(), "assertion_ttl_set": f.AssertionTTLSet, "clock_skew": f.ClockSkew.String(), "break_signature": f.BreakSignature, "drop_claims": f.DropClaims, "token_error": f.TokenError, "saml_status": f.SAMLStatus, "tamper": f.Tamper}
}

func apiParseCount(value any) (int, error) {
	switch v := value.(type) {
	case nil:
		return 0, nil
	case float64:
		if v == float64(int(v)) {
			return int(v), nil
		}
	case string:
		return strconv.Atoi(v)
	}
	return 0, errors.New("count must be an integer")
}
