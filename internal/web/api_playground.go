package web

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type apiOIDCPlaygroundRequest struct {
	UserID          string           `json:"user_id"`
	LoginIdentifier string           `json:"login_identifier"`
	Faults          *apiFaultRequest `json:"faults"`
	Refresh         bool             `json:"refresh"`
}

type apiOIDCPlaygroundResult struct {
	AuthorizeStatus int            `json:"authorize_status"`
	Code            string         `json:"code,omitempty"`
	State           string         `json:"state,omitempty"`
	TokenStatus     int            `json:"token_status,omitempty"`
	Token           map[string]any `json:"token,omitempty"`
	IDTokenHeader   any            `json:"id_token_header,omitempty"`
	IDTokenClaims   any            `json:"id_token_claims,omitempty"`
	UserinfoStatus  int            `json:"userinfo_status,omitempty"`
	Userinfo        any            `json:"userinfo,omitempty"`
	RefreshStatus   int            `json:"refresh_status,omitempty"`
	Refresh         map[string]any `json:"refresh,omitempty"`
	RefreshedClaims any            `json:"refreshed_id_token_claims,omitempty"`
	Error           string         `json:"error,omitempty"`

	// AccessTokenHeader and AccessTokenClaims are set for JWT access tokens.
	AccessTokenHeader any `json:"access_token_header,omitempty"`
	AccessTokenClaims any `json:"access_token_claims,omitempty"`
}

func (a *webApp) handleAPIOIDCPlayground(w http.ResponseWriter, r *http.Request) {
	var request apiOIDCPlaygroundRequest
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
	if strings.TrimSpace(found.OIDCClientID) == "" || (!found.OIDCPublicClient && strings.TrimSpace(found.OIDCClientSecret) == "") {
		apiError(w, http.StatusBadRequest, "OIDC client credentials are incomplete")
		return
	}
	baseURL := strings.TrimRight(a.adminURL, "/")
	if baseURL == "" && a.adminHost != "" {
		baseURL = "http://" + a.adminHost
	}
	if baseURL == "" {
		apiError(w, http.StatusServiceUnavailable, "playground is unavailable: admin URL is not initialized")
		return
	}
	callback := baseURL + "/inspect/oidc/" + url.PathEscape(found.Slug) + "/playground/callback"
	stateValue, err := randomSecret(16)
	if err != nil {
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}
	nonce, err := randomSecret(16)
	if err != nil {
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}
	verifier, err := randomSecret(32)
	if err != nil {
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}
	scope := "openid profile email groups"
	if request.Refresh {
		scope += " offline_access"
	}
	query := url.Values{"response_type": {"code"}, "client_id": {found.OIDCClientID}, "redirect_uri": {callback}, "scope": {scope}, "state": {stateValue}, "nonce": {nonce}, "user_id": {request.UserID}, "login_identifier": {request.LoginIdentifier}}
	if found.OIDCPublicClient {
		challenge := sha256.Sum256([]byte(verifier))
		query.Set("code_challenge", base64.RawURLEncoding.EncodeToString(challenge[:]))
		query.Set("code_challenge_method", "S256")
	}
	if request.Faults != nil {
		faultValues, err := apiFaultValues(*request.Faults)
		if err != nil {
			apiError(w, http.StatusBadRequest, err.Error())
			return
		}
		faults, _ := parseFaultOptionsWithWarnings(faultValues)
		if faults.SAMLStatus != "" {
			apiError(w, http.StatusBadRequest, "saml_status is not valid for an OIDC playground flow")
			return
		}
		if faults.AssertionTTLSet {
			apiError(w, http.StatusBadRequest, "assertion_ttl is not valid for an OIDC playground flow")
			return
		}
		for _, fault := range faults.Tamper {
			if info, _ := tamperFaultInfoByID(fault); info.Protocol == "saml" {
				apiError(w, http.StatusBadRequest, "tamper "+string(fault)+" is not valid for an OIDC playground flow")
				return
			}
		}
		for key, values := range faultValues {
			query[key] = append([]string(nil), values...)
		}
	}
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	authorizeURL := baseURL + "/oidc/" + url.PathEscape(found.Slug) + "/authorize?" + query.Encode()
	authorizeRequest, err := http.NewRequestWithContext(r.Context(), http.MethodGet, authorizeURL, nil)
	if err != nil {
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}
	authorizeResponse, err := client.Do(authorizeRequest)
	if err != nil {
		apiError(w, http.StatusBadGateway, "authorize request: "+err.Error())
		return
	}
	authorizeBody, err := readAndCloseAPIResponse(authorizeResponse, 64<<10)
	if err != nil {
		apiError(w, http.StatusBadGateway, "read authorize response: "+err.Error())
		return
	}
	result := apiOIDCPlaygroundResult{AuthorizeStatus: authorizeResponse.StatusCode, State: stateValue}
	location := authorizeResponse.Header.Get("Location")
	redirected, parseErr := url.Parse(location)
	if parseErr != nil || redirected == nil {
		result.Error = "authorize response did not contain a valid redirect"
		writeJSON(w, result)
		return
	}
	if oauthError := redirected.Query().Get("error"); oauthError != "" {
		result.Error = oauthError + ": " + redirected.Query().Get("error_description")
		writeJSON(w, result)
		return
	}
	result.Code = redirected.Query().Get("code")
	if result.Code == "" {
		result.Error = strings.TrimSpace(string(authorizeBody))
		if result.Error == "" {
			result.Error = "authorize response carried no code"
		}
		writeJSON(w, result)
		return
	}
	tokenForm := url.Values{"grant_type": {"authorization_code"}, "code": {result.Code}, "redirect_uri": {callback}}
	if found.OIDCPublicClient {
		tokenForm.Set("client_id", found.OIDCClientID)
		tokenForm.Set("code_verifier", verifier)
	} else {
		tokenForm.Set("client_id", found.OIDCClientID)
		tokenForm.Set("client_secret", found.OIDCClientSecret)
	}
	tokenRequest, err := http.NewRequestWithContext(r.Context(), http.MethodPost, baseURL+"/oidc/"+url.PathEscape(found.Slug)+"/token", strings.NewReader(tokenForm.Encode()))
	if err != nil {
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}
	tokenRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenResponse, err := client.Do(tokenRequest)
	if err != nil {
		apiError(w, http.StatusBadGateway, "token request: "+err.Error())
		return
	}
	result.TokenStatus = tokenResponse.StatusCode
	tokenBody, err := readAndCloseAPIResponse(tokenResponse, 1<<20)
	if err != nil {
		apiError(w, http.StatusBadGateway, "read token response: "+err.Error())
		return
	}
	if err := json.Unmarshal(tokenBody, &result.Token); err != nil {
		result.Error = strings.TrimSpace(string(tokenBody))
		writeJSON(w, result)
		return
	}
	if tokenResponse.StatusCode < 200 || tokenResponse.StatusCode >= 300 {
		if value, ok := result.Token["error"].(string); ok {
			result.Error = value
		}
		writeJSON(w, result)
		return
	}
	if idToken, ok := result.Token["id_token"].(string); ok {
		result.IDTokenHeader, result.IDTokenClaims = decodeAPIJWT(idToken)
	}
	accessToken, _ := result.Token["access_token"].(string)
	result.AccessTokenHeader, result.AccessTokenClaims = decodeAPIJWT(accessToken)
	if accessToken == "" {
		result.Error = "token response carried no access token"
		writeJSON(w, result)
		return
	}
	userinfoRequest, err := http.NewRequestWithContext(r.Context(), http.MethodGet, baseURL+"/oidc/"+url.PathEscape(found.Slug)+"/userinfo", nil)
	if err != nil {
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}
	userinfoRequest.Header.Set("Authorization", "Bearer "+accessToken)
	userinfoResponse, err := client.Do(userinfoRequest)
	if err != nil {
		apiError(w, http.StatusBadGateway, "userinfo request: "+err.Error())
		return
	}
	result.UserinfoStatus = userinfoResponse.StatusCode
	userinfoBody, err := readAndCloseAPIResponse(userinfoResponse, 1<<20)
	if err != nil {
		apiError(w, http.StatusBadGateway, "read userinfo response: "+err.Error())
		return
	}
	if err := json.NewDecoder(bytes.NewReader(userinfoBody)).Decode(&result.Userinfo); err != nil {
		result.Error = strings.TrimSpace(string(userinfoBody))
	}
	if !request.Refresh || result.Error != "" {
		writeJSON(w, result)
		return
	}
	refreshToken, _ := result.Token["refresh_token"].(string)
	refreshForm := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}, "client_id": {found.OIDCClientID}}
	if !found.OIDCPublicClient {
		refreshForm.Set("client_secret", found.OIDCClientSecret)
	}
	refreshRequest, err := http.NewRequestWithContext(r.Context(), http.MethodPost, baseURL+"/oidc/"+url.PathEscape(found.Slug)+"/token", strings.NewReader(refreshForm.Encode()))
	if err != nil {
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}
	refreshRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	refreshResponse, err := client.Do(refreshRequest)
	if err != nil {
		apiError(w, http.StatusBadGateway, "refresh request: "+err.Error())
		return
	}
	result.RefreshStatus = refreshResponse.StatusCode
	refreshBody, err := readAndCloseAPIResponse(refreshResponse, 1<<20)
	if err != nil {
		apiError(w, http.StatusBadGateway, "read refresh response: "+err.Error())
		return
	}
	if err := json.Unmarshal(refreshBody, &result.Refresh); err != nil {
		result.Error = strings.TrimSpace(string(refreshBody))
		writeJSON(w, result)
		return
	}
	if value, ok := result.Refresh["error"].(string); ok {
		result.Error = value
	}
	if idToken, ok := result.Refresh["id_token"].(string); ok {
		_, result.RefreshedClaims = decodeAPIJWT(idToken)
	}
	writeJSON(w, result)
}

func readAndCloseAPIResponse(response *http.Response, limit int64) ([]byte, error) {
	data, readErr := io.ReadAll(io.LimitReader(response.Body, limit))
	closeErr := response.Body.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return data, nil
}

func decodeAPIJWT(token string) (any, any) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil
	}
	decode := func(value string) any {
		raw, err := base64.RawURLEncoding.DecodeString(value)
		if err != nil {
			return nil
		}
		var decoded any
		if json.Unmarshal(raw, &decoded) != nil {
			return nil
		}
		return decoded
	}
	return decode(parts[0]), decode(parts[1])
}
