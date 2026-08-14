package web

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func oidcFaultTestApp(t *testing.T) *webApp {
	t.Helper()
	setTestStateFile(t)
	svc := newTestIDPApp(t)
	require.NoError(t, saveState(appState{
		Users: []user{{ID: "usr-1", GivenName: "Troy", FamilyName: "Barnes", Email: "troy@greendale.edu", Username: "troy", Active: true}},
		Apps: []app{{
			ID:               "app-1",
			Name:             "Example",
			Slug:             "example",
			Protocol:         "oidc",
			OIDCClientID:     "example-client",
			OIDCClientSecret: "secret",
			OIDCRedirectURIs: []string{"http://client.test/callback"},
		}},
	}))
	return svc
}

func authorizeForCode(t *testing.T, svc *webApp, extra url.Values) string {
	t.Helper()
	form := url.Values{
		"response_type": {"code"},
		"client_id":     {"example-client"},
		"redirect_uri":  {"http://client.test/callback"},
		"scope":         {"openid email"},
		"user_id":       {"usr-1"},
	}
	for key, vals := range extra {
		form[key] = vals
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/oidc/example/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	svc.routes().ServeHTTP(rec, req)
	require.Equal(t, http.StatusFound, rec.Code)
	location, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	return location.Query().Get("code")
}

func redeemToken(t *testing.T, svc *webApp, code string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {"http://client.test/callback"},
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/oidc/example/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("example-client", "secret")
	svc.routes().ServeHTTP(rec, req)
	return rec
}

func decodeIDTokenClaims(t *testing.T, idToken string) map[string]any {
	t.Helper()
	parts := strings.Split(idToken, ".")
	require.Len(t, parts, 3)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, json.Unmarshal(payload, &claims))
	return claims
}

func TestFaultTokenErrorForcesFailure(t *testing.T) {
	r := require.New(t)
	svc := oidcFaultTestApp(t)
	code := authorizeForCode(t, svc, url.Values{"fault_token_error": {"invalid_grant"}})
	rec := redeemToken(t, svc, code)
	r.Equal(http.StatusBadRequest, rec.Code)
	r.Contains(rec.Body.String(), "invalid_grant")
}

func TestFaultExpiredIDToken(t *testing.T) {
	r := require.New(t)
	svc := oidcFaultTestApp(t)
	code := authorizeForCode(t, svc, url.Values{"fault_id_token_ttl": {"-1h"}})
	rec := redeemToken(t, svc, code)
	r.Equal(http.StatusOK, rec.Code)
	var body map[string]any
	r.NoError(json.Unmarshal(rec.Body.Bytes(), &body))
	claims := decodeIDTokenClaims(t, body["id_token"].(string))
	iat := int64(claims["iat"].(float64))
	exp := int64(claims["exp"].(float64))
	r.Less(exp, iat, "an expired token must have exp before iat")
}

func TestFaultDropClaims(t *testing.T) {
	r := require.New(t)
	svc := oidcFaultTestApp(t)
	code := authorizeForCode(t, svc, url.Values{"fault_drop_claims": {"email"}})
	rec := redeemToken(t, svc, code)
	r.Equal(http.StatusOK, rec.Code)
	var body map[string]any
	r.NoError(json.Unmarshal(rec.Body.Bytes(), &body))
	claims := decodeIDTokenClaims(t, body["id_token"].(string))
	_, hasEmail := claims["email"]
	r.False(hasEmail, "dropped claim must be absent")
}

func TestFaultBreakSignatureChangesToken(t *testing.T) {
	r := require.New(t)
	svc := oidcFaultTestApp(t)
	cleanCode := authorizeForCode(t, svc, nil)
	cleanRec := redeemToken(t, svc, cleanCode)
	var cleanBody map[string]any
	r.NoError(json.Unmarshal(cleanRec.Body.Bytes(), &cleanBody))
	cleanSig := strings.Split(cleanBody["id_token"].(string), ".")[2]

	brokenCode := authorizeForCode(t, svc, url.Values{"fault_break_signature": {"1"}})
	brokenRec := redeemToken(t, svc, brokenCode)
	var brokenBody map[string]any
	r.NoError(json.Unmarshal(brokenRec.Body.Bytes(), &brokenBody))
	brokenSig := strings.Split(brokenBody["id_token"].(string), ".")[2]

	r.NotEqual(cleanSig[0], brokenSig[0], "broken signature must differ")
}

func TestArmedFaultsApplyOnceWithoutURLParams(t *testing.T) {
	r := require.New(t)
	svc := oidcFaultTestApp(t)

	// Arm a token error from the inspector form.
	armRec := httptest.NewRecorder()
	armReq := httptest.NewRequest(http.MethodPost, "/inspect/faults/example/arm", strings.NewReader(url.Values{"fault_token_error": {"invalid_grant"}}.Encode()))
	armReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	svc.routes().ServeHTTP(armRec, armReq)
	r.Equal(http.StatusSeeOther, armRec.Code)
	r.Equal("/inspect/oidc/example", armRec.Header().Get("Location"))
	r.True(svc.peekArmedFaults("example").active())

	// The inspector shows the armed banner.
	pageRec := httptest.NewRecorder()
	svc.routes().ServeHTTP(pageRec, httptest.NewRequest(http.MethodGet, "/inspect/oidc/example", nil))
	r.Contains(pageRec.Body.String(), "Faults armed for the next flow")

	// A flow with no fault_* parameters consumes the armed fault.
	code := authorizeForCode(t, svc, nil)
	r.False(svc.peekArmedFaults("example").active(), "armed faults must disarm after one flow")
	rec := redeemToken(t, svc, code)
	r.Equal(http.StatusBadRequest, rec.Code)
	r.Contains(rec.Body.String(), "invalid_grant")

	// The next flow is healthy again.
	code = authorizeForCode(t, svc, nil)
	rec = redeemToken(t, svc, code)
	r.Equal(http.StatusOK, rec.Code)
}

func TestInspectorReturnPathPreservesDashboardInspector(t *testing.T) {
	tests := map[string]string{
		"OIDC": "/?environment=app-1&tab=oidc-inspector",
		"SAML": "/?environment=app-1&tab=saml-inspector",
	}
	for name, referer := range tests {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/inspect/faults/example/arm", nil)
			request.Header.Set("Referer", "http://admin.test"+referer)

			require.Equal(t, referer, inspectorReturnPath(request, app{ID: "app-1", Protocol: "both"}))
		})
	}
	request := httptest.NewRequest(http.MethodPost, "/inspect/faults/example/arm", strings.NewReader("return_tab=saml-inspector"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	require.Equal(t, "/?environment=app-1&tab=saml-inspector", inspectorReturnPath(request, app{ID: "app-1", Protocol: "both"}))
}

func TestFaultDisarmEndpoint(t *testing.T) {
	r := require.New(t)
	svc := oidcFaultTestApp(t)
	svc.armFaults("example", faultOptions{BreakSignature: true})

	rec := httptest.NewRecorder()
	svc.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/inspect/faults/example/disarm", nil))
	r.Equal(http.StatusSeeOther, rec.Code)
	r.False(svc.peekArmedFaults("example").active())
}

func TestInvalidFaultValuesAreReported(t *testing.T) {
	r := require.New(t)
	svc := oidcFaultTestApp(t)

	armRec := httptest.NewRecorder()
	armReq := httptest.NewRequest(http.MethodPost, "/inspect/faults/example/arm", strings.NewReader(url.Values{"fault_id_token_ttl": {"-1min"}}.Encode()))
	armReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	svc.routes().ServeHTTP(armRec, armReq)

	r.False(svc.peekArmedFaults("example").active(), "invalid value must not arm anything")
	events := svc.flowEvents("example")
	r.NotEmpty(events)
	r.Contains(events[0].Detail, "ignored invalid fault_id_token_ttl")
}
