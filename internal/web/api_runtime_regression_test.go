package web

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAPITrafficSettingsDisablesSecretRecordingWithTraffic(t *testing.T) {
	app := &webApp{}
	app.trafficRecord.Store(true)
	app.debugSecrets.Store(true)
	request := httptest.NewRequest(http.MethodPatch, "/api/v1/traffic/settings", strings.NewReader(`{"record":false}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	app.handleAPITrafficSettings(response, request)

	require.Equal(t, http.StatusOK, response.Code)
	require.False(t, app.trafficRecord.Load())
	require.False(t, app.debugSecrets.Load())
}

func TestAPISAMLSignInDoesNotUseOriginalAPIQueryAsSigningInput(t *testing.T) {
	handler, environmentID, adminURL := newAPIPlayground(t, false)
	state, err := loadStateForApp(environmentID)
	require.NoError(t, err)
	state.Apps[0].Protocol = "both"
	state.Apps[0].SAMLEntityID = "greendale-sp"
	state.Apps[0].SAMLACSURL = adminURL + "/saml/callback"
	require.NoError(t, saveEnvironmentState(state))
	requestXML := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_request-b" Version="2.0" AssertionConsumerServiceURL="` + adminURL + `/saml/callback"><saml:Issuer>greendale-sp</saml:Issuer></samlp:AuthnRequest>`
	body := `{"user_id":"user-troy","saml_request":"` + base64.StdEncoding.EncodeToString([]byte(requestXML)) + `"}`
	request := httptest.NewRequest(http.MethodPost, "/api/v1/environments/"+environmentID+"/saml/sign-in?SAMLRequest=signed-a&SigAlg=algorithm&Signature=signature", strings.NewReader(body))
	parsed, err := url.Parse(adminURL)
	require.NoError(t, err)
	request.Host = parsed.Host
	request.Header.Set(instanceTokenHeader, "playground-token")
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	require.Contains(t, response.Body.String(), `"saml_response"`)
}
