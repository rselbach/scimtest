package web

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func acceptanceSharedSAMLLogout(t *testing.T, handler http.Handler) {
	r := require.New(t)
	f := newSharedIdentity(t, handler)
	acceptanceRequest(t, handler, http.MethodPatch, f.base, sharedJSON(t, map[string]any{"saml_slo_url": testSPSLOURL}), http.StatusOK)
	certificate := f.browser(http.MethodGet, "/saml/greendale/certificate.pem", nil)
	r.Equal(http.StatusOK, certificate.Code)
	cert, err := parseSAMLRequestCertificate(certificate.Body.String())
	r.NoError(err)
	for _, binding := range []string{samlHTTPRedirectBinding, samlHTTPPostBinding} {
		t.Run(samlBindingName(binding), func(t *testing.T) {
			r := require.New(t)
			t.Cleanup(func() {
				acceptanceRequest(t, handler, http.MethodDelete, f.base+"/sessions", "", http.StatusOK)
			})
			values := f.authorizeValues()
			values.Set("user_id", f.troy.ID)
			cookie, tokens := f.authorize(t, values)
			response := f.browser(http.MethodPost, "/saml/greendale/sso", url.Values{"user_id": {f.troy.ID}}, cookie)
			assertion := postedSAMLAssertion(t, response)
			index := findElementByLocalName(assertion, "AuthnStatement").SelectAttrValue("SessionIndex", "")
			r.NotEmpty(index)
			issuer := decodeIDTokenClaims(t, tokens["id_token"].(string))["iss"].(string)
			endpoint := strings.TrimSuffix(issuer, "/oidc/greendale") + "/saml/greendale/slo"
			requestID := "greendale-sp-logout"
			message := fmt.Sprintf(`<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="%s" Version="2.0" IssueInstant="%s" Destination="%s"><saml:Issuer>greendale-sp</saml:Issuer><saml:NameID>%s</saml:NameID><samlp:SessionIndex>%s</samlp:SessionIndex></samlp:LogoutRequest>`, requestID, time.Now().UTC().Format(time.RFC3339), endpoint, f.troy.Email, index)
			response = f.logoutMessage(t, binding, "SAMLRequest", message, "greendale-relay", cookie)
			answer, relay := receivedSAMLLogoutMessageWithCertificate(t, response, binding, "SAMLResponse", cert.Raw)
			r.Equal(requestID, answer.SelectAttrValue("InResponseTo", ""))
			r.Equal("greendale-relay", relay)
			r.Equal(samlStatusSuccess, testSAMLStatus(answer).Code)
			var sessions struct{ Sessions []idpSessionView }
			f.decode(t, http.MethodGet, "/sessions", "", http.StatusOK, &sessions)
			r.Empty(sessions.Sessions)
			passive := f.authorizeValues()
			passive.Set("prompt", "none")
			response = f.browser(http.MethodGet, "/oidc/greendale/authorize", passive, cookie)
			location, err := url.Parse(response.Header().Get("Location"))
			r.NoError(err)
			r.Equal("login_required", location.Query().Get("error"))

			cookie, _ = f.authorize(t, values)
			response = f.browser(http.MethodPost, "/saml/greendale/sso", url.Values{"user_id": {f.troy.ID}}, cookie)
			r.Equal(http.StatusOK, response.Code, response.Body.String())
			var started struct {
				RequestID string            `json:"request_id"`
				Binding   string            `json:"binding"`
				URL       string            `json:"url"`
				Form      map[string]string `json:"form"`
			}
			invalid := acceptanceRequest(t, handler, http.MethodPost, f.base+"/saml/logout", sharedJSON(t, map[string]any{"session_id": cookie.Value, "binding": "chang-was-here"}), http.StatusBadRequest)
			r.Contains(invalid.Body.String(), `binding must be redirect or post, not \"chang-was-here\"`)
			f.decode(t, http.MethodPost, "/saml/logout", sharedJSON(t, map[string]any{"session_id": cookie.Value, "binding": samlBindingName(binding)}), http.StatusOK, &started)
			r.Equal(samlBindingName(binding), started.Binding)
			outbound := httptest.NewRecorder()
			if binding == samlHTTPRedirectBinding {
				outbound.Header().Set("Location", started.URL)
				outbound.WriteHeader(http.StatusFound)
			} else {
				r.Equal(testSPSLOURL, started.URL)
				_, err := fmt.Fprintf(outbound, `<form action="%s"><input type="hidden" name="SAMLRequest" value="%s"></form>`, started.URL, started.Form["SAMLRequest"])
				r.NoError(err)
			}
			request, _ := receivedSAMLLogoutMessageWithCertificate(t, outbound, binding, "SAMLRequest", cert.Raw)
			r.Equal(started.RequestID, request.SelectAttrValue("ID", ""))
			r.Equal(f.troy.Email, firstElementTextByLocalName(request, "NameID"))
			answerXML := func(inResponseTo string) string {
				return fmt.Sprintf(`<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="greendale-sp-response" Version="2.0" IssueInstant="%s" Destination="%s" InResponseTo="%s"><saml:Issuer>greendale-sp</saml:Issuer><samlp:Status><samlp:StatusCode Value="%s"/></samlp:Status></samlp:LogoutResponse>`, time.Now().UTC().Format(time.RFC3339), endpoint, inResponseTo, samlStatusSuccess)
			}
			r.Equal(http.StatusBadRequest, f.logoutMessage(t, binding, "SAMLResponse", answerXML("chang-was-here"), "").Code)
			response = f.logoutMessage(t, binding, "SAMLResponse", answerXML(started.RequestID), "")
			r.Equal(http.StatusOK, response.Code, response.Body.String())
			var logouts struct{ Logouts []samlLogout }
			f.decode(t, http.MethodGet, "/saml/logouts", "", http.StatusOK, &logouts)
			r.NotEmpty(logouts.Logouts)
			r.Equal(started.RequestID, logouts.Logouts[0].RequestID)
			r.Equal("ok", logouts.Logouts[0].Outcome)
		})
	}
}

func (f sharedIdentity) logoutMessage(t *testing.T, binding, parameter, message, relay string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	encoded := base64.StdEncoding.EncodeToString([]byte(message))
	method := http.MethodPost
	if binding == samlHTTPRedirectBinding {
		encoded = encodeRedirectSAMLRequest(t, message)
		method = http.MethodGet
	}
	values := url.Values{parameter: {encoded}}
	if relay != "" {
		values.Set("RelayState", relay)
	}
	return f.browser(method, "/saml/greendale/slo", values, cookies...)
}
