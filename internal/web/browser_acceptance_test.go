package web

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func acceptanceOIDCBrowserChooser(t *testing.T, handler http.Handler) {
	f := newSharedIdentity(t, handler)
	for _, mode := range []string{chooserModeList, chooserModeIdentifier} {
		t.Run(mode, func(t *testing.T) {
			r := require.New(t)
			acceptanceRequest(t, handler, http.MethodPatch, f.base, sharedJSON(t, map[string]any{"chooser_mode": mode}), http.StatusOK)
			values := f.authorizeValues()
			values.Set("login_hint", "TROY.BARNES@greendale.edu")
			values.Set("acr_values", mfaContext)
			chooser := f.browser(http.MethodGet, "/oidc/greendale/authorize", values)
			r.Equal(http.StatusOK, chooser.Code, chooser.Body.String())
			body := chooser.Body.String()
			r.Contains(body, `<option value="mfa" selected>`)
			if mode == chooserModeList {
				r.Contains(body, `type="search"`)
				r.Contains(body, `data-user-list`)
				r.Contains(body, `value="`+f.troy.ID+`" required checked`)
				r.Less(strings.Index(body, `value="`+f.troy.ID+`"`), strings.Index(body, `value="`+f.abed.ID+`"`))
			} else {
				r.Contains(body, `name="login_identifier" value="TROY.BARNES@greendale.edu"`)
				r.NotContains(body, "Abed Nadir")
				r.NotContains(body, "Troy Barnes")
			}
			for _, alias := range []string{"LoginHint", "loginHint"} {
				hinted := f.authorizeValues()
				hinted.Set(alias, "TROY.BARNES@greendale.edu")
				response := f.browser(http.MethodGet, "/oidc/greendale/authorize", hinted)
				r.Equal(http.StatusOK, response.Code)
				if mode == chooserModeList {
					r.Contains(response.Body.String(), `value="`+f.troy.ID+`" required checked`)
				} else {
					r.Contains(response.Body.String(), `name="login_identifier" value="TROY.BARNES@greendale.edu"`)
				}
			}
			form := chooserSubmitForm(t, body, "Continue")
			r.Equal("study&group", form.Get("state"))
			r.Empty(form.Get("authn_strength"))
			form.Set("user_id", f.abed.ID)
			form.Set("login_identifier", "ANADIR")
			form.Set("authn_strength", "mfa")
			cookie, tokens := f.authorize(t, form)
			claims := decodeIDTokenClaims(t, tokens["id_token"].(string))
			r.Equal(f.abed.ID, claims["sub"])
			r.Equal(mfaContext, claims["acr"])
			r.Equal([]any{"pwd", "otp", "mfa"}, claims["amr"])

			chooser = f.browser(http.MethodGet, "/oidc/greendale/authorize", f.authorizeValues(), cookie)
			r.Contains(chooser.Body.String(), "Reuse session")
			if mode == chooserModeList {
				r.Contains(chooser.Body.String(), `value="`+f.abed.ID+`" required checked`)
			}
			reuse := chooserSubmitForm(t, chooser.Body.String(), "Reuse session")
			r.Empty(reuse.Get("authn_strength"))
			r.Empty(reuse.Get("user_id"))
			r.Empty(reuse.Get("login_identifier"))
			_, repeated := f.authorize(t, reuse, cookie)
			repeatedClaims := decodeIDTokenClaims(t, repeated["id_token"].(string))
			r.Equal(claims["sid"], repeatedClaims["sid"])
			r.Equal(claims["auth_time"], repeatedClaims["auth_time"])
			r.Equal(claims["acr"], repeatedClaims["acr"])

			for parameter, value := range map[string]string{"prompt": "login", "max_age": "0"} {
				fresh := f.authorizeValues()
				fresh.Set(parameter, value)
				chooser = f.browser(http.MethodGet, "/oidc/greendale/authorize", fresh, cookie)
				r.Equal(http.StatusOK, chooser.Code)
				r.NotContains(chooser.Body.String(), "Reuse session")
				r.Contains(chooser.Body.String(), "requires a fresh sign-in ("+parameter+"="+value+")")
				fresh.Set("continue_session", "1")
				denied := f.browser(http.MethodPost, "/oidc/greendale/authorize", fresh, cookie)
				r.Equal(http.StatusBadRequest, denied.Code)
				r.Contains(denied.Body.String(), "requires a fresh sign-in ("+parameter+"="+value+")")
			}
			passive := f.authorizeValues()
			passive.Set("prompt", "none")
			response := f.browser(http.MethodGet, "/oidc/greendale/authorize", passive, cookie)
			r.Equal(http.StatusFound, response.Code)
			location, err := url.Parse(response.Header().Get("Location"))
			r.NoError(err)
			r.NotEmpty(location.Query().Get("code"))
			deny := chooserSubmitForm(t, body, "Deny")
			response = f.browser(http.MethodPost, "/oidc/greendale/authorize", deny)
			r.Equal(http.StatusFound, response.Code)
			location, err = url.Parse(response.Header().Get("Location"))
			r.NoError(err)
			r.Equal("access_denied", location.Query().Get("error"))
			r.Equal("study&group", location.Query().Get("state"))
		})
	}
}

func acceptanceSAMLBrowserChooser(t *testing.T, handler http.Handler) {
	f := newSharedIdentity(t, handler)
	request := func(force bool) string {
		return base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf(`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="greendale-request" Version="2.0" ForceAuthn="%t" AssertionConsumerServiceURL="http://greendale.test/saml"><saml:Issuer>greendale-sp</saml:Issuer><saml:Subject><saml:NameID>TROY.BARNES@greendale.edu</saml:NameID></saml:Subject><samlp:RequestedAuthnContext><saml:AuthnContextClassRef>%s</saml:AuthnContextClassRef></samlp:RequestedAuthnContext></samlp:AuthnRequest>`, force, mfaContext)))
	}
	for _, mode := range []string{chooserModeList, chooserModeIdentifier} {
		t.Run(mode, func(t *testing.T) {
			r := require.New(t)
			acceptanceRequest(t, handler, http.MethodPatch, f.base, sharedJSON(t, map[string]any{"chooser_mode": mode}), http.StatusOK)
			values := url.Values{"SAMLRequest": {request(false)}, "RelayState": {"study&group"}}
			chooser := f.browser(http.MethodPost, "/saml/greendale/sso", values)
			r.Equal(http.StatusOK, chooser.Code, chooser.Body.String())
			r.Contains(chooser.Body.String(), `<option value="mfa" selected>`)
			if mode == chooserModeList {
				r.Contains(chooser.Body.String(), `value="`+f.troy.ID+`" required checked`)
			} else {
				r.Contains(chooser.Body.String(), `name="login_identifier" value="TROY.BARNES@greendale.edu"`)
				r.NotContains(chooser.Body.String(), "Abed Nadir")
			}
			requestXML, err := base64.StdEncoding.DecodeString(request(false))
			r.NoError(err)
			withoutSubject := strings.Replace(string(requestXML), `<saml:Subject><saml:NameID>TROY.BARNES@greendale.edu</saml:NameID></saml:Subject>`, "", 1)
			for _, relay := range []string{"https://portal.greendale.edu/?LoginHint=TROY.BARNES%40greendale.edu", url.QueryEscape("loginHint=TROY.BARNES%40greendale.edu")} {
				hinted := url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString([]byte(withoutSubject))}, "RelayState": {relay}}
				response := f.browser(http.MethodPost, "/saml/greendale/sso", hinted)
				r.Equal(http.StatusOK, response.Code)
				if mode == chooserModeList {
					r.Contains(response.Body.String(), `value="`+f.troy.ID+`" required checked`)
				} else {
					r.Contains(response.Body.String(), `name="login_identifier" value="TROY.BARNES@greendale.edu"`)
				}
			}
			form := chooserSubmitForm(t, chooser.Body.String(), "Continue")
			form.Set("user_id", f.abed.ID)
			form.Set("login_identifier", "ANADIR")
			form.Set("authn_strength", "mfa")
			response := f.browser(http.MethodPost, "/saml/greendale/sso", form)
			r.Equal(http.StatusOK, response.Code, response.Body.String())
			assertion := postedSAMLAssertion(t, response)
			r.Equal("abed.nadir@greendale.edu", firstElementTextByLocalName(assertion, "NameID"))
			r.Equal(mfaContext, firstElementTextByLocalName(assertion, "AuthnContextClassRef"))
			r.Equal("study&group", hiddenInputValue(response.Body.String(), "RelayState"))
			cookie := sessionCookie(t, response)
			instant := findElementByLocalName(assertion, "AuthnStatement").SelectAttrValue("AuthnInstant", "")
			chooser = f.browser(http.MethodPost, "/saml/greendale/sso", values, cookie)
			reuse := chooserSubmitForm(t, chooser.Body.String(), "Reuse session")
			r.Empty(reuse.Get("authn_strength"))
			response = f.browser(http.MethodPost, "/saml/greendale/sso", reuse, cookie)
			r.Equal(http.StatusOK, response.Code, response.Body.String())
			assertion = postedSAMLAssertion(t, response)
			r.Equal(instant, findElementByLocalName(assertion, "AuthnStatement").SelectAttrValue("AuthnInstant", ""))

			values.Set("SAMLRequest", request(true))
			chooser = f.browser(http.MethodPost, "/saml/greendale/sso", values, cookie)
			r.NotContains(chooser.Body.String(), "Reuse session")
			r.Contains(chooser.Body.String(), "requires a fresh sign-in (ForceAuthn)")
			values.Set("continue_session", "1")
			response = f.browser(http.MethodPost, "/saml/greendale/sso", values, cookie)
			r.Equal(http.StatusBadRequest, response.Code)
			r.Contains(response.Body.String(), "requires a fresh sign-in (ForceAuthn)")
		})
	}
}
