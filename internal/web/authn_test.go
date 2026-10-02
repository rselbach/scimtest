package web

import (
	"encoding/base64"
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	passwordContext = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
	mfaContext      = "https://refeds.org/profile/mfa"
)

func TestIDTokenReportsSignIn(t *testing.T) {
	tests := map[string]struct {
		extra   url.Values
		wantACR string
		wantAMR []any
	}{
		"password by default": {wantACR: passwordContext, wantAMR: []any{"pwd"}},
		"chosen MFA":          {extra: url.Values{"authn_strength": {"mfa"}}, wantACR: mfaContext, wantAMR: []any{"pwd", "otp", "mfa"}},
		"requested synonym is echoed": {
			extra:   url.Values{"acr_values": {"urn:greendale:gold http://schemas.openid.net/pape/policies/2007/06/multi-factor"}},
			wantACR: "http://schemas.openid.net/pape/policies/2007/06/multi-factor",
			wantAMR: []any{"pwd", "otp", "mfa"},
		},
		"unrecognized request falls back": {extra: url.Values{"acr_values": {"urn:greendale:gold"}}, wantACR: passwordContext, wantAMR: []any{"pwd"}},
		"choice overrides request": {
			extra:   url.Values{"acr_values": {mfaContext}, "authn_strength": {"password"}},
			wantACR: passwordContext,
			wantAMR: []any{"pwd"},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			svc := oidcFaultTestApp(t)
			before := time.Now().Unix()
			claims := idTokenClaimsForCode(t, svc, authorizeForCode(t, svc, tc.extra))
			r.Equal(tc.wantACR, claims["acr"])
			r.Equal(tc.wantAMR, claims["amr"])
			r.InDelta(before, claims["auth_time"], 1)
		})
	}
}

func TestPromptNoneReusesRememberedSignIn(t *testing.T) {
	hourAgo := time.Now().Add(-time.Hour).Truncate(time.Second)
	remembered := signInCookie(t, "example", "usr-1", hourAgo, "mfa")
	tests := map[string]struct {
		extra     url.Values
		cookie    *http.Cookie
		wantError string
	}{
		"no remembered sign-in":   {wantError: "login_required"},
		"cookie from older build": {cookie: &http.Cookie{Name: signInCookieName("example"), Value: "usr-1"}, wantError: "login_required"},
		"remembered sign-in":      {cookie: remembered},
		"within max_age":          {extra: url.Values{"max_age": {"7200"}}, cookie: remembered},
		"older than max_age":      {extra: url.Values{"max_age": {"60"}}, cookie: remembered, wantError: "login_required"},
		"max_age=0":               {extra: url.Values{"max_age": {"0"}}, cookie: remembered, wantError: "login_required"},
		"invalid max_age":         {extra: url.Values{"max_age": {"-1"}}, cookie: remembered, wantError: "invalid_request"},
		"combined with login":     {extra: url.Values{"prompt": {"none login"}}, cookie: remembered, wantError: "invalid_request"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			svc := oidcFaultTestApp(t)
			extra := url.Values{"prompt": {"none"}}
			for key, values := range tc.extra {
				extra[key] = values
			}
			var cookies []*http.Cookie
			if tc.cookie != nil {
				cookies = append(cookies, tc.cookie)
			}
			query := redirectQuery(t, oidcAuthorize(t, svc, http.MethodGet, extra, cookies...))
			r.Equal("study-group", query.Get("state"))
			r.Equal(tc.wantError, query.Get("error"))
			if tc.wantError != "" {
				return
			}
			claims := idTokenClaimsForCode(t, svc, query.Get("code"))
			r.Equal(float64(hourAgo.Unix()), claims["auth_time"])
			r.Equal(mfaContext, claims["acr"])
		})
	}
}

func TestRefreshedIDTokenKeepsOriginalSignIn(t *testing.T) {
	r := require.New(t)
	svc := oidcFaultTestApp(t)
	hourAgo := time.Now().Add(-time.Hour).Truncate(time.Second)
	cookie := signInCookie(t, "example", "usr-1", hourAgo, "mfa")
	query := redirectQuery(t, oidcAuthorize(t, svc, http.MethodGet, url.Values{"prompt": {"none"}, "scope": {"openid offline_access"}}, cookie))
	first := tokenBody(t, redeemToken(t, svc, query.Get("code")))

	refreshed := tokenBody(t, refreshTokens(t, svc, first["refresh_token"].(string), nil))
	claims := decodeIDTokenClaims(t, refreshed["id_token"].(string))
	r.Equal(float64(hourAgo.Unix()), claims["auth_time"])
	r.Equal(mfaContext, claims["acr"])
	r.Equal([]any{"pwd", "otp", "mfa"}, claims["amr"])
	r.Greater(claims["iat"], claims["auth_time"])
}

func TestChooserOffersReusableSignIn(t *testing.T) {
	hourAgo := time.Now().Add(-time.Hour).Truncate(time.Second)
	tests := map[string]struct {
		extra     url.Values
		wantReuse bool
		wantFresh string
	}{
		"no constraint":            {wantReuse: true},
		"prompt=login":             {extra: url.Values{"prompt": {"login"}}, wantFresh: "prompt=login"},
		"older than max_age":       {extra: url.Values{"max_age": {"60"}}, wantFresh: "max_age=60"},
		"fresh enough for max_age": {extra: url.Values{"max_age": {"7200"}}, wantReuse: true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			svc := oidcFaultTestApp(t)
			cookie := signInCookie(t, "example", "usr-1", hourAgo, "password")

			chooser := oidcAuthorize(t, svc, http.MethodGet, tc.extra, cookie)
			r.Equal(http.StatusOK, chooser.Code)
			body := chooser.Body.String()
			r.Equal(tc.wantReuse, strings.Contains(body, `name="continue_session"`))
			if tc.wantFresh != "" {
				r.Contains(body, "requires a fresh sign-in ("+tc.wantFresh+")")
			}

			form := url.Values{"continue_session": {"1"}}
			if tc.wantReuse {
				form = chooserSubmitForm(t, body, "Reuse session")
				r.Equal("1", form.Get("continue_session"))
				r.Empty(form.Get("authn_strength"))
				r.Empty(form.Get("user_id"))
			}
			for key, values := range tc.extra {
				form[key] = values
			}
			reuse := oidcAuthorize(t, svc, http.MethodPost, form, cookie)
			if !tc.wantReuse {
				r.Equal(http.StatusBadRequest, reuse.Code)
				r.Contains(reuse.Body.String(), "requires a fresh sign-in ("+tc.wantFresh+")")
				return
			}
			claims := idTokenClaimsForCode(t, svc, redirectQuery(t, reuse).Get("code"))
			r.Equal(float64(hourAgo.Unix()), claims["auth_time"])
			r.Equal(passwordContext, claims["acr"])
		})
	}
}

func TestChooserPreselectsRequestedStrength(t *testing.T) {
	r := require.New(t)
	svc := oidcFaultTestApp(t)
	rec := oidcAuthorize(t, svc, http.MethodGet, url.Values{"acr_values": {"http://schemas.microsoft.com/claims/multipleauthn"}})
	r.Equal(http.StatusOK, rec.Code)
	r.Contains(rec.Body.String(), `<option value="mfa" selected>`)
	r.NotContains(rec.Body.String(), `<option value="password" selected>`)
}

func TestOIDCChooserEnterUsesChangedUserAndStrength(t *testing.T) {
	for mode, selection := range map[string]url.Values{
		chooserModeList:       {"user_id": {"usr-abed"}},
		chooserModeIdentifier: {"login_identifier": {"anadir"}},
	} {
		t.Run(mode, func(t *testing.T) {
			for strength, tc := range map[string]struct {
				remembered string
				wantACR    string
				wantAMR    []any
			}{
				"mfa":      {"password", mfaContext, []any{"pwd", "otp", "mfa"}},
				"password": {"mfa", passwordContext, []any{"pwd"}},
			} {
				t.Run(strength, func(t *testing.T) {
					r := require.New(t)
					svc := oidcFaultTestApp(t)
					state, err := loadState()
					r.NoError(err)
					state.Apps[0].ChooserMode = mode
					state.Users = append(state.Users, user{ID: "usr-abed", GivenName: "Abed", FamilyName: "Nadir", Username: "anadir", Email: "abed@greendale.edu", Active: true})
					r.NoError(saveState(state))
					hourAgo := time.Now().Add(-time.Hour).Truncate(time.Second)
					cookie := signInCookie(t, "example", "usr-1", hourAgo, tc.remembered)
					chooser := oidcAuthorize(t, svc, http.MethodGet, nil, cookie)
					r.Equal(http.StatusOK, chooser.Code)
					r.Contains(chooser.Body.String(), "Reuse session")

					// Enter activates the first submit button owned by chooser-form.
					form := chooserSubmitForm(t, chooser.Body.String(), "Continue")
					for key, values := range selection {
						form[key] = values
					}
					form.Set("authn_strength", strength)
					before := time.Now().Unix()
					result := httptest.NewRecorder()
					req := httptest.NewRequest(http.MethodPost, "/oidc/example/authorize", strings.NewReader(form.Encode()))
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					req.AddCookie(cookie)
					svc.routes().ServeHTTP(result, req)
					claims := idTokenClaimsForCode(t, svc, redirectQuery(t, result).Get("code"))
					r.Equal("usr-abed", claims["sub"])
					r.Equal(tc.wantACR, claims["acr"])
					r.Equal(tc.wantAMR, claims["amr"])
					r.GreaterOrEqual(claims["auth_time"], float64(before))
					r.Greater(claims["auth_time"], float64(hourAgo.Unix()))
				})
			}
		})
	}
}

func TestSAMLChooserEnterUsesChangedUserAndStrength(t *testing.T) {
	for mode, selection := range map[string]url.Values{
		chooserModeList:       {"user_id": {"usr-abed"}},
		chooserModeIdentifier: {"login_identifier": {"anadir"}},
	} {
		t.Run(mode, func(t *testing.T) {
			for strength, tc := range map[string]struct {
				remembered string
				wantClass  string
			}{
				"mfa":      {"password", mfaContext},
				"password": {"mfa", passwordContext},
			} {
				t.Run(strength, func(t *testing.T) {
					r := require.New(t)
					setTestStateFile(t)
					svc := newTestIDPApp(t)
					state, troy := troyGreendaleSAMLState("")
					state.Apps[0].ChooserMode = mode
					state.Users = append(state.Users, user{ID: "usr-abed", GivenName: "Abed", FamilyName: "Nadir", Username: "anadir", Email: "abed@greendale.edu", Active: true})
					r.NoError(saveState(state))
					hourAgo := time.Now().Add(-time.Hour).Truncate(time.Second)
					cookie := signInCookie(t, "greendale", troy.ID, hourAgo, tc.remembered)
					request := url.Values{"SAMLRequest": {greendaleAuthnRequest("", false)}, "RelayState": {"study-group"}}
					chooser := postSAMLSSO(t, svc, request, cookie)
					r.Equal(http.StatusOK, chooser.Code)
					r.Contains(chooser.Body.String(), "Reuse session")

					form := chooserSubmitForm(t, chooser.Body.String(), "Continue")
					for key, values := range selection {
						form[key] = values
					}
					form.Set("authn_strength", strength)
					before := time.Now().UTC().Truncate(time.Second)
					result := postSAMLSSO(t, svc, form, cookie)
					assertion := postedSAMLAssertion(t, result)
					r.Equal("abed@greendale.edu", firstElementTextByLocalName(assertion, "NameID"))
					statement := findElementByLocalName(assertion, "AuthnStatement")
					r.Equal(tc.wantClass, firstElementTextByLocalName(statement, "AuthnContextClassRef"))
					r.False(parseSAMLInstant(t, statement.SelectAttrValue("AuthnInstant", "")).Before(before))
					r.Equal("study-group", hiddenInputValue(result.Body.String(), "RelayState"))
				})
			}
		})
	}
}

// chooserSubmitForm reads the rendered form's protocol fields and submitter.
// The Continue checks enforce native implicit submission, including external
// buttons that can otherwise take precedence over buttons inside the form.
func chooserSubmitForm(t *testing.T, body, submitter string) url.Values {
	t.Helper()
	forms := regexp.MustCompile(`(?s)<form\b[^>]*>.*?</form>`).FindAllString(body, -1)
	for _, form := range forms {
		buttons := regexp.MustCompile(`(?s)<button\b([^>]*)>([^<]*)</button>`).FindAllStringSubmatch(form, -1)
		for _, button := range buttons {
			if button[2] != submitter {
				continue
			}
			if submitter == "Continue" {
				require.Contains(t, form, `id="chooser-form"`)
				require.Equal(t, "Continue", buttons[0][2], "Enter must activate Continue")
				require.NotContains(t, body, `form="chooser-form"`, "external submitters must not take precedence")
			}
			values := url.Values{}
			inputs := regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]*)">`).FindAllStringSubmatch(form, -1)
			for _, input := range inputs {
				values.Add(html.UnescapeString(input[1]), html.UnescapeString(input[2]))
			}
			attrs := regexp.MustCompile(`name="([^"]+)" value="([^"]*)"`).FindStringSubmatch(button[1])
			if attrs != nil {
				values.Add(attrs[1], attrs[2])
			}
			return values
		}
	}
	t.Fatalf("no form owns submit button %q", submitter)
	return nil
}

func TestDiscoveryAdvertisesAuthnContexts(t *testing.T) {
	r := require.New(t)
	svc := oidcFaultTestApp(t)
	rec := httptest.NewRecorder()
	svc.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oidc/example/.well-known/openid-configuration", nil))
	r.Equal(http.StatusOK, rec.Code)
	var discovery struct {
		ACRValues []string `json:"acr_values_supported"`
		Claims    []string `json:"claims_supported"`
	}
	r.NoError(json.Unmarshal(rec.Body.Bytes(), &discovery))
	r.Contains(discovery.ACRValues, mfaContext)
	r.Subset(discovery.Claims, []string{"auth_time", "acr", "amr"})
}

func TestSAMLAuthnStatementReportsSignIn(t *testing.T) {
	tests := map[string]struct {
		requested string
		strength  string
		wantClass string
	}{
		"password by default": {wantClass: passwordContext},
		"requested class is echoed": {
			requested: "http://schemas.microsoft.com/claims/multipleauthn",
			wantClass: "http://schemas.microsoft.com/claims/multipleauthn",
		},
		"choice overrides request": {requested: mfaContext, strength: "password", wantClass: passwordContext},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			setTestStateFile(t)
			svc := newTestIDPApp(t)
			state, troy := troyGreendaleSAMLState("")
			r.NoError(saveState(state))
			before := time.Now().UTC().Truncate(time.Second)

			form := url.Values{"SAMLRequest": {greendaleAuthnRequest(tc.requested, false)}, "user_id": {troy.ID}, "authn_strength": {tc.strength}}
			statement := findElementByLocalName(postedSAMLAssertion(t, postSAMLSSO(t, svc, form)), "AuthnStatement")
			r.Equal(tc.wantClass, firstElementTextByLocalName(statement, "AuthnContextClassRef"))
			r.False(parseSAMLInstant(t, statement.SelectAttrValue("AuthnInstant", "")).Before(before))
		})
	}
}

func TestSAMLForceAuthnRulesOutRememberedSignIn(t *testing.T) {
	tests := map[string]struct {
		force     bool
		wantReuse bool
	}{
		"without ForceAuthn": {wantReuse: true},
		"with ForceAuthn":    {force: true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			setTestStateFile(t)
			svc := newTestIDPApp(t)
			state, troy := troyGreendaleSAMLState("")
			r.NoError(saveState(state))
			hourAgo := time.Now().Add(-time.Hour).Truncate(time.Second)
			cookie := signInCookie(t, "greendale", troy.ID, hourAgo, "mfa")
			request := greendaleAuthnRequest("", tc.force)

			chooser := postSAMLSSO(t, svc, url.Values{"SAMLRequest": {request}}, cookie)
			r.Equal(http.StatusOK, chooser.Code)
			r.Equal(tc.wantReuse, strings.Contains(chooser.Body.String(), `name="continue_session"`))
			r.Equal(tc.force, strings.Contains(chooser.Body.String(), "requires a fresh sign-in (ForceAuthn)"))

			form := url.Values{"SAMLRequest": {request}, "continue_session": {"1"}}
			if tc.wantReuse {
				form = chooserSubmitForm(t, chooser.Body.String(), "Reuse session")
				r.Equal(request, form.Get("SAMLRequest"))
				r.Equal("1", form.Get("continue_session"))
			}
			reuse := postSAMLSSO(t, svc, form, cookie)
			if !tc.wantReuse {
				r.Equal(http.StatusBadRequest, reuse.Code)
				r.Contains(reuse.Body.String(), "requires a fresh sign-in (ForceAuthn)")
				return
			}
			statement := findElementByLocalName(postedSAMLAssertion(t, reuse), "AuthnStatement")
			r.Equal(hourAgo.UTC().Format(time.RFC3339), statement.SelectAttrValue("AuthnInstant", ""))
			r.Equal(mfaContext, firstElementTextByLocalName(statement, "AuthnContextClassRef"))
		})
	}
}

// signInCookie is the cookie a browser keeps after signing in as userID.
func signInCookie(t *testing.T, slug, userID string, at time.Time, strengthID string) *http.Cookie {
	t.Helper()
	strength, ok := authnStrengthByID(strengthID)
	require.True(t, ok)
	rec := httptest.NewRecorder()
	rememberSignIn(rec, slug, signIn{UserID: userID, Time: at, Strength: strength})
	cookies := rec.Result().Cookies()
	require.Len(t, cookies, 1)
	return cookies[0]
}

// oidcAuthorize sends an authorize request for oidcFaultTestApp without
// choosing a user.
func oidcAuthorize(t *testing.T, svc *webApp, method string, extra url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	values := url.Values{
		"response_type": {"code"},
		"client_id":     {"example-client"},
		"redirect_uri":  {"http://client.test/callback"},
		"scope":         {"openid email"},
		"state":         {"study-group"},
	}
	for key, vals := range extra {
		values[key] = vals
	}
	req := httptest.NewRequest(http.MethodGet, "/oidc/example/authorize?"+values.Encode(), nil)
	if method == http.MethodPost {
		req = httptest.NewRequest(http.MethodPost, "/oidc/example/authorize", strings.NewReader(values.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	svc.routes().ServeHTTP(rec, req)
	return rec
}

func redirectQuery(t *testing.T, rec *httptest.ResponseRecorder) url.Values {
	t.Helper()
	require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())
	location, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	return location.Query()
}

func idTokenClaimsForCode(t *testing.T, svc *webApp, code string) map[string]any {
	t.Helper()
	return decodeIDTokenClaims(t, tokenBody(t, redeemToken(t, svc, code))["id_token"].(string))
}

// greendaleAuthnRequest encodes an AuthnRequest for troyGreendaleSAMLState's
// app, optionally requesting a context class or a fresh sign-in.
func greendaleAuthnRequest(requestedClass string, forceAuthn bool) string {
	attributes := ""
	if forceAuthn {
		attributes = ` ForceAuthn="true"`
	}
	requested := ""
	if requestedClass != "" {
		requested = `<samlp:RequestedAuthnContext Comparison="exact"><saml:AuthnContextClassRef>` + requestedClass + `</saml:AuthnContextClassRef></samlp:RequestedAuthnContext>`
	}
	request := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_request-troy"` + attributes +
		` Destination="http://idp.test/saml/greendale/sso" AssertionConsumerServiceURL="https://sp.greendale.test/acs"><saml:Issuer>urn:greendale:sp</saml:Issuer>` +
		requested + `</samlp:AuthnRequest>`
	return base64.StdEncoding.EncodeToString([]byte(request))
}
