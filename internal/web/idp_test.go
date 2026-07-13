package web

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/stretchr/testify/require"
)

func TestOIDCAuthorizationCodeFlowUsesSharedDirectory(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	svc := newTestIDPApp(t)
	state := appState{
		Config: config{IDPBaseURL: "http://idp.test"},
		Users: []user{{
			ID:         "usr-1",
			GivenName:  "Riley",
			FamilyName: "Stone",
			Email:      "riley@example.test",
			Username:   "riley",
			Active:     true,
		}},
		Groups: []group{{
			ID:          "grp-1",
			DisplayName: "Engineering",
			MemberIDs:   []string{"usr-1"},
		}},
		Apps: []app{{
			ID:                 "app-1",
			Name:               "Example",
			Slug:               "example",
			Protocol:           "oidc",
			OIDCClientID:       "example-client",
			OIDCClientSecret:   "secret",
			OIDCRedirectURIs:   []string{"http://client.test/callback"},
			IncludeGroupsClaim: true,
		}},
	}
	r.NoError(saveState(state))

	discovery := httptest.NewRecorder()
	svc.routes().ServeHTTP(discovery, httptest.NewRequest(http.MethodGet, "/oidc/example/.well-known/openid-configuration", nil))
	r.Equal(http.StatusOK, discovery.Code)
	var metadata map[string]any
	r.NoError(json.Unmarshal(discovery.Body.Bytes(), &metadata))
	r.Equal("http://idp.test/oidc/example", metadata["issuer"])

	form := url.Values{
		"response_type": {"code"},
		"client_id":     {"example-client"},
		"redirect_uri":  {"http://client.test/callback"},
		"scope":         {"openid profile email groups"},
		"user_id":       {"usr-1"},
		"state":         {"abc"},
	}
	authorize := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/oidc/example/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	svc.routes().ServeHTTP(authorize, req)
	r.Equal(http.StatusFound, authorize.Code)
	location, err := url.Parse(authorize.Header().Get("Location"))
	r.NoError(err)
	code := location.Query().Get("code")
	r.NotEmpty(code)
	r.Equal("abc", location.Query().Get("state"))
	authorizationInspector := httptest.NewRecorder()
	svc.routes().ServeHTTP(authorizationInspector, httptest.NewRequest(http.MethodGet, "/inspect/oidc/example", nil))
	r.Equal(http.StatusOK, authorizationInspector.Code)
	r.Contains(authorizationInspector.Body.String(), "Authorization code issued")
	r.NotContains(authorizationInspector.Body.String(), code)

	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"http://client.test/callback"},
		"client_id":     {"example-client"},
		"client_secret": {"secret"},
	}
	token := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/oidc/example/token", strings.NewReader(tokenForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	svc.routes().ServeHTTP(token, req)
	r.Equal(http.StatusOK, token.Code)
	r.Equal("no-store", token.Header().Get("Cache-Control"))
	r.Equal("no-cache", token.Header().Get("Pragma"))
	var tokenBody map[string]any
	r.NoError(json.Unmarshal(token.Body.Bytes(), &tokenBody))
	r.NotEmpty(tokenBody["access_token"])
	r.NotEmpty(tokenBody["id_token"])

	inspector := httptest.NewRecorder()
	svc.routes().ServeHTTP(inspector, httptest.NewRequest(http.MethodGet, "/inspect/oidc/example", nil))
	r.Equal(http.StatusOK, inspector.Code)
	body := inspector.Body.String()
	r.Contains(body, "Tokens issued")
	r.Contains(body, "Riley Stone")
	r.Contains(body, "openid profile email groups")
	r.Contains(body, "Decoded ID token claims")
	r.Contains(body, "riley@example.test")
	r.NotContains(body, tokenBody["access_token"])
	r.NotContains(body, tokenBody["id_token"])
	r.NotContains(body, "secret")
}

func TestOIDCFlowProceedsWhileStateLockHeld(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	svc := newTestIDPApp(t)
	r.NoError(saveState(appState{
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

	// Simulate a long-running SCIM sync, which holds mu for its full duration.
	svc.mu.Lock()
	defer svc.mu.Unlock()

	done := make(chan string, 1)
	go func() {
		form := url.Values{
			"response_type": {"code"},
			"client_id":     {"example-client"},
			"redirect_uri":  {"http://client.test/callback"},
			"scope":         {"openid"},
			"user_id":       {"usr-1"},
		}
		authorize := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/oidc/example/authorize", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		svc.routes().ServeHTTP(authorize, req)
		if authorize.Code != http.StatusFound {
			done <- ""
			return
		}
		location, err := url.Parse(authorize.Header().Get("Location"))
		if err != nil {
			done <- ""
			return
		}
		done <- location.Query().Get("code")
	}()

	select {
	case code := <-done:
		r.NotEmpty(code)
	case <-time.After(5 * time.Second):
		t.Fatal("OIDC authorize blocked on the state lock")
	}
}

func TestOIDCDiscoveryAdvertisesConfiguredClientAuthentication(t *testing.T) {
	tests := map[string]struct {
		public bool
		want   []any
	}{
		"confidential": {want: []any{"client_secret_basic", "client_secret_post"}},
		"public":       {public: true, want: []any{"none"}},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			setTestStateFile(t)
			svc := newTestIDPApp(t)
			r.NoError(saveState(appState{Apps: []app{{
				ID:               "app-1",
				Name:             "Greendale",
				Slug:             "greendale",
				Protocol:         "oidc",
				OIDCClientID:     "greendale-client",
				OIDCPublicClient: tc.public,
			}}}))

			rec := httptest.NewRecorder()
			svc.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oidc/greendale/.well-known/openid-configuration", nil))
			r.Equal(http.StatusOK, rec.Code)
			var discovery map[string]any
			r.NoError(json.Unmarshal(rec.Body.Bytes(), &discovery))
			r.Equal(tc.want, discovery["token_endpoint_auth_methods_supported"])
		})
	}
}

func TestOIDCPKCEValidation(t *testing.T) {
	r := require.New(t)
	verifier := "a-long-enough-greendale-community-college-verifier"
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])

	r.NoError(validateAuthorizeRequest(app{
		OIDCClientID:         "greendale-client",
		OIDCPublicClient:     true,
		OIDCRedirectURIs:     []string{"http://localhost/callback"},
		AllowAnyOIDCRedirect: false,
	}, url.Values{
		"response_type":         {"code"},
		"client_id":             {"greendale-client"},
		"redirect_uri":          {"http://localhost/callback"},
		"scope":                 {"openid"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}))
	r.True(validPKCEVerifier(challenge, verifier))
	r.False(validPKCEVerifier(challenge, "chang-cheated"))

	err := validateAuthorizeRequest(app{
		OIDCClientID:         "greendale-client",
		OIDCPublicClient:     true,
		OIDCRedirectURIs:     []string{"http://localhost/callback"},
		AllowAnyOIDCRedirect: false,
	}, url.Values{
		"response_type": {"code"},
		"client_id":     {"greendale-client"},
		"redirect_uri":  {"http://localhost/callback"},
		"scope":         {"openid"},
	})
	r.EqualError(err, "public clients must use PKCE")
}

func TestOIDCRedirectURIValidation(t *testing.T) {
	tests := map[string]struct {
		redirectURI string
		wantError   string
	}{
		"HTTP": {
			redirectURI: "http://localhost/callback",
		},
		"HTTPS": {
			redirectURI: "https://greendale.example/callback?audience=students",
		},
		"malformed": {
			redirectURI: "https://greendale.example/%",
			wantError:   "redirect_uri must be a valid absolute HTTP(S) URL",
		},
		"unsafe scheme": {
			redirectURI: "javascript:alert(1)",
			wantError:   "redirect_uri must be a valid absolute HTTP(S) URL",
		},
		"relative": {
			redirectURI: "/callback",
			wantError:   "redirect_uri must be a valid absolute HTTP(S) URL",
		},
		"fragment": {
			redirectURI: "https://greendale.example/callback#token",
			wantError:   "redirect_uri must be a valid absolute HTTP(S) URL without a fragment",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			err := validateAuthorizeRequest(app{
				OIDCClientID:         "greendale-client",
				AllowAnyOIDCRedirect: true,
			}, url.Values{
				"response_type": {"code"},
				"client_id":     {"greendale-client"},
				"redirect_uri":  {tc.redirectURI},
				"scope":         {"openid"},
			})
			if tc.wantError == "" {
				r.NoError(err)
				return
			}
			r.ErrorContains(err, tc.wantError)
		})
	}
}

func TestUserClaimsHonorScopes(t *testing.T) {
	r := require.New(t)
	state := appState{Groups: []group{{DisplayName: "Study Group", MemberIDs: []string{"troy"}}}}
	configuredApp := app{IncludeGroupsClaim: true}
	troy := user{ID: "troy", GivenName: "Troy", FamilyName: "Barnes", Username: "troy", Email: "troy@greendale.edu"}

	minimal := userClaims(state, configuredApp, troy, "openid")
	r.Equal(map[string]any{"sub": "troy"}, minimal)

	all := userClaims(state, configuredApp, troy, "openid profile email groups")
	r.Equal("Troy Barnes", all["name"])
	r.Equal("troy@greendale.edu", all["email"])
	r.Equal([]string{"Study Group"}, all["groups"])

	withoutConfiguredGroups := userClaims(state, app{}, troy, "openid groups")
	r.NotContains(withoutConfiguredGroups, "groups")

	custom := userClaims(state, app{
		IncludeGroupsClaim: true,
		OIDCClaimMappings: oidcClaimMappings{
			Name: "display_name", GivenName: "first_name", FamilyName: "last_name",
			Username: "login", Email: "mail", Groups: "roles",
		},
	}, troy, "openid profile email groups")
	r.Equal("Troy Barnes", custom["display_name"])
	r.Equal("troy", custom["login"])
	r.Equal("troy@greendale.edu", custom["mail"])
	r.Equal([]string{"Study Group"}, custom["roles"])
	r.NotContains(custom, "preferred_username")
	r.Contains(oidcClaimsSupported(app{OIDCClaimMappings: oidcClaimMappings{Username: "login"}}), "login")
	r.NotContains(oidcClaimsSupported(app{OIDCClaimMappings: oidcClaimMappings{Username: "login"}}), "preferred_username")
}

func TestEffectiveIDPBaseURLOnlyTrustsForwardedProtoWhenConfigured(t *testing.T) {
	tests := map[string]struct {
		trust bool
		want  string
	}{
		"ignored by default": {want: "http://idp.test"},
		"explicitly trusted": {trust: true, want: "https://idp.test"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "http://idp.test/oidc/example/jwks", nil)
			r.Header.Set("X-Forwarded-Proto", "https")
			got := effectiveIDPBaseURL(r, appState{Config: config{TrustForwardedHeaders: tc.trust}})
			require.Equal(t, tc.want, got)
		})
	}
}

func TestOIDCAppUsesGlobalDirectory(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{Users: []user{
		{ID: "troy", GivenName: "Troy", FamilyName: "Barnes", Email: "troy@greendale.edu", Username: "troy", Active: true},
		{ID: "abed", GivenName: "Abed", FamilyName: "Nadir", Email: "abed@greendale.edu", Username: "abed", Active: true},
	}, Apps: []app{{
		ID:               "staging-app",
		Name:             "Portal",
		Slug:             "portal",
		Protocol:         "oidc",
		OIDCClientID:     "client",
		OIDCClientSecret: "secret",
		OIDCRedirectURIs: []string{"http://client.test/callback"},
	}}}))
	svc := newTestIDPApp(t)
	rec := httptest.NewRecorder()

	svc.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oidc/portal/authorize?response_type=code&client_id=client&redirect_uri=http%3A%2F%2Fclient.test%2Fcallback&scope=openid", nil))

	r.Equal(http.StatusOK, rec.Code)
	r.Contains(rec.Body.String(), "Abed Nadir")
	r.Contains(rec.Body.String(), "Troy Barnes")
}

func TestOIDCTokenPrunesExpiredCredentials(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	svc := newTestIDPApp(t)
	r.NoError(saveState(appState{Apps: []app{{
		ID:               "app-1",
		Name:             "Example",
		Slug:             "example",
		Protocol:         "oidc",
		OIDCClientID:     "example-client",
		OIDCClientSecret: "secret",
		OIDCRedirectURIs: []string{"http://client.test/callback"},
	}}}))

	past := time.Now().Add(-time.Minute)
	future := time.Now().Add(time.Minute)
	svc.authCodes["expired-code"] = authCode{ExpiresAt: past}
	svc.authCodes["valid-code"] = authCode{ExpiresAt: future}
	svc.accessTokens["expired-token"] = accessToken{ExpiresAt: past}
	svc.accessTokens["valid-token"] = accessToken{ExpiresAt: future}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"expired-code"},
		"redirect_uri":  {"http://client.test/callback"},
		"client_id":     {"example-client"},
		"client_secret": {"secret"},
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/oidc/example/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	svc.routes().ServeHTTP(rec, req)

	r.Equal(http.StatusBadRequest, rec.Code)
	r.Equal("no-store", rec.Header().Get("Cache-Control"))
	r.Equal("no-cache", rec.Header().Get("Pragma"))
	r.NotContains(svc.authCodes, "expired-code")
	r.Contains(svc.authCodes, "valid-code")
	r.NotContains(svc.accessTokens, "expired-token")
	r.Contains(svc.accessTokens, "valid-token")
}

func TestOIDCAuthorizeLoginHintPreselectsUniqueUser(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	svc := newTestIDPApp(t)
	r.NoError(saveState(appState{
		Users: []user{
			{ID: "usr-alpha", GivenName: "Alpha", FamilyName: "User", Username: "alpha", Email: "alpha@example.test", Active: true},
			{ID: "usr-beta", GivenName: "Beta", FamilyName: "User", Username: "beta", Email: "riley@example.test", Active: true},
		},
		Apps: []app{{
			ID:               "app-1",
			Name:             "Example",
			Slug:             "example",
			Protocol:         "oidc",
			OIDCClientID:     "example-client",
			OIDCRedirectURIs: []string{"http://client.test/callback"},
		}},
	}))

	rec := httptest.NewRecorder()
	svc.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oidc/example/authorize?response_type=code&client_id=example-client&redirect_uri=http%3A%2F%2Fclient.test%2Fcallback&scope=openid&login_hint=RILEY%40EXAMPLE.TEST", nil))

	r.Equal(http.StatusOK, rec.Code)
	body := rec.Body.String()
	r.Contains(body, `value="usr-alpha"`)
	r.Contains(body, `value="usr-beta"`)
	r.Less(strings.Index(body, `value="usr-beta"`), strings.Index(body, `value="usr-alpha"`))
	r.Contains(body, `value="usr-beta" required checked`)
}

func TestChooserRendersScrollableSearchableUserList(t *testing.T) {
	r := require.New(t)
	rec := httptest.NewRecorder()
	renderChooser(rec, chooserData{
		Title:   "SAML sign-in",
		AppName: "Greendale",
		Action:  "/saml/greendale/sso",
		Users: []user{{
			ID:         "usr-troy",
			GivenName:  "Troy",
			FamilyName: "Barnes",
			Username:   "tbarnes",
			Email:      "troy@greendale.edu",
			Active:     true,
		}},
	})

	body := rec.Body.String()
	r.Contains(body, `type="search"`)
	r.Contains(body, `placeholder="Search name, username, or email"`)
	r.Contains(body, `class="user-list"`)
	r.Contains(body, `overflow-y:auto`)
	r.Contains(body, `data-search="Troy Barnes tbarnes troy@greendale.edu"`)
	r.Contains(body, `terms.every`)
	r.Contains(body, `data-no-matches`)
}

func TestIdentifierChooserDoesNotEnumerateUsers(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	svc := newTestIDPApp(t)
	r.NoError(saveState(appState{
		Users: []user{
			{ID: "usr-troy", GivenName: "Troy", FamilyName: "Barnes", Username: "troy", Email: "troy@greendale.edu", Active: true},
			{ID: "usr-abed", GivenName: "Abed", FamilyName: "Nadir", Username: "abed", Email: "abed@greendale.edu", Active: true},
		},
		Apps: []app{{
			ID: "app-1", Name: "Example", Slug: "example", Protocol: "oidc",
			OIDCClientID: "example-client", OIDCRedirectURIs: []string{"http://client.test/callback"},
			ChooserMode: chooserModeIdentifier,
		}},
	}))
	authorizeURL := "/oidc/example/authorize?response_type=code&client_id=example-client&redirect_uri=http%3A%2F%2Fclient.test%2Fcallback&scope=openid"
	getRec := httptest.NewRecorder()

	svc.routes().ServeHTTP(getRec, httptest.NewRequest(http.MethodGet, authorizeURL, nil))

	r.Equal(http.StatusOK, getRec.Code)
	body := getRec.Body.String()
	r.Contains(body, `name="login_identifier"`)
	r.NotContains(body, "Troy Barnes")
	r.NotContains(body, "troy@greendale.edu")
	r.NotContains(body, "Abed Nadir")
	r.NotContains(body, `data-user-option`)

	form := url.Values{
		"response_type":    {"code"},
		"client_id":        {"example-client"},
		"redirect_uri":     {"http://client.test/callback"},
		"scope":            {"openid"},
		"login_identifier": {"TROY@greendale.edu"},
	}
	postReq := httptest.NewRequest(http.MethodPost, "/oidc/example/authorize", strings.NewReader(form.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postRec := httptest.NewRecorder()
	svc.routes().ServeHTTP(postRec, postReq)
	r.Equal(http.StatusFound, postRec.Code)
	r.Contains(postRec.Header().Get("Location"), "code=")

	state, err := loadState()
	r.NoError(err)
	state.Apps[0].Protocol = "saml"
	state.Apps[0].SAMLACSURL = "http://client.test/saml/acs"
	state.Apps[0].SAMLEntityID = "urn:client:test"
	r.NoError(saveState(state))
	samlRec := httptest.NewRecorder()
	svc.routes().ServeHTTP(samlRec, httptest.NewRequest(http.MethodGet, "/saml/example/sso", nil))
	r.Equal(http.StatusOK, samlRec.Code)
	r.Contains(samlRec.Body.String(), `name="login_identifier"`)
	r.NotContains(samlRec.Body.String(), "Troy Barnes")
}

func TestOIDCAuthorizeLoginHintUsesDefaultBehaviorForMultipleMatches(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	svc := newTestIDPApp(t)
	r.NoError(saveState(appState{
		Users: []user{
			{ID: "usr-alpha", GivenName: "Alpha", FamilyName: "User", Username: "alpha", Email: "login@example.test", Active: true},
			{ID: "usr-beta", GivenName: "Beta", FamilyName: "User", Username: "login@example.test", Email: "beta@example.test", Active: true},
		},
		Apps: []app{{
			ID:               "app-1",
			Name:             "Example",
			Slug:             "example",
			Protocol:         "oidc",
			OIDCClientID:     "example-client",
			OIDCRedirectURIs: []string{"http://client.test/callback"},
		}},
	}))

	rec := httptest.NewRecorder()
	svc.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oidc/example/authorize?response_type=code&client_id=example-client&redirect_uri=http%3A%2F%2Fclient.test%2Fcallback&scope=openid&login_hint=login%40example.test", nil))

	r.Equal(http.StatusOK, rec.Code)
	body := rec.Body.String()
	r.Contains(body, `value="usr-alpha"`)
	r.Contains(body, `value="usr-beta"`)
	r.Less(strings.Index(body, `value="usr-alpha"`), strings.Index(body, `value="usr-beta"`))
	r.NotContains(body, "required checked")
}

func TestSAMLSSOLoginHintPreselectsUniqueUser(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	svc := newTestIDPApp(t)
	r.NoError(saveState(appState{
		Users: []user{
			{ID: "usr-jeff", GivenName: "Jeff", FamilyName: "Winger", Username: "jwinger", Email: "jeff@greendale.community", Active: true},
			{ID: "usr-troy", GivenName: "Troy", FamilyName: "Barnes", Username: "troy", Email: "troy@greendale.community", Active: true},
		},
		Apps: []app{{
			ID:       "app-1",
			Name:     "prde",
			Slug:     "prde",
			Protocol: "saml",
		}},
	}))

	rec := httptest.NewRecorder()
	svc.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/saml/prde/sso?login_hint=jeff%40greendale.community", nil))

	r.Equal(http.StatusOK, rec.Code)
	body := rec.Body.String()
	r.Contains(body, `value="usr-jeff"`)
	r.Contains(body, `value="usr-troy"`)
	r.Less(strings.Index(body, `value="usr-jeff"`), strings.Index(body, `value="usr-troy"`))
	r.Contains(body, `value="usr-jeff" required checked`)
}

func TestSAMLSSOLoginHintFromSAMLRequestPreselectsUniqueUser(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	svc := newTestIDPApp(t)
	r.NoError(saveState(appState{
		Users: []user{
			{ID: "usr-jeff", GivenName: "Jeff", FamilyName: "Winger", Username: "jwinger", Email: "jeff@greendale.community", Active: true},
			{ID: "usr-troy", GivenName: "Troy", FamilyName: "Barnes", Username: "troy", Email: "troy@greendale.community", Active: true},
		},
		Apps: []app{{
			ID:       "app-1",
			Name:     "prde",
			Slug:     "prde",
			Protocol: "saml",
		}},
	}))
	samlRequest := encodeRedirectSAMLRequest(t, `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_request-jeff"><saml:Subject><saml:NameID>jeff@greendale.community</saml:NameID></saml:Subject></samlp:AuthnRequest>`)

	rec := httptest.NewRecorder()
	svc.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/saml/prde/sso?SAMLRequest="+url.QueryEscape(samlRequest), nil))

	r.Equal(http.StatusOK, rec.Code)
	body := rec.Body.String()
	r.Contains(body, `value="usr-jeff" required checked`)
	r.Less(strings.Index(body, `value="usr-jeff"`), strings.Index(body, `value="usr-troy"`))
}

func TestSAMLSSOLoginHintFromRelayStatePreselectsUniqueUser(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	svc := newTestIDPApp(t)
	r.NoError(saveState(appState{
		Users: []user{
			{ID: "usr-jeff", GivenName: "Jeff", FamilyName: "Winger", Username: "jwinger", Email: "jeff@greendale.community", Active: true},
			{ID: "usr-troy", GivenName: "Troy", FamilyName: "Barnes", Username: "troy", Email: "troy@greendale.community", Active: true},
		},
		Apps: []app{{
			ID:       "app-1",
			Name:     "prde",
			Slug:     "prde",
			Protocol: "saml",
		}},
	}))
	relayState := "https://rp.example.test/authorize?client_id=example&login_hint=jeff%40greendale.community&state=opaque"

	rec := httptest.NewRecorder()
	svc.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/saml/prde/sso?RelayState="+url.QueryEscape(relayState), nil))

	r.Equal(http.StatusOK, rec.Code)
	body := rec.Body.String()
	r.Contains(body, `value="usr-jeff" required checked`)
	r.Less(strings.Index(body, `value="usr-jeff"`), strings.Index(body, `value="usr-troy"`))
}

func TestSAMLSSOPostBindingLoginHintPreselectsUniqueUser(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	svc := newTestIDPApp(t)
	r.NoError(saveState(appState{
		Users: []user{
			{ID: "usr-jeff", GivenName: "Jeff", FamilyName: "Winger", Username: "jwinger", Email: "jeff@greendale.community", Active: true},
			{ID: "usr-troy", GivenName: "Troy", FamilyName: "Barnes", Username: "troy", Email: "troy@greendale.community", Active: true},
		},
		Apps: []app{{
			ID:       "app-1",
			Name:     "prde",
			Slug:     "prde",
			Protocol: "saml",
		}},
	}))
	form := url.Values{
		"SAMLRequest": {encodeRedirectSAMLRequest(t, `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_request-jeff"><samlp:Extensions><LoginHint>jeff@greendale.community</LoginHint></samlp:Extensions></samlp:AuthnRequest>`)},
		"RelayState":  {"relay"},
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/saml/prde/sso", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	svc.routes().ServeHTTP(rec, req)

	r.Equal(http.StatusOK, rec.Code)
	body := rec.Body.String()
	r.Contains(body, `value="usr-jeff" required checked`)
	r.Less(strings.Index(body, `value="usr-jeff"`), strings.Index(body, `value="usr-troy"`))
}

func TestSAMLResponseMatchesAuthnRequest(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	svc := newTestIDPApp(t)
	state := appState{
		Config: config{IDPBaseURL: "http://idp.test"},
		Users: []user{{
			ID:         "usr-troy",
			GivenName:  "Troy",
			FamilyName: "Barnes",
			Email:      "troy@greendale.edu",
			Username:   "tbarnes",
			Active:     true,
		}},
		Apps: []app{{
			ID:                     "app-1",
			Name:                   "Greendale",
			Slug:                   "greendale",
			Protocol:               "saml",
			SAMLEntityID:           "urn:greendale:sp",
			SAMLACSURL:             "https://sp.greendale.test/acs",
			SAMLNameIDField:        defaultSAMLNameIDField,
			SAMLNameIDFormat:       samlNameIDFormatForField(defaultSAMLNameIDField),
			SAMLEmailAttributeName: defaultSAMLEmailAttributeName,
		}},
	}
	r.NoError(saveState(state))
	authnRequest := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_request-troy" Destination="http://idp.test/saml/greendale/sso" AssertionConsumerServiceURL="https://sp.greendale.test/acs" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"><saml:Issuer>urn:greendale:sp</saml:Issuer></samlp:AuthnRequest>`
	tests := map[string]struct {
		requestXML string
		signature  url.Values
	}{
		"unsigned": {requestXML: authnRequest},
		"redirect signature is ignored": {
			requestXML: authnRequest,
			signature:  url.Values{"SigAlg": {"rsa-sha256"}, "Signature": {"not-validated"}},
		},
		"embedded signature is ignored": {
			requestXML: strings.Replace(authnRequest, "</samlp:AuthnRequest>", `<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"></ds:Signature></samlp:AuthnRequest>`, 1),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			form := url.Values{
				"SAMLRequest": {base64.StdEncoding.EncodeToString([]byte(tc.requestXML))},
				"RelayState":  {"study-room-f"},
				"user_id":     {"usr-troy"},
			}
			for key, values := range tc.signature {
				form[key] = values
			}
			req := httptest.NewRequest(http.MethodPost, "/saml/greendale/sso", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()
			svc.routes().ServeHTTP(rec, req)

			r.Equal(http.StatusOK, rec.Code)
			r.Contains(rec.Body.String(), `action="https://sp.greendale.test/acs"`)
			encodedResponse := hiddenInputValue(rec.Body.String(), "SAMLResponse")
			r.NotEmpty(encodedResponse)
			responseXML, err := base64.StdEncoding.DecodeString(encodedResponse)
			r.NoError(err)
			doc := etree.NewDocument()
			r.NoError(doc.ReadFromBytes(responseXML))
			r.Equal("https://sp.greendale.test/acs", doc.Root().SelectAttrValue("Destination", ""))
			r.Equal("_request-troy", doc.Root().SelectAttrValue("InResponseTo", ""))
			subjectConfirmation := findElementByLocalName(doc.Root(), "SubjectConfirmationData")
			r.NotNil(subjectConfirmation)
			r.Equal("https://sp.greendale.test/acs", subjectConfirmation.SelectAttrValue("Recipient", ""))
			r.Equal("_request-troy", subjectConfirmation.SelectAttrValue("InResponseTo", ""))
		})
	}
}

func TestSAMLAuthnRequestValidation(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	svc := newTestIDPApp(t)
	r.NoError(saveState(appState{
		Config: config{IDPBaseURL: "http://idp.test"},
		Users:  []user{{ID: "usr-abed", GivenName: "Abed", FamilyName: "Nadir", Email: "abed@greendale.edu", Username: "anadir", Active: true}},
		Apps: []app{{
			ID:                     "app-1",
			Name:                   "Greendale",
			Slug:                   "greendale",
			Protocol:               "saml",
			SAMLEntityID:           "urn:greendale:sp",
			SAMLACSURL:             "https://sp.greendale.test/acs",
			SAMLNameIDField:        defaultSAMLNameIDField,
			SAMLNameIDFormat:       samlNameIDFormatForField(defaultSAMLNameIDField),
			SAMLEmailAttributeName: defaultSAMLEmailAttributeName,
		}},
	}))

	validRequest := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_request-abed" Destination="http://idp.test/saml/greendale/sso" AssertionConsumerServiceURL="https://sp.greendale.test/acs" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"><saml:Issuer>urn:greendale:sp</saml:Issuer></samlp:AuthnRequest>`
	tests := map[string]struct {
		requestXML string
		values     url.Values
		want       string
	}{
		"custom ACS override": {
			values: url.Values{"acs_url": {"https://evil.example/acs"}},
			want:   "ACS URL does not match",
		},
		"request ACS mismatch": {
			requestXML: strings.Replace(validRequest, "https://sp.greendale.test/acs", "https://evil.example/acs", 1),
			want:       "ACS URL does not match",
		},
		"issuer mismatch": {
			requestXML: strings.Replace(validRequest, "urn:greendale:sp", "urn:city-college:sp", 1),
			want:       "issuer does not match",
		},
		"destination mismatch": {
			requestXML: strings.Replace(validRequest, "http://idp.test/saml/greendale/sso", "https://evil.example/sso", 1),
			want:       "destination does not match",
		},
		"redirect-signed destination mismatch": {
			requestXML: strings.Replace(validRequest, "http://idp.test/saml/greendale/sso", "https://evil.example/sso", 1),
			values:     url.Values{"SigAlg": {"rsa-sha256"}, "Signature": {"not-validated"}},
			want:       "destination does not match",
		},
		"response binding mismatch": {
			requestXML: strings.Replace(validRequest, samlHTTPPostBinding, "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", 1),
			want:       "HTTP-POST response binding",
		},
		"missing ID": {
			requestXML: strings.Replace(validRequest, ` ID="_request-abed"`, "", 1),
			want:       "ID is required",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			values := url.Values{"user_id": {"usr-abed"}}
			for key, entries := range tc.values {
				values[key] = append([]string(nil), entries...)
			}
			if tc.requestXML != "" {
				values.Set("SAMLRequest", base64.StdEncoding.EncodeToString([]byte(tc.requestXML)))
			}
			req := httptest.NewRequest(http.MethodPost, "/saml/greendale/sso", strings.NewReader(values.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()
			svc.routes().ServeHTTP(rec, req)

			r.Equal(http.StatusBadRequest, rec.Code)
			r.Contains(rec.Body.String(), tc.want)
		})
	}
}

func TestParseSAMLRequestRejectsOversizedInflatedPayload(t *testing.T) {
	r := require.New(t)
	encodedRequest := encodeRedirectSAMLRequest(t, strings.Repeat("A", maxSAMLRequestBytes+1))

	_, err := parseSAMLRequestDocument(encodedRequest)

	r.ErrorIs(err, errSAMLRequestTooLarge)
	r.ErrorContains(err, "inflated SAMLRequest exceeds 1048576 bytes")
}

func TestSignedSAMLResponseUsesSharedGroups(t *testing.T) {
	r := require.New(t)
	svc := newTestIDPApp(t)
	state := appState{
		Config: config{IDPBaseURL: "http://idp.test"},
		Users: []user{{
			ID:       "usr-1",
			Email:    "riley@example.test",
			Username: "riley",
			Active:   true,
		}},
		Groups: []group{{
			ID:          "grp-1",
			DisplayName: "Engineering",
			MemberIDs:   []string{"usr-1"},
		}},
		Apps: []app{{
			ID:                     "app-1",
			Name:                   "Example",
			Slug:                   "example",
			Protocol:               "saml",
			SAMLACSURL:             "http://client.test/saml/acs",
			SAMLEntityID:           "urn:client:test",
			SAMLNameIDField:        defaultSAMLNameIDField,
			SAMLNameIDFormat:       samlNameIDFormatForField(defaultSAMLNameIDField),
			SAMLEmailAttributeName: defaultSAMLEmailAttributeName,
			IncludeGroupsClaim:     true,
		}},
	}

	response, err := svc.buildSignedSAMLResponse(state, state.Config.IDPBaseURL, state.Apps[0], state.Users[0], samlResponseContext{ACSURL: state.Apps[0].SAMLACSURL})
	r.NoError(err)
	r.Contains(response, "<ds:Signature")
	r.Contains(response, `Name="groups"`)
	r.Contains(response, "Engineering")
	r.Contains(response, `Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"`)

	doc := etree.NewDocument()
	r.NoError(doc.ReadFromString(response))
	assertion := findElementByLocalName(doc.Root(), "Assertion")
	r.NotNil(assertion)
	children := assertion.ChildElements()
	r.GreaterOrEqual(len(children), 2)
	r.Equal("Issuer", elementLocalName(children[0]))
	r.Equal("Signature", elementLocalName(children[1]))
	cert, err := x509.ParseCertificate(svc.certDER)
	r.NoError(err)
	validator := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{cert},
	})
	_, err = validator.Validate(assertion)
	r.NoError(err)
}

func TestSignedSAMLResponseUsesConfiguredNameIDField(t *testing.T) {
	r := require.New(t)
	svc := newTestIDPApp(t)
	state := appState{
		Config: config{IDPBaseURL: "http://idp.test"},
		Users: []user{{
			ID:         "usr-1",
			GivenName:  "Troy",
			FamilyName: "Barnes",
			Email:      "troy@example.test",
			Username:   "tbarnes",
			Active:     true,
		}},
		Apps: []app{{
			ID:                     "app-1",
			Name:                   "Example",
			Slug:                   "example",
			Protocol:               "saml",
			SAMLACSURL:             "http://client.test/saml/acs",
			SAMLEntityID:           "urn:client:test",
			SAMLNameIDField:        "username",
			SAMLNameIDFormat:       samlNameIDFormatForField("username"),
			SAMLEmailAttributeName: defaultSAMLEmailAttributeName,
			SAMLAttributeMappings: samlAttributeMappings{
				GivenName: "given_name", FamilyName: "family_name", Username: "login",
				Email: "mail", Groups: "roles",
			},
		}},
	}

	response, err := svc.buildSignedSAMLResponse(state, state.Config.IDPBaseURL, state.Apps[0], state.Users[0], samlResponseContext{ACSURL: state.Apps[0].SAMLACSURL})
	r.NoError(err)
	r.Contains(response, `<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">tbarnes</saml:NameID>`)
	r.Contains(response, `<saml:Attribute Name="mail"><saml:AttributeValue>troy@example.test</saml:AttributeValue></saml:Attribute>`)
	r.Contains(response, `<saml:Attribute Name="login"><saml:AttributeValue>tbarnes</saml:AttributeValue></saml:Attribute>`)
	r.NotContains(response, `Name="username"`)
}

func newTestIDPApp(t *testing.T) *webApp {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	certDER, err := selfSignedCert(key)
	require.NoError(t, err)
	return &webApp{
		signingKey:   key,
		certDER:      certDER,
		authCodes:    make(map[string]authCode),
		accessTokens: make(map[string]accessToken),
	}
}

func encodeRedirectSAMLRequest(t *testing.T, value string) string {
	t.Helper()
	var compressed bytes.Buffer
	writer, err := flate.NewWriter(&compressed, flate.DefaultCompression)
	require.NoError(t, err)
	_, err = writer.Write([]byte(value))
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	return base64.StdEncoding.EncodeToString(compressed.Bytes())
}
