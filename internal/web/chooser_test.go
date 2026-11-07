package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func oidcChooserTestApp(t *testing.T) *webApp {
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

func TestAuthorizeUserIDOnGETCompletesWithoutChooser(t *testing.T) {
	r := require.New(t)
	svc := oidcChooserTestApp(t)
	query := url.Values{
		"response_type": {"code"},
		"client_id":     {"example-client"},
		"redirect_uri":  {"http://client.test/callback"},
		"scope":         {"openid"},
		"user_id":       {"usr-1"},
	}
	rec := httptest.NewRecorder()
	svc.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oidc/example/authorize?"+query.Encode(), nil))
	r.Equal(http.StatusFound, rec.Code)
	location, err := url.Parse(rec.Header().Get("Location"))
	r.NoError(err)
	r.NotEmpty(location.Query().Get("code"))
}

func TestAuthorizeDenyReturnsAccessDenied(t *testing.T) {
	r := require.New(t)
	svc := oidcChooserTestApp(t)
	query := url.Values{
		"response_type": {"code"},
		"client_id":     {"example-client"},
		"redirect_uri":  {"http://client.test/callback"},
		"scope":         {"openid"},
		"state":         {"xyz"},
		"deny":          {"1"},
	}
	rec := httptest.NewRecorder()
	svc.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oidc/example/authorize?"+query.Encode(), nil))
	r.Equal(http.StatusFound, rec.Code)
	location, err := url.Parse(rec.Header().Get("Location"))
	r.NoError(err)
	r.Equal("access_denied", location.Query().Get("error"))
	r.Equal("xyz", location.Query().Get("state"))
}

func TestChooserRemembersLastUser(t *testing.T) {
	r := require.New(t)
	svc := oidcChooserTestApp(t)
	// A successful sign-in sets the cookie that names its IdP session.
	form := url.Values{
		"response_type": {"code"},
		"client_id":     {"example-client"},
		"redirect_uri":  {"http://client.test/callback"},
		"scope":         {"openid"},
		"user_id":       {"usr-1"},
	}
	postRec := httptest.NewRecorder()
	postReq := httptest.NewRequest(http.MethodPost, "/oidc/example/authorize", strings.NewReader(form.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	svc.routes().ServeHTTP(postRec, postReq)
	r.Equal(http.StatusFound, postRec.Code)

	var rememberCookie *http.Cookie
	for _, c := range postRec.Result().Cookies() {
		if c.Name == signInCookieName("example") {
			rememberCookie = c
		}
	}
	r.NotNil(rememberCookie)
	session, live := svc.liveIdPSession("example", rememberCookie.Value)
	r.True(live)
	r.Equal("usr-1", session.SignIn.UserID)

	// The next chooser render pre-checks the remembered user.
	getReq := httptest.NewRequest(http.MethodGet, "/oidc/example/authorize?response_type=code&client_id=example-client&redirect_uri=http://client.test/callback&scope=openid", nil)
	getReq.AddCookie(rememberCookie)
	getRec := httptest.NewRecorder()
	svc.routes().ServeHTTP(getRec, getReq)
	r.Equal(http.StatusOK, getRec.Code)
	r.Contains(getRec.Body.String(), `value="usr-1" required checked`)
}

func TestChooserContinueIsDefaultSubmitter(t *testing.T) {
	for mode, data := range map[string]chooserData{
		"list":       {Users: []user{{ID: "usr-troy", Username: "tbarnes", Active: true}}},
		"identifier": {IdentifierOnly: true},
	} {
		t.Run(mode, func(t *testing.T) {
			for name, session := range map[string]*chooserSession{
				"without session": nil,
				"with session":    {User: "Troy Barnes", Strength: "Password", Age: "1h"},
			} {
				t.Run(name, func(t *testing.T) {
					data.Session = session
					data.Strengths = authnStrengths
					data.Hidden = map[string][]string{"state": {"study&group", "greendale"}}
					rec := httptest.NewRecorder()
					renderChooser(rec, data)
					form := chooserSubmitForm(t, rec.Body.String(), "Continue")
					require.Equal(t, []string{"study&group", "greendale"}, form["state"])
					require.Empty(t, form.Get("continue_session"))
					require.Empty(t, form.Get("deny"))
					if session != nil {
						reuse := chooserSubmitForm(t, rec.Body.String(), "Reuse session")
						require.Equal(t, form["state"], reuse["state"])
						require.Equal(t, "1", reuse.Get("continue_session"))
					}
				})
			}
		})
	}
}
