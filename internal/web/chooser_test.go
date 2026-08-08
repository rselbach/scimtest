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
	// A successful sign-in sets the remember cookie.
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
		if c.Name == chooserCookieName("example") {
			rememberCookie = c
		}
	}
	r.NotNil(rememberCookie)
	r.Equal("usr-1", rememberCookie.Value)

	// The next chooser render pre-checks the remembered user.
	getReq := httptest.NewRequest(http.MethodGet, "/oidc/example/authorize?response_type=code&client_id=example-client&redirect_uri=http://client.test/callback&scope=openid", nil)
	getReq.AddCookie(rememberCookie)
	getRec := httptest.NewRecorder()
	svc.routes().ServeHTTP(getRec, getReq)
	r.Equal(http.StatusOK, getRec.Code)
	r.Contains(getRec.Body.String(), `value="usr-1" required checked`)
}
