package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStaleEnvironmentReferenceDoesNotRewriteOtherEnvironments(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{
		Users: []user{{ID: "troy", GivenName: "Troy", FamilyName: "Barnes", Email: "troy@greendale.edu", Username: "troy", Active: true}},
		Apps: []app{
			{ID: "study-app", Name: "Study App", Slug: "study-app", Protocol: "oidc"},
			{ID: "library-app", Name: "Library App", Slug: "library-app", Protocol: "saml"},
		},
	}))
	appService := newTestIDPApp(t)

	form := url.Values{
		"environment": {"deleted-app"},
		"given_name":  {"Abed"},
		"email":       {"abed@greendale.edu"},
		"username":    {"abed"},
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/users/save", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	appService.routes().ServeHTTP(rec, req)

	r.Equal(http.StatusSeeOther, rec.Code)

	state, err := loadState()
	r.NoError(err)
	r.Len(state.Apps, 2)
	for _, environmentID := range []string{"study-app", "library-app"} {
		environment, err := loadStateForApp(environmentID)
		r.NoError(err)
		r.Len(environment.Users, 1, "environment %s directory must be untouched", environmentID)
		r.Equal("Troy", environment.Users[0].GivenName)
	}
}

func TestStaleEnvironmentLinkRedirectsToDefaultView(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{
		Apps: []app{{ID: "study-app", Name: "Study App", Slug: "study-app", Protocol: "oidc"}},
	}))
	appService := newTestIDPApp(t)

	rec := httptest.NewRecorder()
	appService.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/?tab=users&environment=deleted-app", nil))

	r.Equal(http.StatusSeeOther, rec.Code)
	r.NotContains(rec.Header().Get("Location"), "deleted-app")
}
