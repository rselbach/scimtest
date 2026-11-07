package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEnvironmentBadgeCountsAllEnvironments(t *testing.T) {
	environments := []app{
		{ID: "study-app", Name: "Study App", Slug: "study-app", Protocol: "oidc"},
		{ID: "library-app", Name: "Library App", Slug: "library-app", Protocol: "saml"},
	}
	for name, tc := range map[string]struct {
		apps []app
		want string
	}{
		"none":     {want: "0"},
		"one":      {apps: environments[:1], want: "1"},
		"multiple": {apps: environments, want: "2"},
	} {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			setTestStateFile(t)
			r.NoError(saveState(appState{Apps: tc.apps}))
			appService := newTestIDPApp(t)
			handler := appService.routes()

			selections := []string{""}
			for _, environment := range tc.apps {
				selections = append(selections, environment.ID)
			}
			for _, environmentID := range selections {
				for page, path := range map[string]string{
					"users":   "/?tab=users",
					"groups":  "/?tab=groups",
					"apps":    "/?tab=apps",
					"traffic": "/traffic?",
				} {
					t.Run(page+"/"+environmentID, func(t *testing.T) {
						r := require.New(t)
						rec := httptest.NewRecorder()
						handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path+"&environment="+environmentID, nil))
						if rec.Code == http.StatusSeeOther {
							path = rec.Header().Get("Location")
							rec = httptest.NewRecorder()
							handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
						}
						r.Equal(http.StatusOK, rec.Code)
						r.Regexp(`Environments\s*<span class="badge">`+tc.want+`</span>`, rec.Body.String())
					})
				}
			}
		})
	}
}

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
