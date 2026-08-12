package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	scimtestclient "github.com/rselbach/scimtest/client"
	"github.com/stretchr/testify/require"
)

func TestDesktopRequiresGitHubAccountBeforeServingApp(t *testing.T) {
	r := require.New(t)
	app := newTestIDPApp(t)
	app.requireGitHubAccount = true
	app.tunnelSupported = true

	page := httptest.NewRecorder()
	app.routes().ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/", nil))
	r.Equal(http.StatusOK, page.Code)
	r.Contains(page.Body.String(), "Sign in to use scimtest")
	r.Contains(page.Body.String(), "Connecting securely to GitHub")

	mutation := httptest.NewRecorder()
	app.routes().ServeHTTP(mutation, httptest.NewRequest(http.MethodPost, "/users/save", nil))
	r.Equal(http.StatusUnauthorized, mutation.Code)
	r.Contains(mutation.Body.String(), "GitHub account sign-in is required")

	idp := httptest.NewRecorder()
	app.routes().ServeHTTP(idp, httptest.NewRequest(http.MethodGet, "/oidc/example/jwks", nil))
	r.Equal(http.StatusUnauthorized, idp.Code)

	asset := httptest.NewRecorder()
	app.routes().ServeHTTP(asset, httptest.NewRequest(http.MethodGet, "/assets/app.css", nil))
	r.Equal(http.StatusOK, asset.Code)
}

func TestDesktopRendersGitHubEnrollmentInApp(t *testing.T) {
	r := require.New(t)
	app := newTestIDPApp(t)
	app.requireGitHubAccount = true
	app.tunnelSupported = true
	app.tunnelEnrollmentURL = "https://admin.example.test/enroll?code=study-group"
	app.tunnelEnrollmentCode = "study-group"

	page := httptest.NewRecorder()
	app.routes().ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/", nil))

	r.Equal(http.StatusOK, page.Code)
	r.Contains(page.Body.String(), "Continue with GitHub")
	r.Contains(page.Body.String(), app.tunnelEnrollmentURL)
	r.Contains(page.Body.String(), "study-group")
}

func TestDesktopServesAppAfterAuthenticatedTunnel(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{Apps: []app{{
		ID: "app-1", Name: "Greendale", Slug: "greendale", Protocol: "oidc",
	}}}))
	app := newTestIDPApp(t)
	app.requireGitHubAccount = true
	app.tunnel = &activeTunnel{
		PathPrefix:   "/study-group",
		PublicURL:    "https://scimtest.example.test/study-group",
		GitHubUserID: 42,
		GitHubLogin:  "pierce",
		Tunnel:       &fakeTunnel{},
	}

	page := httptest.NewRecorder()
	app.routes().ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/?tab=apps", nil))

	r.Equal(http.StatusOK, page.Code)
	r.Contains(page.Body.String(), "Environments")
	r.Contains(page.Body.String(), "@pierce")
	r.NotContains(page.Body.String(), "Sign in to use scimtest")
}

func TestDesktopAcceptsEnrollmentProofFromOlderTunnelServer(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	app := newTestIDPApp(t)
	app.requireGitHubAccount = true
	app.adminURL = "http://127.0.0.1:8080"
	opened := ""
	app.browserOpen = func(value string) error {
		opened = value
		return nil
	}
	app.tunnelStart = func(context.Context, scimtestclient.Config) (*startedTunnel, error) {
		return &startedTunnel{
			PublicURL: "https://scimtest.example.test/study-group",
			Tunnel:    &fakeTunnel{},
		}, nil
	}

	app.startAutomaticTunnel(tunnelApplicationIdentity{profileID: "0123456789abcdef0123456789abcdef"})

	r.True(app.githubAccountConnected())
	r.Empty(app.authenticatedGitHubLogin())
	r.Equal(app.adminURL, opened)
}
