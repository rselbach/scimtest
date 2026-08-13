package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	scimtestclient "github.com/rselbach/scimtest/client"
	"github.com/stretchr/testify/require"
)

type logoutWaitTunnel struct {
	once   sync.Once
	done   chan error
	waited chan struct{}
}

func (t *logoutWaitTunnel) Close() error {
	t.once.Do(func() { t.done <- nil })
	return nil
}

func (t *logoutWaitTunnel) Wait() error {
	err := <-t.done
	close(t.waited)
	return err
}

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
	opened := ""
	app.browserOpen = func(value string) error {
		opened = value
		return nil
	}
	app.handleTunnelEnrollmentRequired(scimtestclient.Enrollment{
		URL:               "https://admin.example.test/enroll?code=study-group",
		BrowserHandoffURL: "https://admin.example.test/enroll/browser?handoff=one-use",
		VerificationCode:  "study-group",
	})
	r.Empty(opened)

	page := httptest.NewRecorder()
	app.routes().ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/", nil))

	r.Equal(http.StatusOK, page.Code)
	r.Contains(page.Body.String(), "Continue with GitHub")
	r.Contains(page.Body.String(), `action="/desktop/auth/start"`)
	r.Contains(page.Body.String(), "opens in your default browser")
	r.NotContains(page.Body.String(), "Confirm code")

	start := httptest.NewRecorder()
	app.routes().ServeHTTP(start, httptest.NewRequest(http.MethodPost, "/desktop/auth/start", nil))
	r.Equal(http.StatusSeeOther, start.Code)
	r.Equal("/", start.Header().Get("Location"))
	r.Equal("https://admin.example.test/enroll/browser?handoff=one-use", opened)
}

func TestDesktopGitHubAuthorizationFallsBackForOlderServer(t *testing.T) {
	r := require.New(t)
	app := newTestIDPApp(t)
	app.requireGitHubAccount = true
	app.tunnelSupported = true
	opened := ""
	app.browserOpen = func(value string) error {
		opened = value
		return nil
	}
	app.handleTunnelEnrollmentRequired(scimtestclient.Enrollment{
		URL:              "https://admin.example.test/enroll?code=study-group",
		VerificationCode: "study-group",
	})

	response := httptest.NewRecorder()
	app.routes().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/desktop/auth/start", nil))
	r.Equal(http.StatusSeeOther, response.Code)
	r.Equal("https://admin.example.test/enroll?code=study-group&presentation=desktop", opened)
}

func TestDesktopGitHubAuthorizationRequiresPendingEnrollment(t *testing.T) {
	r := require.New(t)
	app := newTestIDPApp(t)
	app.requireGitHubAccount = true
	app.tunnelSupported = true
	app.browserOpen = func(string) error {
		r.Fail("browser opener must not run without a pending enrollment")
		return nil
	}

	response := httptest.NewRecorder()
	app.routes().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/desktop/auth/start", nil))
	r.Equal(http.StatusConflict, response.Code)
	r.Contains(response.Body.String(), "GitHub authorization is not ready")
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
	r.Contains(page.Body.String(), "Signed in as")
	r.Contains(page.Body.String(), "@pierce")
	r.Contains(page.Body.String(), `action="/desktop/auth/logout"`)
	r.Contains(page.Body.String(), ">Log out</button>")
	r.NotContains(page.Body.String(), "Sign in to use scimtest")

	traffic := httptest.NewRecorder()
	app.routes().ServeHTTP(traffic, httptest.NewRequest(http.MethodGet, "/traffic?environment=app-1", nil))
	r.Equal(http.StatusOK, traffic.Code)
	r.Contains(traffic.Body.String(), "Signed in as")
	r.Contains(traffic.Body.String(), "@pierce")
}

func TestDesktopAcceptsEnrollmentProofFromOlderTunnelServer(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{Apps: []app{{
		ID: "app-1", Name: "Greendale", Slug: "greendale", Protocol: "oidc",
	}}}))
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
	r.Empty(app.githubAccountView().Login)
	r.Equal(app.adminURL, opened)

	page := httptest.NewRecorder()
	app.routes().ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/?tab=apps", nil))
	r.Equal(http.StatusOK, page.Code)
	r.Contains(page.Body.String(), "Signed in with")
	r.Contains(page.Body.String(), "GitHub")
	r.NotContains(page.Body.String(), "GitHub linked")
	r.Contains(page.Body.String(), ">Log out</button>")
}

func TestDesktopLogoutRotatesInstallationIdentityAndReturnsToAccountGate(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{}))
	oldID, err := ensureTunnelInstanceID()
	r.NoError(err)
	oldKey, err := ensureTunnelInstanceKey()
	r.NoError(err)

	oldProfileID, oldRequired := tunnelApplicationProfileID, tunnelReleaseProfileRequired
	tunnelApplicationProfileID = strings.Repeat("a", 32)
	tunnelReleaseProfileRequired = "true"
	t.Cleanup(func() {
		tunnelApplicationProfileID = oldProfileID
		tunnelReleaseProfileRequired = oldRequired
	})

	oldTunnel := &logoutWaitTunnel{done: make(chan error, 1), waited: make(chan struct{})}
	started := make(chan scimtestclient.Config, 1)
	app := newTestIDPApp(t)
	app.requireGitHubAccount = true
	app.tunnelSupported = true
	app.tunnel = &activeTunnel{
		PathPrefix:   "/study-group",
		PublicURL:    "https://scimtest.example.test/study-group",
		GitHubUserID: 42,
		GitHubLogin:  "pierce",
		Tunnel:       oldTunnel,
	}
	go app.watchAutomaticTunnel(app.tunnel)
	app.tunnelStart = func(ctx context.Context, cfg scimtestclient.Config) (*startedTunnel, error) {
		started <- cfg
		<-ctx.Done()
		return nil, ctx.Err()
	}
	t.Cleanup(func() { r.NoError(app.closeAutomaticTunnel()) })

	response := httptest.NewRecorder()
	app.routes().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/desktop/auth/logout", nil))
	r.Equal(http.StatusSeeOther, response.Code)
	r.Equal("/", response.Header().Get("Location"))
	r.False(app.githubAccountConnected())
	select {
	case <-oldTunnel.waited:
	case <-time.After(time.Second):
		r.FailNow("signed-out tunnel watcher did not stop")
	}
	r.Empty(app.tunnelError())

	var newConfig scimtestclient.Config
	select {
	case newConfig = <-started:
	case <-time.After(2 * time.Second):
		r.FailNow("fresh tunnel enrollment did not start")
	}
	r.NotEqual(oldID, newConfig.InstanceID)
	r.NotEqual(oldKey, newConfig.InstancePrivateKey)
	savedID, err := ensureTunnelInstanceID()
	r.NoError(err)
	r.Equal(newConfig.InstanceID, savedID)
	savedKey, err := ensureTunnelInstanceKey()
	r.NoError(err)
	r.Equal(newConfig.InstancePrivateKey, savedKey)

	page := httptest.NewRecorder()
	app.routes().ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/", nil))
	r.Equal(http.StatusOK, page.Code)
	r.Contains(page.Body.String(), "Sign in to use scimtest")
	r.NotContains(page.Body.String(), "Signed in as")
}

func TestDesktopLogoutRejectsGetAndCrossOriginPost(t *testing.T) {
	r := require.New(t)
	tunnel := &fakeTunnel{}
	app := newTestIDPApp(t)
	app.requireGitHubAccount = true
	app.tunnel = &activeTunnel{
		GitHubUserID: 42,
		GitHubLogin:  "pierce",
		Tunnel:       tunnel,
	}

	getResponse := httptest.NewRecorder()
	app.routes().ServeHTTP(getResponse, httptest.NewRequest(http.MethodGet, "/desktop/auth/logout", nil))
	r.Equal(http.StatusMethodNotAllowed, getResponse.Code)

	crossOriginRequest := httptest.NewRequest(http.MethodPost, "/desktop/auth/logout", nil)
	crossOriginRequest.Header.Set("Origin", "https://evil.example")
	crossOriginRequest.Header.Set("Sec-Fetch-Site", "cross-site")
	crossOriginResponse := httptest.NewRecorder()
	app.routes().ServeHTTP(crossOriginResponse, crossOriginRequest)
	r.Equal(http.StatusForbidden, crossOriginResponse.Code)
	r.False(tunnel.closed)
}
