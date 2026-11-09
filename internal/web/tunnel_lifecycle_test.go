package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	scimtestclient "github.com/rselbach/scimtest/client"
	"github.com/stretchr/testify/require"
)

func TestReplacedTunnelCallbacksCannotChangeCurrentConnection(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{}))
	configs := make(chan scimtestclient.Config, 2)
	app := &webApp{
		localPort: 8080,
		noOpen:    true,
		tunnelStart: func(_ context.Context, cfg scimtestclient.Config) (*startedTunnel, error) {
			configs <- cfg
			return &startedTunnel{PublicURL: "https://scimtest.example.test/study-group", Tunnel: &fakeTunnel{}}, nil
		},
	}
	identity := tunnelApplicationIdentity{profileID: strings.Repeat("a", 32)}
	app.startAutomaticTunnel(identity)
	old := <-configs
	r.NoError(app.logoutGitHubAccount(identity))
	select {
	case <-configs:
	case <-time.After(time.Second):
		t.Fatal("replacement tunnel did not start")
	}
	r.Eventually(app.githubAccountConnected, time.Second, time.Millisecond)
	t.Cleanup(func() { r.NoError(app.closeAutomaticTunnel()) })

	old.OnRegistered(scimtestclient.Registration{PublicURL: "https://scimtest.example.test/old"})
	old.OnRegistered(scimtestclient.Registration{PublicURL: "invalid"})
	old.OnEnrollmentRequired(scimtestclient.Enrollment{URL: "https://scimtest.example.test/old-enrollment"})
	r.Equal("https://scimtest.example.test/study-group", app.tunnelPublicURL())
	r.Equal("connected", app.desktopAuthView().State)
	r.Equal("connected", app.tunnelState())
	r.Empty(app.tunnelEnrollmentURLValue())
	r.Empty(app.tunnelError())
}

func TestShutdownRemainsTerminalWhenSignOutFinishes(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{}))
	app := &webApp{}
	app.mu.Lock()
	finished := make(chan error, 1)
	go func() { finished <- app.logoutGitHubAccount(tunnelApplicationIdentity{}) }()
	func() {
		defer app.mu.Unlock()
		r.Eventually(func() bool {
			app.tunnel.mu.Lock()
			defer app.tunnel.mu.Unlock()
			return app.tunnel.mode == tunnelResetting
		}, time.Second, time.Millisecond)
		r.NoError(app.closeAutomaticTunnel())
	}()
	select {
	case err := <-finished:
		r.NoError(err)
	case <-time.After(time.Second):
		t.Fatal("sign-out did not finish")
	}
	r.ErrorContains(app.logoutGitHubAccount(tunnelApplicationIdentity{}), "shutting down")
	r.False(app.tunnelRetryAvailable())
	r.Empty(app.tunnelPublicURL())
}

func TestTunnelAPIDoesNotOfferRetryWhileStartingOrClosed(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{}))
	started := make(chan struct{})
	app := &webApp{localPort: 8080}
	app.tunnelStart = func(ctx context.Context, _ scimtestclient.Config) (*startedTunnel, error) {
		app.setTunnelError("waiting for Greendale")
		close(started)
		<-ctx.Done()
		return nil, errors.New("connection stopped")
	}
	finished := make(chan struct{})
	go func() {
		app.startAutomaticTunnel(tunnelApplicationIdentity{profileID: strings.Repeat("a", 32)})
		close(finished)
	}()
	<-started
	t.Cleanup(func() { r.NoError(app.closeAutomaticTunnel()) })
	check := func() {
		rec := httptest.NewRecorder()
		app.handleAPITunnel(rec, nil)
		var response struct {
			RetryAvailable bool `json:"retry_available"`
		}
		r.NoError(json.Unmarshal(rec.Body.Bytes(), &response))
		r.False(response.RetryAvailable)
		r.False(app.tunnelRetryAvailable())
	}
	check()
	r.NoError(app.closeAutomaticTunnel())
	<-finished
	check()
}
