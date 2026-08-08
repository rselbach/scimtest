package web

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	scimtestclient "github.com/rselbach/scimtest/client"
	"github.com/stretchr/testify/require"
)

type waitFakeTunnel struct {
	done chan error
}

func (f *waitFakeTunnel) Close() error { return nil }
func (f *waitFakeTunnel) Wait() error  { return <-f.done }

func TestTunnelExitClearsPublicURLAndOffersRetry(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{}))

	done := make(chan error, 1)
	app := &webApp{
		localPort: 8080,
		tunnelStart: func(context.Context, scimtestclient.Config) (*startedTunnel, error) {
			return &startedTunnel{
				PublicURL: "https://scimtest.rselbach.com/study-group",
				ClientIP:  "203.0.113.50",
				Tunnel:    &waitFakeTunnel{done: done},
			}, nil
		},
	}
	app.startAutomaticTunnel(tunnelApplicationIdentity{profileID: strings.Repeat("a", 32)})
	r.Equal("https://scimtest.rselbach.com/study-group", app.tunnelPublicURL())

	done <- errors.New("application profile rejected")
	r.Eventually(func() bool { return app.tunnelPublicURL() == "" }, 2*time.Second, 10*time.Millisecond,
		"dead tunnel must stop being advertised")
	r.Eventually(func() bool { return app.tunnelRetryAvailable() }, 2*time.Second, 10*time.Millisecond)
	r.Contains(app.tunnelError(), "application profile rejected")
}

func TestDeliberateTunnelCloseSetsNoError(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{}))

	done := make(chan error, 1)
	app := &webApp{
		localPort: 8080,
		tunnelStart: func(context.Context, scimtestclient.Config) (*startedTunnel, error) {
			return &startedTunnel{
				PublicURL: "https://scimtest.rselbach.com/study-group",
				ClientIP:  "203.0.113.50",
				Tunnel:    &waitFakeTunnel{done: done},
			}, nil
		},
	}
	app.startAutomaticTunnel(tunnelApplicationIdentity{profileID: strings.Repeat("a", 32)})

	r.NoError(app.closeAutomaticTunnel())
	done <- nil
	time.Sleep(50 * time.Millisecond)
	r.Empty(app.tunnelError())
}

func TestCloseCancelsPendingTunnelEnrollment(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{}))

	started := make(chan struct{})
	app := &webApp{
		localPort: 8080,
		noOpen:    true,
		tunnelStart: func(ctx context.Context, cfg scimtestclient.Config) (*startedTunnel, error) {
			cfg.OnEnrollmentRequired(scimtestclient.Enrollment{
				URL:              "https://admin.example.com/enroll?code=study-group",
				VerificationCode: "study-group",
			})
			close(started)
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	done := make(chan struct{})
	go func() {
		app.startAutomaticTunnel(tunnelApplicationIdentity{profileID: strings.Repeat("a", 32)})
		close(done)
	}()
	<-started

	r.NoError(app.closeAutomaticTunnel())
	select {
	case <-done:
	case <-time.After(time.Second):
		r.Fail("pending tunnel start did not stop")
	}
}

func TestClosePreventsLaterAutomaticTunnelStart(t *testing.T) {
	r := require.New(t)
	started := false
	app := &webApp{
		tunnelStart: func(context.Context, scimtestclient.Config) (*startedTunnel, error) {
			started = true
			return nil, errors.New("unexpected tunnel start")
		},
	}

	r.NoError(app.closeAutomaticTunnel())
	app.startAutomaticTunnel(tunnelApplicationIdentity{profileID: strings.Repeat("a", 32)})

	r.False(started)
	r.Nil(app.tunnelStarting)
}
