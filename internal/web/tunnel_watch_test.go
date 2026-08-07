package web

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
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
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	r.NoError(err)

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
	app.startAutomaticTunnel(tunnelApplicationIdentity{profileID: strings.Repeat("a", 32), privateKey: privateKey})
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
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	r.NoError(err)

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
	app.startAutomaticTunnel(tunnelApplicationIdentity{profileID: strings.Repeat("a", 32), privateKey: privateKey})

	r.NoError(app.closeAutomaticTunnel())
	done <- nil
	time.Sleep(50 * time.Millisecond)
	r.Empty(app.tunnelError())
}
