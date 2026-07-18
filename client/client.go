// Package client exposes an embeddable scimtest application tunnel client.
package client

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	internalclient "github.com/rselbach/scimtest/internal/client"
)

type Config struct {
	ServerURL             string
	ServerBaseURL         string
	ApplicationProfileID  string
	InstanceID            string
	ApplicationPrivateKey ed25519.PrivateKey
	LocalHost             string
	LocalPort             int
	PreserveHost          bool
	MaxBodyBytes          int64
	MaxConcurrentRequests int
	Logger                *slog.Logger
	ReconnectTimeout      time.Duration
}

type Tunnel struct {
	ID        string
	PublicURL string

	cancel context.CancelFunc
	done   chan error

	closeOnce sync.Once
	waitOnce  sync.Once
	waitErr   error
}

func Start(ctx context.Context, cfg Config) (*Tunnel, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if cfg.ApplicationProfileID == "" || cfg.InstanceID == "" || len(cfg.ApplicationPrivateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("application profile id, instance id, and Ed25519 private key are required")
	}
	if cfg.LocalPort <= 0 || cfg.LocalPort > 65535 {
		return nil, fmt.Errorf("invalid local port %d", cfg.LocalPort)
	}

	serverURL := cfg.ServerURL
	if serverURL == "" && cfg.ServerBaseURL != "" {
		serverURL = ConnectURLFromBase(cfg.ServerBaseURL)
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	runCtx, cancel := context.WithCancel(ctx)
	registered := make(chan internalclient.Registration, 1)
	var registeredOnce sync.Once

	c := internalclient.New(internalclient.Config{
		ServerURL:             serverURL,
		ApplicationProfileID:  cfg.ApplicationProfileID,
		InstanceID:            cfg.InstanceID,
		ApplicationPrivateKey: cfg.ApplicationPrivateKey,
		LocalHost:             cfg.LocalHost,
		LocalPort:             cfg.LocalPort,
		PreserveHost:          cfg.PreserveHost,
		MaxBodyBytes:          cfg.MaxBodyBytes,
		MaxConcurrentRequests: cfg.MaxConcurrentRequests,
		Logger:                logger,
		ReconnectTimeout:      cfg.ReconnectTimeout,
		Output:                io.Discard,
		OnRegistered: func(reg internalclient.Registration) {
			registeredOnce.Do(func() {
				registered <- reg
			})
		},
	})

	done := make(chan error, 1)
	go func() {
		done <- c.RunContext(runCtx)
	}()

	select {
	case reg := <-registered:
		return &Tunnel{
			ID:        reg.TunnelID,
			PublicURL: reg.PublicURL,
			cancel:    cancel,
			done:      done,
		}, nil
	case err := <-done:
		cancel()
		if errors.Is(err, context.Canceled) {
			err = ctx.Err()
		}
		if err == nil {
			err = errors.New("scimtest tunnel stopped before registration")
		}
		return nil, err
	case <-ctx.Done():
		cancel()
		return nil, ctx.Err()
	}
}

func (t *Tunnel) Close() error {
	t.closeOnce.Do(t.cancel)
	return t.Wait()
}

func (t *Tunnel) Wait() error {
	t.waitOnce.Do(func() {
		err := <-t.done
		if errors.Is(err, context.Canceled) {
			err = nil
		}
		t.waitErr = err
	})
	return t.waitErr
}

func ConnectURLFromBase(base string) string {
	base = strings.TrimRight(base, "/")
	switch {
	case strings.HasPrefix(base, "https://"):
		return "wss://" + strings.TrimPrefix(base, "https://") + "/api/connect"
	case strings.HasPrefix(base, "http://"):
		return "ws://" + strings.TrimPrefix(base, "http://") + "/api/connect"
	default:
		return "wss://" + base + "/api/connect"
	}
}
