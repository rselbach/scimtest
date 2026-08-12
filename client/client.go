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
	ServerURL            string
	ServerBaseURL        string
	ApplicationProfileID string
	InstanceID           string
	// ApplicationPrivateKey authenticates against legacy tunnel servers.
	ApplicationPrivateKey ed25519.PrivateKey
	// InstancePrivateKey is this installation's own key and is sufficient for
	// modern tunnel servers. Persist and reuse it to retain the installation's
	// identity and public tunnel name.
	InstancePrivateKey    ed25519.PrivateKey
	LocalHost             string
	LocalPort             int
	PreserveHost          bool
	MaxBodyBytes          int64
	MaxConcurrentRequests int
	Logger                *slog.Logger
	ReconnectTimeout      time.Duration
	OnRegistered          func(Registration)
	// OnEnrollmentRequired receives the user-facing authorization URL before
	// the client starts polling. It never receives the enrollment credential.
	OnEnrollmentRequired func(Enrollment)
}

// Registration identifies the current public tunnel assigned by the server.
type Registration struct {
	TunnelID     string
	PublicURL    string
	ClientIP     string
	GitHubUserID int64
	GitHubLogin  string
}

// Enrollment identifies the browser page where the user can authorize this
// installation for its first tunnel connection. Show VerificationCode
// independently so the user can compare it with the authorization page.
type Enrollment struct {
	URL              string
	VerificationCode string
}

type Tunnel struct {
	ID        string
	PublicURL string

	cancel       context.CancelFunc
	done         chan error
	registration *registrationState

	closeOnce sync.Once
	waitOnce  sync.Once
	waitErr   error
}

type registrationState struct {
	mu    sync.RWMutex
	value Registration
}

func (s *registrationState) set(registration Registration) {
	s.mu.Lock()
	s.value = registration
	s.mu.Unlock()
}

func (s *registrationState) get() Registration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.value
}

func Start(ctx context.Context, cfg Config) (*Tunnel, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	hasApplicationKey := len(cfg.ApplicationPrivateKey) == ed25519.PrivateKeySize
	hasInstanceKey := len(cfg.InstancePrivateKey) == ed25519.PrivateKeySize
	if cfg.ApplicationProfileID == "" || cfg.InstanceID == "" || (!hasApplicationKey && !hasInstanceKey) {
		return nil, errors.New("application profile id, instance id, and an Ed25519 application or instance private key are required")
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
	enrollmentLogger := cfg.Logger
	if enrollmentLogger == nil {
		enrollmentLogger = slog.Default()
	}

	runCtx, cancel := context.WithCancel(ctx)
	registered := make(chan Registration, 1)
	registration := &registrationState{}
	var registeredOnce sync.Once
	var onEnrollmentRequired func(internalclient.Enrollment)
	if cfg.OnEnrollmentRequired != nil {
		onEnrollmentRequired = func(enrollment internalclient.Enrollment) {
			cfg.OnEnrollmentRequired(Enrollment{URL: enrollment.URL, VerificationCode: enrollment.VerificationCode})
		}
	} else {
		onEnrollmentRequired = func(enrollment internalclient.Enrollment) {
			enrollmentLogger.Warn("scimtest installation authorization required", "url", enrollment.URL, "verification_code", enrollment.VerificationCode)
		}
	}

	c := internalclient.New(internalclient.Config{
		ServerURL:             serverURL,
		ApplicationProfileID:  cfg.ApplicationProfileID,
		InstanceID:            cfg.InstanceID,
		ApplicationPrivateKey: cfg.ApplicationPrivateKey,
		InstancePrivateKey:    cfg.InstancePrivateKey,
		LocalHost:             cfg.LocalHost,
		LocalPort:             cfg.LocalPort,
		PreserveHost:          cfg.PreserveHost,
		MaxBodyBytes:          cfg.MaxBodyBytes,
		MaxConcurrentRequests: cfg.MaxConcurrentRequests,
		Logger:                logger,
		ReconnectTimeout:      cfg.ReconnectTimeout,
		Output:                io.Discard,
		OnEnrollmentRequired:  onEnrollmentRequired,
		OnRegistered: func(reg internalclient.Registration) {
			current := Registration{
				TunnelID:     reg.TunnelID,
				PublicURL:    reg.PublicURL,
				ClientIP:     reg.ClientIP,
				GitHubUserID: reg.GitHubUserID,
				GitHubLogin:  reg.GitHubLogin,
			}
			registration.set(current)
			registeredOnce.Do(func() {
				registered <- current
			})
			if cfg.OnRegistered != nil {
				cfg.OnRegistered(current)
			}
		},
	})

	done := make(chan error, 1)
	go func() {
		done <- c.RunContext(runCtx)
	}()

	select {
	case reg := <-registered:
		return &Tunnel{
			ID:           reg.TunnelID,
			PublicURL:    reg.PublicURL,
			cancel:       cancel,
			done:         done,
			registration: registration,
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

// Registration returns the latest public tunnel assigned by the server.
func (t *Tunnel) Registration() Registration {
	return t.registration.get()
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
