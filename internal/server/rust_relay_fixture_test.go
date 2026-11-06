package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/rselbach/scimtest/internal/atomicfile"
	"github.com/rselbach/scimtest/internal/client"
	"github.com/stretchr/testify/require"
)

type rustRelayClient struct {
	ServerURL      string `json:"server_url"`
	ProfileID      string `json:"profile_id"`
	ReadyPath      string `json:"ready_path"`
	StopPath       string `json:"stop_path"`
	Legacy         bool   `json:"legacy"`
	EnrollmentPath string `json:"enrollment_path"`
	TimeoutSeconds int    `json:"timeout_seconds"`
}

func runRustRelayClient(t *testing.T, input rustRelayClient) any {
	t.Helper()
	r := require.New(t)
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		closeErr := request.Body.Close()
		if err != nil || closeErr != nil {
			t.Errorf("read forwarded request: %v", errors.Join(err, closeErr))
			http.Error(w, "could not read forwarded request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Greendale-Client", "Go")
		w.Header().Add("Set-Cookie", "troy=Greendale")
		w.Header().Add("Set-Cookie", "abed=Community")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"method": request.Method, "path": request.URL.Path,
			"query": request.URL.RawQuery, "host": request.Host,
			"headers": request.Header, "body": body,
		}); err != nil {
			t.Errorf("write forwarded response: %v", err)
		}
	}))
	defer local.Close()
	localURL, err := url.Parse(local.URL)
	r.NoError(err)
	_, portText, err := net.SplitHostPort(localURL.Host)
	r.NoError(err)
	port, err := strconv.Atoi(portText)
	r.NoError(err)
	timeout := 20 * time.Second
	if input.TimeoutSeconds > 0 && input.TimeoutSeconds <= 90 {
		timeout = time.Duration(input.TimeoutSeconds) * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	config := client.Config{
		ServerURL: input.ServerURL, ApplicationProfileID: input.ProfileID,
		InstancePrivateKey: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{24}, 32)),
		LocalPort:          port, PreserveHost: true, Output: io.Discard,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		OnRegistered: func(registration client.Registration) {
			if err := atomicfile.WriteJSON(input.ReadyPath, map[string]any{
				"public_url":     registration.PublicURL,
				"github_user_id": registration.GitHubUserID,
				"github_login":   registration.GitHubLogin,
			}); err != nil {
				t.Errorf("write registration: %v", err)
				cancel()
			}
		},
	}
	if input.Legacy {
		config.InstancePrivateKey = nil
		config.ApplicationPrivateKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{42}, 32))
		config.InstanceID = "legacy-greendale"
	}
	if input.EnrollmentPath != "" {
		config.OnEnrollmentRequired = func(enrollment client.Enrollment) {
			if err := atomicfile.WriteJSON(input.EnrollmentPath, map[string]string{
				"enrollment_url":                 enrollment.URL,
				"enrollment_browser_handoff_url": enrollment.BrowserHandoffURL,
				"enrollment_verification_code":   enrollment.VerificationCode,
			}); err != nil {
				t.Errorf("write enrollment: %v", err)
				cancel()
			}
		}
	}
	peer := client.New(config)
	done := make(chan error, 1)
	go func() { done <- peer.RunContext(ctx) }()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-done:
			t.Fatalf("Go client ended before the stop request: %v", err)
		case <-ctx.Done():
			r.NoError(ctx.Err(), "Rust did not stop its Go client fixture")
		case <-ticker.C:
			_, err := os.Stat(input.StopPath)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			r.NoError(err)
			cancel()
			err = <-done
			if err != nil {
				r.ErrorIs(err, context.Canceled)
			}
			return map[string]bool{"stopped": true}
		}
	}
}
