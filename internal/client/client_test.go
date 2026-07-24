package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rselbach/scimtest/internal/protocol"
	"github.com/stretchr/testify/require"
)

func TestRunOnceReportsHTTPHandshakeStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "tunnel endpoint unavailable", http.StatusBadGateway)
	}))
	defer srv.Close()

	c := New(Config{ServerURL: "ws" + strings.TrimPrefix(srv.URL, "http")})
	err := c.runOnce(context.Background())

	r := require.New(t)
	r.ErrorContains(err, "connect to tunnel server")
	r.ErrorContains(err, "HTTP 502 Bad Gateway")
	r.ErrorContains(err, "websocket: bad handshake")
}

func TestRunOnceReportsRegistrationStage(t *testing.T) {
	serverErr := make(chan error, 1)
	upgrader := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		conn, err := upgrader.Upgrade(w, req, nil)
		if err != nil {
			serverErr <- err
			return
		}
		var registration protocol.Message
		if err := conn.ReadJSON(&registration); err != nil {
			if closeErr := conn.Close(); closeErr != nil {
				err = fmt.Errorf("%w; close test tunnel: %v", err, closeErr)
			}
			serverErr <- err
			return
		}
		serverErr <- conn.Close()
	}))
	defer srv.Close()

	c := New(Config{ServerURL: "ws" + strings.TrimPrefix(srv.URL, "http")})
	err := c.runOnce(context.Background())

	r := require.New(t)
	r.NoError(<-serverErr)
	r.ErrorContains(err, "read application challenge")
}

func TestRunContextLogsConnectionFailureWithoutPrivateKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "tunnel endpoint unavailable", http.StatusBadGateway)
	}))
	defer srv.Close()

	var logs bytes.Buffer
	privateKey := ed25519.PrivateKey("private-key-must-not-appear")
	c := New(Config{
		ServerURL:             "ws" + strings.TrimPrefix(srv.URL, "http"),
		ApplicationProfileID:  "0123456789abcdef0123456789abcdef",
		InstanceID:            "greendale-installation",
		ApplicationPrivateKey: privateKey,
		LocalPort:             8080,
		Logger:                slog.New(slog.NewTextHandler(&logs, nil)),
	})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := c.RunContext(ctx)

	r := require.New(t)
	r.ErrorIs(err, context.DeadlineExceeded)
	r.Contains(logs.String(), "connecting to tunnel server")
	r.Contains(logs.String(), "profile_id=0123456789abcdef0123456789abcdef")
	r.Contains(logs.String(), "instance_id=greendale-installation")
	r.Contains(logs.String(), "HTTP 502 Bad Gateway")
	r.NotContains(logs.String(), string(privateKey))
}

func TestLocalRequestURL(t *testing.T) {
	tests := map[string]struct {
		path    string
		want    string
		wantErr string
	}{
		"root": {
			path: "/",
			want: "http://127.0.0.1:8080/",
		},
		"empty becomes root": {
			path: "",
			want: "http://127.0.0.1:8080/",
		},
		"path with query": {
			path: "/human-timeline-club/oidc/x/authorize?client_id=1",
			want: "http://127.0.0.1:8080/human-timeline-club/oidc/x/authorize?client_id=1",
		},
		"at-host SSRF": {
			path:    "@169.254.169.254:80/latest/meta-data/",
			wantErr: "parse request path",
		},
		"scheme-relative path": {
			path:    "//evil.example/x",
			wantErr: "request path must begin with a single /",
		},
		"absolute http URL": {
			path:    "http://evil.example/x",
			wantErr: "request path must be relative",
		},
		"absolute https URL": {
			path:    "https://evil.example/x",
			wantErr: "request path must be relative",
		},
		"missing leading slash": {
			path:    "oidc/x",
			wantErr: "parse request path",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			got, err := localRequestURL("127.0.0.1", 8080, tc.path)
			if tc.wantErr != "" {
				r.ErrorContains(err, tc.wantErr)
				return
			}
			r.NoError(err)
			r.Equal(tc.want, got)
		})
	}
}

func TestHandleRequestRejectsOffLoopbackPaths(t *testing.T) {
	r := require.New(t)
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		hit = true
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	r.NoError(err)
	host, portValue, err := net.SplitHostPort(u.Host)
	r.NoError(err)
	port, err := strconv.Atoi(portValue)
	r.NoError(err)

	c := New(Config{LocalHost: host, LocalPort: port})
	send := make(chan protocol.Message, 1)
	done := make(chan struct{})
	c.handleRequest(protocol.Message{
		Type:     protocol.TypeRequest,
		StreamID: 1,
		Method:   http.MethodGet,
		Path:     "@evil.example/x",
	}, send, done)

	resp := <-send
	r.False(hit)
	r.Equal("invalid request path", resp.Error)
	r.Zero(resp.StatusCode)
}

func TestHandleRequestForwardsRelativePathAndQuery(t *testing.T) {
	r := require.New(t)
	var gotPath, gotRawQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		gotPath = req.URL.Path
		gotRawQuery = req.URL.RawQuery
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	r.NoError(err)
	host, portValue, err := net.SplitHostPort(u.Host)
	r.NoError(err)
	port, err := strconv.Atoi(portValue)
	r.NoError(err)

	c := New(Config{LocalHost: host, LocalPort: port})
	send := make(chan protocol.Message, 1)
	done := make(chan struct{})
	c.handleRequest(protocol.Message{
		Type:     protocol.TypeRequest,
		StreamID: 1,
		Method:   http.MethodGet,
		Path:     "/tunnel/oidc/app/authorize?client_id=x",
	}, send, done)

	resp := <-send
	r.Empty(resp.Error)
	r.Equal(http.StatusNoContent, resp.StatusCode)
	r.Equal("/tunnel/oidc/app/authorize", gotPath)
	r.Equal("client_id=x", gotRawQuery)
}

func TestHandleRequestDoesNotBlockWhenDoneClosed(t *testing.T) {
	// Start a local HTTP server that returns instantly so handleRequest
	// reaches the send on the unbuffered channel quickly.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	require.NoError(t, err)

	host, portStr, err := net.SplitHostPort(u.Host)
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)

	c := New(Config{
		LocalHost:    host,
		LocalPort:    port,
		MaxBodyBytes: 32 << 20,
	})

	// Override the HTTP client with a very short timeout so the test
	// doesn't hang for the full 2-minute default if the server were
	// unreachable.
	c.httpClient = &http.Client{Timeout: 5 * time.Second}

	send := make(chan protocol.Message) // unbuffered: will block
	done := make(chan struct{})
	close(done)

	msg := protocol.Message{
		Type:     protocol.TypeRequest,
		StreamID: 1,
		Method:   http.MethodGet,
		Path:     "/",
	}

	// handleRequest must return promptly because done is closed; if it
	// blocks on the unbuffered send the test will time out.
	c.handleRequest(msg, send, done)
}

func TestNewSetsDefaultMaxConcurrentRequests(t *testing.T) {
	r := require.New(t)
	c := New(Config{})
	r.Equal(maxConcurrentRequestsDefault, c.cfg.MaxConcurrentRequests)
}

func TestHandleRequestDoesNotFollowRedirects(t *testing.T) {
	r := require.New(t)
	followed := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/redirect":
			http.Redirect(w, req, "/destination", http.StatusFound)
		case "/destination":
			followed = true
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, req)
		}
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	r.NoError(err)
	host, portValue, err := net.SplitHostPort(u.Host)
	r.NoError(err)
	port, err := strconv.Atoi(portValue)
	r.NoError(err)

	c := New(Config{LocalHost: host, LocalPort: port})
	send := make(chan protocol.Message, 1)
	done := make(chan struct{})
	c.handleRequest(protocol.Message{
		Type:     protocol.TypeRequest,
		StreamID: 1,
		Method:   http.MethodGet,
		Path:     "/redirect",
	}, send, done)

	resp := <-send
	r.False(followed)
	r.Equal(http.StatusFound, resp.StatusCode)
	r.Equal("/destination", resp.Header.Get("Location"))
}

func TestSendBusyResponse(t *testing.T) {
	r := require.New(t)
	c := New(Config{})
	send := make(chan protocol.Message, 1)
	done := make(chan struct{})

	c.sendBusyResponse(protocol.Message{StreamID: 7}, send, done)

	resp := <-send
	r.Equal(protocol.TypeResponse, resp.Type)
	r.Equal(uint64(7), resp.StreamID)
	r.Equal("local application is busy", resp.Error)
}

func TestSendBusyResponseDoesNotBlockWhenDoneClosed(t *testing.T) {
	c := New(Config{})
	send := make(chan protocol.Message)
	done := make(chan struct{})
	close(done)

	c.sendBusyResponse(protocol.Message{StreamID: 7}, send, done)
}

func TestNextBackoff(t *testing.T) {
	tests := map[string]struct {
		current time.Duration
		max     time.Duration
		want    time.Duration
	}{
		"from 0 returns 1s":         {current: 0, max: 30 * time.Second, want: time.Second},
		"1s doubles to 2s":          {current: time.Second, max: 30 * time.Second, want: 2 * time.Second},
		"2s doubles to 4s":          {current: 2 * time.Second, max: 30 * time.Second, want: 4 * time.Second},
		"16s doubles to 30s capped": {current: 16 * time.Second, max: 30 * time.Second, want: 30 * time.Second},
		"30s stays at 30s":          {current: 30 * time.Second, max: 30 * time.Second, want: 30 * time.Second},
		"capped by custom max":      {current: 2 * time.Second, max: time.Second, want: time.Second},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			r.Equal(tc.want, nextBackoff(tc.current, tc.max))
		})
	}
}

func TestIsTerminal(t *testing.T) {
	tests := map[string]struct {
		err  error
		want bool
	}{
		"nil is not terminal":                {err: nil, want: false},
		"plain error is not terminal":        {err: fmt.Errorf("network hiccup"), want: false},
		"terminal sentinel is terminal":      {err: fmt.Errorf("%w: bad protocol", errTerminal), want: true},
		"policy violation close is terminal": {err: &websocket.CloseError{Code: websocket.ClosePolicyViolation, Text: "invalid application"}, want: true},
		"normal closure is not terminal":     {err: &websocket.CloseError{Code: websocket.CloseNormalClosure}, want: false},
		"going away is not terminal":         {err: &websocket.CloseError{Code: websocket.CloseGoingAway}, want: false},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			r.Equal(tc.want, isTerminal(tc.err))
		})
	}
}

func TestHandleRequestSanitizesErrors(t *testing.T) {
	// Use a port that is very unlikely to be open so the request fails.
	c := New(Config{
		LocalHost:    "127.0.0.1",
		LocalPort:    1,
		MaxBodyBytes: 32 << 20,
	})

	send := make(chan protocol.Message, 1)
	done := make(chan struct{})

	msg := protocol.Message{
		Type:     protocol.TypeRequest,
		StreamID: 1,
		Method:   http.MethodGet,
		Path:     "/",
	}

	c.handleRequest(msg, send, done)

	resp := <-send
	r := require.New(t)
	r.Equal(protocol.TypeResponse, resp.Type)
	r.Equal("failed to reach local application", resp.Error)
	r.NotContains(resp.Error, "refused")
	r.NotContains(resp.Error, "127.0.0.1")
}
