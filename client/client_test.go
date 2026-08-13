package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rselbach/scimtest/internal/protocol"
	"github.com/stretchr/testify/require"
)

func TestStartReturnsApplicationTunnel(t *testing.T) {
	r := require.New(t)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	r.NoError(err)

	upgrader := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		conn, err := upgrader.Upgrade(w, req, nil)
		r.NoError(err)
		defer func() { r.NoError(conn.Close()) }()

		var registration protocol.Message
		r.NoError(conn.ReadJSON(&registration))
		r.Equal(protocol.TypeRegisterTunnel, registration.Type)
		r.Equal("0123456789abcdef0123456789abcdef", registration.ApplicationProfileID)
		r.Equal("installation-1", registration.InstanceID)
		r.Equal(3000, registration.LocalPort)

		challenge := "greendale-challenge"
		r.NoError(conn.WriteJSON(protocol.Message{
			Type:      protocol.TypeApplicationChallenge,
			Challenge: challenge,
		}))
		var response protocol.Message
		r.NoError(conn.ReadJSON(&response))
		payload := protocol.ApplicationChallengePayload(registration.ApplicationProfileID, registration.InstanceID, challenge)
		r.True(ed25519.Verify(publicKey, payload, response.Signature))
		r.NoError(conn.WriteJSON(protocol.Message{
			Type:      protocol.TypeTunnelRegistered,
			TunnelID:  "human-timeline-club",
			PublicURL: "https://example.com/human-timeline-club",
			ClientIP:  "203.0.113.10",
		}))

		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tunnel, err := Start(ctx, Config{
		ServerURL:             wsURL,
		ApplicationProfileID:  "0123456789abcdef0123456789abcdef",
		InstanceID:            "installation-1",
		ApplicationPrivateKey: privateKey,
		LocalPort:             3000,
	})
	r.NoError(err)
	r.Equal("human-timeline-club", tunnel.ID)
	r.Equal("https://example.com/human-timeline-club", tunnel.PublicURL)
	r.Equal("203.0.113.10", tunnel.Registration().ClientIP)
	r.NoError(tunnel.Close())
	r.NoError(tunnel.Close())
}

func TestStartCompletesFirstRunEnrollmentWithInstanceKey(t *testing.T) {
	r := require.New(t)
	instancePublicKey, instanceKey, err := ed25519.GenerateKey(rand.Reader)
	r.NoError(err)
	wantPublicKey := base64.StdEncoding.EncodeToString(instancePublicKey)
	const deviceCode = "greendale-device-secret"

	var connections atomic.Int32
	upgrader := websocket.Upgrader{}
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/enrollment/status" {
			r.Equal(http.MethodPost, req.Method)
			r.Empty(req.URL.RawQuery)
			r.Zero(req.ContentLength)
			r.Equal("Bearer "+deviceCode, req.Header.Get("Authorization"))
			r.NoError(json.NewEncoder(w).Encode(protocol.EnrollmentStatus{Status: "approved"}))
			return
		}

		conn, err := upgrader.Upgrade(w, req, nil)
		r.NoError(err)
		defer func() { r.NoError(conn.Close()) }()
		var register protocol.Message
		r.NoError(conn.ReadJSON(&register))
		r.Equal(wantPublicKey, register.InstancePublicKey)
		r.NoError(conn.WriteJSON(protocol.Message{
			Type:                protocol.TypeApplicationChallenge,
			Challenge:           "challenge-1",
			EnrollmentSupported: true,
		}))
		var signed protocol.Message
		r.NoError(conn.ReadJSON(&signed))
		payload := protocol.InstanceChallengePayload(register.ApplicationProfileID, wantPublicKey, register.InstanceID, "challenge-1")
		r.True(ed25519.Verify(instancePublicKey, payload, signed.Signature))

		if connections.Add(1) == 1 {
			r.Empty(signed.EnrollmentGrant)
			r.NoError(conn.WriteJSON(protocol.Message{
				Type:                        protocol.TypeEnrollmentRequired,
				EnrollmentURL:               srv.URL + "/enrollment/start",
				EnrollmentBrowserHandoffURL: srv.URL + "/enrollment/browser?handoff=one-use",
				EnrollmentStatusURL:         srv.URL + "/enrollment/status",
				EnrollmentDeviceCode:        deviceCode,
				EnrollmentVerificationCode:  "study-group",
				EnrollmentPollSeconds:       1,
			}))
			return
		}

		r.Equal(deviceCode, signed.EnrollmentGrant)
		r.NoError(conn.WriteJSON(protocol.Message{
			Type:      protocol.TypeTunnelRegistered,
			TunnelID:  "human-timeline-club",
			PublicURL: srv.URL + "/human-timeline-club",
		}))
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	enrollments := make(chan Enrollment, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	tunnel, err := Start(ctx, Config{
		ServerURL:            "ws" + strings.TrimPrefix(srv.URL, "http"),
		ApplicationProfileID: "0123456789abcdef0123456789abcdef",
		InstanceID:           "installation-1",
		InstancePrivateKey:   instanceKey,
		LocalPort:            3000,
		OnEnrollmentRequired: func(enrollment Enrollment) {
			enrollments <- enrollment
		},
	})
	r.NoError(err)
	r.Equal(Enrollment{
		URL:               srv.URL + "/enrollment/start",
		BrowserHandoffURL: srv.URL + "/enrollment/browser?handoff=one-use",
		VerificationCode:  "study-group",
	}, <-enrollments)
	r.Equal("human-timeline-club", tunnel.ID)
	r.Equal(int32(2), connections.Load())
	r.NoError(tunnel.Close())
}

func TestStartWithoutEnrollmentCallbackLogsAuthorizationDetails(t *testing.T) {
	r := require.New(t)
	_, instanceKey, err := ed25519.GenerateKey(rand.Reader)
	r.NoError(err)
	const deviceCode = "greendale-device-secret"

	upgrader := websocket.Upgrader{}
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/enrollment/status" {
			r.NoError(json.NewEncoder(w).Encode(protocol.EnrollmentStatus{
				Status: "rejected",
				Error:  "test authorization rejected",
			}))
			return
		}

		conn, err := upgrader.Upgrade(w, req, nil)
		r.NoError(err)
		defer func() { r.NoError(conn.Close()) }()
		var register protocol.Message
		r.NoError(conn.ReadJSON(&register))
		r.NoError(conn.WriteJSON(protocol.Message{
			Type:                protocol.TypeApplicationChallenge,
			Challenge:           "greendale-challenge",
			EnrollmentSupported: true,
		}))
		var signed protocol.Message
		r.NoError(conn.ReadJSON(&signed))
		r.NoError(conn.WriteJSON(protocol.Message{
			Type:                       protocol.TypeEnrollmentRequired,
			EnrollmentURL:              srv.URL + "/enrollment/start",
			EnrollmentStatusURL:        srv.URL + "/enrollment/status",
			EnrollmentDeviceCode:       deviceCode,
			EnrollmentVerificationCode: "study-group",
		}))
	}))
	defer srv.Close()

	var logs bytes.Buffer
	testLogger := slog.New(slog.NewTextHandler(&logs, nil))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = Start(ctx, Config{
		ServerURL:            "ws" + strings.TrimPrefix(srv.URL, "http"),
		ApplicationProfileID: "0123456789abcdef0123456789abcdef",
		InstanceID:           "installation-1",
		InstancePrivateKey:   instanceKey,
		LocalPort:            3000,
		Logger:               testLogger,
	})
	r.ErrorContains(err, "test authorization rejected")
	r.Contains(logs.String(), srv.URL+"/enrollment/start")
	r.Contains(logs.String(), "verification_code=study-group")
	r.NotContains(logs.String(), deviceCode)
}

func TestTunnelCloseCancelsForwardedRequests(t *testing.T) {
	r := require.New(t)
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	r.NoError(err)

	requestStarted := make(chan struct{})
	requestCanceled := make(chan struct{})
	releaseRequest := make(chan struct{})
	localServer := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		close(requestStarted)
		select {
		case <-req.Context().Done():
			close(requestCanceled)
		case <-releaseRequest:
		}
	}))
	defer func() {
		close(releaseRequest)
		localServer.Close()
	}()
	localURL, err := url.Parse(localServer.URL)
	r.NoError(err)
	localHost, localPortValue, err := net.SplitHostPort(localURL.Host)
	r.NoError(err)
	localPort, err := strconv.Atoi(localPortValue)
	r.NoError(err)

	upgrader := websocket.Upgrader{}
	tunnelServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		conn, err := upgrader.Upgrade(w, req, nil)
		r.NoError(err)
		defer func() { r.NoError(conn.Close()) }()

		var registration protocol.Message
		r.NoError(conn.ReadJSON(&registration))
		r.NoError(conn.WriteJSON(protocol.Message{
			Type:      protocol.TypeApplicationChallenge,
			Challenge: "greendale-challenge",
		}))
		var signature protocol.Message
		r.NoError(conn.ReadJSON(&signature))
		r.NoError(conn.WriteJSON(protocol.Message{
			Type:      protocol.TypeTunnelRegistered,
			TunnelID:  "study-room-f",
			PublicURL: "https://example.com/study-room-f",
		}))
		r.NoError(conn.WriteJSON(protocol.Message{
			Type:     protocol.TypeRequest,
			StreamID: 1,
			Method:   http.MethodPost,
			Path:     "/sync",
		}))
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer tunnelServer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tunnel, err := Start(ctx, Config{
		ServerURL:             "ws" + strings.TrimPrefix(tunnelServer.URL, "http"),
		ApplicationProfileID:  "0123456789abcdef0123456789abcdef",
		InstanceID:            "installation-1",
		ApplicationPrivateKey: privateKey,
		LocalHost:             localHost,
		LocalPort:             localPort,
	})
	r.NoError(err)
	select {
	case <-requestStarted:
	case <-ctx.Done():
		r.Fail("forwarded request did not start")
	}

	closeResult := make(chan error, 1)
	go func() {
		closeResult <- tunnel.Close()
	}()
	select {
	case <-requestCanceled:
	case <-ctx.Done():
		r.Fail("forwarded request context was not canceled")
	}
	select {
	case err := <-closeResult:
		r.NoError(err)
	case <-ctx.Done():
		r.Fail("tunnel close did not return")
	}
}

func TestTunnelReportsReplacementRegistrationAfterReconnect(t *testing.T) {
	r := require.New(t)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	r.NoError(err)

	var connections atomic.Int32
	upgrader := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		conn, err := upgrader.Upgrade(w, req, nil)
		r.NoError(err)
		defer func() { r.NoError(conn.Close()) }()

		var registration protocol.Message
		r.NoError(conn.ReadJSON(&registration))
		challenge := "greendale-challenge"
		r.NoError(conn.WriteJSON(protocol.Message{
			Type:      protocol.TypeApplicationChallenge,
			Challenge: challenge,
		}))
		var response protocol.Message
		r.NoError(conn.ReadJSON(&response))
		payload := protocol.ApplicationChallengePayload(registration.ApplicationProfileID, registration.InstanceID, challenge)
		r.True(ed25519.Verify(publicKey, payload, response.Signature))

		connection := connections.Add(1)
		registrationID := "study-room-a"
		clientIP := "203.0.113.10"
		if connection == 2 {
			registrationID = "study-room-f"
			clientIP = "198.51.100.20"
		}
		r.NoError(conn.WriteJSON(protocol.Message{
			Type:         protocol.TypeTunnelRegistered,
			TunnelID:     registrationID,
			PublicURL:    "https://example.com/" + registrationID,
			ClientIP:     clientIP,
			GitHubUserID: 42,
			GitHubLogin:  "troy-barnes",
		}))
		if connection == 1 {
			return
		}
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	registrations := make(chan Registration, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tunnel, err := Start(ctx, Config{
		ServerURL:             "ws" + strings.TrimPrefix(srv.URL, "http"),
		ApplicationProfileID:  "0123456789abcdef0123456789abcdef",
		InstanceID:            "installation-1",
		ApplicationPrivateKey: privateKey,
		LocalPort:             3000,
		OnRegistered: func(registration Registration) {
			registrations <- registration
		},
	})
	r.NoError(err)
	r.Equal(Registration{
		TunnelID:     "study-room-a",
		PublicURL:    "https://example.com/study-room-a",
		ClientIP:     "203.0.113.10",
		GitHubUserID: 42,
		GitHubLogin:  "troy-barnes",
	}, <-registrations)

	select {
	case registration := <-registrations:
		r.Equal(Registration{
			TunnelID:     "study-room-f",
			PublicURL:    "https://example.com/study-room-f",
			ClientIP:     "198.51.100.20",
			GitHubUserID: 42,
			GitHubLogin:  "troy-barnes",
		}, registration)
		r.Equal(registration, tunnel.Registration())
	case <-ctx.Done():
		r.Fail("tunnel did not report its replacement registration")
	}
	r.NoError(tunnel.Close())
}

func TestStartValidatesApplicationConfiguration(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	tests := map[string]Config{
		"missing profile": {
			InstanceID:            "installation-1",
			ApplicationPrivateKey: privateKey,
			LocalPort:             3000,
		},
		"missing instance": {
			ApplicationProfileID:  "0123456789abcdef0123456789abcdef",
			ApplicationPrivateKey: privateKey,
			LocalPort:             3000,
		},
		"missing key": {
			ApplicationProfileID: "0123456789abcdef0123456789abcdef",
			InstanceID:           "installation-1",
			LocalPort:            3000,
		},
		"invalid port": {
			ApplicationProfileID:  "0123456789abcdef0123456789abcdef",
			InstanceID:            "installation-1",
			ApplicationPrivateKey: privateKey,
		},
	}

	for name, cfg := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := Start(context.Background(), cfg)
			require.Error(t, err)
		})
	}
}

func TestConnectURLFromBase(t *testing.T) {
	tests := map[string]string{
		"https://scimtest.example.com": "wss://scimtest.example.com/api/connect",
		"http://localhost:7000/":       "ws://localhost:7000/api/connect",
		"scimtest.rselbach.com":        "wss://scimtest.rselbach.com/api/connect",
		"https://example.com/root//":   "wss://example.com/root/api/connect",
	}

	for base, want := range tests {
		t.Run(base, func(t *testing.T) {
			require.Equal(t, want, ConnectURLFromBase(base))
		})
	}
}
