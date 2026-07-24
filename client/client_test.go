package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
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
	r.NoError(tunnel.Close())
	r.NoError(tunnel.Close())
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
		if connection == 2 {
			registrationID = "study-room-f"
		}
		r.NoError(conn.WriteJSON(protocol.Message{
			Type:      protocol.TypeTunnelRegistered,
			TunnelID:  registrationID,
			PublicURL: "https://example.com/" + registrationID,
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
		TunnelID:  "study-room-a",
		PublicURL: "https://example.com/study-room-a",
	}, <-registrations)

	select {
	case registration := <-registrations:
		r.Equal(Registration{
			TunnelID:  "study-room-f",
			PublicURL: "https://example.com/study-room-f",
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
