package web

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	scimtestclient "github.com/rselbach/scimtest/client"
	"github.com/rselbach/scimtest/internal/protocol"
	"github.com/stretchr/testify/require"
)

const sharedTunnelProfile = "0123456789abcdef0123456789abcdef"
const sharedTunnelDeviceSecret = "greendale-device-secret"

type sharedTunnelRegistration struct {
	instanceID string
	publicKey  string
	grant      string
}

type sharedTunnelConnection struct {
	conn      *websocket.Conn
	writeMu   sync.Mutex
	responses chan protocol.Message
}

type sharedTunnelServer struct {
	t           *testing.T
	server      *httptest.Server
	mu          sync.Mutex
	connections map[*websocket.Conn]bool
	current     *sharedTunnelConnection
	registered  []sharedTunnelRegistration
	known       map[string]string
	enrollment  bool
	approved    bool
	pollError   int
	polls       int
	login       string
	streamID    uint64
}

func newSharedTunnelServer(t *testing.T, enrollment bool) *sharedTunnelServer {
	t.Helper()
	s := &sharedTunnelServer{t: t, enrollment: enrollment, known: make(map[string]string), connections: make(map[*websocket.Conn]bool), login: "troy-barnes"}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/connect", s.connect)
	mux.HandleFunc("POST /enroll/status", s.status)
	s.server = httptest.NewServer(mux)
	t.Cleanup(func() {
		s.mu.Lock()
		for conn := range s.connections {
			if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				t.Errorf("close shared tunnel socket: %v", err)
			}
		}
		s.mu.Unlock()
		s.server.Close()
	})
	return s
}

func (s *sharedTunnelServer) connect(w http.ResponseWriter, req *http.Request) {
	upgrader := websocket.Upgrader{}
	conn, err := upgrader.Upgrade(w, req, nil)
	if err != nil {
		s.t.Errorf("upgrade shared tunnel: %v", err)
		return
	}
	s.mu.Lock()
	s.connections[conn] = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.connections, conn)
		s.mu.Unlock()
		if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			s.t.Errorf("close shared tunnel: %v", err)
		}
	}()
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		s.t.Errorf("set shared registration deadline: %v", err)
		return
	}
	var registration protocol.Message
	if err := conn.ReadJSON(&registration); err != nil {
		s.t.Errorf("read shared registration: %v", err)
		return
	}
	if registration.Type != protocol.TypeRegisterTunnel || registration.ApplicationProfileID != sharedTunnelProfile {
		s.t.Errorf("unexpected shared registration type/profile: %s %s", registration.Type, registration.ApplicationProfileID)
		return
	}
	if err := conn.WriteJSON(protocol.Message{Type: protocol.TypeApplicationChallenge, EnrollmentSupported: true, Challenge: "greendale-challenge"}); err != nil {
		s.t.Errorf("write shared challenge: %v", err)
		return
	}
	var proof protocol.Message
	if err := conn.ReadJSON(&proof); err != nil {
		s.t.Errorf("read shared signature: %v", err)
		return
	}
	key, err := base64.StdEncoding.DecodeString(registration.InstancePublicKey)
	if err != nil {
		s.t.Errorf("decode shared installation key: %v", err)
		return
	}
	payload := protocol.InstanceChallengePayload(registration.ApplicationProfileID, registration.InstancePublicKey, registration.InstanceID, "greendale-challenge")
	if proof.Type != protocol.TypeApplicationSignature || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, payload, proof.Signature) {
		s.t.Error("shared installation signature did not verify")
		return
	}
	s.mu.Lock()
	s.registered = append(s.registered, sharedTunnelRegistration{registration.InstanceID, registration.InstancePublicKey, proof.EnrollmentGrant})
	_, known := s.known[registration.InstancePublicKey]
	needsEnrollment := s.enrollment && !known && !(s.approved && proof.EnrollmentGrant == sharedTunnelDeviceSecret)
	if !needsEnrollment && !known {
		s.known[registration.InstancePublicKey] = s.login
	}
	login := s.known[registration.InstancePublicKey]
	s.mu.Unlock()
	if needsEnrollment {
		message := protocol.Message{Type: protocol.TypeEnrollmentRequired, EnrollmentURL: s.server.URL + "/enroll?code=greendale", EnrollmentBrowserHandoffURL: s.server.URL + "/enroll/browser?handoff=one-use", EnrollmentStatusURL: s.server.URL + "/enroll/status", EnrollmentDeviceCode: sharedTunnelDeviceSecret, EnrollmentVerificationCode: "GREEN-DALE", EnrollmentPollSeconds: 1}
		if err := conn.WriteJSON(message); err != nil {
			s.t.Errorf("write shared enrollment: %v", err)
		}
		return
	}
	connection := &sharedTunnelConnection{conn: conn, responses: make(chan protocol.Message, 32)}
	message := protocol.Message{Type: protocol.TypeTunnelRegistered, TunnelID: "greendale-tunnel", PublicURL: "https://scimtest.example/greendale", ClientIP: "203.0.113.7", GitHubUserID: 42, GitHubLogin: login}
	if err := conn.WriteJSON(message); err != nil {
		s.t.Errorf("write shared registration result: %v", err)
		return
	}
	s.mu.Lock()
	s.current = connection
	s.mu.Unlock()
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		s.t.Errorf("clear shared registration deadline: %v", err)
		return
	}
	defer close(connection.responses)
	for {
		var response protocol.Message
		if err := conn.ReadJSON(&response); err != nil {
			return
		}
		switch response.Type {
		case protocol.TypeResponse:
			connection.responses <- response
		case protocol.TypePing:
			connection.writeMu.Lock()
			err := conn.WriteJSON(protocol.Message{Type: protocol.TypePong})
			connection.writeMu.Unlock()
			if err != nil {
				return
			}
		}
	}
}

func (s *sharedTunnelServer) status(w http.ResponseWriter, req *http.Request) {
	if req.Header.Get("Authorization") != "Bearer "+sharedTunnelDeviceSecret || req.Header.Get("Cache-Control") != "no-store" {
		s.t.Error("shared enrollment poll omitted its private bearer or no-store header")
		http.Error(w, "invalid enrollment poll", http.StatusUnauthorized)
		return
	}
	s.mu.Lock()
	s.polls++
	status, approved := s.pollError, s.approved
	s.pollError = 0
	s.mu.Unlock()
	if status != 0 {
		w.WriteHeader(status)
		return
	}
	value := "pending"
	if approved {
		value = "approved"
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"status": value}); err != nil {
		s.t.Errorf("write shared enrollment status: %v", err)
	}
}

func (s *sharedTunnelServer) approve(login string) {
	s.mu.Lock()
	s.approved, s.login = true, login
	s.mu.Unlock()
}

func (s *sharedTunnelServer) registrations() []sharedTunnelRegistration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]sharedTunnelRegistration(nil), s.registered...)
}

func (s *sharedTunnelServer) disconnect(code int, reason string) {
	s.t.Helper()
	s.mu.Lock()
	connection := s.current
	s.mu.Unlock()
	r := require.New(s.t)
	r.NotNil(connection)
	r.NoError(connection.conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, reason), time.Now().Add(time.Second)))
}

func (s *sharedTunnelServer) forward(method, path, visitor string, values url.Values, extra ...http.Header) *httptest.ResponseRecorder {
	s.t.Helper()
	r := require.New(s.t)
	s.mu.Lock()
	connection := s.current
	s.streamID++
	id := s.streamID
	s.mu.Unlock()
	r.NotNil(connection)
	header := make(http.Header)
	for _, headers := range extra {
		for name, values := range headers {
			header[name] = append([]string(nil), values...)
		}
	}
	header.Set("X-Forwarded-For", visitor)
	var body []byte
	if method == http.MethodPost {
		header.Set("Content-Type", "application/x-www-form-urlencoded")
		body = []byte(values.Encode())
	} else if len(values) > 0 {
		path += "?" + values.Encode()
	}
	message := protocol.Message{Type: protocol.TypeRequest, StreamID: id, Method: method, Path: path, Host: "scimtest.example", Scheme: "https", Header: header, Body: body}
	connection.writeMu.Lock()
	err := connection.conn.WriteJSON(message)
	connection.writeMu.Unlock()
	r.NoError(err)
	select {
	case response, ok := <-connection.responses:
		r.True(ok, "tunnel disconnected while forwarding %s", path)
		r.Equal(id, response.StreamID)
		r.Empty(response.Error)
		recorder := httptest.NewRecorder()
		for name, values := range response.Header {
			for _, value := range values {
				recorder.Header().Add(name, value)
			}
		}
		recorder.WriteHeader(response.StatusCode)
		_, err := recorder.Write(response.Body)
		r.NoError(err)
		return recorder
	case <-time.After(30 * time.Second):
		r.FailNow("shared tunnel response timed out", "%s %s", method, path)
		return nil
	}
}

type sharedTunnelApp struct {
	handler http.Handler
	base    string
	stop    func()
}

func startSharedTunnelApp(t *testing.T, implementation string, server *sharedTunnelServer, statePath string) sharedTunnelApp {
	t.Helper()
	r := require.New(t)
	t.Setenv("SCIMTEST_STATE_FILE", statePath)
	t.Setenv("SCIMTEST_PORT", "")
	t.Setenv("PORT", "")
	done := make(chan error, 1)
	var cancel func() error
	var log *os.File
	switch implementation {
	case "Go":
		oldProfile, oldRequired := tunnelApplicationProfileID, tunnelReleaseProfileRequired
		tunnelApplicationProfileID, tunnelReleaseProfileRequired = sharedTunnelProfile, "true"
		t.Cleanup(func() {
			tunnelApplicationProfileID, tunnelReleaseProfileRequired = oldProfile, oldRequired
		})
		lease, acquired, err := acquireInstanceLease(statePath)
		r.NoError(err)
		r.True(acquired)
		service := newTestIDPApp(t)
		service.requireGitHubAccount, service.tunnelSupported, service.noOpen = true, true, true
		service.browserOpen = func(string) error { return nil }
		service.tunnelStart = func(ctx context.Context, cfg scimtestclient.Config) (*startedTunnel, error) {
			cfg.ServerBaseURL = server.server.URL
			return startTunnel(ctx, cfg)
		}
		service.instanceToken, err = newInstanceToken()
		r.NoError(err)
		public := httptest.NewServer(service.tunneledIDPRoutes())
		publicURL, err := url.Parse(public.URL)
		r.NoError(err)
		service.localPort, err = strconv.Atoi(publicURL.Port())
		r.NoError(err)
		admin := httptest.NewServer(service.routes())
		adminURL, err := url.Parse(admin.URL)
		r.NoError(err)
		service.adminHost, service.adminURL = adminURL.Host, admin.URL
		r.NoError(lease.Publish(instanceMetadata{URL: admin.URL, Token: service.instanceToken, GitHubAccountRequired: true}))
		go service.startAutomaticTunnel(tunnelApplicationIdentity{profileID: sharedTunnelProfile})
		cancel = func() error {
			tunnelError := service.closeAutomaticTunnel()
			admin.Close()
			public.Close()
			done <- errors.Join(tunnelError, lease.Close())
			return nil
		}
	case "Rust":
		var err error
		log, err = os.CreateTemp(filepath.Dir(statePath), "runtime-*.log")
		r.NoError(err)
		command := exec.Command(os.Getenv("SCIMTEST_ACCEPTANCE_RUST_TUNNEL_FIXTURE"), "--exact", "serve_tunnel_acceptance_fixture", "--ignored", "--nocapture")
		command.Env = append(os.Environ(), "SCIMTEST_TUNNEL_ACCEPTANCE_STATE="+statePath, "SCIMTEST_TUNNEL_ACCEPTANCE_SERVER="+server.server.URL)
		command.Stdout, command.Stderr = log, log
		r.NoError(command.Start())
		cancel = func() error { return command.Process.Signal(syscall.SIGTERM) }
		go func() { done <- command.Wait() }()
	default:
		r.FailNow("unknown shared tunnel implementation", implementation)
	}
	var once sync.Once
	stop := func() {
		once.Do(func() {
			select {
			case err := <-done:
				t.Errorf("shared %s runtime stopped before cleanup: %v", implementation, err)
			default:
				r.NoError(cancel())
				select {
				case err := <-done:
					r.NoError(err)
				case <-time.After(10 * time.Second):
					r.FailNow("shared tunnel runtime did not stop", implementation)
				}
			}
			if log != nil {
				r.NoError(log.Close())
				if t.Failed() {
					contents, err := os.ReadFile(log.Name())
					r.NoError(err)
					t.Logf("Rust tunnel fixture: %s", contents)
				}
			}
			if implementation == "Rust" {
				contents, err := os.ReadFile(statePath + ".lock")
				r.NoError(err)
				r.Empty(strings.TrimSpace(string(contents)), "Rust runtime did not clear its instance metadata")
			}
			lease, acquired, err := acquireInstanceLease(statePath)
			r.NoError(err)
			r.True(acquired, "runtime did not release its instance lease")
			r.NoError(lease.Close())
		})
	}
	t.Cleanup(stop)
	transport := &http.Transport{ResponseHeaderTimeout: 30 * time.Second}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var metadata instanceMetadata
	r.Eventually(func() bool {
		contents, err := os.ReadFile(statePath + ".lock")
		if err != nil || json.Unmarshal(contents, &metadata) != nil || metadata.URL == "" || metadata.Token == "" {
			return false
		}
		req, err := http.NewRequest(http.MethodGet, metadata.URL+instanceReadyPath, nil)
		if err != nil {
			return false
		}
		req.Header.Set(instanceTokenHeader, metadata.Token)
		response, err := client.Do(req)
		if err != nil {
			return false
		}
		err = response.Body.Close()
		return err == nil && response.StatusCode == http.StatusNoContent
	}, 10*time.Second, 10*time.Millisecond)
	base, err := url.Parse(metadata.URL)
	r.NoError(err)
	return sharedTunnelApp{handler: acceptanceHTTPHandler(t, client, base, metadata.Token), base: metadata.URL, stop: stop}
}

func (a sharedTunnelApp) account(t *testing.T) map[string]any {
	t.Helper()
	response := acceptanceRequest(t, a.handler, http.MethodGet, "/api/v1/account", "", http.StatusOK)
	var account map[string]any
	require.New(t).NoError(json.Unmarshal(response.Body.Bytes(), &account))
	return account
}

func (a sharedTunnelApp) waitAccount(t *testing.T, state string) map[string]any {
	t.Helper()
	r := require.New(t)
	var account map[string]any
	r.Eventually(func() bool { account = a.account(t); return account["state"] == state }, 15*time.Second, 20*time.Millisecond)
	r.True(account["required"].(bool))
	r.NotContains(fmt.Sprint(account), sharedTunnelDeviceSecret)
	return account
}
