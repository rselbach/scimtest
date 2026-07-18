package server

import (
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"github.com/rselbach/scimtest/internal/protocol"
	"github.com/stretchr/testify/require"
)

func TestRandomIDIsCommunityPhrase(t *testing.T) {
	r := require.New(t)
	id := randomID()
	parts := regexp.MustCompile(`-`).Split(id, -1)
	r.Len(parts, 3)
	r.NotEmpty(parts[0])
	r.NotEmpty(parts[1])
	r.NotEmpty(parts[2])
}

func TestRandomIDIsAlwaysValidPathSegment(t *testing.T) {
	nameRE := regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	for range 200 {
		id := randomID()
		if !nameRE.MatchString(id) {
			t.Fatalf("randomID generated invalid DNS label %q", id)
		}
	}
}

func TestPublicHostRootRedirectsToDashboardOrigin(t *testing.T) {
	r := require.New(t)
	s := &Server{cfg: Config{Domain: "scimtest.example.com", DashboardDomain: "admin.example.com", PublicScheme: "https"}}

	req := httptest.NewRequest(http.MethodGet, "https://scimtest.example.com/", nil)
	rec := httptest.NewRecorder()
	s.handlePublic(rec, req)
	r.Equal(http.StatusFound, rec.Code)
	r.Equal("https://admin.example.com/", rec.Header().Get("Location"))

	req = httptest.NewRequest(http.MethodGet, "https://scimtest.example.com/missing", nil)
	rec = httptest.NewRecorder()
	s.handlePublic(rec, req)
	r.Equal(http.StatusNotFound, rec.Code)
}

func TestDashboardAndPublicHostsAreSeparated(t *testing.T) {
	r := require.New(t)
	s := &Server{
		cfg: Config{
			Domain:          "scimtest.rselbach.com",
			DashboardDomain: "admin.scimtest.rselbach.com",
			PublicScheme:    "https",
		},
		tunnels: make(map[string]*tunnel),
	}
	dashboardHandler := s.baseHostOnly(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	publicHandler := s.publicHostOnly(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	dashboardRequest := httptest.NewRequest(http.MethodGet, "https://admin.scimtest.rselbach.com/dashboard", nil)
	dashboardResponse := httptest.NewRecorder()
	dashboardHandler(dashboardResponse, dashboardRequest)
	r.Equal(http.StatusNoContent, dashboardResponse.Code)

	publicRequest := httptest.NewRequest(http.MethodGet, "https://scimtest.rselbach.com/dashboard", nil)
	publicResponse := httptest.NewRecorder()
	dashboardHandler(publicResponse, publicRequest)
	r.Equal(http.StatusNotFound, publicResponse.Code)

	wrongPublicRequest := httptest.NewRequest(http.MethodGet, "https://admin.scimtest.rselbach.com/api/connect", nil)
	wrongPublicResponse := httptest.NewRecorder()
	publicHandler(wrongPublicResponse, wrongPublicRequest)
	r.Equal(http.StatusNotFound, wrongPublicResponse.Code)
	r.Equal("https://admin.scimtest.rselbach.com/auth/github/callback", s.callbackURL())
}

func TestBaseHostOnlyAllowsLoopbackManagement(t *testing.T) {
	tests := map[string]struct {
		host string
		want int
	}{
		"configured domain":      {host: "scimtest.rselbach.com", want: http.StatusNoContent},
		"configured domain port": {host: "scimtest.rselbach.com:443", want: http.StatusNoContent},
		"localhost":              {host: "localhost:7000", want: http.StatusNoContent},
		"IPv4 loopback":          {host: "127.0.0.1:7000", want: http.StatusNoContent},
		"IPv6 loopback":          {host: "[::1]:7000", want: http.StatusNoContent},
		"other host":             {host: "demo.scimtest.rselbach.com", want: http.StatusNotFound},
	}
	s := &Server{
		cfg:     Config{Domain: "scimtest.rselbach.com"},
		tunnels: make(map[string]*tunnel),
	}
	handler := s.baseHostOnly(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "http://"+tc.host+"/dashboard", nil)
			request.Host = tc.host
			response := httptest.NewRecorder()
			handler(response, request)
			require.Equal(t, tc.want, response.Code)
		})
	}
}

func TestDashboardRequiresAuthentication(t *testing.T) {
	r := require.New(t)
	store, err := OpenStore(t.TempDir() + "/test.json")
	r.NoError(err)
	s := &Server{
		cfg: Config{
			Domain:       "localhost:7000",
			PublicScheme: "http",
			Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		},
		store:   store,
		tunnels: make(map[string]*tunnel),
	}

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	rec := httptest.NewRecorder()
	s.handleDashboard(rec, req)
	r.Equal(http.StatusFound, rec.Code)
	r.Equal("/login/github", rec.Header().Get("Location"))

	session, err := store.CreateSession("rselbach", true)
	r.NoError(err)
	req = httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session.ID})
	rec = httptest.NewRecorder()
	s.handleDashboard(rec, req)
	r.Equal(http.StatusOK, rec.Code)
	r.Contains(rec.Body.String(), "scimtest server")
	r.Contains(rec.Body.String(), "Signed in as rselbach")
	r.Contains(rec.Body.String(), `name="csrf_token"`)
}

func TestMaxTunnelsPerApplication(t *testing.T) {
	r := require.New(t)
	s := &Server{
		cfg:     Config{MaxTunnelsPerApplication: 2},
		tunnels: make(map[string]*tunnel),
	}

	newTunnel := func(id, profileID, instanceID string) *tunnel {
		return &tunnel{
			id:                   id,
			rootPath:             "/" + id,
			applicationName:      "Greendale SCIM",
			applicationProfileID: profileID,
			instanceID:           instanceID,
			requestSlots:         make(chan struct{}, 1),
		}
	}

	r.NoError(s.registerTunnel(newTunnel("t1", "profile-1", "instance-1")))
	r.NoError(s.registerTunnel(newTunnel("t2", "profile-1", "instance-2")))
	err := s.registerTunnel(newTunnel("t3", "profile-1", "instance-3"))
	r.ErrorContains(err, "maximum number of tunnels")
	r.NoError(s.registerTunnel(newTunnel("t4", "profile-2", "instance-1")))
}

func TestTunnelRequestSlots(t *testing.T) {
	r := require.New(t)
	tunnel := &tunnel{requestSlots: make(chan struct{}, 1)}

	r.True(tunnel.acquireRequestSlot())
	r.False(tunnel.acquireRequestSlot())
	tunnel.releaseRequestSlot()
	r.True(tunnel.acquireRequestSlot())
}

func TestTunnelForPathUsesFirstSegment(t *testing.T) {
	tun := &tunnel{rootPath: "/demo"}
	s := &Server{tunnels: map[string]*tunnel{"/demo": tun}}
	tests := map[string]*tunnel{
		"/demo":          tun,
		"/demo/resource": tun,
		"/demolition":    nil,
		"demo/resource":  nil,
		"/":              nil,
	}

	for value, want := range tests {
		t.Run(value, func(t *testing.T) {
			require.Same(t, want, s.tunnelForPath(value))
		})
	}
}

func TestHandlePublicRejectsWhenTunnelBusy(t *testing.T) {
	r := require.New(t)
	tun := &tunnel{
		id:           "demo",
		rootPath:     "/demo",
		routes:       []StoredApplicationRoute{{Methods: []string{http.MethodGet}, Path: "/"}},
		rateLimiter:  newApplicationRateLimiter(60, 10),
		requestSlots: make(chan struct{}, 1),
	}
	r.True(tun.acquireRequestSlot())
	s := &Server{
		cfg: Config{
			Domain:       "localhost:7000",
			PublicScheme: "http",
			Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		},
		tunnels: map[string]*tunnel{"/demo": tun},
	}

	req := httptest.NewRequest(http.MethodGet, "http://localhost:7000/demo", nil)
	req.Host = "localhost:7000"
	rec := httptest.NewRecorder()
	s.handlePublic(rec, req)
	r.Equal(http.StatusTooManyRequests, rec.Code)
	r.Contains(rec.Body.String(), "tunnel busy")
}

func TestHandlePublicClampsInvalidStatusCode(t *testing.T) {
	tests := map[string]struct {
		statusCode int
		want       int
	}{
		"too large": {statusCode: 99999, want: http.StatusBadGateway},
		"negative":  {statusCode: -1, want: http.StatusBadGateway},
		"below 100": {statusCode: 7, want: http.StatusBadGateway},
		"zero":      {statusCode: 0, want: http.StatusOK},
		"valid":     {statusCode: http.StatusTeapot, want: http.StatusTeapot},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			tun := &tunnel{
				id:           "demo",
				rootPath:     "/demo",
				routes:       []StoredApplicationRoute{{Methods: []string{http.MethodGet}, Path: "/"}},
				rateLimiter:  newApplicationRateLimiter(60, 10),
				requestSlots: make(chan struct{}, 1),
				send:         make(chan protocol.Message, 1),
				done:         make(chan struct{}),
				pending:      make(map[uint64]chan protocol.Message),
			}
			go func() {
				msg := <-tun.send
				tun.dispatch(protocol.Message{
					Type:       protocol.TypeResponse,
					StreamID:   msg.StreamID,
					StatusCode: tc.statusCode,
				})
			}()

			s := &Server{
				cfg: Config{
					Domain:       "localhost:7000",
					PublicScheme: "http",
					MaxBodyBytes: maxBodyBytesDefault,
					Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
				},
				tunnels: map[string]*tunnel{"/demo": tun},
			}

			req := httptest.NewRequest(http.MethodGet, "http://localhost:7000/demo", nil)
			req.Host = "localhost:7000"
			rec := httptest.NewRecorder()
			s.handlePublic(rec, req)
			r.Equal(tc.want, rec.Code)
		})
	}
}

func TestFailPendingDoesNotBlockWhenResponseQueued(t *testing.T) {
	r := require.New(t)
	response := make(chan protocol.Message, 1)
	response <- protocol.Message{Type: protocol.TypeResponse, StreamID: 1, StatusCode: http.StatusOK}
	tunnel := &tunnel{pending: map[uint64]chan protocol.Message{1: response}}

	done := make(chan struct{})
	go func() {
		tunnel.failPending()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("failPending blocked on a full response channel")
	}
	r.Empty(tunnel.pending)
}

func TestSchemeFromRequest(t *testing.T) {
	tests := map[string]struct {
		behindProxy bool
		tls         bool
		fwdProto    string
		want        string
	}{
		"direct http":                    {want: "http"},
		"direct https":                   {tls: true, want: "https"},
		"direct ignores forwarded proto": {fwdProto: "https", want: "http"},
		"trusted proxy proto":            {behindProxy: true, fwdProto: "https", want: "https"},
		"trusted proxy falls back":       {behindProxy: true, tls: true, want: "https"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			s := &Server{cfg: Config{BehindProxy: tc.behindProxy}}
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.behindProxy {
				request.RemoteAddr = "127.0.0.1:12345"
				var err error
				s.trustedProxyNets, err = parseTrustedProxyCIDRs(nil)
				r.NoError(err)
			}
			request.Header.Set("X-Forwarded-Proto", tc.fwdProto)
			if tc.tls {
				request.TLS = &tls.ConnectionState{}
			}
			r.Equal(tc.want, s.schemeFromRequest(request))
		})
	}
}

func TestAddForwardedHeadersStripsUntrusted(t *testing.T) {
	r := require.New(t)
	s := &Server{cfg: Config{BehindProxy: false}}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("X-Forwarded-For", "1.2.3.4")
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("X-Forwarded-Host", "evil.com")

	headers := make(http.Header)
	headers.Set("X-Forwarded-For", "5.6.7.8")
	s.addForwardedHeaders(headers, request)
	r.Equal("192.0.2.1", headers.Get("X-Forwarded-For"))
	r.Equal("example.com", headers.Get("X-Forwarded-Host"))
	r.Equal("http", headers.Get("X-Forwarded-Proto"))
}

func TestClientIPIgnoresSpoofedForwardedPrefix(t *testing.T) {
	r := require.New(t)
	s := &Server{cfg: Config{BehindProxy: true}}
	var err error
	s.trustedProxyNets, err = parseTrustedProxyCIDRs(nil)
	r.NoError(err)

	tests := map[string]struct {
		forwarded string
		want      string
	}{
		"spoofed prefix":        {forwarded: "6.6.6.6, 203.0.113.1", want: "203.0.113.1"},
		"chained trusted proxy": {forwarded: "6.6.6.6, 203.0.113.1, 127.0.0.2", want: "203.0.113.1"},
		"all trusted":           {forwarded: "127.0.0.2", want: "127.0.0.1"},
		"unparsable":            {forwarded: "not-an-ip", want: "127.0.0.1"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			request.RemoteAddr = "127.0.0.1:12345"
			request.Header.Set("X-Forwarded-For", tc.forwarded)
			require.Equal(t, tc.want, s.clientIP(request))
		})
	}
}

func TestParseTrustedProxyCIDRsRejectsInvalidValue(t *testing.T) {
	_, err := parseTrustedProxyCIDRs([]string{"not-a-cidr"})
	require.ErrorContains(t, err, "invalid trusted proxy CIDR")
}

func TestNewRejectsConflictingConnectPath(t *testing.T) {
	tests := map[string]string{
		"dashboard": "/dashboard",
		"escaped":   "/d%61shboard",
		"malformed": "/api/%zz",
		"OAuth":     "/login/github",
		"root":      "/",
		"parameter": "/api/{connect}",
	}
	for name, connectPath := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := New(Config{ConnectPath: connectPath, DataPath: t.TempDir() + "/test.json"})
			require.ErrorContains(t, err, "connect path")
		})
	}
}

func TestNewRequiresSeparateDashboardOriginForOAuth(t *testing.T) {
	for name, cfg := range map[string]Config{
		"same host": {
			Domain:             "scimtest.example.com",
			GitHubClientID:     "client-id",
			GitHubClientSecret: "client-secret",
		},
		"different ports": {
			Domain:             "scimtest.example.com:8443",
			DashboardDomain:    "scimtest.example.com:9443",
			GitHubClientID:     "client-id",
			GitHubClientSecret: "client-secret",
		},
		"implicit port": {
			Domain:             "scimtest.example.com",
			DashboardDomain:    "scimtest.example.com:443",
			GitHubClientID:     "client-id",
			GitHubClientSecret: "client-secret",
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg.DataPath = t.TempDir() + "/test.json"
			_, err := New(cfg)
			require.ErrorContains(t, err, "dashboard domain must differ")
		})
	}

	_, err := New(Config{
		Domain:          "scimtest.example.com",
		DashboardDomain: "admin.example.com",
		GitHubClientID:  "client-id",
		DataPath:        t.TempDir() + "/test.json",
	})
	require.ErrorContains(t, err, "both GitHub client ID and secret")
}

func TestSecurityHeaders(t *testing.T) {
	r := require.New(t)
	s := &Server{
		cfg:     Config{Domain: "example.com", PublicScheme: "https"},
		tunnels: map[string]*tunnel{"/demo": {rootPath: "/demo"}},
	}

	request := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	request.Host = "example.com"
	response := httptest.NewRecorder()
	s.securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(response, request)
	r.NotEmpty(response.Header().Get("Strict-Transport-Security"))
	r.NotEmpty(response.Header().Get("Permissions-Policy"))

	request = httptest.NewRequest(http.MethodGet, "https://example.com/demo", nil)
	request.Host = "example.com"
	response = httptest.NewRecorder()
	s.securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(response, request)
	r.Equal([]string{"SAMEORIGIN"}, response.Header().Values("X-Frame-Options"))
	r.Empty(response.Header().Get("Strict-Transport-Security"))
}

func TestResponseWriterImplementsHijackerAndFlusher(t *testing.T) {
	r := require.New(t)
	rw := &responseWriter{ResponseWriter: httptest.NewRecorder()}
	_, ok := any(rw).(http.Hijacker)
	r.True(ok)
	_, ok = any(rw).(http.Flusher)
	r.True(ok)
}

func TestTemplatesParse(t *testing.T) {
	r := require.New(t)
	r.NotNil(landingTemplate)
	r.NotNil(dashboardTemplate)
	r.NotNil(tunnelTablePartial)
}

func TestHealthReadyAndMetrics(t *testing.T) {
	r := require.New(t)
	s := &Server{
		cfg:     Config{MaxTunnelsPerApplication: 5},
		tunnels: make(map[string]*tunnel),
	}
	for _, handler := range []http.HandlerFunc{s.handleHealthz, s.handleReady} {
		response := httptest.NewRecorder()
		handler(response, httptest.NewRequest(http.MethodGet, "/", nil))
		r.Equal(http.StatusOK, response.Code)
		r.Contains(response.Body.String(), "ok")
	}

	request := httptest.NewRequest(http.MethodGet, "/api/metrics", nil)
	response := httptest.NewRecorder()
	s.handleMetrics(response, request)
	r.Contains(response.Body.String(), `"tunnels_active":0`)

	tunnel := &tunnel{
		id:                   "m1",
		rootPath:             "/m1",
		applicationName:      "Greendale SCIM",
		applicationProfileID: "profile-1",
		instanceID:           "instance-1",
		requestSlots:         make(chan struct{}, 1),
	}
	r.NoError(s.registerTunnel(tunnel))
	response = httptest.NewRecorder()
	s.handleMetrics(response, request)
	r.Contains(response.Body.String(), `"tunnels_active":1`)
	r.Contains(response.Body.String(), `"tunnels_total":1`)

	s.unregisterTunnel(tunnel)
	response = httptest.NewRecorder()
	s.handleMetrics(response, request)
	r.Contains(response.Body.String(), `"tunnels_active":0`)
	r.Contains(response.Body.String(), `"tunnels_total":1`)
}

func TestRequirePost(t *testing.T) {
	r := require.New(t)
	handler := (&Server{}).requirePost(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	response := httptest.NewRecorder()
	handler(response, httptest.NewRequest(http.MethodGet, "/", nil))
	r.Equal(http.StatusMethodNotAllowed, response.Code)
	r.Equal(http.MethodPost, response.Header().Get("Allow"))

	response = httptest.NewRecorder()
	handler(response, httptest.NewRequest(http.MethodPost, "/", nil))
	r.Equal(http.StatusNoContent, response.Code)
}

func TestTrustedProxyIP(t *testing.T) {
	r := require.New(t)
	_, network, err := net.ParseCIDR("192.0.2.0/24")
	r.NoError(err)
	s := &Server{trustedProxyNets: []*net.IPNet{network}}
	r.True(s.trustedProxyIP(net.ParseIP("192.0.2.10")))
	r.False(s.trustedProxyIP(net.ParseIP("198.51.100.10")))
}
