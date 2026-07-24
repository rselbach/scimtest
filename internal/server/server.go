package server

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rselbach/scimtest/internal/auth"
	"github.com/rselbach/scimtest/internal/httputil"
	"github.com/rselbach/scimtest/internal/protocol"
)

const (
	maxBodyBytesDefault   = protocol.MaxBodyBytesDefault
	pingInterval          = 25 * time.Second
	registrationTimeout   = 30 * time.Second
	tunnelReadTimeout     = 3 * pingInterval
	writeTimeout          = 10 * time.Second
	closeWriteTimeout     = 2 * time.Second
	tunnelResponseTimeout = 2 * time.Minute
	maxRandomIDAttempts   = 10
	sendChannelSize       = 64
)

type Config struct {
	Addr                     string
	Domain                   string
	DashboardDomain          string
	PublicScheme             string
	ConnectPath              string
	DataPath                 string
	GitHubClientID           string
	GitHubClientSecret       string
	MaxBodyBytes             int64
	Logger                   *slog.Logger
	ShutdownTimeout          time.Duration
	MaxTunnelsPerApplication int
	BehindProxy              bool
	TrustedProxyCIDRs        []string
}

type Server struct {
	cfg              Config
	store            *Store
	github           auth.GitHubClient
	trustedProxyNets []*net.IPNet

	mu      sync.RWMutex
	tunnels map[string]*tunnel

	nextStream    atomic.Uint64
	requestsTotal atomic.Uint64
	tunnelsActive atomic.Int64
	tunnelsTotal  atomic.Uint64
}

type tunnel struct {
	id                   string
	rootPath             string
	publicURL            string
	applicationName      string
	localPort            int
	connectedAt          time.Time
	requests             atomic.Int64
	applicationProfileID string
	instanceID           string
	routes               []StoredApplicationRoute
	rateLimiter          *applicationRateLimiter
	logger               *slog.Logger
	conn                 *websocket.Conn
	send                 chan protocol.Message
	done                 chan struct{}
	requestSlots         chan struct{}

	pendingMu sync.Mutex
	pending   map[uint64]chan protocol.Message
}

func New(cfg Config) (*Server, error) {
	if cfg.Addr == "" {
		cfg.Addr = ":7000"
	}
	if cfg.Domain == "" {
		cfg.Domain = "localhost:7000"
	}
	if cfg.PublicScheme == "" {
		cfg.PublicScheme = "http"
	}
	if cfg.PublicScheme == "https" || cfg.BehindProxy {
		cfg.PublicScheme = "https"
	}
	if cfg.ConnectPath == "" {
		cfg.ConnectPath = "/api/connect"
	}
	if err := validateConnectPath(cfg.ConnectPath); err != nil {
		return nil, err
	}
	if cfg.DataPath == "" {
		cfg.DataPath = "scimtest-server.json"
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = maxBodyBytesDefault
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	trustedProxyNets, err := parseTrustedProxyCIDRs(cfg.TrustedProxyCIDRs)
	if err != nil {
		return nil, err
	}

	cfg.Domain = strings.TrimPrefix(strings.TrimPrefix(cfg.Domain, "https://"), "http://")
	cfg.Domain = strings.TrimRight(cfg.Domain, "/")
	if cfg.DashboardDomain == "" {
		cfg.DashboardDomain = cfg.Domain
	}
	cfg.DashboardDomain = strings.TrimPrefix(strings.TrimPrefix(cfg.DashboardDomain, "https://"), "http://")
	cfg.DashboardDomain = strings.TrimRight(cfg.DashboardDomain, "/")
	if (cfg.GitHubClientID == "") != (cfg.GitHubClientSecret == "") {
		return nil, errors.New("both GitHub client ID and secret are required")
	}
	if cfg.GitHubClientID != "" && sameHost(cfg.Domain, cfg.DashboardDomain) {
		return nil, errors.New("dashboard domain must differ from the public tunnel domain")
	}

	if cfg.ShutdownTimeout <= 0 {
		cfg.ShutdownTimeout = 30 * time.Second
	}
	if cfg.MaxTunnelsPerApplication <= 0 {
		cfg.MaxTunnelsPerApplication = 5
	}

	store, err := OpenStore(cfg.DataPath)
	if err != nil {
		return nil, err
	}

	return &Server{
		cfg:              cfg,
		store:            store,
		github:           auth.GitHubClient{ClientID: cfg.GitHubClientID, ClientSecret: cfg.GitHubClientSecret},
		trustedProxyNets: trustedProxyNets,
		tunnels:          make(map[string]*tunnel),
	}, nil
}

func (s *Server) Run() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/ready", s.handleReady)
	mux.HandleFunc("/api/metrics", s.baseHostOnly(s.handleMetrics))
	mux.HandleFunc(s.cfg.ConnectPath, s.publicHostOnly(s.handleConnect))
	mux.HandleFunc("/login/github", s.baseHostOnly(s.handleGitHubLogin))
	mux.HandleFunc("/auth/github/callback", s.baseHostOnly(s.handleGitHubCallback))
	mux.HandleFunc("/logout", s.baseHostOnly(s.requirePost(s.handleLogout)))
	mux.HandleFunc("/dashboard", s.baseHostOnly(s.handleDashboard))
	mux.HandleFunc("/dashboard/app.js", s.baseHostOnly(s.handleDashboardJS))
	mux.HandleFunc("/dashboard/tunnels", s.baseHostOnly(s.handleDashboardTunnels))
	mux.HandleFunc("/dashboard/applications/create", s.baseHostOnly(s.requirePost(s.handleCreateApplication)))
	mux.HandleFunc("/dashboard/applications/update", s.baseHostOnly(s.requirePost(s.handleUpdateApplication)))
	mux.HandleFunc("/dashboard/applications/delete", s.baseHostOnly(s.requirePost(s.handleDeleteApplication)))
	mux.HandleFunc("/dashboard/applications/reservations/delete", s.baseHostOnly(s.requirePost(s.handleUnreserveApplicationTunnel)))
	mux.HandleFunc("/dashboard/tunnels/disconnect", s.baseHostOnly(s.requirePost(s.handleDisconnectTunnel)))
	mux.HandleFunc("/", s.handlePublic)

	handler := s.securityHeaders(s.logRequest(mux))

	srv := &http.Server{
		Addr:           s.cfg.Addr,
		Handler:        handler,
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   tunnelResponseTimeout + 10*time.Second,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	s.cfg.Logger.Info("scimtest server listening", "addr", s.cfg.Addr, "domain", s.cfg.Domain, "connect_path", s.cfg.ConnectPath)

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe()
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-errCh:
		return err
	case sig := <-sigCh:
		s.cfg.Logger.Info("shutting down", "signal", sig.String())
		ctx, cancel := context.WithTimeout(context.Background(), s.cfg.ShutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			s.cfg.Logger.Error("shutdown failed", "err", err)
			return err
		}
		s.cfg.Logger.Info("shutdown complete")
		return nil
	}
}

type responseWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (w *responseWriter) WriteHeader(code int) {
	if w.wrote {
		return
	}
	w.status = code
	w.wrote = true
	w.ResponseWriter.WriteHeader(code)
}

func (w *responseWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

func (w *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("response writer does not support hijacking")
	}
	return h.Hijack()
}

func (w *responseWriter) Flush() {
	f, ok := w.ResponseWriter.(http.Flusher)
	if ok {
		f.Flush()
	}
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"status": "ok"}); err != nil {
		s.logger().Warn("health response write failed", "err", err)
	}
}

func (s *Server) handleReady(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"status": "ok"}); err != nil {
		s.logger().Warn("readiness response write failed", "err", err)
	}
}

func (s *Server) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{
		"requests_total": s.requestsTotal.Load(),
		"tunnels_active": s.tunnelsActive.Load(),
		"tunnels_total":  s.tunnelsTotal.Load(),
	}); err != nil {
		s.logger().Warn("metrics response write failed", "err", err)
	}
}

func (s *Server) logger() *slog.Logger {
	if s.cfg.Logger != nil {
		return s.cfg.Logger
	}
	return slog.Default()
}

func (s *Server) cookieSecure() bool {
	return s.cfg.PublicScheme == "https" || s.cfg.BehindProxy
}

func (s *Server) logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriter{ResponseWriter: w}
		next.ServeHTTP(rw, r)
		s.requestsTotal.Add(1)
		s.cfg.Logger.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"remote", r.RemoteAddr,
			"status", rw.status,
			"duration", time.Since(start),
		)
	})
}

// securityHeaders hardens the server's own pages. Tunnel paths are skipped:
// their responses belong to the proxied app, and presetting headers here
// would duplicate or override the app's own policies.
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverPage := s.isDashboardHost(r.Host)
		if s.isPublicHost(r.Host) {
			serverPage = s.tunnelForPath(r.URL.Path) == nil
		}
		if serverPage {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
			w.Header().Set("Permissions-Policy", "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()")
			if s.cfg.PublicScheme == "https" || s.cfg.BehindProxy {
				w.Header().Set("Strict-Transport-Security", "max-age=63072000")
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) baseHostOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.isDashboardHost(r.Host) {
			s.handlePublic(w, r)
			return
		}
		next(w, r)
	}
}

func (s *Server) publicHostOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.isPublicHost(r.Host) {
			http.NotFound(w, r)
			return
		}
		next(w, r)
	}
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			if origin == "" {
				return true
			}
			origin = strings.TrimPrefix(strings.TrimPrefix(origin, "https://"), "http://")
			return s.isPublicHost(origin)
		},
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.cfg.Logger.Warn("websocket upgrade failed", "err", err)
		return
	}
	defer func() {
		if err := conn.Close(); err != nil {
			s.logger().Debug("close tunnel connection failed", "err", err)
		}
	}()
	conn.SetReadLimit(protocol.MaxMessageBytes(s.cfg.MaxBodyBytes))

	// Bound the whole registration handshake, including the application
	// challenge exchange, so unauthenticated connections cannot idle.
	if err := conn.SetReadDeadline(time.Now().Add(registrationTimeout)); err != nil {
		s.logger().Warn("set registration deadline failed", "err", err)
		return
	}

	var reg protocol.Message
	if err := conn.ReadJSON(&reg); err != nil {
		s.cfg.Logger.Warn("registration read failed", "err", err)
		return
	}
	if reg.Type != protocol.TypeRegisterTunnel {
		s.writeClose(conn, websocket.CloseProtocolError, "expected register_tunnel")
		return
	}

	profile, err := s.authenticateApplicationRegistration(conn, reg)
	if err != nil {
		s.writeClose(conn, websocket.ClosePolicyViolation, err.Error())
		return
	}

	id, err := s.chooseApplicationID(profile.ID, reg.InstanceID)
	if err != nil {
		s.writeClose(conn, websocket.ClosePolicyViolation, err.Error())
		return
	}

	rootPath := "/" + id
	t := &tunnel{
		id:                   id,
		rootPath:             rootPath,
		publicURL:            s.cfg.PublicScheme + "://" + s.cfg.Domain + rootPath,
		applicationName:      profile.Name,
		localPort:            reg.LocalPort,
		connectedAt:          time.Now().UTC(),
		applicationProfileID: profile.ID,
		instanceID:           reg.InstanceID,
		routes:               profile.Routes,
		rateLimiter:          newApplicationRateLimiter(profile.RequestsPerMinute, profile.RequestBurst),
		conn:                 conn,
		send:                 make(chan protocol.Message, sendChannelSize),
		done:                 make(chan struct{}),
		requestSlots:         make(chan struct{}, profile.ConcurrentRequests),
		logger:               s.logger(),
		pending:              make(map[uint64]chan protocol.Message),
	}

	if err := s.registerTunnel(t); err != nil {
		s.writeClose(conn, websocket.ClosePolicyViolation, err.Error())
		return
	}
	if err := s.store.RememberApplicationTunnel(profile.ID, reg.InstanceID, id); err != nil {
		s.unregisterTunnel(t)
		s.writeClose(conn, websocket.CloseInternalServerErr, "could not remember application tunnel")
		return
	}
	defer s.unregisterTunnel(t)

	s.cfg.Logger.Info("tunnel connected", "id", t.id, "root_path", t.rootPath, "application", t.applicationName, "local_port", reg.LocalPort)

	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		t.writeLoop()
	}()

	t.send <- protocol.Message{
		Type:      protocol.TypeTunnelRegistered,
		TunnelID:  t.id,
		PublicURL: t.publicURL,
		ClientIP:  s.clientIP(r),
	}

	// The client answers every ping, so a healthy tunnel delivers a message
	// at least once per ping interval; refreshing the read deadline on each
	// message tears down dead connections instead of holding their names.
	for {
		if err := conn.SetReadDeadline(time.Now().Add(tunnelReadTimeout)); err != nil {
			s.logger().Warn("set tunnel read deadline failed", "id", t.id, "err", err)
			break
		}
		var msg protocol.Message
		if err := conn.ReadJSON(&msg); err != nil {
			if !websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				s.cfg.Logger.Warn("tunnel read failed", "id", t.id, "err", err)
			}
			break
		}
		switch msg.Type {
		case protocol.TypeResponse:
			t.dispatch(msg)
		case protocol.TypePong:
		default:
			s.cfg.Logger.Debug("ignoring tunnel message", "id", t.id, "type", msg.Type)
		}
	}

	close(t.done)
	t.failPending()
	<-writerDone
	s.cfg.Logger.Info("tunnel disconnected", "id", t.id)
}

func (s *Server) handlePublic(w http.ResponseWriter, r *http.Request) {
	if s.isDashboardHost(r.Host) && r.URL.Path == "/" {
		s.handleLanding(w, r)
		return
	}
	if !s.isPublicHost(r.Host) {
		http.NotFound(w, r)
		return
	}

	t := s.tunnelForPath(r.URL.Path)
	if t == nil {
		s.writeIndexOrNotFound(w, r)
		return
	}
	if !applicationRequestAllowed(t.routes, t.rootPath, r) {
		http.NotFound(w, r)
		return
	}
	if !t.rateLimiter.allow() {
		http.Error(w, "tunnel rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	if !t.acquireRequestSlot() {
		http.Error(w, "tunnel busy", http.StatusTooManyRequests)
		return
	}
	defer t.releaseRequestSlot()
	t.requests.Add(1)

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes))
	if err != nil {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	defer func() {
		if err := r.Body.Close(); err != nil {
			s.logger().Warn("close public request body failed", "err", err)
		}
	}()

	streamID := s.nextStream.Add(1)
	respCh := t.addPending(streamID)
	defer t.removePending(streamID)

	headers := httputil.CloneHeader(r.Header)
	httputil.RemoveHopHeaders(headers)
	s.addForwardedHeaders(headers, r)

	req := protocol.Message{
		Type:     protocol.TypeRequest,
		StreamID: streamID,
		Method:   r.Method,
		Path:     r.URL.RequestURI(),
		Host:     r.Host,
		Scheme:   s.schemeFromRequest(r),
		Header:   headers,
		Body:     body,
	}

	select {
	case t.send <- req:
	case <-t.done:
		http.Error(w, "tunnel disconnected", http.StatusBadGateway)
		return
	case <-r.Context().Done():
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), tunnelResponseTimeout)
	defer cancel()

	var resp protocol.Message
	select {
	case resp = <-respCh:
	case <-t.done:
		http.Error(w, "tunnel disconnected", http.StatusBadGateway)
		return
	case <-ctx.Done():
		http.Error(w, "tunnel response timed out", http.StatusGatewayTimeout)
		return
	}

	if resp.Error != "" {
		http.Error(w, resp.Error, http.StatusBadGateway)
		return
	}

	respHeaders := httputil.CloneHeader(resp.Header)
	httputil.RemoveHopHeaders(respHeaders)
	for key, values := range respHeaders {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	status := resp.StatusCode
	if status == 0 {
		status = http.StatusOK
	}
	// The status comes from client JSON; WriteHeader panics outside 1xx-9xx.
	if status < 100 || status > 999 {
		status = http.StatusBadGateway
	}
	w.WriteHeader(status)
	if _, err := w.Write(resp.Body); err != nil {
		s.logger().Warn("public response write failed", "err", err)
	}
}

func (s *Server) authenticateApplicationRegistration(conn *websocket.Conn, reg protocol.Message) (*StoredApplicationProfile, error) {
	if !applicationIDRE.MatchString(reg.ApplicationProfileID) || !instanceIDRE.MatchString(reg.InstanceID) {
		return nil, errors.New("invalid application profile or instance id")
	}
	profile, ok := s.store.ApplicationProfile(reg.ApplicationProfileID)
	if !ok {
		return nil, errors.New("invalid application profile")
	}
	challenge, err := randomHex(32)
	if err != nil {
		return nil, errors.New("could not create application challenge")
	}
	if err := conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return nil, fmt.Errorf("set application challenge deadline: %w", err)
	}
	if err := conn.WriteJSON(protocol.Message{
		Type:      protocol.TypeApplicationChallenge,
		Challenge: challenge,
	}); err != nil {
		return nil, fmt.Errorf("write application challenge: %w", err)
	}
	var response protocol.Message
	if err := conn.ReadJSON(&response); err != nil {
		return nil, fmt.Errorf("read application signature: %w", err)
	}
	if response.Type != protocol.TypeApplicationSignature {
		return nil, errors.New("expected application signature")
	}
	_, publicKey, _, err := parseEd25519PublicKey(profile.PublicKey)
	if err != nil {
		return nil, errors.New("application profile has an invalid public key")
	}
	payload := protocol.ApplicationChallengePayload(profile.ID, reg.InstanceID, challenge)
	if !ed25519.Verify(publicKey, payload, response.Signature) {
		return nil, errors.New("invalid application signature")
	}
	return &profile, nil
}

func (s *Server) tunnelForPath(value string) *tunnel {
	if value == "" || value[0] != '/' {
		return nil
	}
	rootPath := value
	if end := strings.IndexByte(value[1:], '/'); end >= 0 {
		rootPath = value[:end+1]
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tunnels[rootPath]
}

func (s *Server) writeIndexOrNotFound(w http.ResponseWriter, r *http.Request) {
	host := strings.ToLower(r.Host)
	if !s.isPublicHost(host) || r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	http.Redirect(w, r, s.cfg.PublicScheme+"://"+s.dashboardDomain()+"/", http.StatusFound)
}

func (s *Server) chooseID() (string, error) {
	for i := 0; i < maxRandomIDAttempts; i++ {
		id := randomID()
		if id == s.connectRootSegment() {
			continue
		}
		s.mu.RLock()
		_, exists := s.tunnels["/"+id]
		s.mu.RUnlock()
		if !exists && !s.store.TunnelIDReserved(id) {
			return id, nil
		}
	}
	return "", errors.New("could not allocate tunnel id")
}

func (s *Server) chooseApplicationID(profileID, instanceID string) (string, error) {
	s.mu.RLock()
	for _, existing := range s.tunnels {
		if existing.applicationProfileID == profileID && existing.instanceID == instanceID {
			s.mu.RUnlock()
			return "", errors.New("application instance already has an active tunnel")
		}
	}
	s.mu.RUnlock()

	remembered := s.store.ApplicationTunnelID(profileID, instanceID)
	if remembered != "" && remembered != s.connectRootSegment() {
		s.mu.RLock()
		_, exists := s.tunnels["/"+remembered]
		s.mu.RUnlock()
		if !exists {
			return remembered, nil
		}
	}
	return s.chooseID()
}

func (s *Server) registerTunnel(t *tunnel) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	count := 0
	for _, existing := range s.tunnels {
		if existing.applicationProfileID == t.applicationProfileID && existing.instanceID == t.instanceID {
			return errors.New("application instance already has an active tunnel")
		}
		if existing.applicationProfileID == t.applicationProfileID {
			count++
		}
	}
	if count >= s.cfg.MaxTunnelsPerApplication {
		return fmt.Errorf("maximum number of tunnels (%d) reached for application %s", s.cfg.MaxTunnelsPerApplication, t.applicationName)
	}

	if t.requestSlots == nil {
		return errors.New("application tunnel has no request limit")
	}

	if _, exists := s.tunnels[t.rootPath]; exists {
		return fmt.Errorf("root path %q is already connected", t.rootPath)
	}
	s.tunnels[t.rootPath] = t
	s.tunnelsActive.Add(1)
	s.tunnelsTotal.Add(1)
	return nil
}

func (s *Server) unregisterTunnel(t *tunnel) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tunnels, t.rootPath)
	s.tunnelsActive.Add(-1)
}

func (t *tunnel) writeLoop() {
	ticker := time.NewTicker(pingInterval)
	defer ticker.Stop()

	for {
		select {
		case msg := <-t.send:
			if err := t.conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
				t.failWrite("set tunnel write deadline failed", err)
				return
			}
			if err := t.conn.WriteJSON(msg); err != nil {
				t.failWrite("tunnel write failed", err)
				return
			}
		case <-ticker.C:
			if err := t.conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
				t.failWrite("set tunnel ping deadline failed", err)
				return
			}
			if err := t.conn.WriteJSON(protocol.Message{Type: protocol.TypePing}); err != nil {
				t.failWrite("tunnel ping failed", err)
				return
			}
		case <-t.done:
			if err := t.conn.SetWriteDeadline(time.Now().Add(closeWriteTimeout)); err != nil {
				t.log().Warn("set tunnel close deadline failed", "id", t.id, "err", err)
				return
			}
			if err := t.conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "bye")); err != nil {
				t.log().Warn("tunnel close message failed", "id", t.id, "err", err)
			}
			return
		}
	}
}

func (t *tunnel) failWrite(message string, err error) {
	if closeErr := t.conn.Close(); closeErr != nil {
		err = errors.Join(err, fmt.Errorf("close tunnel connection: %w", closeErr))
	}
	t.log().Warn(message, "id", t.id, "err", err)
}

func (t *tunnel) log() *slog.Logger {
	if t.logger != nil {
		return t.logger
	}
	return slog.Default()
}

func (t *tunnel) acquireRequestSlot() bool {
	select {
	case t.requestSlots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (t *tunnel) releaseRequestSlot() {
	select {
	case <-t.requestSlots:
	default:
	}
}

func (t *tunnel) addPending(streamID uint64) chan protocol.Message {
	ch := make(chan protocol.Message, 1)
	t.pendingMu.Lock()
	t.pending[streamID] = ch
	t.pendingMu.Unlock()
	return ch
}

func (t *tunnel) removePending(streamID uint64) {
	t.pendingMu.Lock()
	delete(t.pending, streamID)
	t.pendingMu.Unlock()
}

func (t *tunnel) dispatch(msg protocol.Message) {
	t.pendingMu.Lock()
	ch := t.pending[msg.StreamID]
	t.pendingMu.Unlock()
	if ch == nil {
		return
	}
	select {
	case ch <- msg:
	default:
	}
}

func (t *tunnel) failPending() {
	t.pendingMu.Lock()
	defer t.pendingMu.Unlock()
	for streamID, ch := range t.pending {
		msg := protocol.Message{
			Type:     protocol.TypeResponse,
			StreamID: streamID,
			Error:    "tunnel disconnected",
		}
		select {
		case ch <- msg:
		default:
		}
		delete(t.pending, streamID)
	}
}

func randomID() string {
	adjectives := []string{
		"airconditioned",
		"blanket",
		"campus",
		"chicken",
		"cosmic",
		"deans",
		"dreamatorium",
		"greendale",
		"human",
		"paintball",
		"pillow",
		"remedial",
		"study",
	}
	nouns := []string{
		"annex",
		"beetle",
		"changnesia",
		"dean",
		"diorama",
		"inspector",
		"meowmeow",
		"pelton",
		"popper",
		"room",
		"timeline",
		"troy",
		"winger",
	}
	suffixes := []string{
		"club",
		"college",
		"committee",
		"fort",
		"group",
		"heist",
		"night",
		"party",
		"quest",
		"semester",
		"table",
		"year",
	}

	name := strings.Join([]string{
		randomChoice(adjectives),
		randomChoice(nouns),
		randomChoice(suffixes),
	}, "-")
	return name
}

func randomChoice(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[rand.IntN(len(values))]
}

func (s *Server) writeClose(conn *websocket.Conn, code int, text string) {
	if err := conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(code, text)); err != nil {
		s.logger().Warn("tunnel close write failed", "code", code, "err", err)
	}
}

// clientIP returns the address of the closest untrusted hop. Behind a
// trusted proxy that is the rightmost X-Forwarded-For entry not itself a
// trusted proxy; leftmost entries are client-supplied and spoofable.
func (s *Server) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if !s.requestFromTrustedProxy(r) {
		return host
	}
	entries := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(entries) - 1; i >= 0; i-- {
		entry := strings.TrimSpace(entries[i])
		if entry == "" {
			continue
		}
		ip := net.ParseIP(entry)
		if ip == nil {
			return host
		}
		if !s.trustedProxyIP(ip) {
			return entry
		}
	}
	return host
}

func (s *Server) addForwardedHeaders(h http.Header, r *http.Request) {
	h.Del("X-Forwarded-For")
	h.Del("X-Forwarded-Host")
	h.Del("X-Forwarded-Proto")

	h.Set("X-Forwarded-For", s.clientIP(r))
	h.Set("X-Forwarded-Host", r.Host)
	h.Set("X-Forwarded-Proto", s.schemeFromRequest(r))
}

func (s *Server) schemeFromRequest(r *http.Request) string {
	if s.requestFromTrustedProxy(r) {
		if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
			return proto
		}
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func parseTrustedProxyCIDRs(raw []string) ([]*net.IPNet, error) {
	if len(raw) == 0 {
		raw = []string{"127.0.0.0/8", "::1/128"}
	}
	nets := make([]*net.IPNet, 0, len(raw))
	for _, value := range raw {
		for _, part := range strings.Split(value, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			_, ipNet, err := net.ParseCIDR(part)
			if err != nil {
				return nil, fmt.Errorf("invalid trusted proxy CIDR %q: %w", part, err)
			}
			nets = append(nets, ipNet)
		}
	}
	return nets, nil
}

func (s *Server) requestFromTrustedProxy(r *http.Request) bool {
	if !s.cfg.BehindProxy {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return s.trustedProxyIP(ip)
}

func (s *Server) trustedProxyIP(ip net.IP) bool {
	for _, ipNet := range s.trustedProxyNets {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

func sameHost(a, b string) bool {
	return normalizedHostname(a) == normalizedHostname(b)
}

func (s *Server) isPublicHost(host string) bool {
	return sameHostOrLoopback(host, s.cfg.Domain)
}

func (s *Server) isDashboardHost(host string) bool {
	return sameHostOrLoopback(host, s.dashboardDomain())
}

func (s *Server) dashboardDomain() string {
	if s.cfg.DashboardDomain != "" {
		return s.cfg.DashboardDomain
	}
	return s.cfg.Domain
}

func sameHostOrLoopback(host, configured string) bool {
	if sameHost(host, configured) {
		return true
	}
	host = normalizedHostname(host)
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validateConnectPath(value string) error {
	if err := validateApplicationPath(value); err != nil {
		return fmt.Errorf("invalid connect path: %w", err)
	}
	for _, char := range value {
		switch {
		case char >= 'a' && char <= 'z':
		case char >= 'A' && char <= 'Z':
		case char >= '0' && char <= '9':
		case strings.ContainsRune("/-._~", char):
		default:
			return errors.New("invalid connect path: only literal URL path characters are allowed")
		}
	}
	managementPaths := map[string]bool{
		"/":                              true,
		"/healthz":                       true,
		"/ready":                         true,
		"/api/metrics":                   true,
		"/login/github":                  true,
		"/auth/github/callback":          true,
		"/logout":                        true,
		"/dashboard":                     true,
		"/dashboard/app.js":              true,
		"/dashboard/tunnels":             true,
		"/dashboard/applications/create": true,
		"/dashboard/applications/update": true,
		"/dashboard/applications/delete": true,
		"/dashboard/applications/reservations/delete": true,
		"/dashboard/tunnels/disconnect":               true,
	}
	if managementPaths[value] {
		return fmt.Errorf("connect path %q conflicts with a server route", value)
	}
	return nil
}

func normalizedHostname(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if withoutPort, _, err := net.SplitHostPort(value); err == nil {
		value = withoutPort
	}
	return strings.TrimSuffix(strings.Trim(value, "[]"), ".")
}

func (s *Server) connectRootSegment() string {
	value := strings.TrimPrefix(s.cfg.ConnectPath, "/")
	if end := strings.IndexByte(value, '/'); end >= 0 {
		return value[:end]
	}
	return value
}
