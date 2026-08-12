package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rselbach/scimtest/internal/httputil"
	"github.com/rselbach/scimtest/internal/protocol"
)

const (
	maxBodyBytesDefault                 = 32 << 20
	writeTimeout                        = 10 * time.Second
	httpClientTimeout                   = 2 * time.Minute
	enrollmentRequestTimeout            = 15 * time.Second
	defaultEnrollmentPoll               = 2 * time.Second
	maxEnrollmentPoll                   = 60 * time.Second
	maxEnrollmentURLLength              = 2048
	maxEnrollmentDeviceCodeLength       = 256
	maxEnrollmentVerificationCodeLength = 64
	sendChannelSize                     = 64
	maxConcurrentRequestsDefault        = 32
)

type Config struct {
	ServerURL             string
	ApplicationProfileID  string
	InstanceID            string
	ApplicationPrivateKey ed25519.PrivateKey
	InstancePrivateKey    ed25519.PrivateKey
	LocalHost             string
	LocalPort             int
	PreserveHost          bool
	MaxBodyBytes          int64
	Logger                *slog.Logger
	ReconnectTimeout      time.Duration
	MaxConcurrentRequests int
	Output                io.Writer
	OnRegistered          func(Registration)
	OnEnrollmentRequired  func(Enrollment)
}

type Registration struct {
	TunnelID     string
	PublicURL    string
	ClientIP     string
	GitHubUserID int64
	GitHubLogin  string
}

// Enrollment identifies where the user can authorize this installation.
// Generic clients should open URL and show VerificationCode independently for
// comparison. Trusted local UIs may open the short-lived, single-use
// BrowserHandoffURL directly instead. The device secret used to poll enrollment
// status is never exposed to callbacks.
type Enrollment struct {
	URL               string
	BrowserHandoffURL string
	VerificationCode  string
}

type Client struct {
	cfg             Config
	httpClient      *http.Client
	enrollmentGrant string
}

type enrollmentRequiredError struct {
	url               string
	browserHandoffURL string
	verificationCode  string
	statusURL         string
	deviceCode        string
	pollInterval      time.Duration
}

func (e *enrollmentRequiredError) Error() string {
	return "tunnel enrollment required"
}

func New(cfg Config) *Client {
	if cfg.ServerURL == "" {
		cfg.ServerURL = "ws://localhost:7000/api/connect"
	}
	if cfg.LocalHost == "" {
		cfg.LocalHost = "127.0.0.1"
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = maxBodyBytesDefault
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Output == nil {
		cfg.Output = os.Stdout
	}
	if cfg.ReconnectTimeout <= 0 {
		cfg.ReconnectTimeout = 30 * time.Second
	}
	if cfg.MaxConcurrentRequests <= 0 {
		cfg.MaxConcurrentRequests = maxConcurrentRequestsDefault
	}

	return &Client{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout:       httpClientTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

var errTerminal = errors.New("terminal error")

func isTerminal(err error) bool {
	if errors.Is(err, errTerminal) {
		return true
	}
	var closeErr *websocket.CloseError
	if errors.As(err, &closeErr) {
		switch closeErr.Code {
		case websocket.ClosePolicyViolation:
			return true
		}
	}
	return false
}

// Run connects to the scimtest server and forwards requests until the context is
// cancelled or a fatal error occurs. It automatically reconnects with
// exponential backoff on disconnect.
func (c *Client) Run(ctx context.Context) error {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	return c.RunContext(ctx)
}

// RunContext connects to the scimtest server without installing signal handlers.
// This is intended for callers embedding the client in another process.
func (c *Client) RunContext(ctx context.Context) error {
	backoff := time.Duration(0)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		c.cfg.Logger.Info(
			"connecting to tunnel server",
			"server_url", c.cfg.ServerURL,
			"profile_id", c.cfg.ApplicationProfileID,
			"instance_id", c.cfg.InstanceID,
			"local_port", c.cfg.LocalPort,
		)
		err := c.runOnce(ctx)
		if err == nil {
			return nil
		}
		var enrollmentRequired *enrollmentRequiredError
		if errors.As(err, &enrollmentRequired) {
			c.enrollmentGrant = ""
			if c.cfg.OnEnrollmentRequired != nil {
				c.cfg.OnEnrollmentRequired(Enrollment{
					URL:               enrollmentRequired.url,
					BrowserHandoffURL: enrollmentRequired.browserHandoffURL,
					VerificationCode:  enrollmentRequired.verificationCode,
				})
			}
			if pollErr := c.pollEnrollment(ctx, enrollmentRequired); pollErr != nil {
				err = pollErr
			} else {
				backoff = 0
				continue
			}
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if isTerminal(err) {
			c.cfg.Logger.Error(
				"tunnel connection failed permanently",
				"server_url", c.cfg.ServerURL,
				"error", err,
			)
			return fmt.Errorf("tunnel closed: %w", err)
		}

		backoff = nextBackoff(backoff, c.cfg.ReconnectTimeout)
		c.cfg.Logger.Warn(
			"tunnel connection failed; retrying",
			"server_url", c.cfg.ServerURL,
			"error", err,
			"backoff", backoff,
		)

		timer := time.NewTimer(backoff)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		}
	}
}

func nextBackoff(current, max time.Duration) time.Duration {
	if current == 0 {
		return time.Second
	}
	next := current * 2
	if next > max {
		return max
	}
	return next
}

func (c *Client) runOnce(ctx context.Context) error {
	conn, response, err := websocket.DefaultDialer.DialContext(ctx, c.cfg.ServerURL, nil)
	if err != nil {
		connectErr := fmt.Errorf("connect to tunnel server %s: %w", c.cfg.ServerURL, err)
		if response != nil {
			connectErr = fmt.Errorf("connect to tunnel server %s: HTTP %s: %w", c.cfg.ServerURL, response.Status, err)
			if response.Body != nil {
				if closeErr := response.Body.Close(); closeErr != nil {
					connectErr = fmt.Errorf("%w; close handshake response: %v", connectErr, closeErr)
				}
			}
		}
		return connectErr
	}
	var closeOnce sync.Once
	closeConn := func() {
		closeOnce.Do(func() {
			if err := conn.Close(); err != nil {
				c.cfg.Logger.Warn("close tunnel connection failed", "error", err)
			}
		})
	}
	defer closeConn()
	conn.SetReadLimit(protocol.MaxMessageBytes(c.cfg.MaxBodyBytes))

	childCtx, cancel := context.WithCancel(ctx)
	var requestWG sync.WaitGroup
	defer func() {
		cancel()
		requestWG.Wait()
	}()
	go func() {
		<-childCtx.Done()
		closeConn()
	}()

	register := protocol.Message{
		Type:                 protocol.TypeRegisterTunnel,
		LocalPort:            c.cfg.LocalPort,
		ApplicationProfileID: c.cfg.ApplicationProfileID,
		InstanceID:           c.cfg.InstanceID,
	}
	if len(c.cfg.InstancePrivateKey) == ed25519.PrivateKeySize {
		register.InstancePublicKey = base64.StdEncoding.EncodeToString(c.cfg.InstancePrivateKey.Public().(ed25519.PublicKey))
	}
	if err := conn.WriteJSON(register); err != nil {
		return fmt.Errorf("write tunnel registration: %w", err)
	}

	var registered protocol.Message
	if err := conn.ReadJSON(&registered); err != nil {
		return fmt.Errorf("read application challenge: %w", err)
	}
	if registered.Type != protocol.TypeApplicationChallenge {
		return fmt.Errorf("%w: expected application_challenge, got %q", errTerminal, registered.Type)
	}
	signed, err := c.signChallenge(registered)
	if err != nil {
		return err
	}
	if err := conn.WriteJSON(signed); err != nil {
		return fmt.Errorf("write application signature: %w", err)
	}
	if err := conn.ReadJSON(&registered); err != nil {
		return fmt.Errorf("read tunnel registration: %w", err)
	}
	switch registered.Type {
	case protocol.TypeEnrollmentRequired:
		enrollment, err := c.enrollmentRequired(registered)
		if err != nil {
			return fmt.Errorf("%w: invalid enrollment request: %v", errTerminal, err)
		}
		return enrollment
	case protocol.TypeTunnelRegistered:
	default:
		return fmt.Errorf("%w: expected tunnel_registered, got %q", errTerminal, registered.Type)
	}
	c.enrollmentGrant = ""

	registration := Registration{
		TunnelID:     registered.TunnelID,
		PublicURL:    registered.PublicURL,
		ClientIP:     registered.ClientIP,
		GitHubUserID: registered.GitHubUserID,
		GitHubLogin:  registered.GitHubLogin,
	}
	c.cfg.Logger.Info(
		"tunnel registered",
		"tunnel_id", registration.TunnelID,
		"public_url", registration.PublicURL,
		"client_ip", registration.ClientIP,
	)
	if c.cfg.OnRegistered != nil {
		c.cfg.OnRegistered(registration)
	}
	if _, err := fmt.Fprintf(c.cfg.Output, "Connected\nForwarding %s -> %s:%d\n", registered.PublicURL, c.cfg.LocalHost, c.cfg.LocalPort); err != nil {
		return fmt.Errorf("write tunnel registration output: %w", err)
	}

	send := make(chan protocol.Message, sendChannelSize)
	done := make(chan struct{})
	requestSlots := make(chan struct{}, c.cfg.MaxConcurrentRequests)
	writerErr := make(chan error, 1)
	go writeLoop(conn, send, done, writerErr, closeConn)

	for {
		select {
		case <-ctx.Done():
			if err := conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(5*time.Second)); err != nil {
				c.cfg.Logger.Warn("write tunnel close message failed", "error", err)
			}
			close(done)
			return ctx.Err()
		default:
		}

		var msg protocol.Message
		if err := conn.ReadJSON(&msg); err != nil {
			close(done)
			select {
			case werr := <-writerErr:
				if werr != nil {
					return werr
				}
			default:
			}
			return fmt.Errorf("read tunnel message: %w", err)
		}

		switch msg.Type {
		case protocol.TypeRequest:
			select {
			case requestSlots <- struct{}{}:
				requestWG.Add(1)
				go func(msg protocol.Message) {
					defer requestWG.Done()
					defer func() { <-requestSlots }()
					c.handleRequest(childCtx, msg, send, done)
				}(msg)
			default:
				c.sendBusyResponse(msg, send, done)
			}
		case protocol.TypePing:
			select {
			case send <- protocol.Message{Type: protocol.TypePong}:
			case <-done:
			}
		default:
			c.cfg.Logger.Debug("ignoring server message", "type", msg.Type)
		}
	}
}

// signChallenge answers modern servers with the per-install key and an
// optional one-use enrollment grant. Older servers get the legacy shared-key
// signature over the client-chosen instance ID.
func (c *Client) signChallenge(challenge protocol.Message) (protocol.Message, error) {
	if !challenge.EnrollmentSupported {
		if len(c.cfg.ApplicationPrivateKey) != ed25519.PrivateKeySize {
			return protocol.Message{}, fmt.Errorf("%w: application private key is required", errTerminal)
		}
		payload := protocol.ApplicationChallengePayload(
			c.cfg.ApplicationProfileID,
			c.cfg.InstanceID,
			challenge.Challenge,
		)
		return protocol.Message{
			Type:      protocol.TypeApplicationSignature,
			Signature: ed25519.Sign(c.cfg.ApplicationPrivateKey, payload),
		}, nil
	}

	if len(c.cfg.InstancePrivateKey) != ed25519.PrivateKeySize {
		return protocol.Message{}, fmt.Errorf("%w: instance private key is required", errTerminal)
	}
	instancePublicKey := base64.StdEncoding.EncodeToString(c.cfg.InstancePrivateKey.Public().(ed25519.PublicKey))
	payload := protocol.InstanceChallengePayload(
		c.cfg.ApplicationProfileID,
		instancePublicKey,
		c.cfg.InstanceID,
		challenge.Challenge,
	)
	signed := protocol.Message{
		Type:            protocol.TypeApplicationSignature,
		Signature:       ed25519.Sign(c.cfg.InstancePrivateKey, payload),
		EnrollmentGrant: c.enrollmentGrant,
	}
	return signed, nil
}

func (c *Client) enrollmentRequired(msg protocol.Message) (*enrollmentRequiredError, error) {
	if len(msg.EnrollmentURL) > maxEnrollmentURLLength ||
		len(msg.EnrollmentBrowserHandoffURL) > maxEnrollmentURLLength ||
		len(msg.EnrollmentStatusURL) > maxEnrollmentURLLength {
		return nil, errors.New("enrollment URL is too long")
	}
	enrollmentURL, err := url.Parse(msg.EnrollmentURL)
	if err != nil || enrollmentURL.Scheme == "" || enrollmentURL.Host == "" {
		return nil, errors.New("enrollment URL must be absolute")
	}
	if enrollmentURL.Scheme != "http" && enrollmentURL.Scheme != "https" {
		return nil, errors.New("enrollment URL must use HTTP or HTTPS")
	}
	if enrollmentURL.User != nil {
		return nil, errors.New("enrollment URL must not contain user information")
	}
	serverURL, err := url.Parse(c.cfg.ServerURL)
	if err != nil {
		return nil, fmt.Errorf("parse tunnel server URL: %w", err)
	}
	if serverURL.Scheme == "wss" && enrollmentURL.Scheme != "https" {
		return nil, errors.New("enrollment URL must use HTTPS with a secure tunnel server")
	}
	browserHandoffURL := strings.TrimSpace(msg.EnrollmentBrowserHandoffURL)
	if browserHandoffURL != "" {
		browserURL, parseErr := url.Parse(browserHandoffURL)
		if parseErr != nil || browserURL.Scheme == "" || browserURL.Host == "" {
			return nil, errors.New("browser handoff URL must be absolute")
		}
		if browserURL.Scheme != "http" && browserURL.Scheme != "https" {
			return nil, errors.New("browser handoff URL must use HTTP or HTTPS")
		}
		if browserURL.User != nil {
			return nil, errors.New("browser handoff URL must not contain user information")
		}
		if serverURL.Scheme == "wss" && browserURL.Scheme != "https" {
			return nil, errors.New("browser handoff URL must use HTTPS with a secure tunnel server")
		}
		enrollmentOrigin, originErr := httpOrigin(enrollmentURL)
		if originErr != nil {
			return nil, fmt.Errorf("parse enrollment page origin: %w", originErr)
		}
		browserOrigin, originErr := httpOrigin(browserURL)
		if originErr != nil {
			return nil, fmt.Errorf("parse browser handoff origin: %w", originErr)
		}
		if browserOrigin != enrollmentOrigin {
			return nil, errors.New("browser handoff URL must use the enrollment page origin")
		}
	}
	if err := validateEnrollmentStatusURL(c.cfg.ServerURL, msg.EnrollmentStatusURL); err != nil {
		return nil, err
	}
	deviceCode := msg.EnrollmentDeviceCode
	if len(deviceCode) > maxEnrollmentDeviceCodeLength || !validBearerToken(deviceCode) {
		return nil, errors.New("enrollment device code is invalid")
	}
	verificationCode := strings.TrimSpace(msg.EnrollmentVerificationCode)
	if verificationCode == "" || len(verificationCode) > maxEnrollmentVerificationCodeLength || !validBearerToken(verificationCode) {
		return nil, errors.New("enrollment verification code is invalid")
	}

	pollInterval := defaultEnrollmentPoll
	if msg.EnrollmentPollSeconds > 0 {
		if msg.EnrollmentPollSeconds > int(maxEnrollmentPoll/time.Second) {
			pollInterval = maxEnrollmentPoll
		} else {
			pollInterval = time.Duration(msg.EnrollmentPollSeconds) * time.Second
		}
	}
	return &enrollmentRequiredError{
		url:               msg.EnrollmentURL,
		browserHandoffURL: browserHandoffURL,
		verificationCode:  verificationCode,
		statusURL:         msg.EnrollmentStatusURL,
		deviceCode:        deviceCode,
		pollInterval:      pollInterval,
	}, nil
}

func validateEnrollmentStatusURL(serverURL, statusURL string) error {
	server, err := url.Parse(serverURL)
	if err != nil {
		return fmt.Errorf("parse tunnel server URL: %w", err)
	}
	switch server.Scheme {
	case "ws":
		server.Scheme = "http"
	case "wss":
		server.Scheme = "https"
	default:
		return errors.New("tunnel server URL must use WS or WSS")
	}
	want, err := httpOrigin(server)
	if err != nil {
		return fmt.Errorf("parse tunnel server origin: %w", err)
	}

	status, err := url.Parse(statusURL)
	if err != nil {
		return fmt.Errorf("parse enrollment status URL: %w", err)
	}
	if status.User != nil || status.RawQuery != "" || status.Fragment != "" {
		return errors.New("enrollment status URL must not contain user information, a query, or a fragment")
	}
	got, err := httpOrigin(status)
	if err != nil {
		return fmt.Errorf("parse enrollment status origin: %w", err)
	}
	if got != want {
		return errors.New("enrollment status URL must use the tunnel server origin")
	}
	return nil
}

func validBearerToken(value string) bool {
	if value == "" {
		return false
	}
	for i := range len(value) {
		if value[i] <= ' ' || value[i] >= 0x7f {
			return false
		}
	}
	return true
}

func httpOrigin(value *url.URL) (string, error) {
	if value.Scheme != "http" && value.Scheme != "https" {
		return "", errors.New("URL must use HTTP or HTTPS")
	}
	host := strings.ToLower(strings.TrimSuffix(value.Hostname(), "."))
	if host == "" {
		return "", errors.New("URL host is required")
	}
	port := value.Port()
	if port == "" {
		port = "80"
		if value.Scheme == "https" {
			port = "443"
		}
	}
	return value.Scheme + "://" + net.JoinHostPort(host, port), nil
}

func (c *Client) pollEnrollment(ctx context.Context, enrollment *enrollmentRequiredError) error {
	for {
		status, retry, err := c.fetchEnrollmentStatus(ctx, enrollment)
		if err == nil {
			switch status.Status {
			case "approved":
				c.enrollmentGrant = enrollment.deviceCode
				return nil
			case "pending":
			default:
				message := strings.TrimSpace(status.Error)
				if message == "" {
					message = fmt.Sprintf("unexpected status %q", status.Status)
				}
				return fmt.Errorf("%w: tunnel enrollment failed: %s", errTerminal, message)
			}
		} else if !retry {
			return err
		} else {
			c.cfg.Logger.Warn("enrollment status request failed; retrying", "error", err)
		}

		timer := time.NewTimer(enrollment.pollInterval)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		}
	}
}

func (c *Client) fetchEnrollmentStatus(ctx context.Context, enrollment *enrollmentRequiredError) (protocol.EnrollmentStatus, bool, error) {
	requestCtx, cancel := context.WithTimeout(ctx, enrollmentRequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodPost, enrollment.statusURL, nil)
	if err != nil {
		return protocol.EnrollmentStatus{}, false, fmt.Errorf("create enrollment status request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+enrollment.deviceCode)
	req.Header.Set("Cache-Control", "no-store")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return protocol.EnrollmentStatus{}, false, ctx.Err()
		}
		return protocol.EnrollmentStatus{}, true, fmt.Errorf("get enrollment status: %w", err)
	}
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= http.StatusInternalServerError {
		closeErr := resp.Body.Close()
		return protocol.EnrollmentStatus{}, true, errors.Join(fmt.Errorf("get enrollment status: HTTP %s", resp.Status), closeErr)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		closeErr := resp.Body.Close()
		return protocol.EnrollmentStatus{}, false, errors.Join(fmt.Errorf("%w: get enrollment status: HTTP %s", errTerminal, resp.Status), closeErr)
	}

	var status protocol.EnrollmentStatus
	decodeErr := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&status)
	closeErr := resp.Body.Close()
	if err := errors.Join(decodeErr, closeErr); err != nil {
		return protocol.EnrollmentStatus{}, false, fmt.Errorf("%w: decode enrollment status: %v", errTerminal, err)
	}
	return status, false, nil
}

func writeLoop(conn *websocket.Conn, send <-chan protocol.Message, done <-chan struct{}, errCh chan<- error, closeConn func()) {
	for {
		select {
		case msg := <-send:
			if err := conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
				errCh <- fmt.Errorf("set tunnel write deadline: %w", err)
				closeConn()
				return
			}
			if err := conn.WriteJSON(msg); err != nil {
				errCh <- err
				closeConn()
				return
			}
		case <-done:
			return
		}
	}
}

func (c *Client) sendBusyResponse(msg protocol.Message, send chan<- protocol.Message, done <-chan struct{}) {
	resp := protocol.Message{
		Type:     protocol.TypeResponse,
		StreamID: msg.StreamID,
		Error:    "local application is busy",
	}
	select {
	case send <- resp:
	case <-done:
	}
}

func (c *Client) handleRequest(ctx context.Context, msg protocol.Message, send chan<- protocol.Message, done <-chan struct{}) {
	resp := protocol.Message{
		Type:     protocol.TypeResponse,
		StreamID: msg.StreamID,
	}

	localURL, err := localRequestURL(c.cfg.LocalHost, c.cfg.LocalPort, msg.Path)
	if err != nil {
		c.cfg.Logger.Warn("rejecting tunneled request path", "path", msg.Path, "error", err)
		resp.Error = "invalid request path"
		select {
		case send <- resp:
		case <-done:
		}
		return
	}

	req, err := http.NewRequestWithContext(ctx, msg.Method, localURL, bytes.NewReader(msg.Body))
	if err != nil {
		c.cfg.Logger.Warn("local forward failed", "error", err)
		resp.Error = "failed to reach local application"
		select {
		case send <- resp:
		case <-done:
		}
		return
	}
	expectedHost := net.JoinHostPort(c.cfg.LocalHost, strconv.Itoa(c.cfg.LocalPort))
	if req.URL.Host != expectedHost {
		c.cfg.Logger.Warn("rejecting tunneled request path", "path", msg.Path, "host", req.URL.Host)
		resp.Error = "invalid request path"
		select {
		case send <- resp:
		case <-done:
		}
		return
	}

	req.Header = httputil.CloneHeader(msg.Header)
	httputil.RemoveHopHeaders(req.Header)
	if c.cfg.PreserveHost {
		req.Host = msg.Host
	}

	localResp, err := c.httpClient.Do(req)
	if err != nil {
		c.cfg.Logger.Warn("local forward failed", "error", err)
		resp.Error = "failed to reach local application"
		select {
		case send <- resp:
		case <-done:
		}
		return
	}
	defer func() {
		if err := localResp.Body.Close(); err != nil {
			c.cfg.Logger.Warn("close local response body failed", "error", err)
		}
	}()

	body, err := io.ReadAll(io.LimitReader(localResp.Body, c.cfg.MaxBodyBytes+1))
	if err != nil {
		c.cfg.Logger.Warn("local forward failed", "error", err)
		resp.Error = "failed to read local response"
		select {
		case send <- resp:
		case <-done:
		}
		return
	}
	if int64(len(body)) > c.cfg.MaxBodyBytes {
		resp.Error = "local response body too large"
		select {
		case send <- resp:
		case <-done:
		}
		return
	}

	resp.StatusCode = localResp.StatusCode
	resp.Header = httputil.CloneHeader(localResp.Header)
	httputil.RemoveHopHeaders(resp.Header)
	resp.Body = body
	select {
	case send <- resp:
	case <-done:
	}
}

// localRequestURL builds an http URL for the configured local application from a
// tunneled request URI. The path must be a relative request URI beginning with a
// single "/"; schemes, hosts, userinfo, and "//"-prefixed paths are rejected so a
// malicious tunnel server cannot redirect the client off-loopback (SSRF).
func localRequestURL(localHost string, localPort int, requestURI string) (string, error) {
	if requestURI == "" {
		requestURI = "/"
	}
	ref, err := url.ParseRequestURI(requestURI)
	if err != nil {
		return "", fmt.Errorf("parse request path: %w", err)
	}
	if ref.Scheme != "" || ref.Opaque != "" || ref.Host != "" || ref.User != nil {
		return "", errors.New("request path must be relative")
	}
	if !strings.HasPrefix(ref.Path, "/") || strings.HasPrefix(ref.Path, "//") {
		return "", errors.New("request path must begin with a single /")
	}
	base := &url.URL{
		Scheme: "http",
		Host:   net.JoinHostPort(localHost, strconv.Itoa(localPort)),
	}
	return base.ResolveReference(ref).String(), nil
}
