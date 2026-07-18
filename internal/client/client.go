package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rselbach/scimtest/internal/httputil"
	"github.com/rselbach/scimtest/internal/protocol"
)

const (
	maxBodyBytesDefault          = 32 << 20
	writeTimeout                 = 10 * time.Second
	httpClientTimeout            = 2 * time.Minute
	readLimitOverhead            = 1 << 20
	sendChannelSize              = 64
	maxConcurrentRequestsDefault = 32
)

type Config struct {
	ServerURL             string
	ApplicationProfileID  string
	InstanceID            string
	ApplicationPrivateKey ed25519.PrivateKey
	LocalHost             string
	LocalPort             int
	PreserveHost          bool
	MaxBodyBytes          int64
	Logger                *slog.Logger
	ReconnectTimeout      time.Duration
	MaxConcurrentRequests int
	Output                io.Writer
	OnRegistered          func(Registration)
}

type Registration struct {
	TunnelID  string
	PublicURL string
}

type Client struct {
	cfg        Config
	httpClient *http.Client
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
	conn.SetReadLimit(c.cfg.MaxBodyBytes + readLimitOverhead)

	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-childCtx.Done()
		closeConn()
	}()

	if err := conn.WriteJSON(protocol.Message{
		Type:                 protocol.TypeRegisterTunnel,
		LocalPort:            c.cfg.LocalPort,
		ApplicationProfileID: c.cfg.ApplicationProfileID,
		InstanceID:           c.cfg.InstanceID,
	}); err != nil {
		return fmt.Errorf("write tunnel registration: %w", err)
	}

	var registered protocol.Message
	if err := conn.ReadJSON(&registered); err != nil {
		return fmt.Errorf("read application challenge: %w", err)
	}
	if registered.Type != protocol.TypeApplicationChallenge {
		return fmt.Errorf("%w: expected application_challenge, got %q", errTerminal, registered.Type)
	}
	if len(c.cfg.ApplicationPrivateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("%w: application private key is required", errTerminal)
	}
	payload := protocol.ApplicationChallengePayload(
		c.cfg.ApplicationProfileID,
		c.cfg.InstanceID,
		registered.Challenge,
	)
	signature := ed25519.Sign(c.cfg.ApplicationPrivateKey, payload)
	if err := conn.WriteJSON(protocol.Message{
		Type:      protocol.TypeApplicationSignature,
		Signature: signature,
	}); err != nil {
		return fmt.Errorf("write application signature: %w", err)
	}
	if err := conn.ReadJSON(&registered); err != nil {
		return fmt.Errorf("read tunnel registration: %w", err)
	}
	if registered.Type != protocol.TypeTunnelRegistered {
		return fmt.Errorf("%w: expected tunnel_registered, got %q", errTerminal, registered.Type)
	}

	registration := Registration{
		TunnelID:  registered.TunnelID,
		PublicURL: registered.PublicURL,
	}
	c.cfg.Logger.Info(
		"tunnel registered",
		"tunnel_id", registration.TunnelID,
		"public_url", registration.PublicURL,
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
				go func() {
					defer func() { <-requestSlots }()
					c.handleRequest(msg, send, done)
				}()
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

func (c *Client) handleRequest(msg protocol.Message, send chan<- protocol.Message, done <-chan struct{}) {
	resp := protocol.Message{
		Type:     protocol.TypeResponse,
		StreamID: msg.StreamID,
	}

	localURL := "http://" + c.cfg.LocalHost + ":" + strconv.Itoa(c.cfg.LocalPort)
	path := msg.Path
	if path == "" {
		path = "/"
	}

	req, err := http.NewRequestWithContext(context.Background(), msg.Method, localURL+path, bytes.NewReader(msg.Body))
	if err != nil {
		c.cfg.Logger.Warn("local forward failed", "error", err)
		resp.Error = "failed to reach local application"
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
