package main

import (
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/rselbach/scimtest/internal/protocol"
	"github.com/rselbach/scimtest/internal/server"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("scimtest-server", flag.ContinueOnError)
	addr := fs.String("addr", ":7000", "HTTP listen address")
	domain := fs.String("domain", "localhost:7000", "public server host, without scheme")
	dashboardDomain := fs.String("dashboard-domain", "", "dashboard host, without scheme (default: public server host)")
	publicScheme := fs.String("scheme", "http", "public URL scheme")
	behindProxy := fs.Bool("behind-proxy", false, "server is behind a trusted reverse proxy")
	trustedProxyCIDRs := fs.String("trusted-proxy-cidrs", "127.0.0.0/8,::1/128", "comma-separated proxy CIDRs trusted for X-Forwarded-* when --behind-proxy is set")
	connectPath := fs.String("connect-path", "/api/connect", "WebSocket tunnel path")
	dataPath := fs.String("data", "scimtest-server.json", "path to persistent server data")
	githubClientID := fs.String("github-client-id", os.Getenv("SCIMTEST_GITHUB_CLIENT_ID"), "GitHub OAuth app client ID")
	githubClientSecret := fs.String("github-client-secret", os.Getenv("SCIMTEST_GITHUB_CLIENT_SECRET"), "GitHub OAuth app client secret")
	maxBody := fs.Int64("max-body", protocol.MaxBodyBytesDefault, "maximum request or response body bytes")
	maxTunnelsPerApplication := fs.Int("max-tunnels-per-application", 0, "maximum active tunnels per application (0 = default 5)")
	showLogs := fs.Bool("logs", false, "show server logs")
	logFormat := fs.String("log-format", "text", "log format: text or json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}

	log, err := newLogger(*showLogs, *logFormat)
	if err != nil {
		return err
	}
	s, err := server.New(server.Config{
		Addr:                     *addr,
		Domain:                   *domain,
		DashboardDomain:          *dashboardDomain,
		PublicScheme:             *publicScheme,
		ConnectPath:              *connectPath,
		DataPath:                 *dataPath,
		GitHubClientID:           *githubClientID,
		GitHubClientSecret:       *githubClientSecret,
		MaxBodyBytes:             *maxBody,
		MaxTunnelsPerApplication: *maxTunnelsPerApplication,
		BehindProxy:              *behindProxy,
		TrustedProxyCIDRs:        strings.Split(*trustedProxyCIDRs, ","),
		Logger:                   log,
	})
	if err != nil {
		return err
	}
	return s.Run()
}

func newLogger(enabled bool, format string) (*slog.Logger, error) {
	if !enabled {
		return slog.New(slog.NewTextHandler(io.Discard, nil)), nil
	}
	opts := &slog.HandlerOptions{Level: slog.LevelInfo}
	switch format {
	case "json":
		return slog.New(slog.NewJSONHandler(os.Stderr, opts)), nil
	case "text":
		return slog.New(slog.NewTextHandler(os.Stderr, opts)), nil
	default:
		return nil, fmt.Errorf("invalid log format %q: use text or json", format)
	}
}
