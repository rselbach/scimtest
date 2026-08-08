package web

import (
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

const (
	defaultHost = "127.0.0.1"
	defaultPort = 8080
	// maxAdminPortScan bounds the upward search for a free admin port so
	// fallback cannot land on an unrelated well-known port far from the
	// requested one.
	maxAdminPortScan = 100
)

// resolveAdminPort picks the admin port and reports whether it must bind
// exactly. Sources in priority order: the --port flag, SCIMTEST_PORT, the
// deprecated PORT variable, the port bound on the previous run, and the
// default. Only the first three pin the port; the last two allow fallback
// to a nearby free port.
func resolveAdminPort(flagPort, lastPort string) (port string, pinned bool) {
	if port = strings.TrimSpace(flagPort); port != "" {
		return port, true
	}
	if port = strings.TrimSpace(os.Getenv("SCIMTEST_PORT")); port != "" {
		return port, true
	}
	if port = strings.TrimSpace(os.Getenv("PORT")); port != "" {
		log.Printf("using port %s from the ambient PORT variable; set SCIMTEST_PORT or pass --port to silence this", port)
		return port, true
	}
	if port = strings.TrimSpace(lastPort); port != "" {
		return port, false
	}
	return strconv.Itoa(defaultPort), false
}

type browserOpener func(string) error

func listenForAdmin(host, port string, fallback bool) (net.Listener, error) {
	start, err := strconv.Atoi(port)
	if err != nil || start < 1 || start > 65535 {
		return nil, fmt.Errorf("invalid admin port %q: must be an integer from 1 through 65535", port)
	}
	if !fallback {
		address := net.JoinHostPort(host, strconv.Itoa(start))
		listener, err := net.Listen("tcp", address)
		if err != nil {
			return nil, fmt.Errorf("listen on %s: %w", address, err)
		}
		return listener, nil
	}

	end := min(start+maxAdminPortScan, 65535)
	for candidate := start; candidate <= end; candidate++ {
		address := net.JoinHostPort(host, strconv.Itoa(candidate))
		listener, listenErr := net.Listen("tcp", address)
		if listenErr == nil {
			return listener, nil
		}
		if !isAddrInUse(listenErr) {
			return nil, fmt.Errorf("listen on %s: %w", address, listenErr)
		}
	}
	return nil, fmt.Errorf("no available port from %d through %d on %s; pass --port to choose one", start, end, host)
}

func listenerURL(listener net.Listener) (string, error) {
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		return "", fmt.Errorf("get local TCP listener address")
	}
	host := address.IP.String()
	if address.IP.IsUnspecified() {
		if address.IP.To4() != nil {
			host = "127.0.0.1"
		} else {
			host = "::1"
		}
	}
	if address.Zone != "" {
		host += "%" + address.Zone
	}
	return (&url.URL{
		Scheme: "http",
		Host:   net.JoinHostPort(host, strconv.Itoa(address.Port)),
	}).String(), nil
}

func openBrowser(localURL string) error {
	var name string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		name, args = "open", []string{localURL}
	case "windows":
		name, args = "rundll32", []string{"url.dll,FileProtocolHandler", localURL}
	default:
		name, args = "xdg-open", []string{localURL}
	}

	cmd := exec.Command(name, args...)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %s: %w", name, err)
	}
	go func() {
		if err := cmd.Wait(); err != nil {
			log.Printf("browser command exited: %v", err)
		}
	}()
	return nil
}

func maybeOpenBrowser(localURL string, disabled bool, opener browserOpener) {
	if disabled {
		return
	}
	if opener == nil {
		opener = openBrowser
	}
	if err := opener(localURL); err != nil {
		log.Printf("warning: open browser at %s: %v", localURL, err)
	}
}
