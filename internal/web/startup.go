package web

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"os/exec"
	"runtime"
	"strconv"
	"syscall"
)

const (
	defaultHost = "127.0.0.1"
	defaultPort = 8080
)

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

	for candidate := start; candidate <= 65535; candidate++ {
		address := net.JoinHostPort(host, strconv.Itoa(candidate))
		listener, listenErr := net.Listen("tcp", address)
		if listenErr == nil {
			return listener, nil
		}
		if !errors.Is(listenErr, syscall.EADDRINUSE) {
			return nil, fmt.Errorf("listen on %s: %w", address, listenErr)
		}
	}
	return nil, fmt.Errorf("no available port from %d through 65535 on %s", start, host)
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
