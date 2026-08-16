//go:build desktop

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"strings"

	webview "github.com/webview/webview_go"

	"github.com/rselbach/scimtest/internal/web"
)

func main() {
	if err := run(); err != nil {
		log.Printf("scimtest desktop: %v", err)
		os.Exit(1)
	}
}

func run() error {
	if err := initializeDesktopWindowing(); err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	urls := make(chan string, 16)
	stopped := make(chan struct{})
	serverResult := make(chan error, 1)
	go func() {
		serverResult <- web.Run(web.RunOptions{
			Context:              ctx,
			OpenURL:              desktopOpener(urls, stopped, web.OpenBrowser),
			RequireGitHubAccount: true,
		})
	}()

	initialURL, err := waitForAdminURL(urls, serverResult)
	if err != nil {
		close(stopped)
		return err
	}

	window := webview.New(false)
	if !hasNativeWindow(window) {
		close(stopped)
		cancel()
		return errors.New("could not create the native WebView window")
	}
	installApplicationMenu()
	window.SetTitle("scimtest")
	window.SetSize(1280, 820, webview.HintNone)
	window.Navigate(initialURL)

	navigationDone := make(chan struct{})
	go func() {
		defer close(navigationDone)
		for {
			select {
			case value := <-urls:
				destination := value
				window.Dispatch(func() { window.Navigate(destination) })
			case <-stopped:
				return
			}
		}
	}()

	observedResult := make(chan error, 1)
	observerDone := make(chan struct{})
	go func() {
		defer close(observerDone)
		err := <-serverResult
		observedResult <- err
		window.Terminate()
	}()

	window.Run()
	close(stopped)
	cancel()
	<-navigationDone
	err = <-observedResult
	<-observerDone
	window.Destroy()
	return err
}

func desktopOpener(urls chan<- string, stopped <-chan struct{}, openExternal func(string) error) func(string) error {
	return func(value string) error {
		parsed, err := url.Parse(value)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
			return fmt.Errorf("refuse to open invalid URL %q", value)
		}
		select {
		case <-stopped:
			return errors.New("desktop window is closed")
		default:
		}
		if parsed.Scheme != "http" || !isLoopbackHost(parsed.Hostname()) {
			if openExternal == nil {
				return errors.New("default browser opener is unavailable")
			}
			return openExternal(value)
		}
		select {
		case urls <- value:
			return nil
		case <-stopped:
			return errors.New("desktop window is closed")
		}
	}
}

func waitForAdminURL(urls <-chan string, serverResult <-chan error) (string, error) {
	for {
		select {
		case value := <-urls:
			parsed, err := url.Parse(value)
			if err == nil && parsed.Scheme == "http" && isLoopbackHost(parsed.Hostname()) {
				return value, nil
			}
			return "", fmt.Errorf("desktop received a non-loopback application URL %q", value)
		case err := <-serverResult:
			if err == nil {
				err = errors.New("local scimtest server stopped before opening the desktop window")
			}
			return "", err
		}
	}
}

func isLoopbackHost(host string) bool {
	host = strings.TrimSpace(strings.TrimSuffix(host, "."))
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
