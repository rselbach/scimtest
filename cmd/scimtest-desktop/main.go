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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	urls := make(chan string, 16)
	stopped := make(chan struct{})
	serverResult := make(chan error, 1)
	go func() {
		serverResult <- web.Run(web.RunOptions{
			Context:              ctx,
			OpenURL:              queuedOpener(urls, stopped),
			RequireGitHubAccount: true,
		})
	}()

	initialURL, pending, err := waitForAdminURL(urls, serverResult)
	if err != nil {
		close(stopped)
		return err
	}

	window := webview.New(false)
	if window == nil || window.Window() == nil {
		close(stopped)
		cancel()
		return errors.New("could not create the native WebView window")
	}
	window.SetTitle("scimtest")
	window.SetSize(1280, 820, webview.HintNone)
	window.Navigate(initialURL)
	for _, value := range pending {
		window.Navigate(value)
	}

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

func queuedOpener(urls chan<- string, stopped <-chan struct{}) func(string) error {
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
		select {
		case urls <- value:
			return nil
		case <-stopped:
			return errors.New("desktop window is closed")
		}
	}
}

func waitForAdminURL(urls <-chan string, serverResult <-chan error) (string, []string, error) {
	var pending []string
	for {
		select {
		case value := <-urls:
			parsed, err := url.Parse(value)
			if err == nil && parsed.Scheme == "http" && isLoopbackHost(parsed.Hostname()) {
				return value, pending, nil
			}
			pending = append(pending, value)
		case err := <-serverResult:
			if err == nil {
				err = errors.New("local scimtest server stopped before opening the desktop window")
			}
			return "", nil, err
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
