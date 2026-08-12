//go:build desktop

package main

import (
	"errors"
	"testing"
)

func TestQueuedOpenerValidatesAndQueuesWebURLs(t *testing.T) {
	urls := make(chan string, 1)
	stopped := make(chan struct{})
	open := queuedOpener(urls, stopped)

	const value = "https://github.com/login/oauth/authorize"
	if err := open(value); err != nil {
		t.Fatalf("open valid URL: %v", err)
	}
	if got := <-urls; got != value {
		t.Fatalf("queued URL = %q, want %q", got, value)
	}

	for _, invalid := range []string{"github.com/login", "file:///tmp/scimtest", "javascript:alert(1)"} {
		if err := open(invalid); err == nil {
			t.Errorf("open(%q) succeeded, want validation error", invalid)
		}
	}

	close(stopped)
	if err := open(value); err == nil {
		t.Fatal("open after window close succeeded, want error")
	}
}

func TestWaitForAdminURLKeepsExternalNavigationPending(t *testing.T) {
	urls := make(chan string, 2)
	serverResult := make(chan error, 1)
	urls <- "https://github.com/login/oauth/authorize"
	urls <- "http://127.0.0.1:8080"

	initial, pending, err := waitForAdminURL(urls, serverResult)
	if err != nil {
		t.Fatalf("wait for admin URL: %v", err)
	}
	if initial != "http://127.0.0.1:8080" {
		t.Fatalf("initial URL = %q", initial)
	}
	if len(pending) != 1 || pending[0] != "https://github.com/login/oauth/authorize" {
		t.Fatalf("pending URLs = %#v", pending)
	}
}

func TestWaitForAdminURLReportsEarlyServerFailure(t *testing.T) {
	urls := make(chan string)
	serverResult := make(chan error, 1)
	want := errors.New("startup failed")
	serverResult <- want

	_, _, err := waitForAdminURL(urls, serverResult)
	if !errors.Is(err, want) {
		t.Fatalf("wait error = %v, want %v", err, want)
	}
}

func TestIsLoopbackHost(t *testing.T) {
	for _, host := range []string{"localhost", "LOCALHOST.", "127.0.0.1", "::1"} {
		if !isLoopbackHost(host) {
			t.Errorf("isLoopbackHost(%q) = false", host)
		}
	}
	for _, host := range []string{"", "example.com", "192.0.2.1"} {
		if isLoopbackHost(host) {
			t.Errorf("isLoopbackHost(%q) = true", host)
		}
	}
}
