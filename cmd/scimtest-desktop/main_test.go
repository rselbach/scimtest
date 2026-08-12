//go:build desktop

package main

import (
	"errors"
	"testing"
)

func TestDesktopOpenerQueuesLoopbackAndOpensExternalURLs(t *testing.T) {
	urls := make(chan string, 1)
	stopped := make(chan struct{})
	var external string
	open := desktopOpener(urls, stopped, func(value string) error {
		external = value
		return nil
	})

	const local = "http://127.0.0.1:8080"
	if err := open(local); err != nil {
		t.Fatalf("open local URL: %v", err)
	}
	if got := <-urls; got != local {
		t.Fatalf("queued URL = %q, want %q", got, local)
	}

	const github = "https://github.com/login/oauth/authorize"
	if err := open(github); err != nil {
		t.Fatalf("open external URL: %v", err)
	}
	if external != github {
		t.Fatalf("external URL = %q, want %q", external, github)
	}

	for _, invalid := range []string{"github.com/login", "file:///tmp/scimtest", "javascript:alert(1)"} {
		if err := open(invalid); err == nil {
			t.Errorf("open(%q) succeeded, want validation error", invalid)
		}
	}

	close(stopped)
	if err := open(local); err == nil {
		t.Fatal("open after window close succeeded, want error")
	}
}

func TestWaitForAdminURLReturnsLoopbackURL(t *testing.T) {
	urls := make(chan string, 1)
	serverResult := make(chan error, 1)
	urls <- "http://127.0.0.1:8080"

	initial, err := waitForAdminURL(urls, serverResult)
	if err != nil {
		t.Fatalf("wait for admin URL: %v", err)
	}
	if initial != "http://127.0.0.1:8080" {
		t.Fatalf("initial URL = %q", initial)
	}
}

func TestWaitForAdminURLRejectsExternalURL(t *testing.T) {
	urls := make(chan string, 1)
	serverResult := make(chan error, 1)
	urls <- "https://github.com/login/oauth/authorize"

	_, err := waitForAdminURL(urls, serverResult)
	if err == nil {
		t.Fatal("wait for external URL succeeded, want error")
	}
}

func TestWaitForAdminURLReportsEarlyServerFailure(t *testing.T) {
	urls := make(chan string)
	serverResult := make(chan error, 1)
	want := errors.New("startup failed")
	serverResult <- want

	_, err := waitForAdminURL(urls, serverResult)
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
