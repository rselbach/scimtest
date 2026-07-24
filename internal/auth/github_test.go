package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestGitHubWebAuthentication(t *testing.T) {
	r := require.New(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/access-token":
			r.NoError(req.ParseForm())
			r.Equal("test-client-id", req.PostForm.Get("client_id"))
			r.Equal("test-secret", req.PostForm.Get("client_secret"))
			r.Equal("auth-code", req.PostForm.Get("code"))
			r.Equal("https://example.com/auth/github/callback", req.PostForm.Get("redirect_uri"))
			r.NoError(json.NewEncoder(w).Encode(TokenResponse{AccessToken: "token-123"}))
		case "/user":
			r.Equal("Bearer token-123", req.Header.Get("Authorization"))
			r.NoError(json.NewEncoder(w).Encode(GitHubUser{Login: "rselbach"}))
		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()

	client := GitHubClient{
		ClientID:     "test-client-id",
		ClientSecret: "test-secret",
		HTTPClient:   server.Client(),
		TokenURL:     server.URL + "/access-token",
		UserURL:      server.URL + "/user",
	}
	token, err := client.ExchangeWebCode(context.Background(), "auth-code", "https://example.com/auth/github/callback")
	r.NoError(err)
	user, err := client.User(context.Background(), token.AccessToken)
	r.NoError(err)
	r.Equal("rselbach", user.Login)
}

func TestGitHubAuthorizeURL(t *testing.T) {
	client := GitHubClient{ClientID: "test-client-id"}
	value := client.AuthorizeURL("state-123", "https://example.com/auth/github/callback")
	require.True(t, strings.HasPrefix(value, GitHubAuthorizeURL))
	require.Contains(t, value, "client_id=test-client-id")
	require.Contains(t, value, "state=state-123")
	require.Contains(t, value, "redirect_uri=https%3A%2F%2Fexample.com%2Fauth%2Fgithub%2Fcallback")
}

func TestGitHubExchangeRequiresCredentials(t *testing.T) {
	_, err := (GitHubClient{}).ExchangeWebCode(context.Background(), "code", "")
	require.ErrorContains(t, err, "client id and secret are required")
}

func TestGitHubClientTimesOutHungEndpoints(t *testing.T) {
	r := require.New(t)
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		close(started)
		time.Sleep(time.Second)
	}))
	defer server.Close()

	client := GitHubClient{
		ClientID:     "test-client-id",
		ClientSecret: "test-secret",
		HTTPClient:   &http.Client{Timeout: 50 * time.Millisecond},
		TokenURL:     server.URL + "/access-token",
	}

	errCh := make(chan error, 1)
	go func() {
		_, err := client.ExchangeWebCode(context.Background(), "auth-code", "https://example.com/callback")
		errCh <- err
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("GitHub request did not start")
	}

	select {
	case err := <-errCh:
		r.Error(err)
		r.ErrorContains(err, "context deadline exceeded")
	case <-time.After(time.Second):
		t.Fatal("GitHub token exchange did not time out")
	}
}

func TestGitHubClientDefaultTimeoutIsFinite(t *testing.T) {
	client := (GitHubClient{}).client()
	require.Equal(t, defaultHTTPTimeout, client.Timeout)
}
