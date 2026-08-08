package web

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func newTestCookieJar(t *testing.T) *cookiejar.Jar {
	t.Helper()
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	return jar
}

func readAll(t *testing.T, r io.Reader) string {
	t.Helper()
	data, err := io.ReadAll(r)
	require.NoError(t, err)
	return string(data)
}

func TestPlaygroundCompletesFullExchange(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{
		Users: []user{{ID: "usr-1", GivenName: "Troy", FamilyName: "Barnes", Email: "troy@greendale.edu", Username: "troy", Active: true}},
		Apps: []app{{
			ID:               "app-1",
			Name:             "Example",
			Slug:             "example",
			Protocol:         "oidc",
			OIDCClientID:     "example-client",
			OIDCClientSecret: "secret",
			OIDCRedirectURIs: []string{"http://client.test/callback"},
		}},
	}))
	svc := newTestIDPApp(t)

	// A real listener is required: the playground callback exchanges the code
	// by calling the token endpoint over HTTP against the admin host.
	server := httptest.NewServer(svc.routes())
	defer server.Close()
	svc.adminHost = strings.TrimPrefix(server.URL, "http://")

	// An active tunnel must not divert the playground: its callback is a
	// loopback URI that only the loopback authorize endpoint accepts.
	svc.tunnel = &activeTunnel{
		PathPrefix: "study-group",
		PublicURL:  "https://scimtest.rselbach.com/study-group",
		Tunnel:     &fakeTunnel{},
	}

	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Jar:           newTestCookieJar(t),
	}

	// Start the playground; it redirects to the authorize chooser.
	startResp, err := client.Get(server.URL + "/inspect/oidc/example/playground")
	r.NoError(err)
	r.NoError(startResp.Body.Close())
	r.Equal(http.StatusFound, startResp.StatusCode)
	r.True(strings.HasPrefix(startResp.Header.Get("Location"), server.URL+"/oidc/example/authorize"),
		"playground must stay on the loopback host, got %s", startResp.Header.Get("Location"))
	authorizeURL, err := url.Parse(startResp.Header.Get("Location"))
	r.NoError(err)
	r.NotEmpty(authorizeURL.Query().Get("state"))
	r.NotEmpty(authorizeURL.Query().Get("nonce"))

	// Post the chooser selection to get the code, preserving the flow params.
	form := authorizeURL.Query()
	form.Set("user_id", "usr-1")
	authorizeResp, err := client.PostForm(server.URL+authorizeURL.Path, form)
	r.NoError(err)
	r.NoError(authorizeResp.Body.Close())
	r.Equal(http.StatusFound, authorizeResp.StatusCode)

	// Follow the redirect to the playground callback, which exchanges the code.
	callbackResp, err := client.Get(authorizeResp.Header.Get("Location"))
	r.NoError(err)
	body := readAll(t, callbackResp.Body)
	r.NoError(callbackResp.Body.Close())
	r.Equal(http.StatusOK, callbackResp.StatusCode)
	r.Contains(body, "Token response")
	r.Contains(body, "Decoded ID token")
	r.Contains(body, "troy@greendale.edu")
}

func TestPlaygroundWorksWithoutRegisteredRedirectURIs(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{
		Apps: []app{{
			ID:               "app-1",
			Name:             "Example",
			Slug:             "example",
			Protocol:         "oidc",
			OIDCClientID:     "example-client",
			OIDCClientSecret: "secret",
		}},
	}))
	svc := newTestIDPApp(t)
	svc.adminHost = "127.0.0.1:8080"

	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/inspect/oidc/example/playground", nil)
	req.Host = svc.adminHost
	svc.routes().ServeHTTP(resp, req)

	r.Equal(http.StatusFound, resp.Code, resp.Body.String())
	r.Contains(resp.Header().Get("Location"), "http://127.0.0.1:8080/oidc/example/authorize")
}
