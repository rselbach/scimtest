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
	for name, tc := range map[string]struct {
		clientID string
		secret   string
	}{
		"plain credentials": {clientID: "example-client", secret: "secret"},
		"form characters":   {clientID: "greendale+client", secret: "study+group%42"},
		"colon and Unicode": {clientID: "greendale:client", secret: "café study:group"},
	} {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			setTestStateFile(t)
			r.NoError(saveState(appState{
				Users: []user{{ID: "usr-1", GivenName: "Troy", FamilyName: "Barnes", Email: "troy@greendale.edu", Username: "troy", Active: true}},
				Apps: []app{{
					ID:               "app-1",
					Name:             "Example",
					Slug:             "example",
					Protocol:         "oidc",
					OIDCClientID:     tc.clientID,
					OIDCClientSecret: tc.secret,
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
		})
	}
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

func TestPlaygroundRefreshesTokens(t *testing.T) {
	for name, public := range map[string]bool{"confidential client": false, "public client": true} {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			setTestStateFile(t)
			secret := "secret"
			if public {
				secret = ""
			}
			r.NoError(saveState(appState{
				Users: []user{{ID: "usr-1", GivenName: "Troy", FamilyName: "Barnes", Email: "troy@greendale.edu", Username: "troy", Active: true}},
				Apps:  []app{{ID: "app-1", Name: "Example", Slug: "example", Protocol: "oidc", OIDCClientID: "example-client", OIDCClientSecret: secret, OIDCPublicClient: public}},
			}))
			svc := newTestIDPApp(t)
			server := httptest.NewServer(svc.routes())
			defer server.Close()
			svc.adminHost = strings.TrimPrefix(server.URL, "http://")
			client := &http.Client{
				CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
				Jar:           newTestCookieJar(t),
			}

			startResp, err := client.Get(server.URL + "/inspect/oidc/example/playground")
			r.NoError(err)
			r.NoError(startResp.Body.Close())
			authorizeURL, err := url.Parse(startResp.Header.Get("Location"))
			r.NoError(err)
			r.Contains(authorizeURL.Query().Get("scope"), "offline_access")
			form := authorizeURL.Query()
			form.Set("user_id", "usr-1")
			authorizeResp, err := client.PostForm(server.URL+authorizeURL.Path, form)
			r.NoError(err)
			r.NoError(authorizeResp.Body.Close())
			callbackResp, err := client.Get(authorizeResp.Header.Get("Location"))
			r.NoError(err)
			signedIn := readAll(t, callbackResp.Body)
			r.NoError(callbackResp.Body.Close())
			firstRefresh := hiddenInputValue(signedIn, "refresh_token")
			r.NotEmpty(firstRefresh, "the playground must offer a refresh")

			refreshPage := func(refreshToken, previousIDToken, scope string) string {
				t.Helper()
				resp, err := client.PostForm(server.URL+"/inspect/oidc/example/playground/refresh", url.Values{
					"refresh_token":     {refreshToken},
					"previous_id_token": {previousIDToken},
					"scope":             {scope},
				})
				r.NoError(err)
				body := readAll(t, resp.Body)
				r.NoError(resp.Body.Close())
				r.Equal(http.StatusOK, resp.StatusCode)
				return body
			}

			refreshed := refreshPage(firstRefresh, hiddenInputValue(signedIn, "previous_id_token"), "")
			r.Contains(refreshed, "Refresh request")
			r.Contains(refreshed, "original grant")
			r.Contains(refreshed, "Claims before this refresh")
			r.Contains(refreshed, "200 OK")
			r.Contains(decodedPlaygroundClaims(t, refreshed), "troy@greendale.edu")
			secondRefresh := hiddenInputValue(refreshed, "refresh_token")
			r.NotEmpty(secondRefresh)
			r.NotEqual(firstRefresh, secondRefresh, "the token must rotate")

			narrowed := refreshPage(secondRefresh, hiddenInputValue(refreshed, "previous_id_token"), "openid")
			r.Contains(narrowed, `<dd class="mono">openid</dd>`)
			r.NotContains(decodedPlaygroundClaims(t, narrowed), "troy@greendale.edu")

			reused := refreshPage(firstRefresh, "", "")
			r.Contains(reused, "400 Bad Request")
			r.Contains(reused, "invalid_grant")
			r.NotContains(reused, `name="refresh_token"`, "a rejected refresh offers nothing to redeem")
		})
	}
}

// decodedPlaygroundClaims returns the ID token claims block of a playground page.
func decodedPlaygroundClaims(t *testing.T, body string) string {
	t.Helper()
	_, after, found := strings.Cut(body, "<h3>Claims</h3>")
	require.True(t, found)
	claims, _, found := strings.Cut(after, "</pre>")
	require.True(t, found)
	return claims
}
