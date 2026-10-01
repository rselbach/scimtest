package web

import (
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPublicClientTestSignInCompletesPKCEExchange(t *testing.T) {
	for name, tc := range map[string][]string{
		"registered callback":    {"https://rp.greendale.edu/callback"},
		"no registered callback": nil,
	} {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			setTestStateFile(t)
			r.NoError(saveState(appState{
				Config: config{IDPBaseURL: "https://idp.greendale.edu"},
				Users:  []user{{ID: "troy", GivenName: "Troy", FamilyName: "Barnes", Email: "troy@greendale.edu", Username: "troy", Active: true}},
				Apps: []app{{
					ID: "greendale", Name: "Greendale", Slug: "greendale", Protocol: "oidc",
					OIDCClientID: "greendale-client", OIDCPublicClient: true, OIDCRedirectURIs: tc,
					AllowAnyOIDCRedirect: len(tc) == 0,
				}},
			}))
			svc := newTestIDPApp(t)
			server := httptest.NewServer(svc.routes())
			defer server.Close()
			svc.adminHost = strings.TrimPrefix(server.URL, "http://")
			svc.tunnel = &activeTunnel{PathPrefix: "study-group", PublicURL: "https://scimtest.rselbach.com/study-group", Tunnel: &fakeTunnel{}}
			client := &http.Client{
				CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
				Jar:           newTestCookieJar(t),
			}

			page, err := client.Get(server.URL + "/?tab=apps")
			r.NoError(err)
			body := readAll(t, page.Body)
			r.NoError(page.Body.Close())
			r.Equal(http.StatusOK, page.StatusCode)
			links := regexp.MustCompile(`href="([^"]+)"[^>]*>Test sign-in</a>`).FindAllStringSubmatch(body, -1)
			r.Len(links, 1)
			testURL := html.UnescapeString(links[0][1])
			r.Equal("/inspect/oidc/greendale/playground", testURL)

			start, err := client.Get(server.URL + testURL)
			r.NoError(err)
			r.NoError(start.Body.Close())
			r.Equal(http.StatusFound, start.StatusCode)
			authorizeURL, err := url.Parse(start.Header.Get("Location"))
			r.NoError(err)
			r.Equal(server.URL+"/oidc/greendale/authorize", authorizeURL.Scheme+"://"+authorizeURL.Host+authorizeURL.Path)
			r.Equal("S256", authorizeURL.Query().Get("code_challenge_method"))
			r.NotEmpty(authorizeURL.Query().Get("code_challenge"))
			r.NotEmpty(authorizeURL.Query().Get("state"))
			r.NotEmpty(authorizeURL.Query().Get("nonce"))
			r.Equal(server.URL+"/inspect/oidc/greendale/playground/callback", authorizeURL.Query().Get("redirect_uri"))

			chooser, err := client.Get(authorizeURL.String())
			r.NoError(err)
			chooserBody := readAll(t, chooser.Body)
			r.NoError(chooser.Body.Close())
			r.Equal(http.StatusOK, chooser.StatusCode)
			r.Contains(chooserBody, "Troy Barnes")
			form := authorizeURL.Query()
			form.Set("user_id", "troy")
			authorize, err := client.PostForm(server.URL+authorizeURL.Path, form)
			r.NoError(err)
			r.NoError(authorize.Body.Close())
			r.Equal(http.StatusFound, authorize.StatusCode)

			callback, err := client.Get(authorize.Header.Get("Location"))
			r.NoError(err)
			result := readAll(t, callback.Body)
			r.NoError(callback.Body.Close())
			r.Equal(http.StatusOK, callback.StatusCode)
			r.Contains(result, "Token response")
			r.Contains(result, "200 OK")
			r.Contains(result, "Decoded ID token")
			r.Contains(result, "troy@greendale.edu")
		})
	}
}
