package web

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"html"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func acceptanceBrowserPlayground(t *testing.T, handler http.Handler) {
	f := newSharedIdentity(t, handler)
	path := "/inspect/oidc/greendale/playground"
	for name, tc := range map[string]struct {
		clientID string
		secret   string
		public   bool
	}{
		"plain credentials": {clientID: "greendale-client", secret: "study-group"},
		"form characters":   {clientID: "greendale+client", secret: "study+group%42"},
		"colon and Unicode": {clientID: "greendale:client", secret: "café study:group"},
		"public PKCE":       {clientID: "greendale-public", public: true},
	} {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			acceptanceRequest(t, handler, http.MethodPatch, f.base, sharedJSON(t, map[string]any{
				"oidc_client_id": tc.clientID, "oidc_client_secret": tc.secret,
				"oidc_public_client": tc.public, "oidc_redirect_uris": []string{},
				"oidc_jwt_access_tokens": true, "oidc_access_token_audience": "https://api.greendale.edu",
			}), http.StatusOK)
			start := f.browser(http.MethodGet, path, nil)
			r.Equal(http.StatusFound, start.Code, start.Body.String())
			location, err := url.Parse(start.Header().Get("Location"))
			r.NoError(err)
			r.Equal("http", location.Scheme)
			r.Equal("127.0.0.1", location.Hostname())
			r.Equal("/oidc/greendale/authorize", location.Path)
			values := location.Query()
			r.Equal("code", values.Get("response_type"))
			r.Equal(tc.clientID, values.Get("client_id"))
			r.Equal("openid profile email groups offline_access", values.Get("scope"))
			r.Equal("http://"+location.Host+path+"/callback", values.Get("redirect_uri"))
			cookies := start.Result().Cookies()
			r.Len(cookies, 1)
			cookie := cookies[0]
			r.Equal("scimtest_playground_greendale", cookie.Name)
			r.Equal("/inspect/oidc/greendale", cookie.Path)
			r.Equal(600, cookie.MaxAge)
			r.True(cookie.HttpOnly)
			r.Equal(http.SameSiteLaxMode, cookie.SameSite)
			parts := strings.Split(cookie.Value, "|")
			r.Len(parts, 3)
			r.NotEmpty(parts[0])
			r.NotEmpty(parts[1])
			r.Equal(parts[0], values.Get("state"))
			r.Equal(parts[1], values.Get("nonce"))
			if tc.public {
				r.GreaterOrEqual(len(parts[2]), 43)
				challenge := sha256.Sum256([]byte(parts[2]))
				r.Equal(base64.RawURLEncoding.EncodeToString(challenge[:]), values.Get("code_challenge"))
				r.Equal("S256", values.Get("code_challenge_method"))
			} else {
				r.Empty(parts[2])
				r.Empty(values.Get("code_challenge"))
			}
			chooser := f.browser(http.MethodGet, location.Path, values, cookie)
			r.Equal(http.StatusOK, chooser.Code, chooser.Body.String())
			form := chooserSubmitForm(t, chooser.Body.String(), "Continue")
			form.Set("user_id", f.troy.ID)
			form.Set("authn_strength", "mfa")
			authorized := f.browser(http.MethodPost, location.Path, form, cookie)
			r.Equal(http.StatusFound, authorized.Code, authorized.Body.String())
			callback, err := url.Parse(authorized.Header().Get("Location"))
			r.NoError(err)
			r.NotEmpty(callback.Query().Get("code"))
			r.Equal(parts[0], callback.Query().Get("state"))
			page := f.browser(http.MethodGet, callback.Path, callback.Query(), cookie)
			r.Equal(http.StatusOK, page.Code, page.Body.String())
			body := page.Body.String()
			r.Contains(body, "200 OK")
			r.Contains(body, "Authorization response")
			r.Contains(body, "Decoded ID token")
			r.Contains(body, "Decoded access token")
			r.Contains(body, "Userinfo")
			r.Contains(body, "https://api.greendale.edu")
			r.Contains(body, "troy.barnes@greendale.edu")
			token := hiddenInputValue(body, "previous_id_token")
			claims := decodeIDTokenClaims(t, token)
			r.Equal(claims, playgroundDisplayedClaims(t, body))
			r.Equal(parts[1], claims["nonce"])
			r.Equal(f.troy.ID, claims["sub"])
			r.Equal(mfaContext, claims["acr"])
			firstRefresh := hiddenInputValue(body, "refresh_token")
			r.NotEmpty(firstRefresh)
			refresh := func(refreshToken, previousToken, scope string) string {
				result := f.browser(http.MethodPost, path+"/refresh", url.Values{
					"refresh_token": {refreshToken}, "previous_id_token": {previousToken}, "scope": {scope},
				})
				r.Equal(http.StatusOK, result.Code, result.Body.String())
				return result.Body.String()
			}
			refreshed := refresh(firstRefresh, token, "")
			r.Contains(refreshed, "200 OK")
			r.Contains(refreshed, "original grant")
			r.Contains(refreshed, "Claims before this refresh")
			current := decodeIDTokenClaims(t, hiddenInputValue(refreshed, "previous_id_token"))
			r.Equal(claims["sid"], current["sid"])
			r.Equal(claims["auth_time"], current["auth_time"])
			r.Equal(claims["acr"], current["acr"])
			secondRefresh := hiddenInputValue(refreshed, "refresh_token")
			r.NotEmpty(secondRefresh)
			r.NotEqual(firstRefresh, secondRefresh)
			narrowed := refresh(secondRefresh, hiddenInputValue(refreshed, "previous_id_token"), " openid ")
			r.Contains(narrowed, `<dd class="mono">openid</dd>`)
			r.NotContains(playgroundDisplayedClaims(t, narrowed), "email")
			rejected := refresh(firstRefresh, "", "")
			r.Contains(rejected, "400 Bad Request")
			r.Contains(rejected, "invalid_grant")
			r.NotContains(rejected, `name="refresh_token"`)

			inspector := f.browser(http.MethodGet, "/inspect/oidc/greendale", nil)
			r.Equal(http.StatusOK, inspector.Code, inspector.Body.String())
			r.Contains(inspector.Body.String(), claims["sid"].(string))
			r.Contains(inspector.Body.String(), "Troy Barnes")
			ended := f.browser(http.MethodPost, "/inspect/oidc/greendale/sessions/end", url.Values{"session_id": {claims["sid"].(string)}})
			r.Contains([]int{http.StatusFound, http.StatusSeeOther}, ended.Code)
			revoked := f.browser(http.MethodPost, "/inspect/oidc/greendale/revoke", url.Values{"user_id": {f.troy.ID}})
			r.Contains([]int{http.StatusFound, http.StatusSeeOther}, revoked.Code)
			var sessions struct {
				Sessions []map[string]any `json:"sessions"`
			}
			f.decode(t, http.MethodGet, "/sessions", "", http.StatusOK, &sessions)
			r.Empty(sessions.Sessions)
			var holders struct {
				Holders []map[string]any `json:"holders"`
			}
			f.decode(t, http.MethodGet, "/oidc/tokens", "", http.StatusOK, &holders)
			r.Empty(holders.Holders)
		})
	}
	for name, tc := range map[string]struct {
		query  url.Values
		cookie *http.Cookie
		want   string
	}{
		"OAuth error":      {query: url.Values{"error": {"access_denied"}, "error_description": {"<script>study-group</script>"}}, want: "access_denied: &lt;script&gt;study-group&lt;/script&gt;"},
		"expired session":  {query: url.Values{"code": {"unused"}}, want: "playground session expired"},
		"state mismatch":   {query: url.Values{"state": {"wrong"}}, cookie: &http.Cookie{Name: "scimtest_playground_greendale", Value: "study|group|"}, want: "state did not match"},
		"malformed cookie": {query: url.Values{"state": {"study"}}, cookie: &http.Cookie{Name: "scimtest_playground_greendale", Value: "study"}, want: "state did not match"},
		"missing code":     {query: url.Values{"state": {"study"}}, cookie: &http.Cookie{Name: "scimtest_playground_greendale", Value: "study|group|"}, want: "authorization response carried no code"},
	} {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			cookies := []*http.Cookie{}
			if tc.cookie != nil {
				cookies = append(cookies, tc.cookie)
			}
			page := f.browser(http.MethodGet, path+"/callback", tc.query, cookies...)
			r.Equal(http.StatusOK, page.Code)
			r.Contains(page.Body.String(), tc.want)
			r.NotContains(page.Body.String(), "<script>study-group</script>")
		})
	}
	t.Run("faults stay on local origin", func(t *testing.T) {
		r := require.New(t)
		start := f.browser(http.MethodGet, path, url.Values{"fault_token_error": {"invalid_grant"}, "fault_drop_claims": {"email", "name"}, "unrelated": {"discard"}})
		r.Equal(http.StatusFound, start.Code)
		location, err := url.Parse(start.Header().Get("Location"))
		r.NoError(err)
		r.Equal("invalid_grant", location.Query().Get("fault_token_error"))
		r.Equal([]string{"email", "name"}, location.Query()["fault_drop_claims"])
		r.Empty(location.Query().Get("unrelated"))
		form := location.Query()
		form.Set("user_id", f.troy.ID)
		authorized := f.browser(http.MethodPost, location.Path, form)
		r.Equal(http.StatusFound, authorized.Code, authorized.Body.String())
		callback, err := url.Parse(authorized.Header().Get("Location"))
		r.NoError(err)
		page := f.browser(http.MethodGet, callback.Path, callback.Query(), start.Result().Cookies()...)
		r.Equal(http.StatusOK, page.Code)
		r.Contains(page.Body.String(), "400 Bad Request")
		r.Contains(page.Body.String(), "invalid_grant")
		r.NotContains(page.Body.String(), `name="refresh_token"`)
	})
}

func playgroundDisplayedClaims(t *testing.T, body string) map[string]any {
	t.Helper()
	_, after, found := strings.Cut(body, "<h3>Claims</h3>")
	r := require.New(t)
	r.True(found)
	_, after, found = strings.Cut(after, ">")
	r.True(found)
	claims, _, found := strings.Cut(after, "</pre>")
	r.True(found)
	var value map[string]any
	r.NoError(json.Unmarshal([]byte(html.UnescapeString(claims)), &value))
	return value
}
