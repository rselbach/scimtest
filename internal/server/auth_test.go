package server

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/rselbach/scimtest/internal/auth"
	"github.com/stretchr/testify/require"
)

func TestGitHubLoginCreatesAllowedSession(t *testing.T) {
	r := require.New(t)
	github := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/token":
			r.NoError(json.NewEncoder(w).Encode(auth.TokenResponse{AccessToken: "greendale-token"}))
		case "/user":
			r.NoError(json.NewEncoder(w).Encode(auth.GitHubUser{Login: "rselbach"}))
		default:
			http.NotFound(w, req)
		}
	}))
	defer github.Close()

	store, err := OpenStore(t.TempDir() + "/test.json")
	r.NoError(err)
	s := &Server{
		cfg: Config{
			Domain:             "scimtest.example.com",
			PublicScheme:       "https",
			GitHubClientID:     "client-id",
			GitHubClientSecret: "client-secret",
			Logger:             slog.New(slog.NewTextHandler(io.Discard, nil)),
		},
		store: store,
		github: auth.GitHubClient{
			ClientID:     "client-id",
			ClientSecret: "client-secret",
			HTTPClient:   github.Client(),
			TokenURL:     github.URL + "/token",
			UserURL:      github.URL + "/user",
		},
	}

	loginRequest := httptest.NewRequest(http.MethodGet, "/login/github", nil)
	loginResponse := httptest.NewRecorder()
	s.handleGitHubLogin(loginResponse, loginRequest)
	r.Equal(http.StatusFound, loginResponse.Code)
	r.Contains(loginResponse.Header().Get("Location"), auth.GitHubAuthorizeURL)
	stateCookie := cookieNamed(t, loginResponse.Result().Cookies(), stateCookieName)
	r.True(stateCookie.HttpOnly)
	r.True(stateCookie.Secure)

	callbackRequest := httptest.NewRequest(http.MethodGet, "/auth/github/callback?code=paintball&state="+url.QueryEscape(stateCookie.Value), nil)
	callbackRequest.AddCookie(stateCookie)
	callbackResponse := httptest.NewRecorder()
	s.handleGitHubCallback(callbackResponse, callbackRequest)
	r.Equal(http.StatusFound, callbackResponse.Code)
	r.Equal("/dashboard", callbackResponse.Header().Get("Location"))
	sessionCookie := cookieNamed(t, callbackResponse.Result().Cookies(), sessionCookieName)
	r.True(sessionCookie.HttpOnly)
	r.True(sessionCookie.Secure)
	session, ok, err := store.Session(sessionCookie.Value)
	r.NoError(err)
	r.True(ok)
	r.Equal("rselbach", session.Login)
	r.True(session.Admin)
	r.NotEmpty(session.CSRFToken)
}

func TestGitHubLoginRequiresConfiguration(t *testing.T) {
	response := httptest.NewRecorder()
	(&Server{}).handleGitHubLogin(response, httptest.NewRequest(http.MethodGet, "/login/github", nil))
	require.Equal(t, http.StatusServiceUnavailable, response.Code)
}

func TestDashboardLandingRequiresExplicitSignIn(t *testing.T) {
	s := &Server{
		cfg:     Config{Domain: "scimtest.example.com", DashboardDomain: "admin.example.com"},
		tunnels: make(map[string]*tunnel),
	}
	request := httptest.NewRequest(http.MethodGet, "https://admin.example.com/", nil)
	response := httptest.NewRecorder()
	s.handlePublic(response, request)
	require.Equal(t, http.StatusOK, response.Code)
	require.Contains(t, response.Body.String(), "Sign in with GitHub")
	require.Contains(t, response.Body.String(), `href="/login/github"`)
}

func TestGitHubLoginRejectsUnlistedUser(t *testing.T) {
	r := require.New(t)
	github := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/token":
			r.NoError(json.NewEncoder(w).Encode(auth.TokenResponse{AccessToken: "greendale-token"}))
		case "/user":
			r.NoError(json.NewEncoder(w).Encode(auth.GitHubUser{Login: "pierce"}))
		}
	}))
	defer github.Close()
	store, err := OpenStore(t.TempDir() + "/test.json")
	r.NoError(err)
	s := &Server{
		cfg:   Config{Domain: "example.com", PublicScheme: "https", Logger: slog.New(slog.NewTextHandler(io.Discard, nil))},
		store: store,
		github: auth.GitHubClient{
			ClientID:     "client-id",
			ClientSecret: "client-secret",
			HTTPClient:   github.Client(),
			TokenURL:     github.URL + "/token",
			UserURL:      github.URL + "/user",
		},
	}
	request := httptest.NewRequest(http.MethodGet, "/auth/github/callback?code=paintball&state=state", nil)
	request.AddCookie(&http.Cookie{Name: stateCookieName, Value: "state"})
	response := httptest.NewRecorder()
	s.handleGitHubCallback(response, request)
	r.Equal(http.StatusForbidden, response.Code)
	r.Empty(response.Header().Get("Location"))
}

func TestDashboardMutationRequiresCSRF(t *testing.T) {
	r := require.New(t)
	store, err := OpenStore(t.TempDir() + "/test.json")
	r.NoError(err)
	session, err := store.CreateSession("rselbach", true)
	r.NoError(err)
	s := &Server{store: store}
	request := httptest.NewRequest(http.MethodPost, "/dashboard/applications/create", strings.NewReader("name=Greendale"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session.ID})
	response := httptest.NewRecorder()
	s.handleCreateApplication(response, request)
	r.Equal(http.StatusForbidden, response.Code)
	r.Empty(store.ListApplicationProfiles())
}

func TestInvalidDashboardSessionIsCleared(t *testing.T) {
	r := require.New(t)
	store, err := OpenStore(t.TempDir() + "/test.json")
	r.NoError(err)
	s := &Server{store: store}
	request := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "invalid-session"})
	response := httptest.NewRecorder()
	s.handleDashboard(response, request)
	r.Equal(http.StatusFound, response.Code)
	r.Equal("/login/github", response.Header().Get("Location"))
	r.Equal(-1, cookieNamed(t, response.Result().Cookies(), sessionCookieName).MaxAge)
}

func TestStorePersistsDashboardSession(t *testing.T) {
	r := require.New(t)
	path := t.TempDir() + "/test.json"
	store, err := OpenStore(path)
	r.NoError(err)
	session, err := store.CreateSession("RSELBACH", true)
	r.NoError(err)

	reopened, err := OpenStore(path)
	r.NoError(err)
	stored, ok, err := reopened.Session(session.ID)
	r.NoError(err)
	r.True(ok)
	r.Equal("rselbach", stored.Login)
	r.Equal(session.CSRFToken, stored.CSRFToken)
}

func TestLogoutDeletesSession(t *testing.T) {
	r := require.New(t)
	store, err := OpenStore(t.TempDir() + "/test.json")
	r.NoError(err)
	session, err := store.CreateSession("rselbach", true)
	r.NoError(err)
	s := &Server{store: store, cfg: Config{PublicScheme: "https"}}
	request := httptest.NewRequest(http.MethodPost, "/logout", strings.NewReader("csrf_token="+session.CSRFToken))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session.ID})
	response := httptest.NewRecorder()
	s.handleLogout(response, request)
	r.Equal(http.StatusFound, response.Code)
	r.Equal("/", response.Header().Get("Location"))
	_, ok, err := store.Session(session.ID)
	r.NoError(err)
	r.False(ok)
	cookie := cookieNamed(t, response.Result().Cookies(), sessionCookieName)
	r.Equal(-1, cookie.MaxAge)
	r.True(cookie.Secure)
}

func TestStoreRejectsSessionForOtherUser(t *testing.T) {
	r := require.New(t)
	store, err := OpenStore(t.TempDir() + "/test.json")
	r.NoError(err)
	_, err = store.CreateSession("pierce", true)
	r.ErrorContains(err, "restricted to rselbach")

	store.mu.Lock()
	store.data.Sessions["legacy-session"] = StoredSession{
		ID:        "legacy-session",
		Login:     "pierce",
		Admin:     true,
		CSRFToken: "legacy-csrf",
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	}
	store.mu.Unlock()
	_, ok, err := store.Session("legacy-session")
	r.NoError(err)
	r.False(ok)
}

func cookieNamed(t *testing.T, cookies []*http.Cookie, name string) *http.Cookie {
	t.Helper()
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	require.FailNow(t, "cookie not found", name)
	return nil
}
