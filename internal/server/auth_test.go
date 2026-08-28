package server

import (
	"crypto/sha256"
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
			r.NoError(json.NewEncoder(w).Encode(auth.GitHubUser{ID: 1, Login: "rselbach"}))
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
	stateCookie := cookieNamed(t, loginResponse.Result().Cookies(), s.cookieName(stateCookieName))
	r.Equal("__Host-"+stateCookieName, stateCookie.Name)
	r.True(stateCookie.HttpOnly)
	r.True(stateCookie.Secure)

	callbackRequest := httptest.NewRequest(http.MethodGet, "/auth/github/callback?code=paintball&state="+url.QueryEscape(stateCookie.Value), nil)
	callbackRequest.AddCookie(stateCookie)
	callbackResponse := httptest.NewRecorder()
	s.handleGitHubCallback(callbackResponse, callbackRequest)
	r.Equal(http.StatusFound, callbackResponse.Code)
	r.Equal("/dashboard", callbackResponse.Header().Get("Location"))
	sessionCookie := cookieNamed(t, callbackResponse.Result().Cookies(), s.cookieName(sessionCookieName))
	r.Equal("__Host-"+sessionCookieName, sessionCookie.Name)
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
			r.NoError(json.NewEncoder(w).Encode(auth.GitHubUser{ID: 2, Login: "pierce"}))
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
	loginResponse := httptest.NewRecorder()
	s.handleGitHubLogin(loginResponse, httptest.NewRequest(http.MethodGet, "/login/github", nil))
	stateCookie := cookieNamed(t, loginResponse.Result().Cookies(), s.cookieName(stateCookieName))
	request := httptest.NewRequest(http.MethodGet, "/auth/github/callback?code=paintball&state="+url.QueryEscape(stateCookie.Value), nil)
	request.AddCookie(stateCookie)
	response := httptest.NewRecorder()
	s.handleGitHubCallback(response, request)
	r.Equal(http.StatusForbidden, response.Code)
	r.Empty(response.Header().Get("Location"))
}

func TestGitHubEnrollmentAuthorizesNonAdminWithoutDashboardSession(t *testing.T) {
	r := require.New(t)
	github := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/token":
			r.NoError(req.ParseForm())
			r.NotEmpty(req.PostForm.Get("code_verifier"))
			r.NoError(json.NewEncoder(w).Encode(auth.TokenResponse{AccessToken: "greendale-token"}))
		case "/user":
			r.NoError(json.NewEncoder(w).Encode(auth.GitHubUser{ID: 42, Login: "pierce"}))
		default:
			http.NotFound(w, req)
		}
	}))
	defer github.Close()

	store, profile, _ := newEnrollmentProfile(t)
	s := &Server{
		cfg: Config{
			Domain:                  "scimtest.example.com",
			DashboardDomain:         "admin.example.com",
			PublicScheme:            "https",
			MaxInstallationsPerUser: 5,
			Logger:                  slog.New(slog.NewTextHandler(io.Discard, nil)),
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
	_, publicKey, instanceID := testInstanceKey(t)
	required, err := s.beginEnrollment(profile.ID, instanceID, publicKey, "", "192.0.2.10")
	r.NoError(err)
	verificationURL, err := url.Parse(required.EnrollmentURL)
	r.NoError(err)
	userCode := verificationURL.Query().Get("code")
	r.NotEmpty(userCode)

	pageResponse := httptest.NewRecorder()
	s.handleEnrollmentAuthorization(pageResponse, httptest.NewRequest(http.MethodGet, "/enroll?code="+url.QueryEscape(userCode), nil))
	r.Equal(http.StatusOK, pageResponse.Code)
	r.Contains(pageResponse.Header().Get("Content-Security-Policy"), "form-action 'self' https://github.com")
	r.NotContains(pageResponse.Body.String(), required.EnrollmentDeviceCode)
	r.Contains(pageResponse.Body.String(), instanceID)
	r.Contains(pageResponse.Body.String(), `class="verification-code"`)
	r.Contains(pageResponse.Body.String(), `class="brand"`)
	confirmCookie := cookieNamed(t, pageResponse.Result().Cookies(), s.cookieName(enrollmentConfirmCookieName))
	r.Equal("__Host-"+enrollmentConfirmCookieName, confirmCookie.Name)

	desktopPageResponse := httptest.NewRecorder()
	desktopPageRequest := httptest.NewRequest(
		http.MethodGet,
		"/enroll?code="+url.QueryEscape(userCode)+"&presentation=desktop",
		nil,
	)
	s.handleEnrollmentAuthorization(desktopPageResponse, desktopPageRequest)
	r.Equal(http.StatusOK, desktopPageResponse.Code)
	r.Contains(desktopPageResponse.Body.String(), instanceID)
	r.NotContains(desktopPageResponse.Body.String(), `class="verification-code"`)
	r.NotContains(desktopPageResponse.Body.String(), "If the codes do not match")

	form := url.Values{"code": {userCode}, "csrf_token": {confirmCookie.Value}}
	wrongOriginRequest := httptest.NewRequest(http.MethodPost, "/enroll", strings.NewReader(form.Encode()))
	wrongOriginRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	wrongOriginRequest.Header.Set("Origin", "https://scimtest.example.com")
	wrongOriginRequest.AddCookie(confirmCookie)
	wrongOriginResponse := httptest.NewRecorder()
	s.handleEnrollmentAuthorization(wrongOriginResponse, wrongOriginRequest)
	r.Equal(http.StatusForbidden, wrongOriginResponse.Code)

	startRequest := httptest.NewRequest(http.MethodPost, "/enroll", strings.NewReader(form.Encode()))
	startRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	startRequest.Header.Set("Origin", "https://admin.example.com")
	startRequest.AddCookie(confirmCookie)
	startResponse := httptest.NewRecorder()
	s.handleEnrollmentAuthorization(startResponse, startRequest)
	r.Equal(http.StatusFound, startResponse.Code)
	r.Contains(startResponse.Header().Get("Location"), auth.GitHubAuthorizeURL)
	stateCookie := cookieNamed(t, startResponse.Result().Cookies(), s.cookieName(stateCookieName))

	callbackRequest := httptest.NewRequest(http.MethodGet, "/auth/github/callback?code=paintball&state="+url.QueryEscape(stateCookie.Value), nil)
	callbackRequest.AddCookie(stateCookie)
	callbackResponse := httptest.NewRecorder()
	s.handleGitHubCallback(callbackResponse, callbackRequest)
	r.Equal(http.StatusOK, callbackResponse.Code)
	r.Contains(callbackResponse.Body.String(), "Installation authorized")
	r.Contains(callbackResponse.Body.String(), `class="card complete-card"`)
	for _, cookie := range callbackResponse.Result().Cookies() {
		r.NotEqual(s.cookieName(sessionCookieName), cookie.Name)
	}
	hash := sha256.Sum256([]byte(required.EnrollmentDeviceCode))
	s.enrollMu.Lock()
	pending := s.pendingEnrollments[hash]
	s.enrollMu.Unlock()
	r.Equal(int64(42), pending.actor.GitHubUserID)
	r.Equal("pierce", pending.actor.GitHubLogin)

	replayResponse := httptest.NewRecorder()
	s.handleGitHubCallback(replayResponse, callbackRequest)
	r.Equal(http.StatusBadRequest, replayResponse.Code)

	store.mu.Lock()
	r.Empty(store.data.Sessions)
	store.mu.Unlock()
}

func TestEnrollmentBrowserHandoffStartsGitHubOAuthOnce(t *testing.T) {
	r := require.New(t)
	store, profile, _ := newEnrollmentProfile(t)
	s, _ := newEnrollmentTestServer(t, store)
	_, publicKey, instanceID := testInstanceKey(t)
	required, err := s.beginEnrollment(profile.ID, instanceID, publicKey, "", "192.0.2.20")
	r.NoError(err)
	handoffURL, err := url.Parse(required.EnrollmentBrowserHandoffURL)
	r.NoError(err)
	r.NotEmpty(handoffURL.Query().Get("handoff"))

	methodResponse := httptest.NewRecorder()
	s.handleEnrollmentBrowserHandoff(
		methodResponse,
		httptest.NewRequest(http.MethodPost, handoffURL.RequestURI(), nil),
	)
	r.Equal(http.StatusMethodNotAllowed, methodResponse.Code)
	r.Equal(http.MethodGet, methodResponse.Header().Get("Allow"))

	response := httptest.NewRecorder()
	s.handleEnrollmentBrowserHandoff(
		response,
		httptest.NewRequest(http.MethodGet, handoffURL.RequestURI(), nil),
	)
	r.Equal(http.StatusFound, response.Code)
	r.Contains(response.Header().Get("Location"), auth.GitHubAuthorizeURL)
	r.Equal("no-store", response.Header().Get("Cache-Control"))
	r.Equal("no-referrer", response.Header().Get("Referrer-Policy"))
	stateCookie := cookieNamed(t, response.Result().Cookies(), s.cookieName(stateCookieName))
	r.NotEmpty(stateCookie.Value)

	s.enrollMu.Lock()
	intent, exists := s.oauthIntents[stateCookie.Value]
	s.enrollMu.Unlock()
	r.True(exists)
	r.Equal(oauthIntentEnrollment, intent.kind)
	r.Equal(sha256.Sum256([]byte(required.EnrollmentDeviceCode)), intent.enrollmentHash)

	replayResponse := httptest.NewRecorder()
	s.handleEnrollmentBrowserHandoff(
		replayResponse,
		httptest.NewRequest(http.MethodGet, handoffURL.RequestURI(), nil),
	)
	r.Equal(http.StatusGone, replayResponse.Code)
}

func TestEnrollmentBrowserHandoffCanRetryTransientOAuthFailure(t *testing.T) {
	r := require.New(t)
	store, profile, _ := newEnrollmentProfile(t)
	s, _ := newEnrollmentTestServer(t, store)
	_, publicKey, instanceID := testInstanceKey(t)
	required, err := s.beginEnrollment(profile.ID, instanceID, publicKey, "", "192.0.2.21")
	r.NoError(err)
	handoffURL, err := url.Parse(required.EnrollmentBrowserHandoffURL)
	r.NoError(err)

	github := s.github
	s.github = auth.GitHubClient{}
	failureResponse := httptest.NewRecorder()
	s.handleEnrollmentBrowserHandoff(
		failureResponse,
		httptest.NewRequest(http.MethodGet, handoffURL.RequestURI(), nil),
	)
	r.Equal(http.StatusServiceUnavailable, failureResponse.Code)

	s.github = github
	retryResponse := httptest.NewRecorder()
	s.handleEnrollmentBrowserHandoff(
		retryResponse,
		httptest.NewRequest(http.MethodGet, handoffURL.RequestURI(), nil),
	)
	r.Equal(http.StatusFound, retryResponse.Code)
}

func TestGitHubEnrollmentLimitOffersInstallationReplacement(t *testing.T) {
	r := require.New(t)
	github := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/token":
			r.NoError(json.NewEncoder(w).Encode(auth.TokenResponse{AccessToken: "greendale-token"}))
		case "/user":
			r.NoError(json.NewEncoder(w).Encode(auth.GitHubUser{ID: 42, Login: "troy-barnes"}))
		default:
			http.NotFound(w, req)
		}
	}))
	defer github.Close()

	store, profile, _ := newEnrollmentProfile(t)
	r.NoError(store.EnrollApplicationInstance(
		profile.ID,
		"existing-installation",
		"existing-public-key",
		enrollmentActor{GitHubUserID: 42, GitHubLogin: "troy-barnes"},
	))
	r.NoError(store.RememberApplicationTunnel(profile.ID, "existing-installation", "study-group"))
	s := &Server{
		cfg: Config{
			Domain:                  "scimtest.example.com",
			DashboardDomain:         "admin.example.com",
			PublicScheme:            "https",
			MaxInstallationsPerUser: 1,
			Logger:                  slog.New(slog.NewTextHandler(io.Discard, nil)),
		},
		store: store,
		github: auth.GitHubClient{
			ClientID:     "client-id",
			ClientSecret: "client-secret",
			HTTPClient:   github.Client(),
			TokenURL:     github.URL + "/token",
			UserURL:      github.URL + "/user",
		},
		tunnels: make(map[string]*tunnel),
	}
	_, publicKey, instanceID := testInstanceKey(t)
	required, err := s.beginEnrollment(profile.ID, instanceID, publicKey, "", "192.0.2.22")
	r.NoError(err)
	deviceHash := sha256.Sum256([]byte(required.EnrollmentDeviceCode))

	startResponse := httptest.NewRecorder()
	s.beginGitHubOAuth(
		startResponse,
		httptest.NewRequest(http.MethodGet, "/enroll/browser", nil),
		oauthIntent{kind: oauthIntentEnrollment, enrollmentHash: deviceHash},
	)
	stateCookie := cookieNamed(t, startResponse.Result().Cookies(), s.cookieName(stateCookieName))
	callbackRequest := httptest.NewRequest(
		http.MethodGet,
		"/auth/github/callback?code=paintball&state="+url.QueryEscape(stateCookie.Value),
		nil,
	)
	callbackRequest.AddCookie(stateCookie)
	callbackResponse := httptest.NewRecorder()
	s.handleGitHubCallback(callbackResponse, callbackRequest)

	r.Equal(http.StatusOK, callbackResponse.Code)
	r.Contains(callbackResponse.Body.String(), "Make room for this installation")
	r.Contains(callbackResponse.Body.String(), "study-group")
	r.Contains(callbackResponse.Body.String(), "Recommended")
	r.NotContains(callbackResponse.Body.String(), errInstallationLimitReached.Error())
	replacementCookie := cookieNamed(
		t,
		callbackResponse.Result().Cookies(),
		s.cookieName(enrollmentReplacementCookieName),
	)
	r.NotEmpty(replacementCookie.Value)
}

func TestEnrollmentReplacementDeactivatesSelectedInstallationAndApprovesNewOne(t *testing.T) {
	r := require.New(t)
	store, profile, _ := newEnrollmentProfile(t)
	s, _ := newEnrollmentTestServer(t, store)
	s.cfg.MaxInstallationsPerUser = 2
	user := auth.GitHubUser{ID: 43, Login: "abed-nadir"}
	for _, installation := range []struct {
		id       string
		key      string
		tunnelID string
	}{
		{id: "old-installation", key: "old-public-key", tunnelID: "dreamatorium"},
		{id: "active-installation", key: "active-public-key", tunnelID: "study-room-f"},
	} {
		r.NoError(store.EnrollApplicationInstance(
			profile.ID,
			installation.id,
			installation.key,
			enrollmentActor{GitHubUserID: user.ID, GitHubLogin: user.Login},
		))
		r.NoError(store.RememberApplicationTunnel(profile.ID, installation.id, installation.tunnelID))
	}
	now := time.Now().UTC()
	store.mu.Lock()
	storedProfile := cloneApplicationProfile(store.data.ApplicationProfiles[profile.ID])
	old := storedProfile.Instances["old-installation"]
	old.CreatedAt = now.Add(-180 * 24 * time.Hour)
	old.LastUsedAt = now.Add(-30 * 24 * time.Hour)
	storedProfile.Instances["old-installation"] = old
	active := storedProfile.Instances["active-installation"]
	active.CreatedAt = now.Add(-60 * 24 * time.Hour)
	active.LastUsedAt = now.Add(-24 * time.Hour)
	storedProfile.Instances["active-installation"] = active
	store.data.ApplicationProfiles[profile.ID] = storedProfile
	store.mu.Unlock()
	s.tunnels["/study-room-f"] = &tunnel{
		id:                   "study-room-f",
		applicationProfileID: profile.ID,
		instanceID:           "active-installation",
	}

	_, publicKey, instanceID := testInstanceKey(t)
	required, err := s.beginEnrollment(profile.ID, instanceID, publicKey, "", "192.0.2.23")
	r.NoError(err)
	deviceHash := sha256.Sum256([]byte(required.EnrollmentDeviceCode))
	r.ErrorIs(s.approveEnrollment(deviceHash, user), errInstallationLimitReached)

	pageResponse := httptest.NewRecorder()
	r.NoError(s.renderEnrollmentReplacement(pageResponse, deviceHash, user, ""))
	body := pageResponse.Body.String()
	r.Contains(body, "dreamatorium")
	r.Contains(body, "study-room-f")
	r.Less(strings.Index(body, "dreamatorium"), strings.Index(body, "study-room-f"))
	r.Contains(body, "Recommended")
	r.Contains(body, "Connected now")
	r.Contains(body, "Disconnect and continue")
	replacementCookie := cookieNamed(
		t,
		pageResponse.Result().Cookies(),
		s.cookieName(enrollmentReplacementCookieName),
	)
	tokenHash := sha256.Sum256([]byte(replacementCookie.Value))
	s.enrollMu.Lock()
	intent := s.replacementIntents[tokenHash]
	s.enrollMu.Unlock()
	r.NotEmpty(intent.csrfToken)

	form := url.Values{
		"csrf_token":  {intent.csrfToken},
		"instance_id": {"old-installation"},
	}
	wrongOriginRequest := httptest.NewRequest(http.MethodPost, "/enroll/replace", strings.NewReader(form.Encode()))
	wrongOriginRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	wrongOriginRequest.Header.Set("Origin", "https://malicious.example.com")
	wrongOriginRequest.AddCookie(replacementCookie)
	wrongOriginResponse := httptest.NewRecorder()
	s.handleEnrollmentReplacement(wrongOriginResponse, wrongOriginRequest)
	r.Equal(http.StatusForbidden, wrongOriginResponse.Code)

	wrongCSRFForm := url.Values{
		"csrf_token":  {"wrong-token"},
		"instance_id": {"old-installation"},
	}
	wrongCSRFRequest := httptest.NewRequest(http.MethodPost, "/enroll/replace", strings.NewReader(wrongCSRFForm.Encode()))
	wrongCSRFRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	wrongCSRFRequest.Header.Set("Origin", "http://admin.localhost:7000")
	wrongCSRFRequest.AddCookie(replacementCookie)
	wrongCSRFResponse := httptest.NewRecorder()
	s.handleEnrollmentReplacement(wrongCSRFResponse, wrongCSRFRequest)
	r.Equal(http.StatusBadRequest, wrongCSRFResponse.Code)

	replaceRequest := httptest.NewRequest(http.MethodPost, "/enroll/replace", strings.NewReader(form.Encode()))
	replaceRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	replaceRequest.Header.Set("Origin", "http://admin.localhost:7000")
	replaceRequest.AddCookie(replacementCookie)
	replaceResponse := httptest.NewRecorder()
	s.handleEnrollmentReplacement(replaceResponse, replaceRequest)

	r.Equal(http.StatusOK, replaceResponse.Code)
	r.Contains(replaceResponse.Body.String(), "Installation authorized")
	replaced, exists := store.ApplicationInstance(profile.ID, "old-installation")
	r.True(exists)
	r.True(replaced.Revoked)
	stillActive, exists := store.ApplicationInstance(profile.ID, "active-installation")
	r.True(exists)
	r.False(stillActive.Revoked)
	s.enrollMu.Lock()
	pending := s.pendingEnrollments[deviceHash]
	s.enrollMu.Unlock()
	r.Equal(user.ID, pending.actor.GitHubUserID)
	r.False(pending.approvedAt.IsZero())
	r.NoError(s.consumeEnrollmentGrant(required.EnrollmentDeviceCode, profile.ID, instanceID, publicKey, ""))
	r.Equal(2, store.CountApplicationInstancesByGitHubUserID(profile.ID, user.ID))

	replayResponse := httptest.NewRecorder()
	s.handleEnrollmentReplacement(replayResponse, replaceRequest)
	r.Equal(http.StatusGone, replayResponse.Code)
}

func TestEnrollmentReplacementAcceptsLoopbackOrigin(t *testing.T) {
	r := require.New(t)
	store, profile, _ := newEnrollmentProfile(t)
	s, _ := newEnrollmentTestServer(t, store)
	s.cfg.MaxInstallationsPerUser = 1
	user := auth.GitHubUser{ID: 47, Login: "troy-barnes"}
	r.NoError(store.EnrollApplicationInstance(
		profile.ID,
		"old-installation",
		"old-public-key",
		enrollmentActor{GitHubUserID: user.ID, GitHubLogin: user.Login},
	))
	_, publicKey, instanceID := testInstanceKey(t)
	required, err := s.beginEnrollment(profile.ID, instanceID, publicKey, "", "192.0.2.27")
	r.NoError(err)
	deviceHash := sha256.Sum256([]byte(required.EnrollmentDeviceCode))
	r.ErrorIs(s.approveEnrollment(deviceHash, user), errInstallationLimitReached)

	pageResponse := httptest.NewRecorder()
	r.NoError(s.renderEnrollmentReplacement(pageResponse, deviceHash, user, ""))
	replacementCookie := cookieNamed(
		t,
		pageResponse.Result().Cookies(),
		s.cookieName(enrollmentReplacementCookieName),
	)
	tokenHash := sha256.Sum256([]byte(replacementCookie.Value))
	s.enrollMu.Lock()
	intent := s.replacementIntents[tokenHash]
	s.enrollMu.Unlock()
	form := url.Values{
		"csrf_token":  {intent.csrfToken},
		"instance_id": {"old-installation"},
	}

	missingOrigin := httptest.NewRequest(http.MethodPost, "/enroll/replace", strings.NewReader(form.Encode()))
	missingOrigin.Host = "127.0.0.1:7000"
	missingOrigin.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	missingOrigin.AddCookie(replacementCookie)
	missingOriginResponse := httptest.NewRecorder()
	s.handleEnrollmentReplacement(missingOriginResponse, missingOrigin)
	r.Equal(http.StatusForbidden, missingOriginResponse.Code)

	replaceRequest := httptest.NewRequest(http.MethodPost, "/enroll/replace", strings.NewReader(form.Encode()))
	replaceRequest.Host = "127.0.0.1:7000"
	replaceRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	replaceRequest.Header.Set("Origin", "http://127.0.0.1:7000")
	replaceRequest.AddCookie(replacementCookie)
	replaceResponse := httptest.NewRecorder()
	s.handleEnrollmentReplacement(replaceResponse, replaceRequest)
	r.Equal(http.StatusOK, replaceResponse.Code)
	r.Contains(replaceResponse.Body.String(), "Installation authorized")
}

func TestEnrollmentReplacementRejectsAnotherAccountsInstallation(t *testing.T) {
	r := require.New(t)
	store, profile, _ := newEnrollmentProfile(t)
	s, _ := newEnrollmentTestServer(t, store)
	s.cfg.MaxInstallationsPerUser = 1
	user := auth.GitHubUser{ID: 44, Login: "britta-perry"}
	r.NoError(store.EnrollApplicationInstance(
		profile.ID,
		"owned-installation",
		"owned-public-key",
		enrollmentActor{GitHubUserID: user.ID, GitHubLogin: user.Login},
	))
	r.NoError(store.EnrollApplicationInstance(
		profile.ID,
		"other-installation",
		"other-public-key",
		enrollmentActor{GitHubUserID: 45, GitHubLogin: "annie-edison"},
	))
	_, publicKey, instanceID := testInstanceKey(t)
	required, err := s.beginEnrollment(profile.ID, instanceID, publicKey, "", "192.0.2.24")
	r.NoError(err)
	deviceHash := sha256.Sum256([]byte(required.EnrollmentDeviceCode))
	r.ErrorIs(s.approveEnrollment(deviceHash, user), errInstallationLimitReached)

	pageResponse := httptest.NewRecorder()
	r.NoError(s.renderEnrollmentReplacement(pageResponse, deviceHash, user, ""))
	r.Contains(pageResponse.Body.String(), "owned-installation")
	r.NotContains(pageResponse.Body.String(), "other-installation")
	replacementCookie := cookieNamed(
		t,
		pageResponse.Result().Cookies(),
		s.cookieName(enrollmentReplacementCookieName),
	)
	tokenHash := sha256.Sum256([]byte(replacementCookie.Value))
	s.enrollMu.Lock()
	intent := s.replacementIntents[tokenHash]
	s.enrollMu.Unlock()
	form := url.Values{
		"csrf_token":  {intent.csrfToken},
		"instance_id": {"other-installation"},
	}
	request := httptest.NewRequest(http.MethodPost, "/enroll/replace", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "http://admin.localhost:7000")
	request.AddCookie(replacementCookie)
	response := httptest.NewRecorder()
	s.handleEnrollmentReplacement(response, request)

	r.Equal(http.StatusOK, response.Code)
	r.Contains(response.Body.String(), "no longer available")
	other, exists := store.ApplicationInstance(profile.ID, "other-installation")
	r.True(exists)
	r.False(other.Revoked)
	s.enrollMu.Lock()
	pending := s.pendingEnrollments[deviceHash]
	s.enrollMu.Unlock()
	r.True(pending.approvedAt.IsZero())
}

func TestEnrollmentReplacementCanCancelApprovedPendingSetup(t *testing.T) {
	r := require.New(t)
	store, profile, _ := newEnrollmentProfile(t)
	s, _ := newEnrollmentTestServer(t, store)
	s.cfg.MaxInstallationsPerUser = 1
	user := auth.GitHubUser{ID: 46, Login: "elroy-patashnik"}
	_, firstPublicKey, firstInstanceID := testInstanceKey(t)
	first, err := s.beginEnrollment(profile.ID, firstInstanceID, firstPublicKey, "", "192.0.2.25")
	r.NoError(err)
	firstHash := sha256.Sum256([]byte(first.EnrollmentDeviceCode))
	r.NoError(s.approveEnrollment(firstHash, user))

	_, secondPublicKey, secondInstanceID := testInstanceKey(t)
	second, err := s.beginEnrollment(profile.ID, secondInstanceID, secondPublicKey, "", "192.0.2.26")
	r.NoError(err)
	secondHash := sha256.Sum256([]byte(second.EnrollmentDeviceCode))
	r.ErrorIs(s.approveEnrollment(secondHash, user), errInstallationLimitReached)

	pageResponse := httptest.NewRecorder()
	r.NoError(s.renderEnrollmentReplacement(pageResponse, secondHash, user, ""))
	r.Contains(pageResponse.Body.String(), firstInstanceID)
	r.Contains(pageResponse.Body.String(), "Setup pending")
	r.Contains(pageResponse.Body.String(), "Recommended")
	replacementCookie := cookieNamed(
		t,
		pageResponse.Result().Cookies(),
		s.cookieName(enrollmentReplacementCookieName),
	)
	tokenHash := sha256.Sum256([]byte(replacementCookie.Value))
	s.enrollMu.Lock()
	intent := s.replacementIntents[tokenHash]
	s.enrollMu.Unlock()
	form := url.Values{
		"csrf_token":  {intent.csrfToken},
		"instance_id": {firstInstanceID},
	}
	request := httptest.NewRequest(http.MethodPost, "/enroll/replace", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "http://admin.localhost:7000")
	request.AddCookie(replacementCookie)
	response := httptest.NewRecorder()
	s.handleEnrollmentReplacement(response, request)

	r.Equal(http.StatusOK, response.Code)
	s.enrollMu.Lock()
	_, firstExists := s.pendingEnrollments[firstHash]
	secondPending := s.pendingEnrollments[secondHash]
	s.enrollMu.Unlock()
	r.False(firstExists)
	r.False(secondPending.approvedAt.IsZero())
}

func TestGitHubCallbackRejectsUnknownServerSideState(t *testing.T) {
	s := &Server{cfg: Config{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}}
	request := httptest.NewRequest(http.MethodGet, "/auth/github/callback?code=paintball&state=state", nil)
	request.AddCookie(&http.Cookie{Name: stateCookieName, Value: "state"})
	response := httptest.NewRecorder()
	s.handleGitHubCallback(response, request)
	require.Equal(t, http.StatusBadRequest, response.Code)
}

func TestGitHubOAuthIntentRateLimit(t *testing.T) {
	s := &Server{
		cfg: Config{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))},
		github: auth.GitHubClient{
			ClientID:     "client-id",
			ClientSecret: "client-secret",
		},
	}
	for range oauthIntentsPerIPLimit {
		response := httptest.NewRecorder()
		s.handleGitHubLogin(response, httptest.NewRequest(http.MethodGet, "/login/github", nil))
		require.Equal(t, http.StatusFound, response.Code)
	}
	response := httptest.NewRecorder()
	s.handleGitHubLogin(response, httptest.NewRequest(http.MethodGet, "/login/github", nil))
	require.Equal(t, http.StatusTooManyRequests, response.Code)
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
	request.AddCookie(&http.Cookie{Name: s.cookieName(sessionCookieName), Value: session.ID})
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
	request.AddCookie(&http.Cookie{Name: s.cookieName(sessionCookieName), Value: session.ID})
	response := httptest.NewRecorder()
	s.handleLogout(response, request)
	r.Equal(http.StatusFound, response.Code)
	r.Equal("/", response.Header().Get("Location"))
	_, ok, err := store.Session(session.ID)
	r.NoError(err)
	r.False(ok)
	cookie := cookieNamed(t, response.Result().Cookies(), s.cookieName(sessionCookieName))
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
