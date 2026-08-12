package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rselbach/scimtest/internal/auth"
	"github.com/rselbach/scimtest/internal/protocol"
	"github.com/stretchr/testify/require"
)

func testInstanceKey(t *testing.T) (ed25519.PrivateKey, string, string) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sum := sha256.Sum256(publicKey)
	return privateKey, base64.StdEncoding.EncodeToString(publicKey), base64.RawURLEncoding.EncodeToString(sum[:])
}

func newEnrollmentTestServer(t *testing.T, store *Store) (*Server, string) {
	t.Helper()
	s := &Server{
		cfg: Config{
			Domain:                   "localhost:7000",
			DashboardDomain:          "admin.localhost:7000",
			PublicScheme:             "http",
			MaxTunnelsPerApplication: 5,
			MaxInstallationsPerUser:  5,
			Logger:                   slog.New(slog.NewTextHandler(io.Discard, nil)),
		},
		store: store,
		github: auth.GitHubClient{
			ClientID:     "client-id",
			ClientSecret: "client-secret",
		},
		tunnels: make(map[string]*tunnel),
	}
	srv := httptest.NewServer(http.HandlerFunc(s.handleConnect))
	t.Cleanup(srv.Close)
	return s, "ws" + strings.TrimPrefix(srv.URL, "http") + "/api/connect"
}

type enrollmentOptions struct {
	legacyInstanceID string
	grant            string
	instanceSigKey   ed25519.PrivateKey
}

func dialInstallation(t *testing.T, wsURL, profileID, instancePublicKey string, instanceKey ed25519.PrivateKey, opts enrollmentOptions) (*websocket.Conn, protocol.Message, error) {
	t.Helper()
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)
	require.NoError(t, conn.WriteJSON(protocol.Message{
		Type:                 protocol.TypeRegisterTunnel,
		ApplicationProfileID: profileID,
		InstanceID:           opts.legacyInstanceID,
		InstancePublicKey:    instancePublicKey,
		LocalPort:            4321,
	}))
	var challenge protocol.Message
	if err := conn.ReadJSON(&challenge); err != nil {
		return conn, protocol.Message{}, err
	}
	require.Equal(t, protocol.TypeApplicationChallenge, challenge.Type)
	require.True(t, challenge.EnrollmentSupported)

	sigKey := instanceKey
	if opts.instanceSigKey != nil {
		sigKey = opts.instanceSigKey
	}
	payload := protocol.InstanceChallengePayload(profileID, instancePublicKey, opts.legacyInstanceID, challenge.Challenge)
	require.NoError(t, conn.WriteJSON(protocol.Message{
		Type:            protocol.TypeApplicationSignature,
		Signature:       ed25519.Sign(sigKey, payload),
		EnrollmentGrant: opts.grant,
	}))

	var response protocol.Message
	err = conn.ReadJSON(&response)
	return conn, response, err
}

func approveRequiredEnrollment(t *testing.T, s *Server, required protocol.Message, user auth.GitHubUser) {
	t.Helper()
	require.Equal(t, protocol.TypeEnrollmentRequired, required.Type)
	hash := sha256.Sum256([]byte(required.EnrollmentDeviceCode))
	require.NoError(t, s.approveEnrollment(hash, user))
}

func newEnrollmentProfile(t *testing.T) (*Store, StoredApplicationProfile, ed25519.PrivateKey) {
	t.Helper()
	_, appKey, publicKeyText := testEd25519Key(t)
	store, err := OpenStore(t.TempDir() + "/test.json")
	require.NoError(t, err)
	profile, err := store.CreateApplicationProfile(
		"Greendale Identity",
		publicKeyText,
		[]StoredApplicationRoute{{Methods: []string{"GET"}, Path: "/oidc/{slug}/jwks"}},
		30,
		10,
		4,
	)
	require.NoError(t, err)
	return store, profile, appKey
}

func TestEnrollmentRequiresGitHubWithoutClaimingLegacyReservation(t *testing.T) {
	r := require.New(t)
	store, profile, _ := newEnrollmentProfile(t)
	r.NoError(store.RememberApplicationTunnel(profile.ID, "legacy-uuid-1", "human-timeline-club"))
	s, wsURL := newEnrollmentTestServer(t, store)
	instanceKey, instancePublicKey, fingerprint := testInstanceKey(t)

	conn, required, err := dialInstallation(t, wsURL, profile.ID, instancePublicKey, instanceKey, enrollmentOptions{legacyInstanceID: "legacy-uuid-1"})
	r.NoError(err)
	r.Equal(protocol.TypeEnrollmentRequired, required.Type)
	r.NotEmpty(required.EnrollmentDeviceCode)
	r.NotEmpty(required.EnrollmentVerificationCode)
	r.Contains(required.EnrollmentURL, "/enroll?code=")
	r.NotContains(required.EnrollmentURL, required.EnrollmentDeviceCode)
	r.Contains(required.EnrollmentBrowserHandoffURL, "/enroll/browser?handoff=")
	r.NotContains(required.EnrollmentBrowserHandoffURL, required.EnrollmentDeviceCode)
	r.Equal("http://localhost:7000/api/enroll/status", required.EnrollmentStatusURL)
	r.NoError(conn.Close())

	approveRequiredEnrollment(t, s, required, auth.GitHubUser{ID: 8675309, Login: "troy-barnes"})
	conn, registered, err := dialInstallation(t, wsURL, profile.ID, instancePublicKey, instanceKey, enrollmentOptions{
		legacyInstanceID: "legacy-uuid-1",
		grant:            required.EnrollmentDeviceCode,
	})
	r.NoError(err)
	r.Equal(protocol.TypeTunnelRegistered, registered.Type)
	r.NotEqual("human-timeline-club", registered.TunnelID)
	r.Equal(int64(8675309), registered.GitHubUserID)
	r.Equal("troy-barnes", registered.GitHubLogin)

	instance, ok := store.ApplicationInstance(profile.ID, fingerprint)
	r.True(ok)
	r.True(instance.Enrolled())
	r.Equal(instancePublicKey, instance.PublicKey)
	r.Equal(int64(8675309), instance.GitHubUserID)
	r.Equal("troy-barnes", instance.GitHubLogin)
	r.Equal(registered.TunnelID, instance.TunnelID)
	legacy, ok := store.ApplicationInstance(profile.ID, "legacy-uuid-1")
	r.True(ok)
	r.Equal("human-timeline-club", legacy.TunnelID)
	r.NoError(conn.Close())
}

func TestEnrolledInstallationReconnectsWithoutGrant(t *testing.T) {
	r := require.New(t)
	store, profile, _ := newEnrollmentProfile(t)
	s, wsURL := newEnrollmentTestServer(t, store)
	instanceKey, instancePublicKey, _ := testInstanceKey(t)

	conn, required, err := dialInstallation(t, wsURL, profile.ID, instancePublicKey, instanceKey, enrollmentOptions{})
	r.NoError(err)
	r.NoError(conn.Close())
	approveRequiredEnrollment(t, s, required, auth.GitHubUser{ID: 101, Login: "troy"})
	conn, registered, err := dialInstallation(t, wsURL, profile.ID, instancePublicKey, instanceKey, enrollmentOptions{grant: required.EnrollmentDeviceCode})
	r.NoError(err)
	r.Equal(protocol.TypeTunnelRegistered, registered.Type)
	firstTunnelID := registered.TunnelID
	r.NoError(conn.Close())

	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, registered, err = dialInstallation(t, wsURL, profile.ID, instancePublicKey, instanceKey, enrollmentOptions{})
		if err == nil {
			break
		}
		r.NoError(conn.Close())
		if time.Now().After(deadline) {
			r.NoError(err)
		}
		time.Sleep(25 * time.Millisecond)
	}
	r.Equal(protocol.TypeTunnelRegistered, registered.Type)
	r.Equal(firstTunnelID, registered.TunnelID)
	r.NoError(conn.Close())
}

func TestActorlessEnrolledInstallationRequiresGitHubAuthorization(t *testing.T) {
	r := require.New(t)
	store, profile, _ := newEnrollmentProfile(t)
	s, wsURL := newEnrollmentTestServer(t, store)
	instanceKey, instancePublicKey, fingerprint := testInstanceKey(t)

	store.mu.Lock()
	storedProfile := cloneApplicationProfile(store.data.ApplicationProfiles[profile.ID])
	now := time.Now().UTC()
	storedProfile.Instances[fingerprint] = StoredApplicationInstance{
		TunnelID:   "study-group",
		PublicKey:  instancePublicKey,
		CreatedAt:  now,
		LastUsedAt: now,
	}
	store.data.ApplicationProfiles[profile.ID] = storedProfile
	saveErr := store.saveLocked()
	store.mu.Unlock()
	r.NoError(saveErr)

	conn, required, err := dialInstallation(t, wsURL, profile.ID, instancePublicKey, instanceKey, enrollmentOptions{})
	r.NoError(err)
	r.Equal(protocol.TypeEnrollmentRequired, required.Type)
	r.NoError(conn.Close())

	approveRequiredEnrollment(t, s, required, auth.GitHubUser{ID: 108, Login: "pierce"})
	conn, registered, err := dialInstallation(t, wsURL, profile.ID, instancePublicKey, instanceKey, enrollmentOptions{grant: required.EnrollmentDeviceCode})
	r.NoError(err)
	r.Equal(protocol.TypeTunnelRegistered, registered.Type)
	r.Equal("study-group", registered.TunnelID)
	instance, exists := store.ApplicationInstance(profile.ID, fingerprint)
	r.True(exists)
	r.Equal(int64(108), instance.GitHubUserID)
	r.Equal("pierce", instance.GitHubLogin)
	r.NoError(conn.Close())
}

func TestEnrollmentVerifiesInstallationBeforeIssuingOrConsumingGrant(t *testing.T) {
	r := require.New(t)
	store, profile, _ := newEnrollmentProfile(t)
	s, wsURL := newEnrollmentTestServer(t, store)
	instanceKey, instancePublicKey, fingerprint := testInstanceKey(t)
	wrongKey, _, _ := testInstanceKey(t)

	conn, _, err := dialInstallation(t, wsURL, profile.ID, instancePublicKey, instanceKey, enrollmentOptions{instanceSigKey: wrongKey})
	r.ErrorContains(err, "invalid instance signature")
	r.NoError(conn.Close())
	r.Empty(s.pendingEnrollments)

	conn, required, err := dialInstallation(t, wsURL, profile.ID, instancePublicKey, instanceKey, enrollmentOptions{})
	r.NoError(err)
	r.NoError(conn.Close())
	approveRequiredEnrollment(t, s, required, auth.GitHubUser{ID: 102, Login: "annie"})

	otherKey, otherPublicKey, _ := testInstanceKey(t)
	conn, _, err = dialInstallation(t, wsURL, profile.ID, otherPublicKey, otherKey, enrollmentOptions{grant: required.EnrollmentDeviceCode})
	r.ErrorContains(err, "grant does not match")
	r.NoError(conn.Close())

	conn, registered, err := dialInstallation(t, wsURL, profile.ID, instancePublicKey, instanceKey, enrollmentOptions{grant: required.EnrollmentDeviceCode})
	r.NoError(err)
	r.Equal(protocol.TypeTunnelRegistered, registered.Type)
	_, ok := store.ApplicationInstance(profile.ID, fingerprint)
	r.True(ok)
	r.NoError(conn.Close())
}

func TestEnrollmentGrantIsAtomicAndOneUse(t *testing.T) {
	r := require.New(t)
	store, profile, _ := newEnrollmentProfile(t)
	s, _ := newEnrollmentTestServer(t, store)
	_, publicKey, instanceID := testInstanceKey(t)
	required, err := s.beginEnrollment(profile.ID, instanceID, publicKey, "", "10.0.0.4")
	r.NoError(err)
	approveRequiredEnrollment(t, s, required, auth.GitHubUser{ID: 103, Login: "abed"})

	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- s.consumeEnrollmentGrant(required.EnrollmentDeviceCode, profile.ID, instanceID, publicKey, "")
		}()
	}
	wg.Wait()
	close(errs)
	successes := 0
	for err := range errs {
		if err == nil {
			successes++
		}
	}
	r.Equal(1, successes)
	r.Equal(1, store.CountApplicationInstancesByGitHubUserID(profile.ID, 103))
}

func TestEnrollmentRejectsRevokedInstance(t *testing.T) {
	r := require.New(t)
	store, profile, _ := newEnrollmentProfile(t)
	s, wsURL := newEnrollmentTestServer(t, store)
	instanceKey, instancePublicKey, fingerprint := testInstanceKey(t)

	conn, required, err := dialInstallation(t, wsURL, profile.ID, instancePublicKey, instanceKey, enrollmentOptions{})
	r.NoError(err)
	r.NoError(conn.Close())
	approveRequiredEnrollment(t, s, required, auth.GitHubUser{ID: 104, Login: "britta"})
	conn, _, err = dialInstallation(t, wsURL, profile.ID, instancePublicKey, instanceKey, enrollmentOptions{grant: required.EnrollmentDeviceCode})
	r.NoError(err)
	r.NoError(conn.Close())
	changed, err := store.SetApplicationInstanceRevoked(profile.ID, fingerprint, true)
	r.NoError(err)
	r.True(changed)

	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, _, err = dialInstallation(t, wsURL, profile.ID, instancePublicKey, instanceKey, enrollmentOptions{})
		r.NoError(conn.Close())
		if err != nil && strings.Contains(err.Error(), revokedInstanceMessage) {
			break
		}
		if time.Now().After(deadline) {
			r.ErrorContains(err, revokedInstanceMessage)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func TestEnrollmentStatusRequiresDeviceSecret(t *testing.T) {
	r := require.New(t)
	store, profile, _ := newEnrollmentProfile(t)
	s, _ := newEnrollmentTestServer(t, store)
	_, publicKey, instanceID := testInstanceKey(t)
	required, err := s.beginEnrollment(profile.ID, instanceID, publicKey, "", "10.0.0.5")
	r.NoError(err)

	missingResponse := httptest.NewRecorder()
	s.handleEnrollmentStatus(missingResponse, httptest.NewRequest(http.MethodPost, "/api/enroll/status", nil))
	r.Equal(http.StatusUnauthorized, missingResponse.Code)
	malformedRequest := httptest.NewRequest(http.MethodPost, "/api/enroll/status", nil)
	malformedRequest.Header.Set("Authorization", "Bearer not-a-device-secret")
	malformedResponse := httptest.NewRecorder()
	s.handleEnrollmentStatus(malformedResponse, malformedRequest)
	r.Equal(http.StatusUnauthorized, malformedResponse.Code)

	request := httptest.NewRequest(http.MethodPost, "/api/enroll/status", nil)
	request.Header.Set("Authorization", "Bearer "+required.EnrollmentDeviceCode)
	response := httptest.NewRecorder()
	s.handleEnrollmentStatus(response, request)
	r.Equal(http.StatusOK, response.Code)
	r.Equal("no-store", response.Header().Get("Cache-Control"))
	var status protocol.EnrollmentStatus
	r.NoError(json.NewDecoder(response.Body).Decode(&status))
	r.Equal("pending", status.Status)

	approveRequiredEnrollment(t, s, required, auth.GitHubUser{ID: 105, Login: "shirley"})
	response = httptest.NewRecorder()
	s.handleEnrollmentStatus(response, request)
	r.Equal(http.StatusOK, response.Code)
	r.NoError(json.NewDecoder(response.Body).Decode(&status))
	r.Equal("approved", status.Status)
}

func TestEnrollmentAccountAndNetworkLimits(t *testing.T) {
	r := require.New(t)
	store, profile, _ := newEnrollmentProfile(t)
	s, _ := newEnrollmentTestServer(t, store)
	s.cfg.MaxInstallationsPerUser = 1
	_, firstKey, firstID := testInstanceKey(t)
	first, err := s.beginEnrollment(profile.ID, firstID, firstKey, "", "10.0.0.6")
	r.NoError(err)
	approveRequiredEnrollment(t, s, first, auth.GitHubUser{ID: 106, Login: "dean"})
	_, secondKey, secondID := testInstanceKey(t)
	second, err := s.beginEnrollment(profile.ID, secondID, secondKey, "", "10.0.0.7")
	r.NoError(err)
	secondHash := sha256.Sum256([]byte(second.EnrollmentDeviceCode))
	r.ErrorContains(s.approveEnrollment(secondHash, auth.GitHubUser{ID: 106, Login: "dean-pelton"}), "installation limit")

	networkServer, _ := newEnrollmentTestServer(t, store)
	for i := 0; i < enrollmentsPerIPLimit; i++ {
		_, key, id := testInstanceKey(t)
		_, err := networkServer.beginEnrollment(profile.ID, id, key, "", "10.0.0.8")
		r.NoError(err)
	}
	_, key, id := testInstanceKey(t)
	_, err = networkServer.beginEnrollment(profile.ID, id, key, "", "10.0.0.8")
	r.ErrorContains(err, enrollmentThrottledMessage)
}

func TestEnrollmentLimitPrunesIdleInstallationBeforeCounting(t *testing.T) {
	r := require.New(t)
	store, profile, _ := newEnrollmentProfile(t)
	s, _ := newEnrollmentTestServer(t, store)
	s.cfg.MaxInstallationsPerUser = 1
	user := auth.GitHubUser{ID: 109, Login: "professor-duncan"}
	r.NoError(store.EnrollApplicationInstance(
		profile.ID,
		"idle-installation",
		"idle-public-key",
		enrollmentActor{GitHubUserID: user.ID, GitHubLogin: user.Login},
	))
	store.mu.Lock()
	storedProfile := cloneApplicationProfile(store.data.ApplicationProfiles[profile.ID])
	idle := storedProfile.Instances["idle-installation"]
	idle.LastUsedAt = time.Now().UTC().Add(-applicationInstanceMaxIdle - time.Hour)
	storedProfile.Instances["idle-installation"] = idle
	store.data.ApplicationProfiles[profile.ID] = storedProfile
	store.mu.Unlock()

	_, publicKey, instanceID := testInstanceKey(t)
	required, err := s.beginEnrollment(profile.ID, instanceID, publicKey, "", "10.0.0.10")
	r.NoError(err)
	hash := sha256.Sum256([]byte(required.EnrollmentDeviceCode))
	r.NoError(s.approveEnrollment(hash, user))
	_, exists := store.ApplicationInstance(profile.ID, "idle-installation")
	r.False(exists)
}

func TestEnrollmentLimitPreservesConnectedIdleInstallation(t *testing.T) {
	r := require.New(t)
	store, profile, _ := newEnrollmentProfile(t)
	s, _ := newEnrollmentTestServer(t, store)
	s.cfg.MaxInstallationsPerUser = 1
	user := auth.GitHubUser{ID: 110, Login: "frankie-dart"}
	r.NoError(store.EnrollApplicationInstance(
		profile.ID,
		"connected-installation",
		"connected-public-key",
		enrollmentActor{GitHubUserID: user.ID, GitHubLogin: user.Login},
	))
	store.mu.Lock()
	storedProfile := cloneApplicationProfile(store.data.ApplicationProfiles[profile.ID])
	connected := storedProfile.Instances["connected-installation"]
	connected.LastUsedAt = time.Now().UTC().Add(-applicationInstanceMaxIdle - time.Hour)
	storedProfile.Instances["connected-installation"] = connected
	store.data.ApplicationProfiles[profile.ID] = storedProfile
	store.mu.Unlock()
	s.tunnels["/connected"] = &tunnel{
		applicationProfileID: profile.ID,
		instanceID:           "connected-installation",
	}

	_, publicKey, instanceID := testInstanceKey(t)
	required, err := s.beginEnrollment(profile.ID, instanceID, publicKey, "", "10.0.0.11")
	r.NoError(err)
	hash := sha256.Sum256([]byte(required.EnrollmentDeviceCode))
	r.ErrorIs(s.approveEnrollment(hash, user), errInstallationLimitReached)
	_, exists := store.ApplicationInstance(profile.ID, "connected-installation")
	r.True(exists)
}

func TestEnrollmentPrunesExpiredState(t *testing.T) {
	r := require.New(t)
	store, profile, _ := newEnrollmentProfile(t)
	s, _ := newEnrollmentTestServer(t, store)
	_, key, id := testInstanceKey(t)
	required, err := s.beginEnrollment(profile.ID, id, key, "", "10.0.0.9")
	r.NoError(err)
	hash := sha256.Sum256([]byte(required.EnrollmentDeviceCode))
	s.enrollMu.Lock()
	pending := s.pendingEnrollments[hash]
	pending.expiresAt = time.Now().Add(-time.Second)
	s.pendingEnrollments[hash] = pending
	s.enrollMu.Unlock()
	r.ErrorContains(s.approveEnrollment(hash, auth.GitHubUser{ID: 107, Login: "chang"}), "invalid or expired")
	r.Empty(s.pendingEnrollments)
	r.Empty(s.pendingByHandoff)

	s.enrollments["10.0.0.9"] = []time.Time{time.Now().Add(-2 * enrollmentWindow)}
	s.enrollMu.Lock()
	r.Empty(s.pruneEnrollmentsLocked("10.0.0.9", time.Now()))
	s.enrollMu.Unlock()
}

func TestEnrollmentIPKeyUsesIPv6Network(t *testing.T) {
	tests := map[string]struct {
		value string
		want  string
	}{
		"IPv4":        {value: "192.0.2.10", want: "192.0.2.10"},
		"mapped IPv4": {value: "::ffff:192.0.2.10", want: "192.0.2.10"},
		"IPv6":        {value: "2001:db8:1234:5678:abcd::1", want: "2001:db8:1234:5678::/64"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, tc.want, enrollmentIPKey(tc.value))
		})
	}
}

func TestUnknownLegacyInstallationIsRejectedWithoutCreatingRecord(t *testing.T) {
	r := require.New(t)
	store, profile, appKey := newEnrollmentProfile(t)
	_, wsURL := newEnrollmentTestServer(t, store)
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	r.NoError(err)
	r.NoError(conn.WriteJSON(protocol.Message{
		Type:                 protocol.TypeRegisterTunnel,
		ApplicationProfileID: profile.ID,
		InstanceID:           "unknown-legacy-installation",
		LocalPort:            4321,
	}))
	var response protocol.Message
	err = conn.ReadJSON(&response)
	r.ErrorContains(err, "legacy installation is not registered")
	r.NoError(conn.Close())
	_, exists := store.ApplicationInstance(profile.ID, "unknown-legacy-installation")
	r.False(exists)
	_ = appKey
}

func TestKnownLegacyInstallationCanReconnectDuringMigration(t *testing.T) {
	r := require.New(t)
	store, profile, appKey := newEnrollmentProfile(t)
	r.NoError(store.RememberApplicationTunnel(profile.ID, "legacy-installation", "study-room-club"))
	_, wsURL := newEnrollmentTestServer(t, store)
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	r.NoError(err)
	r.NoError(conn.WriteJSON(protocol.Message{
		Type:                 protocol.TypeRegisterTunnel,
		ApplicationProfileID: profile.ID,
		InstanceID:           "legacy-installation",
		LocalPort:            4321,
	}))
	var challenge protocol.Message
	r.NoError(conn.ReadJSON(&challenge))
	r.False(challenge.EnrollmentSupported)
	payload := protocol.ApplicationChallengePayload(profile.ID, "legacy-installation", challenge.Challenge)
	r.NoError(conn.WriteJSON(protocol.Message{Type: protocol.TypeApplicationSignature, Signature: ed25519.Sign(appKey, payload)}))
	var registered protocol.Message
	r.NoError(conn.ReadJSON(&registered))
	r.Equal(protocol.TypeTunnelRegistered, registered.Type)
	r.Equal("study-room-club", registered.TunnelID)
	r.NoError(conn.Close())
}

func TestLegacyRegistrationRejectsProfileChangeDuringChallenge(t *testing.T) {
	r := require.New(t)
	store, profile, appKey := newEnrollmentProfile(t)
	r.NoError(store.RememberApplicationTunnel(profile.ID, "legacy-installation", "study-room-club"))
	s, wsURL := newEnrollmentTestServer(t, store)
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	r.NoError(err)
	r.NoError(conn.WriteJSON(protocol.Message{
		Type:                 protocol.TypeRegisterTunnel,
		ApplicationProfileID: profile.ID,
		InstanceID:           "legacy-installation",
		LocalPort:            4321,
	}))
	var challenge protocol.Message
	r.NoError(conn.ReadJSON(&challenge))

	_, _, rotatedPublicKey := testEd25519Key(t)
	session, err := store.CreateSession("rselbach", true)
	r.NoError(err)
	form := url.Values{
		"csrf_token":          {session.CSRFToken},
		"id":                  {profile.ID},
		"name":                {profile.Name},
		"public_key":          {rotatedPublicKey},
		"routes":              {"GET /oidc/{slug}/jwks"},
		"requests_per_minute": {"30"},
		"request_burst":       {"10"},
		"concurrent_requests": {"4"},
	}
	updateRequest := httptest.NewRequest(http.MethodPost, "/dashboard/applications/update", strings.NewReader(form.Encode()))
	updateRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	updateRequest.AddCookie(&http.Cookie{Name: s.cookieName(sessionCookieName), Value: session.ID})
	updateResponse := httptest.NewRecorder()
	s.handleUpdateApplication(updateResponse, updateRequest)
	r.Equal(http.StatusFound, updateResponse.Code)

	payload := protocol.ApplicationChallengePayload(profile.ID, "legacy-installation", challenge.Challenge)
	r.NoError(conn.WriteJSON(protocol.Message{Type: protocol.TypeApplicationSignature, Signature: ed25519.Sign(appKey, payload)}))
	var registered protocol.Message
	err = conn.ReadJSON(&registered)
	r.ErrorContains(err, "application profile changed during registration")
	r.NoError(conn.Close())
	r.Empty(s.tunnels)
}
