package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
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
			PublicScheme:             "http",
			MaxTunnelsPerApplication: 5,
			Logger:                   slog.New(slog.NewTextHandler(io.Discard, nil)),
		},
		store:   store,
		tunnels: make(map[string]*tunnel),
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		s.handleConnect(w, req)
	}))
	t.Cleanup(srv.Close)
	return s, "ws" + strings.TrimPrefix(srv.URL, "http") + "/api/connect"
}

type enrollmentOptions struct {
	legacyInstanceID  string
	skipEnrollmentSig bool
	instanceSigKey    ed25519.PrivateKey
}

func dialEnrollment(t *testing.T, wsURL, profileID, instancePublicKey string, instanceKey, appKey ed25519.PrivateKey, opts enrollmentOptions) (*websocket.Conn, protocol.Message, error) {
	t.Helper()
	r := require.New(t)
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	r.NoError(err)
	r.NoError(conn.WriteJSON(protocol.Message{
		Type:                 protocol.TypeRegisterTunnel,
		ApplicationProfileID: profileID,
		InstanceID:           opts.legacyInstanceID,
		InstancePublicKey:    instancePublicKey,
		LocalPort:            4321,
	}))
	var challenge protocol.Message
	r.NoError(conn.ReadJSON(&challenge))
	r.Equal(protocol.TypeApplicationChallenge, challenge.Type)
	r.True(challenge.EnrollmentSupported)

	sigKey := instanceKey
	if opts.instanceSigKey != nil {
		sigKey = opts.instanceSigKey
	}
	payload := protocol.InstanceChallengePayload(profileID, instancePublicKey, opts.legacyInstanceID, challenge.Challenge)
	signed := protocol.Message{
		Type:      protocol.TypeApplicationSignature,
		Signature: ed25519.Sign(sigKey, payload),
	}
	if !opts.skipEnrollmentSig {
		enrollPayload := protocol.EnrollmentAuthorizationPayload(profileID, instancePublicKey, opts.legacyInstanceID, challenge.Challenge)
		signed.EnrollmentSignature = ed25519.Sign(appKey, enrollPayload)
	}
	r.NoError(conn.WriteJSON(signed))

	var registered protocol.Message
	err = conn.ReadJSON(&registered)
	return conn, registered, err
}

func TestEnrollmentMigratesLegacyReservation(t *testing.T) {
	r := require.New(t)
	_, appKey, publicKeyText := testEd25519Key(t)
	store, err := OpenStore(t.TempDir() + "/test.json")
	r.NoError(err)
	profile, err := store.CreateApplicationProfile(
		"Greendale Identity",
		publicKeyText,
		[]StoredApplicationRoute{{Methods: []string{"GET"}, Path: "/oidc/{slug}/jwks"}},
		30,
		10,
		4,
	)
	r.NoError(err)
	r.NoError(store.RememberApplicationTunnel(profile.ID, "legacy-uuid-1", "human-timeline-club"))

	_, wsURL := newEnrollmentTestServer(t, store)
	instanceKey, instancePublicKey, fingerprint := testInstanceKey(t)

	conn, registered, err := dialEnrollment(t, wsURL, profile.ID, instancePublicKey, instanceKey, appKey, enrollmentOptions{legacyInstanceID: "legacy-uuid-1"})
	r.NoError(err)
	r.Equal(protocol.TypeTunnelRegistered, registered.Type)
	r.Equal("human-timeline-club", registered.TunnelID)

	instance, ok := store.ApplicationInstance(profile.ID, fingerprint)
	r.True(ok)
	r.True(instance.Enrolled())
	r.Equal(instancePublicKey, instance.PublicKey)
	r.Equal("human-timeline-club", instance.TunnelID)
	_, ok = store.ApplicationInstance(profile.ID, "legacy-uuid-1")
	r.False(ok)
	r.NoError(conn.Close())
}

func TestEnrolledReconnectWithoutEnrollmentSignature(t *testing.T) {
	r := require.New(t)
	_, appKey, publicKeyText := testEd25519Key(t)
	store, err := OpenStore(t.TempDir() + "/test.json")
	r.NoError(err)
	profile, err := store.CreateApplicationProfile(
		"Greendale Identity",
		publicKeyText,
		[]StoredApplicationRoute{{Methods: []string{"GET"}, Path: "/oidc/{slug}/jwks"}},
		30,
		10,
		4,
	)
	r.NoError(err)

	_, wsURL := newEnrollmentTestServer(t, store)
	instanceKey, instancePublicKey, _ := testInstanceKey(t)

	conn, registered, err := dialEnrollment(t, wsURL, profile.ID, instancePublicKey, instanceKey, appKey, enrollmentOptions{})
	r.NoError(err)
	r.Equal(protocol.TypeTunnelRegistered, registered.Type)
	firstTunnelID := registered.TunnelID
	r.NoError(conn.Close())

	// An enrolled installation stays valid after the release key rotates:
	// the reconnect carries no enrollment signature at all. The previous
	// tunnel may linger briefly while the server notices the close, so retry.
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, registered, err = dialEnrollment(t, wsURL, profile.ID, instancePublicKey, instanceKey, nil, enrollmentOptions{skipEnrollmentSig: true})
		if err == nil {
			break
		}
		r.NoError(conn.Close())
		if time.Now().After(deadline) {
			r.NoError(err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	r.Equal(protocol.TypeTunnelRegistered, registered.Type)
	r.Equal(firstTunnelID, registered.TunnelID)
	r.NoError(conn.Close())
}

func TestEnrollmentRejectsInvalidSignatures(t *testing.T) {
	r := require.New(t)
	_, appKey, publicKeyText := testEd25519Key(t)
	store, err := OpenStore(t.TempDir() + "/test.json")
	r.NoError(err)
	profile, err := store.CreateApplicationProfile(
		"Greendale Identity",
		publicKeyText,
		[]StoredApplicationRoute{{Methods: []string{"GET"}, Path: "/oidc/{slug}/jwks"}},
		30,
		10,
		4,
	)
	r.NoError(err)

	_, wsURL := newEnrollmentTestServer(t, store)
	instanceKey, instancePublicKey, fingerprint := testInstanceKey(t)

	// Enrollment signed by something other than the release key is refused.
	wrongKey, _, _ := testInstanceKey(t)
	conn, _, err := dialEnrollment(t, wsURL, profile.ID, instancePublicKey, instanceKey, wrongKey, enrollmentOptions{})
	r.Error(err)
	r.ErrorContains(err, "invalid enrollment signature")
	r.NoError(conn.Close())

	// A challenge answered by a key other than the presented one is refused.
	conn, _, err = dialEnrollment(t, wsURL, profile.ID, instancePublicKey, instanceKey, appKey, enrollmentOptions{instanceSigKey: wrongKey})
	r.Error(err)
	r.ErrorContains(err, "invalid instance signature")
	r.NoError(conn.Close())

	_, ok := store.ApplicationInstance(profile.ID, fingerprint)
	r.False(ok)
}

func TestEnrollmentRejectsRevokedInstance(t *testing.T) {
	r := require.New(t)
	_, appKey, publicKeyText := testEd25519Key(t)
	store, err := OpenStore(t.TempDir() + "/test.json")
	r.NoError(err)
	profile, err := store.CreateApplicationProfile(
		"Greendale Identity",
		publicKeyText,
		[]StoredApplicationRoute{{Methods: []string{"GET"}, Path: "/oidc/{slug}/jwks"}},
		30,
		10,
		4,
	)
	r.NoError(err)

	_, wsURL := newEnrollmentTestServer(t, store)
	instanceKey, instancePublicKey, fingerprint := testInstanceKey(t)

	conn, registered, err := dialEnrollment(t, wsURL, profile.ID, instancePublicKey, instanceKey, appKey, enrollmentOptions{})
	r.NoError(err)
	r.Equal(protocol.TypeTunnelRegistered, registered.Type)
	r.NoError(conn.Close())

	changed, err := store.SetApplicationInstanceRevoked(profile.ID, fingerprint, true)
	r.NoError(err)
	r.True(changed)

	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, _, err = dialEnrollment(t, wsURL, profile.ID, instancePublicKey, instanceKey, appKey, enrollmentOptions{})
		r.NoError(conn.Close())
		r.Error(err)
		if strings.Contains(err.Error(), revokedInstanceMessage) {
			break
		}
		if time.Now().After(deadline) {
			r.ErrorContains(err, revokedInstanceMessage)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestEnrollmentThrottled(t *testing.T) {
	r := require.New(t)
	_, appKey, publicKeyText := testEd25519Key(t)
	store, err := OpenStore(t.TempDir() + "/test.json")
	r.NoError(err)
	profile, err := store.CreateApplicationProfile(
		"Greendale Identity",
		publicKeyText,
		[]StoredApplicationRoute{{Methods: []string{"GET"}, Path: "/oidc/{slug}/jwks"}},
		30,
		10,
		4,
	)
	r.NoError(err)

	s, wsURL := newEnrollmentTestServer(t, store)
	for range enrollmentsPerIPLimit {
		s.recordEnrollment("127.0.0.1")
	}

	instanceKey, instancePublicKey, _ := testInstanceKey(t)
	conn, _, err := dialEnrollment(t, wsURL, profile.ID, instancePublicKey, instanceKey, appKey, enrollmentOptions{})
	r.Error(err)
	r.ErrorContains(err, enrollmentThrottledMessage)
	r.NoError(conn.Close())
}

func TestEnrollmentAllowedPrunesOldEntries(t *testing.T) {
	r := require.New(t)
	s := &Server{enrollments: map[string][]time.Time{
		"10.0.0.9": {time.Now().Add(-2 * enrollmentWindow)},
	}}
	r.True(s.enrollmentAllowed("10.0.0.9"))
	r.Empty(s.enrollments)
}

func TestEnrollApplicationInstanceRejectsDifferentKey(t *testing.T) {
	r := require.New(t)
	store, profile := newTestApplicationProfile(t)
	_, firstKey, _ := testInstanceKey(t)
	_, secondKey, _ := testInstanceKey(t)

	r.NoError(store.EnrollApplicationInstance(profile.ID, "fingerprint-1", firstKey, ""))
	err := store.EnrollApplicationInstance(profile.ID, "fingerprint-1", secondKey, "")
	r.ErrorContains(err, "already enrolled with a different key")
}

func TestSetApplicationInstanceRevokedRequiresEnrollment(t *testing.T) {
	r := require.New(t)
	store, profile := newTestApplicationProfile(t)
	r.NoError(store.RememberApplicationTunnel(profile.ID, "legacy-uuid-1", "human-timeline-club"))

	changed, err := store.SetApplicationInstanceRevoked(profile.ID, "legacy-uuid-1", true)
	r.NoError(err)
	r.False(changed)
}
