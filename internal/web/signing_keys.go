package web

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// sharedSigningKeyID names the shared key every environment signs with
// until its first rotation.
const sharedSigningKeyID = "scimtest-dev"

const (
	// defaultSigningKeyGrace keeps a retired key published long enough for
	// tokens it signed to expire and for pinned certificates to be updated.
	defaultSigningKeyGrace = 24 * time.Hour
	maxSigningKeyGrace     = 7 * 24 * time.Hour
)

// signingKey is a parsed key from an environment's signing key ring.
type signingKey struct {
	ID             string
	PrivateKey     *rsa.PrivateKey
	CertDER        []byte
	CreatedAt      time.Time
	PublishedUntil time.Time // zero for the active key
}

func (a *webApp) sharedSigningKey() signingKey {
	return signingKey{ID: sharedSigningKeyID, PrivateKey: a.signingKey, CertDER: a.certDER}
}

// activeSigningKey returns the key that signs the environment's tokens and
// assertions.
func (a *webApp) activeSigningKey(state appState) (signingKey, error) {
	ring := state.Config.SigningKeys
	if len(ring) == 0 {
		return a.sharedSigningKey(), nil
	}
	return parseStoredSigningKey(ring[len(ring)-1])
}

// publishedSigningKeys lists the keys the JWKS and SAML metadata publish:
// the active key first, then retired keys still inside their grace period,
// newest first.
func (a *webApp) publishedSigningKeys(state appState, now time.Time) ([]signingKey, error) {
	ring := state.Config.SigningKeys
	if len(ring) == 0 {
		return []signingKey{a.sharedSigningKey()}, nil
	}
	keys := make([]signingKey, 0, len(ring))
	for i := len(ring) - 1; i >= 0; i-- {
		if i < len(ring)-1 && !now.Before(ring[i].PublishedUntil) {
			continue
		}
		key, err := parseStoredSigningKey(ring[i])
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// rotateSigningKeys retires the active key, keeps it published for grace,
// drops retired keys whose grace period has ended, and appends a new active
// key. A ring that never rotated starts from the shared key, so relying
// parties and service providers that trusted it keep working.
func (a *webApp) rotateSigningKeys(ring []storedSigningKey, grace time.Duration, now time.Time) ([]storedSigningKey, error) {
	if len(ring) == 0 {
		ring = []storedSigningKey{{
			ID:             sharedSigningKeyID,
			PrivateKeyPEM:  privateKeyPEM(a.signingKey),
			CertificatePEM: certificatePEM(a.certDER),
		}}
	}
	rotated := make([]storedSigningKey, 0, len(ring)+1)
	for i, stored := range ring {
		if i == len(ring)-1 {
			stored.PublishedUntil = now.Add(grace)
		}
		if now.Before(stored.PublishedUntil) {
			rotated = append(rotated, stored)
		}
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}
	certDER, err := selfSignedCert(key)
	if err != nil {
		return nil, fmt.Errorf("generate signing certificate: %w", err)
	}
	id, err := newID("scimtest")
	if err != nil {
		return nil, fmt.Errorf("generate signing key ID: %w", err)
	}
	return append(rotated, storedSigningKey{
		ID:             id,
		PrivateKeyPEM:  privateKeyPEM(key),
		CertificatePEM: certificatePEM(certDER),
		CreatedAt:      now.UTC(),
	}), nil
}

func parseStoredSigningKey(stored storedSigningKey) (signingKey, error) {
	key, err := parseRSAPrivateKeyPEM(stored.PrivateKeyPEM)
	if err != nil {
		return signingKey{}, fmt.Errorf("parse signing key %s: %w", stored.ID, err)
	}
	certDER, err := parseCertificatePEM(stored.CertificatePEM)
	if err != nil {
		return signingKey{}, fmt.Errorf("parse signing certificate %s: %w", stored.ID, err)
	}
	return signingKey{
		ID:             stored.ID,
		PrivateKey:     key,
		CertDER:        certDER,
		CreatedAt:      stored.CreatedAt,
		PublishedUntil: stored.PublishedUntil,
	}, nil
}

// parseSigningKeyGrace reads a grace period such as 24h. Empty means the
// default; zero removes the retired key at once.
func parseSigningKeyGrace(raw string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return defaultSigningKeyGrace, nil
	}
	grace, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("grace period %q is not a duration such as 24h", raw)
	}
	if grace < 0 || grace > maxSigningKeyGrace {
		return 0, fmt.Errorf("grace period must be between 0s and %s", maxSigningKeyGrace)
	}
	return grace, nil
}

// rotateEnvironmentSigningKey rotates one environment's signing key and
// records the change in its flow activity.
func (a *webApp) rotateEnvironmentSigningKey(foundApp app, grace time.Duration, now time.Time) (appState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	state, err := loadStateForApp(foundApp.ID)
	if err != nil {
		return appState{}, err
	}
	retired, err := a.activeSigningKey(state)
	if err != nil {
		return appState{}, err
	}
	ring, err := a.rotateSigningKeys(state.Config.SigningKeys, grace, now)
	if err != nil {
		return appState{}, err
	}
	state.Config.SigningKeys = ring
	if err := saveEnvironmentState(state); err != nil {
		return appState{}, err
	}
	detail := fmt.Sprintf("Signing with %s; %s removed from the JWKS and SAML metadata", ring[len(ring)-1].ID, retired.ID)
	if grace > 0 {
		detail = fmt.Sprintf("Signing with %s; %s published until %s", ring[len(ring)-1].ID, retired.ID, now.Add(grace).UTC().Format(time.RFC3339))
	}
	a.recordFlowEvent(foundApp.Slug, "keys", "rotate", "ok", "", detail)
	return state, nil
}

// signingKeyView describes a published signing key for the inspectors and
// the local API.
type signingKeyView struct {
	ID             string `json:"kid"`
	Active         bool   `json:"active"`
	CreatedAt      string `json:"created_at,omitempty"`
	PublishedUntil string `json:"published_until,omitempty"`
	CertificatePEM string `json:"certificate_pem"`
}

func (a *webApp) signingKeyViews(state appState, now time.Time) ([]signingKeyView, error) {
	keys, err := a.publishedSigningKeys(state, now)
	if err != nil {
		return nil, err
	}
	views := make([]signingKeyView, len(keys))
	for i, key := range keys {
		views[i] = signingKeyView{
			ID:             key.ID,
			Active:         i == 0,
			CertificatePEM: certificatePEM(key.CertDER),
		}
		if !key.CreatedAt.IsZero() {
			views[i].CreatedAt = key.CreatedAt.UTC().Format(time.RFC3339)
		}
		if !key.PublishedUntil.IsZero() {
			views[i].PublishedUntil = key.PublishedUntil.UTC().Format(time.RFC3339)
		}
	}
	return views, nil
}

// signingKeyJWK renders the public half of key as an RS256 JWK.
func signingKeyJWK(key signingKey) map[string]string {
	pub := key.PrivateKey.PublicKey
	return map[string]string{
		"kty": "RSA",
		"use": "sig",
		"kid": key.ID,
		"alg": "RS256",
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

func (a *webApp) handleSigningKeyRotate(w http.ResponseWriter, r *http.Request) {
	_, foundApp, ok := appForProtocol(w, r, supportsAnyIDP)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	grace, err := parseSigningKeyGrace(r.FormValue("grace_period"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if _, err := a.rotateEnvironmentSigningKey(foundApp, grace, time.Now()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, inspectorReturnPath(r, foundApp), http.StatusSeeOther)
}

// apiIDPEnvironment loads an environment that must have OIDC or SAML
// enabled.
func (a *webApp) apiIDPEnvironment(w http.ResponseWriter, r *http.Request) (appState, app, bool) {
	state, err := a.loadAPIEnvironment(r.PathValue("environment_id"))
	if err != nil {
		apiError(w, http.StatusNotFound, err.Error())
		return appState{}, app{}, false
	}
	found, _ := apiAppByID(state, r.PathValue("environment_id"))
	if !supportsAnyIDP(found) {
		apiError(w, http.StatusBadRequest, "OIDC or SAML is not enabled")
		return appState{}, app{}, false
	}
	return state, found, true
}

func (a *webApp) handleAPISigningKeys(w http.ResponseWriter, r *http.Request) {
	state, _, ok := a.apiIDPEnvironment(w, r)
	if !ok {
		return
	}
	views, err := a.signingKeyViews(state, time.Now())
	if err != nil {
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, views)
}

func (a *webApp) handleAPISigningKeyRotate(w http.ResponseWriter, r *http.Request) {
	_, found, ok := a.apiIDPEnvironment(w, r)
	if !ok {
		return
	}
	var request struct {
		GracePeriod string `json:"grace_period"`
	}
	if r.ContentLength != 0 && decodeAPIJSON(w, r, &request) != nil {
		return
	}
	grace, err := parseSigningKeyGrace(request.GracePeriod)
	if err != nil {
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	now := time.Now()
	state, err := a.rotateEnvironmentSigningKey(found, grace, now)
	if err != nil {
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}
	views, err := a.signingKeyViews(state, now)
	if err != nil {
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, views)
}
