package web

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/require"
)

func signingKeysEnvironment(t *testing.T, handler http.Handler, slug string) (app, user) {
	t.Helper()
	environment := acceptanceEnvironment(t, handler, fmt.Sprintf(`{"name":%q,"slug":%q,"oidc_enabled":true,"oidc_client_id":%q,"oidc_client_secret":"study-group-secret","oidc_redirect_uris":["http://greendale.test/callback"],"saml_enabled":true,"saml_entity_id":%q,"saml_acs_url":"http://greendale.test/saml"}`, slug, slug, slug+"-client", slug+"-sp"))
	return environment, acceptanceUser(t, handler, environment.ID)
}

func listSigningKeys(t *testing.T, handler http.Handler, environmentID string) []signingKeyView {
	t.Helper()
	rec := acceptanceRequest(t, handler, http.MethodGet, "/api/v1/environments/"+environmentID+"/signing-keys", "", http.StatusOK)
	var keys []signingKeyView
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &keys))
	return keys
}

func rotateSigningKeyAPI(t *testing.T, handler http.Handler, environmentID, body string) []signingKeyView {
	t.Helper()
	rec := acceptanceRequest(t, handler, http.MethodPost, "/api/v1/environments/"+environmentID+"/signing-keys/rotate", body, http.StatusOK)
	var keys []signingKeyView
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &keys))
	return keys
}

// fetchJWKS returns the published key IDs in order and their public keys.
func fetchJWKS(t *testing.T, handler http.Handler, slug string) ([]string, map[string]*rsa.PublicKey) {
	t.Helper()
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/oidc/"+slug+"/jwks", nil))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var jwks struct {
		Keys []map[string]string `json:"keys"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &jwks))
	ids := []string{}
	keys := make(map[string]*rsa.PublicKey)
	for _, jwk := range jwks.Keys {
		n, err := base64.RawURLEncoding.DecodeString(jwk["n"])
		require.NoError(t, err)
		e, err := base64.RawURLEncoding.DecodeString(jwk["e"])
		require.NoError(t, err)
		ids = append(ids, jwk["kid"])
		keys[jwk["kid"]] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	}
	return ids, keys
}

func signingKeysIDToken(t *testing.T, handler http.Handler, environment app, userID string) string {
	t.Helper()
	authorize := acceptanceRequest(t, handler, http.MethodPost, "/api/v1/environments/"+environment.ID+"/oidc/authorize", fmt.Sprintf(`{"user_id":%q,"response_type":"code","client_id":%q,"redirect_uri":"http://greendale.test/callback","scope":"openid email"}`, userID, environment.OIDCClientID), http.StatusOK)
	var authorization struct {
		Code string `json:"code"`
	}
	require.NoError(t, json.Unmarshal(authorize.Body.Bytes(), &authorization))
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authorization.Code},
		"client_id":     {environment.OIDCClientID},
		"client_secret": {"study-group-secret"},
		"redirect_uri":  {"http://greendale.test/callback"},
	}
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/oidc/"+environment.Slug+"/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var tokens struct {
		IDToken string `json:"id_token"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &tokens))
	return tokens.IDToken
}

// verifyJWTWithJWKS checks token's RS256 signature with the JWKS key its
// header names and returns that key ID.
func verifyJWTWithJWKS(t *testing.T, token string, keys map[string]*rsa.PublicKey) string {
	t.Helper()
	kid, _ := decodeJWTHeader(t, token)["kid"].(string)
	key, ok := keys[kid]
	require.True(t, ok, "JWKS does not publish kid %q", kid)
	parts := strings.Split(token, ".")
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)
	require.NoError(t, rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature))
	return kid
}

func samlMetadataCertificates(t *testing.T, handler http.Handler, slug string) [][]byte {
	t.Helper()
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/saml/"+slug+"/metadata", nil))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var certificates [][]byte
	for _, element := range mustParseXML(t, rec.Body.String()).FindElements("//X509Certificate") {
		der, err := base64.StdEncoding.DecodeString(element.Text())
		require.NoError(t, err)
		certificates = append(certificates, der)
	}
	return certificates
}

func signingKeysSAMLAssertion(t *testing.T, handler http.Handler, environmentID, userID string) *etree.Element {
	t.Helper()
	rec := acceptanceRequest(t, handler, http.MethodPost, "/api/v1/environments/"+environmentID+"/saml/sign-in", fmt.Sprintf(`{"user_id":%q}`, userID), http.StatusOK)
	var response struct {
		SAMLResponse string `json:"saml_response"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))
	decoded, err := base64.StdEncoding.DecodeString(response.SAMLResponse)
	require.NoError(t, err)
	return findElementByLocalName(mustParseXML(t, string(decoded)).Root(), "Assertion")
}

func certificateDER(t *testing.T, pemValue string) []byte {
	t.Helper()
	der, err := parseCertificatePEM(pemValue)
	require.NoError(t, err)
	return der
}

func TestSigningKeyRotationKeepsSharedKeyPublishedDuringGrace(t *testing.T) {
	r := require.New(t)
	svc, handler := newAcceptanceAPI(t)
	greendale, troy := signingKeysEnvironment(t, handler, "greendale")

	before := listSigningKeys(t, handler, greendale.ID)
	r.Len(before, 1)
	r.Equal(sharedSigningKeyID, before[0].ID)
	r.True(before[0].Active)
	r.Empty(before[0].CreatedAt)
	oldToken := signingKeysIDToken(t, handler, greendale, troy.ID)

	rotatedAt := time.Now()
	after := rotateSigningKeyAPI(t, handler, greendale.ID, `{"grace_period":"1h"}`)
	r.Len(after, 2)
	r.True(after[0].Active)
	r.NotEqual(sharedSigningKeyID, after[0].ID)
	r.NotEmpty(after[0].CreatedAt)
	r.Empty(after[0].PublishedUntil)
	r.Equal(sharedSigningKeyID, after[1].ID)
	r.False(after[1].Active)
	publishedUntil, err := time.Parse(time.RFC3339, after[1].PublishedUntil)
	r.NoError(err)
	r.WithinDuration(rotatedAt.Add(time.Hour), publishedUntil, 5*time.Second)
	r.Equal(after, listSigningKeys(t, handler, greendale.ID))

	ids, jwks := fetchJWKS(t, handler, "greendale")
	r.Equal([]string{after[0].ID, sharedSigningKeyID}, ids)
	r.Equal(svc.signingKey.N, jwks[sharedSigningKeyID].N, "the shared key keeps its key material after the upgrade")
	r.Equal(sharedSigningKeyID, verifyJWTWithJWKS(t, oldToken, jwks), "tokens signed before rotation still verify")
	r.Equal(after[0].ID, verifyJWTWithJWKS(t, signingKeysIDToken(t, handler, greendale, troy.ID), jwks))

	newCertificate := certificateDER(t, after[0].CertificatePEM)
	r.Equal([][]byte{newCertificate, svc.certDER}, samlMetadataCertificates(t, handler, "greendale"))
	validateSAMLAssertionSignature(t, newCertificate, signingKeysSAMLAssertion(t, handler, greendale.ID, troy.ID))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/saml/greendale/certificate.pem", nil))
	r.Equal(http.StatusOK, rec.Code)
	r.Equal(after[0].CertificatePEM, rec.Body.String())
	connection := acceptanceRequest(t, handler, http.MethodGet, "/api/v1/environments/"+greendale.ID+"/connection", "", http.StatusOK)
	var export appConfigExport
	r.NoError(json.Unmarshal(connection.Body.Bytes(), &export))
	r.Equal(after[0].CertificatePEM, export.SAML.CertificatePEM)
}

func TestSigningKeyRotationGracePeriod(t *testing.T) {
	tests := map[string]struct {
		body          string
		wantStatus    int
		wantPublished int
		wantGrace     time.Duration
	}{
		"default grace":   {body: "", wantStatus: http.StatusOK, wantPublished: 2, wantGrace: defaultSigningKeyGrace},
		"empty request":   {body: `{}`, wantStatus: http.StatusOK, wantPublished: 2, wantGrace: defaultSigningKeyGrace},
		"no grace":        {body: `{"grace_period":"0s"}`, wantStatus: http.StatusOK, wantPublished: 1},
		"not a duration":  {body: `{"grace_period":"forever"}`, wantStatus: http.StatusBadRequest},
		"negative":        {body: `{"grace_period":"-1h"}`, wantStatus: http.StatusBadRequest},
		"beyond 7 days":   {body: `{"grace_period":"169h"}`, wantStatus: http.StatusBadRequest},
		"unknown setting": {body: `{"grace":"1h"}`, wantStatus: http.StatusBadRequest},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			_, handler := newAcceptanceAPI(t)
			greendale, _ := signingKeysEnvironment(t, handler, "greendale")

			rotatedAt := time.Now()
			acceptanceRequest(t, handler, http.MethodPost, "/api/v1/environments/"+greendale.ID+"/signing-keys/rotate", tc.body, tc.wantStatus)
			keys := listSigningKeys(t, handler, greendale.ID)
			ids, _ := fetchJWKS(t, handler, "greendale")
			if tc.wantStatus != http.StatusOK {
				r.Equal([]string{sharedSigningKeyID}, ids, "a rejected rotation leaves the ring alone")
				return
			}
			r.Len(keys, tc.wantPublished)
			r.Len(ids, tc.wantPublished)
			r.NotEqual(sharedSigningKeyID, ids[0])
			if tc.wantPublished == 1 {
				return
			}
			publishedUntil, err := time.Parse(time.RFC3339, keys[1].PublishedUntil)
			r.NoError(err)
			r.WithinDuration(rotatedAt.Add(tc.wantGrace), publishedUntil, 5*time.Second)
		})
	}
}

func TestRetiredSigningKeysLeaveAfterGrace(t *testing.T) {
	r := require.New(t)
	svc := newTestIDPApp(t)
	start := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)

	ring, err := svc.rotateSigningKeys(nil, time.Hour, start)
	r.NoError(err)
	state := appState{Config: config{SigningKeys: ring}}
	published, err := svc.publishedSigningKeys(state, start.Add(59*time.Minute))
	r.NoError(err)
	r.Len(published, 2)
	published, err = svc.publishedSigningKeys(state, start.Add(time.Hour))
	r.NoError(err)
	r.Len(published, 1)
	r.Equal(ring[1].ID, published[0].ID)

	ring, err = svc.rotateSigningKeys(ring, time.Hour, start.Add(2*time.Hour))
	r.NoError(err)
	r.Len(ring, 2, "rotation drops keys whose grace period ended")
	r.Equal(published[0].ID, ring[0].ID)
}

func TestSigningKeysArePerEnvironment(t *testing.T) {
	r := require.New(t)
	svc, handler := newAcceptanceAPI(t)
	greendale, _ := signingKeysEnvironment(t, handler, "greendale")
	rotated := rotateSigningKeyAPI(t, handler, greendale.ID, `{"grace_period":"0s"}`)
	r.Len(rotated, 1)
	// A new environment starts from the shared key, not another
	// environment's ring.
	cityCollege, dean := signingKeysEnvironment(t, handler, "city-college")

	r.Equal([]signingKeyView{{ID: sharedSigningKeyID, Active: true, CertificatePEM: certificatePEM(svc.certDER)}}, listSigningKeys(t, handler, cityCollege.ID))
	ids, jwks := fetchJWKS(t, handler, "city-college")
	r.Equal([]string{sharedSigningKeyID}, ids)
	r.Equal(sharedSigningKeyID, verifyJWTWithJWKS(t, signingKeysIDToken(t, handler, cityCollege, dean.ID), jwks))
	r.Equal([][]byte{svc.certDER}, samlMetadataCertificates(t, handler, "city-college"))
	validateSAMLAssertionSignature(t, svc.certDER, signingKeysSAMLAssertion(t, handler, cityCollege.ID, dean.ID))

	ids, _ = fetchJWKS(t, handler, "greendale")
	r.Equal([]string{rotated[0].ID}, ids)
}

func TestStaleJWKSScenarioOmitsCurrentKey(t *testing.T) {
	tests := map[string]struct {
		rotate    bool
		wantStale func(active string) []string
	}{
		"before rotation": {wantStale: func(string) []string { return []string{} }},
		"during rollover": {rotate: true, wantStale: func(string) []string { return []string{sharedSigningKeyID} }},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			svc, handler := newAcceptanceAPI(t)
			greendale, _ := signingKeysEnvironment(t, handler, "greendale")
			if tc.rotate {
				rotateSigningKeyAPI(t, handler, greendale.ID, `{"grace_period":"1h"}`)
			}
			healthy, _ := fetchJWKS(t, handler, "greendale")
			active := healthy[0]

			acceptanceRequest(t, handler, http.MethodPost, "/api/v1/environments/"+greendale.ID+"/scenarios/arm", `{"preset_id":"stale-jwks","count":2}`, http.StatusCreated)
			for range 2 {
				stale, _ := fetchJWKS(t, handler, "greendale")
				r.Equal(tc.wantStale(active), stale)
			}
			recovered, _ := fetchJWKS(t, handler, "greendale")
			r.Equal(healthy, recovered)

			run, ok := svc.resilienceRun("greendale", time.Now())
			r.True(ok)
			r.Equal(resilienceRunCompleted, run.State)
			r.Equal("JWKS without the current signing key", run.Decisions[len(run.Decisions)-1].Detail)
			r.Contains(svc.flowEvents("greendale")[0].Detail, "without the current signing key "+active)
		})
	}
}

func TestSigningKeysSurviveBackupRestore(t *testing.T) {
	r := require.New(t)
	svc, handler := newAcceptanceAPI(t)
	greendale, troy := signingKeysEnvironment(t, handler, "greendale")
	base := "/api/v1/environments/" + greendale.ID
	backedUp := rotateSigningKeyAPI(t, handler, greendale.ID, `{"grace_period":"1h"}`)

	backup := acceptanceRequest(t, handler, http.MethodGet, base+"/backup", "", http.StatusOK).Body.String()
	var decoded stateBackup
	r.NoError(json.Unmarshal([]byte(backup), &decoded))
	r.Len(decoded.State.Config.SigningKeys, 2, "the backup carries every stored key")

	rotateSigningKeyAPI(t, handler, greendale.ID, `{"grace_period":"0s"}`)
	acceptanceRequest(t, handler, http.MethodPost, base+"/restore", backup, http.StatusOK)
	r.Equal(backedUp, listSigningKeys(t, handler, greendale.ID))
	_, jwks := fetchJWKS(t, handler, "greendale")
	r.Equal(backedUp[0].ID, verifyJWTWithJWKS(t, signingKeysIDToken(t, handler, greendale, troy.ID), jwks))

	// Backups from before key rotation have no signing_keys. Restoring one
	// returns the environment to the shared key it signed with then.
	var legacy map[string]any
	r.NoError(json.Unmarshal([]byte(backup), &legacy))
	delete(legacy["state"].(map[string]any)["config"].(map[string]any), "signing_keys")
	legacyBackup, err := json.Marshal(legacy)
	r.NoError(err)
	acceptanceRequest(t, handler, http.MethodPost, base+"/restore", string(legacyBackup), http.StatusOK)
	r.Equal([]signingKeyView{{ID: sharedSigningKeyID, Active: true, CertificatePEM: certificatePEM(svc.certDER)}}, listSigningKeys(t, handler, greendale.ID))
	validateSAMLAssertionSignature(t, svc.certDER, signingKeysSAMLAssertion(t, handler, greendale.ID, troy.ID))
}

func TestInspectorRotatesSigningKey(t *testing.T) {
	tests := map[string]struct {
		returnTab string
		wantPath  string
	}{
		"OIDC inspector": {returnTab: "oidc-inspector", wantPath: "tab=oidc-inspector"},
		"SAML inspector": {returnTab: "saml-inspector", wantPath: "tab=saml-inspector"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			svc, handler := newAcceptanceAPI(t)
			greendale, _ := signingKeysEnvironment(t, handler, "greendale")

			page := httptest.NewRecorder()
			handler.ServeHTTP(page, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/?environment="+greendale.ID+"&tab="+tc.returnTab, nil))
			r.Equal(http.StatusOK, page.Code)
			r.Contains(page.Body.String(), "Signing keys")
			r.Contains(page.Body.String(), sharedSigningKeyID)

			form := url.Values{"return_tab": {tc.returnTab}, "grace_period": {"1h"}}
			req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/inspect/signing-keys/greendale/rotate", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			r.Equal(http.StatusSeeOther, rec.Code, rec.Body.String())
			r.Contains(rec.Header().Get("Location"), tc.wantPath)

			keys := listSigningKeys(t, handler, greendale.ID)
			r.Len(keys, 2)
			event := svc.flowEvents("greendale")[0]
			r.Equal("keys", event.Protocol)
			r.Equal("rotate", event.Stage)
			r.Contains(event.Detail, "Signing with "+keys[0].ID)

			page = httptest.NewRecorder()
			handler.ServeHTTP(page, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/?environment="+greendale.ID+"&tab="+tc.returnTab, nil))
			r.Equal(http.StatusOK, page.Code)
			r.Contains(page.Body.String(), keys[0].ID)
			r.Contains(page.Body.String(), "Retired, published until")
		})
	}
}
