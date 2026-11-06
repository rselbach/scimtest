package main

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/beevik/etree"
	"github.com/rselbach/scimtest/internal/core"
	"github.com/rselbach/scimtest/internal/protocol"
	dsig "github.com/russellhaering/goxmldsig"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) != 3 {
		return fmt.Errorf("usage: statebridge seed|dump STATE_FILE")
	}
	if err := os.Setenv("SCIMTEST_STATE_FILE", os.Args[2]); err != nil {
		return err
	}
	switch os.Args[1] {
	case "sign-update-feed", "verify-update-feed":
		return updateFeed(os.Args[1])
	case "seed":
		return seed()
	case "seed-legacy":
		return seedLegacy()
	case "dump":
		return dump()
	case "casefold-table":
		return casefoldTable()
	case "check-casefold":
		return checkCasefold()
	case "installation-identity", "rotate-installation":
		var id string
		var key ed25519.PrivateKey
		var err error
		if os.Args[1] == "rotate-installation" {
			id, key, err = core.RotateTunnelInstanceIdentity()
		} else {
			id, err = core.EnsureTunnelInstanceID()
			if err == nil {
				key, err = core.EnsureTunnelInstanceKey()
			}
		}
		if err != nil {
			return err
		}
		public := key.Public().(ed25519.PublicKey)
		sum := sha256.Sum256(public)
		return json.NewEncoder(os.Stdout).Encode(map[string]string{"instance_id": id, "public_key": base64.StdEncoding.EncodeToString(public), "fingerprint": base64.RawURLEncoding.EncodeToString(sum[:])})
	case "verify-installation-signature":
		var input struct {
			Profile    string `json:"profile"`
			PublicKey  string `json:"public_key"`
			InstanceID string `json:"instance_id"`
			Challenge  string `json:"challenge"`
			Signature  []byte `json:"signature"`
		}
		if err := json.NewDecoder(os.Stdin).Decode(&input); err != nil {
			return err
		}
		public, err := base64.StdEncoding.DecodeString(input.PublicKey)
		if err != nil {
			return err
		}
		if len(public) != ed25519.PublicKeySize {
			return fmt.Errorf("invalid public key size")
		}
		valid := ed25519.Verify(public, protocol.InstanceChallengePayload(input.Profile, input.PublicKey, input.InstanceID, input.Challenge), input.Signature)
		return json.NewEncoder(os.Stdout).Encode(map[string]bool{"valid": valid})
	case "durations":
		var values []string
		if err := json.NewDecoder(os.Stdin).Decode(&values); err != nil {
			return err
		}
		results := make([]*string, len(values))
		for i, value := range values {
			duration, err := time.ParseDuration(value)
			if err != nil {
				continue
			}
			text := duration.String()
			results[i] = &text
		}
		return json.NewEncoder(os.Stdout).Encode(results)
	case "verify-jwt":
		return verifyJWT()
	case "scim-run":
		return runSCIM()
	case "verify-saml":
		return verifySAML()
	case "sign-saml-redirect":
		return signSAMLRedirect()
	case "verify-saml-redirect":
		return verifySAMLRedirect()
	case "restore":
		var backup core.StateBackup
		if err := json.NewDecoder(os.Stdin).Decode(&backup); err != nil {
			return err
		}
		state, err := backup.RestoredState()
		if err != nil {
			return err
		}
		return core.SaveEnvironmentState(state)
	default:
		return fmt.Errorf("unknown operation %q", os.Args[1])
	}
}

func signSAMLRedirect() error {
	var input struct {
		XML           string `json:"xml"`
		PrivateKeyPEM string `json:"private_key_pem"`
		Algorithm     int    `json:"algorithm"`
		RelayState    string `json:"relay_state"`
		Param         string `json:"param"`
	}
	if err := json.NewDecoder(os.Stdin).Decode(&input); err != nil {
		return err
	}
	block, _ := pem.Decode([]byte(input.PrivateKeyPEM))
	if block == nil {
		return fmt.Errorf("private key is required")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	var compressed bytes.Buffer
	writer, err := flate.NewWriter(&compressed, flate.BestCompression)
	if err != nil {
		return err
	}
	if _, err := writer.Write([]byte(input.XML)); err != nil {
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	if input.Param == "" {
		input.Param = "SAMLRequest"
	}
	if input.Algorithm == 0 {
		input.Algorithm = 256
	}
	query := input.Param + "=" + url.QueryEscape(base64.StdEncoding.EncodeToString(compressed.Bytes()))
	if input.RelayState != "" {
		query += "&RelayState=" + url.QueryEscape(input.RelayState)
	}
	query += "&SigAlg=" + url.QueryEscape(fmt.Sprintf("http://www.w3.org/2001/04/xmldsig-more#rsa-sha%d", input.Algorithm))
	var hash crypto.Hash
	var digest []byte
	switch input.Algorithm {
	case 256:
		hash = crypto.SHA256
		value := sha256.Sum256([]byte(query))
		digest = value[:]
	case 384:
		hash = crypto.SHA384
		value := sha512.Sum384([]byte(query))
		digest = value[:]
	case 512:
		hash = crypto.SHA512
		value := sha512.Sum512([]byte(query))
		digest = value[:]
	default:
		return fmt.Errorf("unsupported hash %d", input.Algorithm)
	}
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, hash, digest)
	if err != nil {
		return err
	}
	_, err = fmt.Fprint(os.Stdout, query+"&Signature="+url.QueryEscape(base64.StdEncoding.EncodeToString(signature)))
	return err
}

func verifySAMLRedirect() error {
	var input struct {
		Query          string `json:"query"`
		CertificatePEM string `json:"certificate_pem"`
		Param          string `json:"param"`
	}
	if err := json.NewDecoder(os.Stdin).Decode(&input); err != nil {
		return err
	}
	block, _ := pem.Decode([]byte(input.CertificatePEM))
	if block == nil {
		return fmt.Errorf("certificate is required")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	key, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("RSA certificate is required")
	}
	values, err := url.ParseQuery(input.Query)
	if err != nil {
		return err
	}
	var signed []string
	for _, name := range []string{input.Param, "RelayState", "SigAlg"} {
		for _, part := range strings.Split(input.Query, "&") {
			if strings.HasPrefix(part, name+"=") {
				signed = append(signed, part)
				break
			}
		}
	}
	signature, err := base64.StdEncoding.DecodeString(values.Get("Signature"))
	if err != nil {
		return err
	}
	if values.Get("SigAlg") != "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" {
		return fmt.Errorf("expected RSA-SHA256")
	}
	digest := sha256.Sum256([]byte(strings.Join(signed, "&")))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(true)
}

func verifySAML() error {
	var input struct {
		XML            string `json:"xml"`
		CertificatePEM string `json:"certificate_pem"`
		PrivateKeyPEM  string `json:"private_key_pem"`
		ScanSignatures bool   `json:"scan_signatures"`
	}
	if err := json.NewDecoder(os.Stdin).Decode(&input); err != nil {
		return err
	}
	block, _ := pem.Decode([]byte(input.CertificatePEM))
	if block == nil {
		return fmt.Errorf("signing certificate is required")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	validator := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}})
	doc := etree.NewDocument()
	if err := doc.ReadFromString(input.XML); err != nil {
		return err
	}
	root := doc.Root()
	if root == nil {
		return fmt.Errorf("SAML root is required")
	}
	child := func(el *etree.Element, name string) *etree.Element {
		for _, c := range el.ChildElements() {
			if c.Tag == name {
				return c
			}
		}
		return nil
	}
	var descendant func(*etree.Element, string) *etree.Element
	descendant = func(el *etree.Element, name string) *etree.Element {
		if el.Tag == name {
			return el
		}
		for _, c := range el.ChildElements() {
			if found := descendant(c, name); found != nil {
				return found
			}
		}
		return nil
	}
	if input.ScanSignatures {
		var valid []string
		var walk func(*etree.Element)
		walk = func(el *etree.Element) {
			if child(el, "Signature") != nil {
				if _, err := validator.Validate(el); err == nil {
					valid = append(valid, el.SelectAttrValue("ID", ""))
				}
			}
			for _, nested := range el.ChildElements() {
				walk(nested)
			}
		}
		walk(root)
		return json.NewEncoder(os.Stdout).Encode(valid)
	}
	responseValid := false
	messageValid := false
	if root.Tag != "Assertion" && root.Tag != "Response" && child(root, "Signature") != nil {
		if _, err := validator.Validate(root); err != nil {
			return fmt.Errorf("message signature: %w", err)
		}
		messageValid = true
	}
	if root.Tag == "Response" && child(root, "Signature") != nil {
		if _, err := validator.Validate(root); err != nil {
			return fmt.Errorf("response signature: %w", err)
		}
		responseValid = true
	}
	assertion := root
	if root.Tag != "Assertion" {
		assertion = child(root, "Assertion")
	}
	plaintext := ""
	if encrypted := descendant(root, "EncryptedData"); encrypted != nil {
		block, _ := pem.Decode([]byte(input.PrivateKeyPEM))
		if block == nil {
			return fmt.Errorf("decryption key is required")
		}
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return err
		}
		wrapped := descendant(descendant(encrypted, "EncryptedKey"), "CipherValue")
		wrappedBytes, err := base64.StdEncoding.DecodeString(wrapped.Text())
		if err != nil {
			return err
		}
		secret, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, key, wrappedBytes, nil)
		if err != nil {
			return err
		}
		data := child(child(encrypted, "CipherData"), "CipherValue")
		ciphertext, err := base64.StdEncoding.DecodeString(data.Text())
		if err != nil {
			return err
		}
		aesBlock, err := aes.NewCipher(secret)
		if err != nil {
			return err
		}
		gcm, err := cipher.NewGCM(aesBlock)
		if err != nil {
			return err
		}
		if len(ciphertext) < gcm.NonceSize() {
			return fmt.Errorf("encrypted assertion is truncated")
		}
		decrypted, err := gcm.Open(nil, ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():], nil)
		if err != nil {
			return err
		}
		plaintext = string(decrypted)
		assertionDoc := etree.NewDocument()
		if err := assertionDoc.ReadFromString(plaintext); err != nil {
			return err
		}
		assertion = assertionDoc.Root()
	}
	assertionValid := false
	if assertion != nil && assertion.Tag == "Assertion" && child(assertion, "Signature") != nil {
		if _, err := validator.Validate(assertion); err != nil {
			return fmt.Errorf("assertion signature: %w", err)
		}
		assertionValid = true
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"response_valid": responseValid, "assertion_valid": assertionValid, "message_valid": messageValid, "plaintext_assertion": plaintext})
}

func runSCIM() error {
	var input struct {
		EnvironmentID string `json:"environment_id"`
		Mode          string `json:"mode"`
	}
	if err := json.NewDecoder(os.Stdin).Decode(&input); err != nil {
		return err
	}
	state, err := core.LoadStateForApp(input.EnvironmentID)
	if err != nil {
		return err
	}
	projected, err := core.StateForApp(state, input.EnvironmentID)
	if err != nil {
		return err
	}
	var result core.SyncResult
	if input.Mode == "reconcile" {
		result = core.ReconcileState(projected)
	} else {
		result = core.SyncDirtyState(projected)
	}
	if result.Fatal != nil {
		return result.Fatal
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"status": result.Status, "users": result.State.Users, "groups": result.State.Groups, "traces": result.Traces, "failed": result.Failed})
}

func verifyJWT() error {
	var input struct {
		Token          string `json:"token"`
		CertificatePEM string `json:"certificate_pem"`
	}
	if err := json.NewDecoder(os.Stdin).Decode(&input); err != nil {
		return err
	}
	block, _ := pem.Decode([]byte(input.CertificatePEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return fmt.Errorf("certificate PEM is required")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	if err := certificate.CheckSignature(certificate.SignatureAlgorithm, certificate.RawTBSCertificate, certificate.Signature); err != nil {
		return fmt.Errorf("certificate self-signature: %w", err)
	}
	public, ok := certificate.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("certificate public key must be RSA")
	}
	parts := strings.Split(input.Token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("JWT must have three parts")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(public, crypto.SHA256, digest[:], signature); err != nil {
		return err
	}
	claims, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return err
	}
	var value any
	if err := json.Unmarshal(claims, &value); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"claims": value, "bits": public.N.BitLen(), "not_before": certificate.NotBefore.UTC().Format(time.RFC3339), "not_after": certificate.NotAfter.UTC().Format(time.RFC3339)})
}

func seedLegacy() error {
	db, err := sql.Open("sqlite", os.Args[2])
	if err != nil {
		return err
	}
	defer func() {
		if err := db.Close(); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	}()
	_, err = db.Exec(`
		CREATE TABLE config (key TEXT PRIMARY KEY, value TEXT NOT NULL);
		INSERT INTO config VALUES ('base_url', 'https://greendale.example/scim'), ('bearer_token', 'greendale-provisioning-secret'), ('future_global', 'preserve me');
		CREATE TABLE users (id TEXT PRIMARY KEY, given_name TEXT NOT NULL, family_name TEXT NOT NULL, email TEXT NOT NULL, username TEXT NOT NULL, active INTEGER NOT NULL, remote_id TEXT NOT NULL DEFAULT '', dirty INTEGER NOT NULL, deleted INTEGER NOT NULL, last_error TEXT NOT NULL DEFAULT '');
		INSERT INTO users VALUES ('user_troy', 'Troy', 'Barnes', 'troy@greendale.edu', 'tbarnes', 1, 'remote_troy', 0, 0, '');
		CREATE TABLE groups (id TEXT PRIMARY KEY, display_name TEXT NOT NULL, remote_id TEXT NOT NULL DEFAULT '', dirty INTEGER NOT NULL, deleted INTEGER NOT NULL, last_error TEXT NOT NULL DEFAULT '');
		INSERT INTO groups VALUES ('group_study', 'Study Group', 'remote_study', 1, 0, 'remember this failure');
		CREATE TABLE group_members (group_id TEXT NOT NULL, user_id TEXT NOT NULL, position INTEGER NOT NULL, PRIMARY KEY (group_id, user_id));
		INSERT INTO group_members VALUES ('group_study', 'user_troy', 0);
		CREATE TABLE apps (id TEXT PRIMARY KEY, name TEXT NOT NULL, slug TEXT NOT NULL, protocol TEXT NOT NULL,
            oidc_client_id TEXT NOT NULL DEFAULT '', oidc_client_secret TEXT NOT NULL DEFAULT '', oidc_redirect_uris TEXT NOT NULL DEFAULT '',
            saml_entity_id TEXT NOT NULL DEFAULT '', saml_acs_url TEXT NOT NULL DEFAULT '', saml_audience TEXT NOT NULL DEFAULT '',
            saml_name_id_format TEXT NOT NULL DEFAULT '', saml_email_attribute_name TEXT NOT NULL DEFAULT '', include_groups_claim INTEGER NOT NULL DEFAULT 0);
		INSERT INTO apps (id, name, slug, protocol) VALUES ('app_greendale', 'Greendale', 'greendale', 'oidc'), ('app_city_college', 'City College', 'city-college', 'saml');
		UPDATE apps SET saml_email_attribute_name = 'urn:greendale:mail' WHERE id = 'app_city_college';
		CREATE TABLE operation_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, resource_type TEXT NOT NULL, resource_id TEXT NOT NULL, label TEXT NOT NULL, operation TEXT NOT NULL, method TEXT NOT NULL, path TEXT NOT NULL, request_body TEXT NOT NULL, status TEXT NOT NULL, response_body TEXT NOT NULL, error_text TEXT NOT NULL, created_at TEXT NOT NULL);
		INSERT INTO operation_logs(resource_type, resource_id, label, operation, method, path, request_body, status, response_body, error_text, created_at) VALUES ('user', 'user_troy', 'Troy Barnes', 'create', 'POST', '/Users', '{}', '201 Created', '{}', '', '2026-01-01T00:00:00Z');
	`)
	return err
}

func seed() error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Truncate(time.Second)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "Greendale"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return err
	}
	privatePEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	certificatePEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate}))
	if _, err := core.LoadState(); err != nil {
		return err
	}
	if err := core.SaveGlobalConfig(core.Config{
		IDPBaseURL: "https://greendale.example", TrustForwardedHeaders: true,
		TunnelInstanceID: "greendale-installation", SigningPrivateKeyPEM: privatePEM,
		SigningCertificatePEM: certificatePEM,
	}); err != nil {
		return err
	}
	if _, err := core.EnsureTunnelInstanceKey(); err != nil {
		return err
	}
	for _, id := range []string{"app_greendale", "app_city_college"} {
		app := core.App{
			ID: id, Name: id, Slug: id, Protocol: "both", OIDCClientID: id + "-client",
			OIDCClientSecret: "greendale-confidential-secret", OIDCRedirectURIs: []string{"https://greendale.example/callback?source=oidc", "http://127.0.0.1:4242/callback"},
			OIDCJWTAccessTokens: true, OIDCAccessTokenAudience: "greendale-api",
			OIDCBackchannelLogoutURI: "https://greendale.example/logout?source=oidc", OIDCBackchannelLogoutSessionRequired: true,
			SAMLEntityID: "urn:greendale:sp", SAMLACSURL: "https://greendale.example/acs",
			SAMLSLOURL: "https://greendale.example/slo", SAMLAudience: "urn:greendale:audience",
			SAMLNameIDField: "username", SAMLRequestCertPEM: certificatePEM, SAMLEncryptionCertPEM: certificatePEM,
			SAMLEncryptionAlgorithm: "aes192-gcm", SAMLSigningMode: "both", IncludeGroupsClaim: true,
			OIDCClaimMappings:     core.OIDCClaimMappings{Name: "display_name", Email: "mail"},
			SAMLAttributeMappings: core.SAMLAttributeMappings{Username: "login"},
			ChooserMode:           "identifier", Persona: "entra", GroupsOverageThreshold: 5,
			SCIMEnabled: true, SCIMBaseURL: "https://greendale.example/scim/v2", SCIMBearerToken: "greendale-provisioning-secret",
			SCIMAutoOpenTrace: true, SCIMCapabilitiesKnown: true, SCIMPatchSupported: true, SCIMFilterSupported: true,
		}
		state := core.AppState{
			Environment: core.Environment{ID: id, Name: app.Name, Slug: app.Slug}, Apps: []core.App{app},
			Config: core.Config{SCIMEnterpriseUsed: true, SigningKeys: []core.SigningKey{{ID: "greendale-key", PrivateKeyPEM: privatePEM, CertificatePEM: certificatePEM, CreatedAt: now}}},
			Users: []core.User{{ID: "user_troy", GivenName: "Troy", FamilyName: "Barnes", Email: "troy@greendale.edu", Username: "tbarnes", Active: true,
				EmployeeNumber: "GCC42", CostCenter: "AC", Organization: "Greendale Community College", Division: "Annex", Department: "Air Conditioning", ManagerID: "user_abed", Attributes: map[string]string{"role": "student"}},
				{ID: "user_abed", GivenName: "Abed", FamilyName: "Nadir", Email: "abed@greendale.edu", Username: "anadir", Active: true}},
			Groups:    []core.Group{{ID: "group_study", DisplayName: "Study Group", MemberIDs: []string{"user_abed", "user_troy"}}},
			UserSync:  map[string]map[string]core.ResourceSyncState{id: {"user_troy": {RemoteID: "remote_troy", LastError: "remember this failure"}, "user_abed": {RemoteID: "remote_abed"}}},
			GroupSync: map[string]map[string]core.ResourceSyncState{id: {"group_study": {RemoteID: "remote_study", Dirty: true}}},
		}
		core.AppendLocalOperationLog(&state, "user", "user_troy", "Created")
		core.AppendLocalOperationLog(&state, "group", "group_study", "Created")
		if err := core.SaveEnvironmentState(state); err != nil {
			return err
		}
	}
	db, err := sql.Open("sqlite", os.Args[2])
	if err != nil {
		return err
	}
	defer func() {
		if err := db.Close(); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	}()
	_, err = db.Exec(`INSERT INTO config VALUES ('future_global', 'preserve me'); INSERT INTO environment_config VALUES ('app_greendale', 'future_environment', 'preserve me')`)
	return err
}

func dump() error {
	global, err := core.LoadState()
	if err != nil {
		return err
	}
	states := make(map[string]core.StateBackup)
	for _, app := range global.Apps {
		state, err := core.LoadStateForApp(app.ID)
		if err != nil {
			return err
		}
		backup := core.NewStateBackup(state)
		backup.ExportedAt = ""
		states[app.ID] = backup
	}
	return json.NewEncoder(os.Stdout).Encode(states)
}
