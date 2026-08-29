package web

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/stretchr/testify/require"
)

func TestSignedSAMLResponseEmptyPEMStaysPlaintext(t *testing.T) {
	r := require.New(t)
	svc := newTestIDPApp(t)
	state, troy := troyGreendaleSAMLState("")

	posted, err := svc.buildSignedSAMLResponse(state, state.Config.IDPBaseURL, state.Apps[0], troy, samlResponseContext{ACSURL: state.Apps[0].SAMLACSURL}, nil, faultOptions{})
	r.NoError(err)
	r.NotContains(posted.XML, "EncryptedAssertion")
	r.Contains(posted.XML, "<saml:Assertion")
	r.Contains(posted.XML, "ds:Signature")
	r.Contains(posted.XML, "troy@greendale.edu")
	r.Empty(posted.SignedAssertion)
}

func TestSignedSAMLResponseEncryptsAssertionToSPCertificate(t *testing.T) {
	r := require.New(t)
	svc := newTestIDPApp(t)
	spKey, dest, pem := newSPEncryptionMaterial(t)
	state, troy := troyGreendaleSAMLState(pem)
	encryption := samlTestEncryption(t, dest, defaultSAMLEncryptionAlgorithm)

	posted, err := svc.buildSignedSAMLResponse(state, state.Config.IDPBaseURL, state.Apps[0], troy, samlResponseContext{ACSURL: state.Apps[0].SAMLACSURL}, encryption, faultOptions{})
	r.NoError(err)
	r.Contains(posted.XML, "EncryptedAssertion")
	r.Contains(posted.XML, "EncryptedData")
	r.Contains(posted.XML, xmlenc11NS+"aes256-gcm")
	r.Contains(posted.XML, algRSAOAEP)
	r.NotContains(posted.XML, "<saml:Assertion")
	r.NotContains(posted.XML, "troy@greendale.edu")
	r.NotContains(posted.XML, "troy.barnes@greendale.edu")
	r.Contains(posted.SignedAssertion, "troy@greendale.edu")
	r.Contains(posted.SignedAssertion, "Signature")

	signedDoc := etree.NewDocument()
	r.NoError(signedDoc.ReadFromString(posted.SignedAssertion))
	assertion := signedDoc.Root()
	r.Equal("Assertion", elementLocalName(assertion))
	children := assertion.ChildElements()
	r.GreaterOrEqual(len(children), 2)
	r.Equal("Issuer", elementLocalName(children[0]))
	r.Equal("Signature", elementLocalName(children[1]))

	recovered := decryptPostedAssertion(t, posted.XML, spKey)
	idpCert, err := x509.ParseCertificate(svc.certDER)
	r.NoError(err)
	validator := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{idpCert},
	})
	_, err = validator.Validate(recovered)
	r.NoError(err)
	r.Equal("troy@greendale.edu", firstElementTextByLocalName(recovered, "NameID"))
}

func TestEncryptSAMLAssertionRoundTripValidatesSignature(t *testing.T) {
	r := require.New(t)
	svc := newTestIDPApp(t)
	spKey, dest, pem := newSPEncryptionMaterial(t)
	state, troy := troyGreendaleSAMLState(pem)
	encryption := samlTestEncryption(t, dest, defaultSAMLEncryptionAlgorithm)

	posted, err := svc.buildSignedSAMLResponse(state, state.Config.IDPBaseURL, state.Apps[0], troy, samlResponseContext{ACSURL: state.Apps[0].SAMLACSURL}, encryption, faultOptions{})
	r.NoError(err)

	recovered := decryptPostedAssertion(t, posted.XML, spKey)
	idpCert, err := x509.ParseCertificate(svc.certDER)
	r.NoError(err)
	validator := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{idpCert},
	})
	_, err = validator.Validate(recovered)
	r.NoError(err)
}

func TestSignedSAMLResponseEncryptsWithConfiguredAlgorithm(t *testing.T) {
	tests := map[string]struct {
		value    string
		xmlURI   string
		keyBytes int
	}{
		"AES-128-GCM": {
			value:    samlEncryptionAlgorithmAES128GCM,
			xmlURI:   xmlenc11NS + "aes128-gcm",
			keyBytes: 16,
		},
		"AES-192-GCM": {
			value:    samlEncryptionAlgorithmAES192GCM,
			xmlURI:   xmlenc11NS + "aes192-gcm",
			keyBytes: 24,
		},
		"AES-256-GCM": {
			value:    samlEncryptionAlgorithmAES256GCM,
			xmlURI:   xmlenc11NS + "aes256-gcm",
			keyBytes: 32,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			svc := newTestIDPApp(t)
			spKey, _, pem := newSPEncryptionMaterial(t)
			state, troy := troyGreendaleSAMLState(pem)
			state.Apps[0].SAMLEncryptionAlgorithm = tc.value
			encryption, err := samlAssertionEncryptionForApp(state.Apps[0])
			r.NoError(err)

			posted, err := svc.buildSignedSAMLResponse(state, state.Config.IDPBaseURL, state.Apps[0], troy, samlResponseContext{ACSURL: state.Apps[0].SAMLACSURL}, encryption, faultOptions{})
			r.NoError(err)

			decrypted := decryptPostedAssertionDetails(t, posted.XML, spKey)
			r.Equal(tc.xmlURI, decrypted.Algorithm)
			r.Equal(tc.keyBytes, decrypted.KeyBytes)
			r.Equal("troy@greendale.edu", firstElementTextByLocalName(decrypted.Assertion, "NameID"))
			validateSAMLAssertionSignature(t, svc.certDER, decrypted.Assertion)
		})
	}
}

func TestSignedSAMLResponseBreakSignatureThenEncrypts(t *testing.T) {
	r := require.New(t)
	svc := newTestIDPApp(t)
	spKey, dest, pem := newSPEncryptionMaterial(t)
	state, troy := troyGreendaleSAMLState(pem)
	encryption := samlTestEncryption(t, dest, defaultSAMLEncryptionAlgorithm)

	posted, err := svc.buildSignedSAMLResponse(state, state.Config.IDPBaseURL, state.Apps[0], troy, samlResponseContext{ACSURL: state.Apps[0].SAMLACSURL}, encryption, faultOptions{BreakSignature: true})
	r.NoError(err)

	signedValue := findElementByLocalName(mustParseXML(t, posted.SignedAssertion).Root(), "SignatureValue")
	r.NotNil(signedValue)
	recovered := decryptPostedAssertion(t, posted.XML, spKey)
	broken := findElementByLocalName(recovered, "SignatureValue")
	r.NotNil(broken)
	r.Equal(signedValue.Text(), broken.Text())
	r.NotEmpty(broken.Text())

	idpCert, err := x509.ParseCertificate(svc.certDER)
	r.NoError(err)
	validator := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{idpCert},
	})
	_, err = validator.Validate(recovered)
	r.Error(err)
}

func TestSignedSAMLResponseStatusDoesNotEncrypt(t *testing.T) {
	r := require.New(t)
	svc := newTestIDPApp(t)
	_, dest, pem := newSPEncryptionMaterial(t)
	state, troy := troyGreendaleSAMLState(pem)
	encryption := samlTestEncryption(t, dest, defaultSAMLEncryptionAlgorithm)

	posted, err := svc.buildSignedSAMLResponse(state, state.Config.IDPBaseURL, state.Apps[0], troy, samlResponseContext{ACSURL: state.Apps[0].SAMLACSURL}, encryption, faultOptions{
		SAMLStatus: "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed",
	})
	r.NoError(err)
	r.NotContains(posted.XML, "EncryptedAssertion")
	r.NotContains(posted.XML, "Assertion")
	r.Empty(posted.SignedAssertion)
	r.Contains(posted.XML, "AuthnFailed")
}

func TestSAMLSSOPostsEncryptedAssertion(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	svc := newTestIDPApp(t)
	_, _, pem := newSPEncryptionMaterial(t)
	state, troy := troyGreendaleSAMLState(pem)
	r.NoError(saveState(state))

	form := url.Values{"user_id": {troy.ID}}
	req := httptest.NewRequest(http.MethodPost, "/saml/greendale/sso", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	svc.routes().ServeHTTP(rec, req)

	r.Equal(http.StatusOK, rec.Code)
	encoded := hiddenInputValue(rec.Body.String(), "SAMLResponse")
	r.NotEmpty(encoded)
	responseXML, err := base64.StdEncoding.DecodeString(encoded)
	r.NoError(err)
	r.Contains(string(responseXML), "EncryptedAssertion")
	r.NotContains(string(responseXML), "troy@greendale.edu")

	inspector := httptest.NewRecorder()
	svc.routes().ServeHTTP(inspector, httptest.NewRequest(http.MethodGet, "/inspect/saml/greendale", nil))
	r.Equal(http.StatusOK, inspector.Code)
	body := inspector.Body.String()
	r.Contains(body, "Decoded SAML response")
	r.Contains(body, "Signed assertion (before encryption)")
	r.Contains(body, "EncryptedAssertion")
	r.Contains(body, "troy@greendale.edu")
}

func TestSAMLSSORejectsInvalidEncryptionCertificate(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	svc := newTestIDPApp(t)
	state, troy := troyGreendaleSAMLState("not-a-cert")
	r.NoError(saveState(state))

	form := url.Values{"user_id": {troy.ID}}
	req := httptest.NewRequest(http.MethodPost, "/saml/greendale/sso", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	svc.routes().ServeHTTP(rec, req)

	r.Equal(http.StatusBadRequest, rec.Code)
	r.Contains(rec.Body.String(), "SAML encryption certificate is invalid")
	r.NotContains(rec.Body.String(), "SAMLResponse")
	r.NotContains(rec.Body.String(), `action="https://sp.greendale.test/acs"`)
}

func TestSAMLDenyDoesNotEncrypt(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	svc := newTestIDPApp(t)
	_, _, pem := newSPEncryptionMaterial(t)
	state, troy := troyGreendaleSAMLState(pem)
	r.NoError(saveState(state))

	form := url.Values{"user_id": {troy.ID}, "deny": {"1"}}
	req := httptest.NewRequest(http.MethodPost, "/saml/greendale/sso", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	svc.routes().ServeHTTP(rec, req)

	r.Equal(http.StatusOK, rec.Code)
	encoded := hiddenInputValue(rec.Body.String(), "SAMLResponse")
	responseXML, err := base64.StdEncoding.DecodeString(encoded)
	r.NoError(err)
	r.Contains(string(responseXML), "AuthnFailed")
	r.NotContains(string(responseXML), "EncryptedAssertion")
	r.NotContains(string(responseXML), "Assertion")
}

func TestClearAppProtocolClearsSAMLEncryptionSettings(t *testing.T) {
	r := require.New(t)
	app := app{
		SAMLEntityID:            "urn:greendale:sp",
		SAMLACSURL:              "https://sp.greendale.test/acs",
		SAMLRequestCertPEM:      "request-cert",
		SAMLEncryptionCertPEM:   "encryption-cert",
		SAMLEncryptionAlgorithm: samlEncryptionAlgorithmAES192GCM,
	}
	clearAppProtocol(&app, "saml")
	r.Empty(app.SAMLEntityID)
	r.Empty(app.SAMLACSURL)
	r.Empty(app.SAMLRequestCertPEM)
	r.Empty(app.SAMLEncryptionCertPEM)
	r.Empty(app.SAMLEncryptionAlgorithm)
	r.Equal("none", inferAppProtocol(app))
}

func troyGreendaleSAMLState(encryptionPEM string) (appState, user) {
	troy := user{
		ID: "usr-troy", GivenName: "Troy", FamilyName: "Barnes",
		Email: "troy@greendale.edu", Username: "tbarnes", Active: true,
	}
	state := appState{
		Config: config{IDPBaseURL: "http://idp.test"},
		Users:  []user{troy},
		Apps: []app{{
			ID:                     "app-1",
			Name:                   "Greendale",
			Slug:                   "greendale",
			Protocol:               "saml",
			SAMLEntityID:           "urn:greendale:sp",
			SAMLACSURL:             "https://sp.greendale.test/acs",
			SAMLNameIDField:        defaultSAMLNameIDField,
			SAMLNameIDFormat:       samlNameIDFormatForField(defaultSAMLNameIDField),
			SAMLEmailAttributeName: defaultSAMLEmailAttributeName,
			SAMLEncryptionCertPEM:  encryptionPEM,
		}},
	}
	return state, troy
}

func newSPEncryptionMaterial(t *testing.T) (*rsa.PrivateKey, *x509.Certificate, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := selfSignedCert(key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return key, cert, certificatePEM(der)
}

func samlTestEncryption(t *testing.T, dest *x509.Certificate, algorithm string) *samlAssertionEncryption {
	t.Helper()
	spec, err := samlEncryptionAlgorithmSpecFor(algorithm)
	require.NoError(t, err)
	return &samlAssertionEncryption{destination: dest, algorithm: spec}
}

type decryptedSAMLAssertion struct {
	Assertion *etree.Element
	Algorithm string
	KeyBytes  int
}

func decryptPostedAssertion(t *testing.T, responseXML string, key *rsa.PrivateKey) *etree.Element {
	t.Helper()
	return decryptPostedAssertionDetails(t, responseXML, key).Assertion
}

func decryptPostedAssertionDetails(t *testing.T, responseXML string, key *rsa.PrivateKey) decryptedSAMLAssertion {
	t.Helper()
	r := require.New(t)
	doc := mustParseXML(t, responseXML)
	encryptedAssertion := findElementByLocalName(doc.Root(), "EncryptedAssertion")
	r.NotNil(encryptedAssertion)
	encryptedData := childElementByLocalName(encryptedAssertion, "EncryptedData")
	r.NotNil(encryptedData)
	dataMethod := childElementByLocalName(encryptedData, "EncryptionMethod")
	r.NotNil(dataMethod)
	algorithm := dataMethod.SelectAttrValue("Algorithm", "")
	keyInfo := childElementByLocalName(encryptedData, "KeyInfo")
	encryptedKey := childElementByLocalName(keyInfo, "EncryptedKey")
	r.NotNil(encryptedKey)
	wrapped, err := base64.StdEncoding.DecodeString(strings.TrimSpace(childElementByLocalName(childElementByLocalName(encryptedKey, "CipherData"), "CipherValue").Text()))
	r.NoError(err)
	aesKey, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, key, wrapped, nil)
	r.NoError(err)
	packed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(childElementByLocalName(childElementByLocalName(encryptedData, "CipherData"), "CipherValue").Text()))
	r.NoError(err)
	block, err := aes.NewCipher(aesKey)
	r.NoError(err)
	aead, err := cipher.NewGCM(block)
	r.NoError(err)
	r.Greater(len(packed), aead.NonceSize())
	plaintext, err := aead.Open(nil, packed[:aead.NonceSize()], packed[aead.NonceSize():], nil)
	r.NoError(err)
	assertionDoc := etree.NewDocument()
	r.NoError(assertionDoc.ReadFromBytes(plaintext))
	assertion := assertionDoc.Root()
	r.NotNil(assertion)
	r.Equal("Assertion", elementLocalName(assertion))
	return decryptedSAMLAssertion{Assertion: assertion, Algorithm: algorithm, KeyBytes: len(aesKey)}
}

func validateSAMLAssertionSignature(t *testing.T, certificateDER []byte, assertion *etree.Element) {
	t.Helper()
	idpCert, err := x509.ParseCertificate(certificateDER)
	require.NoError(t, err)
	validator := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{idpCert},
	})
	_, err = validator.Validate(assertion)
	require.NoError(t, err)
}

func mustParseXML(t *testing.T, value string) *etree.Document {
	t.Helper()
	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromString(value))
	return doc
}
