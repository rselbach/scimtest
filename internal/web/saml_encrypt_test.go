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

	posted, err := svc.buildSignedSAMLResponse(state, state.Config.IDPBaseURL, state.Apps[0], troy, samlResponseContext{ACSURL: state.Apps[0].SAMLACSURL}, dest, faultOptions{})
	r.NoError(err)
	r.Contains(posted.XML, "EncryptedAssertion")
	r.Contains(posted.XML, "EncryptedData")
	r.Contains(posted.XML, algAES256GCM)
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

	posted, err := svc.buildSignedSAMLResponse(state, state.Config.IDPBaseURL, state.Apps[0], troy, samlResponseContext{ACSURL: state.Apps[0].SAMLACSURL}, dest, faultOptions{})
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

func TestSignedSAMLResponseBreakSignatureThenEncrypts(t *testing.T) {
	r := require.New(t)
	svc := newTestIDPApp(t)
	spKey, dest, pem := newSPEncryptionMaterial(t)
	state, troy := troyGreendaleSAMLState(pem)

	posted, err := svc.buildSignedSAMLResponse(state, state.Config.IDPBaseURL, state.Apps[0], troy, samlResponseContext{ACSURL: state.Apps[0].SAMLACSURL}, dest, faultOptions{BreakSignature: true})
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

	posted, err := svc.buildSignedSAMLResponse(state, state.Config.IDPBaseURL, state.Apps[0], troy, samlResponseContext{ACSURL: state.Apps[0].SAMLACSURL}, dest, faultOptions{
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

func TestClearAppProtocolClearsSAMLEncryptionCertPEM(t *testing.T) {
	r := require.New(t)
	app := app{
		SAMLEntityID:          "urn:greendale:sp",
		SAMLACSURL:            "https://sp.greendale.test/acs",
		SAMLRequestCertPEM:    "request-cert",
		SAMLEncryptionCertPEM: "encryption-cert",
	}
	clearAppProtocol(&app, "saml")
	r.Empty(app.SAMLEntityID)
	r.Empty(app.SAMLACSURL)
	r.Empty(app.SAMLRequestCertPEM)
	r.Empty(app.SAMLEncryptionCertPEM)
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

func decryptPostedAssertion(t *testing.T, responseXML string, key *rsa.PrivateKey) *etree.Element {
	t.Helper()
	r := require.New(t)
	doc := mustParseXML(t, responseXML)
	encryptedAssertion := findElementByLocalName(doc.Root(), "EncryptedAssertion")
	r.NotNil(encryptedAssertion)
	encryptedData := childElementByLocalName(encryptedAssertion, "EncryptedData")
	r.NotNil(encryptedData)
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
	return assertion
}

func mustParseXML(t *testing.T, value string) *etree.Document {
	t.Helper()
	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromString(value))
	return doc
}
