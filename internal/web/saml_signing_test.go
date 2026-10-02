package web

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/stretchr/testify/require"
)

func TestSignedSAMLResponseSigningModes(t *testing.T) {
	tests := map[string]struct {
		mode          string
		encrypt       bool
		wantResponse  bool
		wantAssertion bool
	}{
		"assertion":           {mode: samlSigningModeAssertion, wantAssertion: true},
		"default":             {mode: "", wantAssertion: true},
		"response":            {mode: samlSigningModeResponse, wantResponse: true},
		"both":                {mode: samlSigningModeBoth, wantResponse: true, wantAssertion: true},
		"assertion encrypted": {mode: samlSigningModeAssertion, encrypt: true, wantAssertion: true},
		"response encrypted":  {mode: samlSigningModeResponse, encrypt: true, wantResponse: true},
		"both encrypted":      {mode: samlSigningModeBoth, encrypt: true, wantResponse: true, wantAssertion: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			svc := newTestIDPApp(t)
			posted, spKey := buildSAMLResponseForSigningMode(t, svc, tc.mode, tc.encrypt, faultOptions{})
			cert := activeSAMLSigningCertificate(t, svc)

			root := mustParseXML(t, posted.XML).Root()
			r.Equal(tc.wantResponse, childElementByLocalName(root, "Signature") != nil)
			_, err := samlSignatureValidator(cert).Validate(root)
			if tc.wantResponse {
				r.NoError(err)
				r.Equal([]string{"Issuer", "Signature", "Status"}, childLocalNames(root)[:3])
			} else {
				r.ErrorIs(err, dsig.ErrMissingSignature)
			}

			assertion := postedAssertionForSigningTest(t, posted, spKey, tc.encrypt)
			r.Equal(tc.wantAssertion, childElementByLocalName(assertion, "Signature") != nil)
			_, err = samlSignatureValidator(cert).Validate(assertion)
			if tc.wantAssertion {
				r.NoError(err)
				r.Equal([]string{"Issuer", "Signature", "Subject"}, childLocalNames(assertion)[:3])
			} else {
				r.ErrorIs(err, dsig.ErrMissingSignature)
			}
			r.Equal("troy@greendale.edu", firstElementTextByLocalName(assertion, "NameID"))
		})
	}
}

func TestSignedSAMLResponseBreakSignatureBreaksEverySignature(t *testing.T) {
	tests := map[string]struct {
		mode    string
		encrypt bool
	}{
		"assertion":           {mode: samlSigningModeAssertion},
		"response":            {mode: samlSigningModeResponse},
		"both":                {mode: samlSigningModeBoth},
		"assertion encrypted": {mode: samlSigningModeAssertion, encrypt: true},
		"response encrypted":  {mode: samlSigningModeResponse, encrypt: true},
		"both encrypted":      {mode: samlSigningModeBoth, encrypt: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			svc := newTestIDPApp(t)
			posted, spKey := buildSAMLResponseForSigningMode(t, svc, tc.mode, tc.encrypt, faultOptions{BreakSignature: true})
			cert := activeSAMLSigningCertificate(t, svc)

			signed := []*etree.Element{mustParseXML(t, posted.XML).Root(), postedAssertionForSigningTest(t, posted, spKey, tc.encrypt)}
			var signatures int
			for _, el := range signed {
				if childElementByLocalName(el, "Signature") == nil {
					continue
				}
				signatures++
				_, err := samlSignatureValidator(cert).Validate(el)
				r.Error(err, "%s signature must be broken", elementLocalName(el))
				r.NotErrorIs(err, dsig.ErrMissingSignature)
			}
			want := 1
			if tc.mode == samlSigningModeBoth {
				want = 2
			}
			r.Equal(want, signatures)
		})
	}
}

func TestSignedSAMLResponseRejectsUnknownSigningMode(t *testing.T) {
	r := require.New(t)
	svc := newTestIDPApp(t)
	state, troy := troyGreendaleSAMLState("")
	state.Apps[0].SAMLSigningMode = "everything"

	posted, err := svc.buildSignedSAMLResponse(state, state.Config.IDPBaseURL, state.Apps[0], troy, samlResponseContext{ACSURL: state.Apps[0].SAMLACSURL}, nil, faultOptions{})
	r.ErrorContains(err, `unknown SAML signing mode "everything"`)
	r.Empty(posted.XML)
}

func TestSAMLSSOPostsConfiguredSignatures(t *testing.T) {
	tests := map[string]struct {
		mode          string
		wantResponse  bool
		wantAssertion bool
	}{
		"assertion": {mode: samlSigningModeAssertion, wantAssertion: true},
		"response":  {mode: samlSigningModeResponse, wantResponse: true},
		"both":      {mode: samlSigningModeBoth, wantResponse: true, wantAssertion: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			setTestStateFile(t)
			svc := newTestIDPApp(t)
			state, troy := troyGreendaleSAMLState("")
			state.Apps[0].SAMLSigningMode = tc.mode
			r.NoError(saveState(state))

			rec := postSAMLSSO(t, svc, url.Values{"user_id": {troy.ID}})
			r.Equal(http.StatusOK, rec.Code, rec.Body.String())
			responseXML, err := base64.StdEncoding.DecodeString(hiddenInputValue(rec.Body.String(), "SAMLResponse"))
			r.NoError(err)
			cert := activeSAMLSigningCertificate(t, svc)
			root := mustParseXML(t, string(responseXML)).Root()
			_, err = samlSignatureValidator(cert).Validate(root)
			r.Equal(tc.wantResponse, err == nil, "response signature: %v", err)
			_, err = samlSignatureValidator(cert).Validate(findElementByLocalName(root, "Assertion"))
			r.Equal(tc.wantAssertion, err == nil, "assertion signature: %v", err)
		})
	}
}

func TestAPISAMLSigningModePersistsThroughBackup(t *testing.T) {
	r := require.New(t)
	_, handler := newAcceptanceAPI(t)
	created := acceptanceEnvironment(t, handler, `{"name":"Greendale Portal","slug":"greendale","saml_enabled":true,"saml_acs_url":"https://greendale.test/saml/acs","saml_signing_mode":"both"}`)
	r.Equal(samlSigningModeBoth, created.SAMLSigningMode)
	base := "/api/v1/environments/" + created.ID

	acceptanceRequest(t, handler, http.MethodPatch, base, `{"saml_signing_mode":"everything"}`, http.StatusBadRequest)
	var current app
	r.NoError(json.Unmarshal(acceptanceRequest(t, handler, http.MethodGet, base, "", http.StatusOK).Body.Bytes(), &current))
	r.Equal(samlSigningModeBoth, current.SAMLSigningMode)

	backup := acceptanceRequest(t, handler, http.MethodGet, base+"/backup", "", http.StatusOK).Body.String()
	r.Contains(backup, `"saml_signing_mode":"both"`)
	acceptanceRequest(t, handler, http.MethodPatch, base, `{"saml_signing_mode":"response"}`, http.StatusOK)
	acceptanceRequest(t, handler, http.MethodPost, base+"/restore", backup, http.StatusOK)
	r.NoError(json.Unmarshal(acceptanceRequest(t, handler, http.MethodGet, base, "", http.StatusOK).Body.Bytes(), &current))
	r.Equal(samlSigningModeBoth, current.SAMLSigningMode)

	// a backup from before this setting existed restores to assertion signing
	older := strings.Replace(backup, `"saml_signing_mode":"both",`, "", 1)
	r.NotContains(older, "saml_signing_mode")
	acceptanceRequest(t, handler, http.MethodPost, base+"/restore", older, http.StatusOK)
	r.NoError(json.Unmarshal(acceptanceRequest(t, handler, http.MethodGet, base, "", http.StatusOK).Body.Bytes(), &current))
	r.Equal(samlSigningModeAssertion, current.SAMLSigningMode)

	acceptanceRequest(t, handler, http.MethodPatch, base, `{"saml_enabled":false,"oidc_enabled":true,"oidc_client_id":"greendale","oidc_redirect_uris":["http://greendale.test/callback"]}`, http.StatusOK)
	var disabled app
	r.NoError(json.Unmarshal(acceptanceRequest(t, handler, http.MethodGet, base, "", http.StatusOK).Body.Bytes(), &disabled))
	r.Equal("oidc", disabled.Protocol)
	r.Empty(disabled.SAMLSigningMode)
}

func TestAppSaveSelectsSAMLSigningMode(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{}))
	appService := newTestIDPApp(t)
	form := url.Values{
		"tab":                       {"apps"},
		"name":                      {"Greendale Portal"},
		"slug":                      {"greendale"},
		"protocol_switches_present": {"true"},
		"saml_enabled":              {"on"},
		"saml_acs_url":              {"https://greendale.test/saml/acs"},
		"saml_signing_mode":         {samlSigningModeResponse},
	}
	req := httptest.NewRequest(http.MethodPost, "/apps/save", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	appService.routes().ServeHTTP(rec, req)

	r.Equal(http.StatusSeeOther, rec.Code)
	state, err := loadState()
	r.NoError(err)
	r.Len(state.Apps, 1)
	r.Equal(samlSigningModeResponse, state.Apps[0].SAMLSigningMode)

	formRec := httptest.NewRecorder()
	appService.routes().ServeHTTP(formRec, httptest.NewRequest(http.MethodGet, "/?tab=apps&modal=app&id="+url.QueryEscape(state.Apps[0].ID), nil))
	r.Equal(http.StatusOK, formRec.Code)
	r.Contains(formRec.Body.String(), `<option value="response" selected>Response</option>`)
}

func buildSAMLResponseForSigningMode(t *testing.T, svc *webApp, mode string, encrypt bool, faults faultOptions) (samlPostedResponse, *rsa.PrivateKey) {
	t.Helper()
	var spKey *rsa.PrivateKey
	var encryption *samlAssertionEncryption
	pem := ""
	if encrypt {
		var dest *x509.Certificate
		spKey, dest, pem = newSPEncryptionMaterial(t)
		encryption = samlTestEncryption(t, dest, defaultSAMLEncryptionAlgorithm)
	}
	state, troy := troyGreendaleSAMLState(pem)
	state.Apps[0].SAMLSigningMode = mode
	posted, err := svc.buildSignedSAMLResponse(state, state.Config.IDPBaseURL, state.Apps[0], troy, samlResponseContext{ACSURL: state.Apps[0].SAMLACSURL}, encryption, faults)
	require.NoError(t, err)
	return posted, spKey
}

// postedAssertionForSigningTest returns the assertion an SP would check: the
// one in the response, or the decrypted one.
func postedAssertionForSigningTest(t *testing.T, posted samlPostedResponse, spKey *rsa.PrivateKey, encrypted bool) *etree.Element {
	t.Helper()
	if encrypted {
		require.NotContains(t, posted.XML, "<saml:Assertion")
		return decryptPostedAssertion(t, posted.XML, spKey)
	}
	assertion := findElementByLocalName(mustParseXML(t, posted.XML).Root(), "Assertion")
	require.NotNil(t, assertion)
	return assertion
}

func activeSAMLSigningCertificate(t *testing.T, svc *webApp) *x509.Certificate {
	t.Helper()
	state, _ := troyGreendaleSAMLState("")
	key, err := svc.activeSigningKey(state)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(key.CertDER)
	require.NoError(t, err)
	return cert
}

func samlSignatureValidator(cert *x509.Certificate) *dsig.ValidationContext {
	return dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{cert},
	})
}

func childLocalNames(el *etree.Element) []string {
	var names []string
	for _, child := range el.ChildElements() {
		names = append(names, elementLocalName(child))
	}
	return names
}
