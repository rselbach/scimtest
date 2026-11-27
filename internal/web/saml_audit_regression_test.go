package web

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/require"
)

func TestSAMLAuthnRequestRejectsCommentTruncatedIssuer(t *testing.T) {
	r := require.New(t)
	requestXML := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_req-troy" Destination="http://idp.test/saml/greendale/sso" AssertionConsumerServiceURL="https://sp.greendale.test/acs"><saml:Issuer>urn:greendale:sp<!---->.evil</saml:Issuer></samlp:AuthnRequest>`
	encoded := base64.StdEncoding.EncodeToString([]byte(requestXML))

	parsed, err := parseSAMLAuthnRequest(encoded)
	r.NoError(err)
	r.Equal("urn:greendale:sp.evil", parsed.Issuer, "XML comment must not truncate Issuer")

	req := httptest.NewRequest(http.MethodPost, "/saml/greendale/sso", nil)
	_, err = resolveSAMLResponseContext(req, url.Values{"SAMLRequest": {encoded}}, app{
		Slug:         "greendale",
		SAMLEntityID: "urn:greendale:sp",
		SAMLACSURL:   "https://sp.greendale.test/acs",
	}, "http://idp.test")
	r.Error(err)
	r.Contains(err.Error(), "issuer does not match")
}

func TestSAMLLogoutRequestDoesNotTruncateNameIDOrSessionIndexOnComment(t *testing.T) {
	r := require.New(t)
	doc := etree.NewDocument()
	r.NoError(doc.ReadFromString(`<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_slo-abed"><saml:Issuer>urn:greendale:sp<!---->.evil</saml:Issuer><saml:NameID>abed@greendale.edu<!---->.evil</saml:NameID><samlp:SessionIndex>idx-1<!---->-evil</samlp:SessionIndex></samlp:LogoutRequest>`))

	parsed, err := parseSAMLLogoutRequest(doc.Root())
	r.NoError(err)
	r.Equal("abed@greendale.edu.evil", parsed.NameID)
	r.Equal([]string{"idx-1-evil"}, parsed.SessionIndexes)
	r.Equal("urn:greendale:sp.evil", childElementTextByLocalName(doc.Root(), "Issuer"))
}

func TestUniqueRawQueryValueRejectsValuelessDuplicateKey(t *testing.T) {
	tests := map[string]struct {
		rawQuery string
		name     string
		required bool
	}{
		"valueless RelayState before signed RelayState": {
			rawQuery: "RelayState&SAMLRequest=abc&RelayState=real&SigAlg=alg&Signature=sig",
			name:     "RelayState",
			required: false,
		},
		"percent-encoded valueless RelayState": {
			rawQuery: "%52elayState&SAMLRequest=abc&RelayState=real",
			name:     "RelayState",
			required: false,
		},
		"valueless SAMLRequest before real SAMLRequest": {
			rawQuery: "SAMLRequest&SAMLRequest=abc",
			name:     "SAMLRequest",
			required: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			_, _, err := uniqueRawQueryValue(tc.rawQuery, tc.name, tc.required)
			r.Error(err)
		})
	}
}

func TestSignedSAMLAuthnRequestRequiresDestination(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	svc := newTestIDPApp(t)
	state := signedRequestTestState(svc)
	r.NoError(saveState(state))

	requestXML := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_req-annie" AssertionConsumerServiceURL="https://sp.greendale.test/acs"><saml:Issuer>urn:greendale:sp</saml:Issuer></samlp:AuthnRequest>`
	encoded := encodeRedirectSAMLRequest(t, requestXML)
	rawQuery := signedRedirectSAMLQuery(t, svc.signingKey, encoded, "")

	req := httptest.NewRequest(http.MethodGet, "http://idp.test/saml/greendale/sso?"+rawQuery, nil)
	_, err := resolveSAMLResponseContext(req, req.URL.Query(), state.Apps[0], "http://idp.test")
	r.Error(err)
	r.Contains(err.Error(), "must carry Destination")
}

func TestCompleteSAMLSSODoesNotCreateSessionOnStatusFaultOrBuildError(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	state := appState{
		Config: config{IDPBaseURL: "http://idp.test"},
		Users: []user{
			{ID: "troy", GivenName: "Troy", FamilyName: "Barnes", Email: "troy@greendale.edu", Username: "troy", Active: true},
		},
		Apps: []app{{
			ID:           "greendale",
			Name:         "Greendale",
			Slug:         "greendale",
			Protocol:     "saml",
			SAMLEntityID: "urn:greendale:sp",
			SAMLACSURL:   "https://sp.greendale.test/acs",
		}},
	}
	r.NoError(saveState(state))
	webApp := newTestIDPApp(t)

	// 1. SAMLStatus fault must not create an IdP session, set a cookie, or record an AssertionID.
	statusRec := httptest.NewRecorder()
	statusReq := httptest.NewRequest(http.MethodGet, "/saml/greendale/sso?user_id=troy&fault_saml_status=AuthnFailed", nil)
	webApp.routes().ServeHTTP(statusRec, statusReq)
	r.Equal(http.StatusOK, statusRec.Code)
	r.Empty(statusRec.Result().Cookies())
	r.Empty(webApp.liveSAMLSessions("greendale"))
	webApp.samlInspectorMu.Lock()
	inspections := append([]samlInspection(nil), webApp.samlInspections["greendale"]...)
	webApp.samlInspectorMu.Unlock()
	r.Len(inspections, 1)
	r.Empty(inspections[0].AssertionID)

	// 2. Build error (xsw_assertion with only one active user) must not leak Set-Cookie or create session.
	errRec := httptest.NewRecorder()
	errReq := httptest.NewRequest(http.MethodGet, "/saml/greendale/sso?user_id=troy&fault_tamper=xsw_assertion", nil)
	webApp.routes().ServeHTTP(errRec, errReq)
	r.Equal(http.StatusInternalServerError, errRec.Code)
	r.Empty(errRec.Result().Cookies())
	r.Empty(webApp.liveSAMLSessions("greendale"))
}

func TestWrapSignedSAMLResponseStripsStaleAssertionSignatureUnderBothMode(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	state := appState{
		Config: config{IDPBaseURL: "http://idp.test"},
		Users: []user{
			{ID: "troy", GivenName: "Troy", FamilyName: "Barnes", Email: "troy@greendale.edu", Username: "troy", Active: true},
			{ID: "abed", GivenName: "Abed", FamilyName: "Nadir", Email: "abed@greendale.edu", Username: "abed", Active: true},
		},
		Apps: []app{{
			ID:              "greendale",
			Name:            "Greendale",
			Slug:            "greendale",
			Protocol:        "saml",
			SAMLEntityID:    "urn:greendale:sp",
			SAMLACSURL:      "https://sp.greendale.test/acs",
			SAMLSigningMode: "both",
		}},
	}
	r.NoError(saveState(state))
	webApp := newTestIDPApp(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/saml/greendale/sso?user_id=troy&fault_tamper=xsw_response", nil)
	webApp.routes().ServeHTTP(rec, req)
	r.Equal(http.StatusOK, rec.Code)

	encoded := hiddenInputValue(rec.Body.String(), "SAMLResponse")
	r.NotEmpty(encoded)
	rawXML, err := base64.StdEncoding.DecodeString(encoded)
	r.NoError(err)

	doc := etree.NewDocument()
	r.NoError(doc.ReadFromString(string(rawXML)))
	root := doc.Root()
	r.NotNil(root)
	// The forged root response's own direct Assertion child must not carry a
	// stale <ds:Signature> pointing at the original wrapped assertion's ID.
	forgedAssertion := childElementByLocalName(root, "Assertion")
	r.NotNil(forgedAssertion)
	r.Nil(childElementByLocalName(forgedAssertion, "Signature"), "forged assertion must not retain a stale signature")
	r.True(strings.Contains(string(rawXML), "abed@greendale.edu"))
}
