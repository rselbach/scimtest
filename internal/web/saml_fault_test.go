package web

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/require"
)

func TestSAMLTamperFaultsBreakOneRule(t *testing.T) {
	tests := map[string]struct {
		tamper     tamperFault
		wantFields []string
	}{
		"wrong issuer":           {tamper: tamperWrongIssuer, wantFields: []string{"issuer", "assertion_issuer"}},
		"wrong audience":         {tamper: tamperWrongAudience, wantFields: []string{"audience"}},
		"wrong destination":      {tamper: tamperWrongDestination, wantFields: []string{"destination"}},
		"wrong recipient":        {tamper: tamperWrongRecipient, wantFields: []string{"recipient"}},
		"InResponseTo mismatch":  {tamper: tamperInResponseToMismatch, wantFields: []string{"in_response_to", "subject_in_response_to"}},
		"OIDC-only tamper fault": {tamper: tamperAlgNone},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			svc := newTestIDPApp(t)
			state, troy := troyGreendaleSAMLState("")
			context := samlResponseContext{ACSURL: state.Apps[0].SAMLACSURL, InResponseTo: "request-1"}

			clean, err := svc.buildSignedSAMLResponse(state, state.Config.IDPBaseURL, state.Apps[0], troy, context, nil, faultOptions{})
			r.NoError(err)
			tampered, err := svc.buildSignedSAMLResponse(state, state.Config.IDPBaseURL, state.Apps[0], troy, context, nil, faultOptions{Tamper: []tamperFault{tc.tamper}})
			r.NoError(err)

			want := samlValidationFields(t, clean.XML)
			for _, field := range tc.wantFields {
				want[field] += "-wrong"
			}
			r.Equal(want, samlValidationFields(t, tampered.XML))
			assertion := findElementByLocalName(mustParseXML(t, tampered.XML).Root(), "Assertion")
			validateSAMLAssertionSignature(t, svc.certDER, assertion)
		})
	}
}

func TestSAMLAssertionTTLFault(t *testing.T) {
	r := require.New(t)
	svc := newTestIDPApp(t)
	state, troy := troyGreendaleSAMLState("")

	posted, err := svc.buildSignedSAMLResponse(state, state.Config.IDPBaseURL, state.Apps[0], troy, samlResponseContext{ACSURL: state.Apps[0].SAMLACSURL}, nil, faultOptions{AssertionTTL: -10 * time.Minute, AssertionTTLSet: true})
	r.NoError(err)

	root := mustParseXML(t, posted.XML).Root()
	assertion := findElementByLocalName(root, "Assertion")
	issued := parseSAMLInstant(t, assertion.SelectAttrValue("IssueInstant", ""))
	conditions := findElementByLocalName(assertion, "Conditions")
	notBefore := parseSAMLInstant(t, conditions.SelectAttrValue("NotBefore", ""))
	notOnOrAfter := parseSAMLInstant(t, conditions.SelectAttrValue("NotOnOrAfter", ""))
	subjectExpiry := parseSAMLInstant(t, findElementByLocalName(assertion, "SubjectConfirmationData").SelectAttrValue("NotOnOrAfter", ""))
	r.Equal(issued.Add(-10*time.Minute), notOnOrAfter)
	r.Equal(notOnOrAfter, subjectExpiry)
	r.True(notBefore.Before(notOnOrAfter), "the validity window must stay ordered")
	validateSAMLAssertionSignature(t, svc.certDER, assertion)
}

func TestSAMLReplayedAssertionReusesPreviousID(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	svc := newTestIDPApp(t)
	state, troy := troyGreendaleSAMLState("")
	r.NoError(saveState(state))

	early := postSAMLSSO(t, svc, url.Values{"user_id": {troy.ID}, "fault_tamper": {"replayed_assertion"}})
	r.Equal(http.StatusBadRequest, early.Code)
	r.Contains(early.Body.String(), "no earlier SAML assertion to replay")

	first := postedSAMLAssertion(t, postSAMLSSO(t, svc, url.Values{"user_id": {troy.ID}}))
	fresh := postedSAMLAssertion(t, postSAMLSSO(t, svc, url.Values{"user_id": {troy.ID}}))
	r.NotEqual(first.SelectAttrValue("ID", ""), fresh.SelectAttrValue("ID", ""))

	replayed := postedSAMLAssertion(t, postSAMLSSO(t, svc, url.Values{"user_id": {troy.ID}, "fault_tamper": {"replayed_assertion"}}))
	r.Equal(fresh.SelectAttrValue("ID", ""), replayed.SelectAttrValue("ID", ""))
	validateSAMLAssertionSignature(t, svc.certDER, replayed)
}

func TestSAMLInspectorOffersSAMLTamperFaults(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	svc := newTestIDPApp(t)
	state, _ := troyGreendaleSAMLState("")
	r.NoError(saveState(state))

	rec := httptest.NewRecorder()
	svc.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/inspect/saml/greendale", nil))
	r.Equal(http.StatusOK, rec.Code)
	body := rec.Body.String()
	r.Contains(body, `name="fault_tamper" value="wrong_audience"`)
	r.Contains(body, `name="fault_tamper" value="replayed_assertion"`)
	r.Contains(body, `name="fault_assertion_ttl"`)
	r.NotContains(body, `name="fault_tamper" value="alg_none"`)
}

// samlValidationFields collects the response values an SP must check, keyed
// by a short name, so tests can compare a tampered response field by field.
func samlValidationFields(t *testing.T, responseXML string) map[string]string {
	t.Helper()
	root := mustParseXML(t, responseXML).Root()
	assertion := findElementByLocalName(root, "Assertion")
	subject := findElementByLocalName(assertion, "SubjectConfirmationData")
	return map[string]string{
		"destination":            root.SelectAttrValue("Destination", ""),
		"in_response_to":         root.SelectAttrValue("InResponseTo", ""),
		"issuer":                 childElementTextByLocalName(root, "Issuer"),
		"assertion_issuer":       childElementTextByLocalName(assertion, "Issuer"),
		"audience":               firstElementTextByLocalName(assertion, "Audience"),
		"recipient":              subject.SelectAttrValue("Recipient", ""),
		"subject_in_response_to": subject.SelectAttrValue("InResponseTo", ""),
	}
}

func parseSAMLInstant(t *testing.T, value string) time.Time {
	t.Helper()
	instant, err := time.Parse(time.RFC3339, value)
	require.NoError(t, err)
	return instant
}

func postSAMLSSO(t *testing.T, svc *webApp, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/saml/greendale/sso", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	svc.routes().ServeHTTP(rec, req)
	return rec
}

func postedSAMLAssertion(t *testing.T, rec *httptest.ResponseRecorder) *etree.Element {
	t.Helper()
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	responseXML, err := base64.StdEncoding.DecodeString(hiddenInputValue(rec.Body.String(), "SAMLResponse"))
	require.NoError(t, err)
	assertion := findElementByLocalName(mustParseXML(t, string(responseXML)).Root(), "Assertion")
	require.NotNil(t, assertion)
	return assertion
}
