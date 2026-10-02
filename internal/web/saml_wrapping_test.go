package web

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"testing"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/require"
)

// twoUserGreendaleSAMLState adds Abed to the Greendale directory so a forgery
// fault has another user to impersonate. Troy is the user who signs in.
func twoUserGreendaleSAMLState() (appState, user, user) {
	state, troy := troyGreendaleSAMLState("")
	abed := user{
		ID: "usr-abed", GivenName: "Abed", FamilyName: "Nadir",
		Email: "abed@greendale.edu", Username: "anadir", Active: true,
	}
	state.Users = append(state.Users, abed)
	return state, troy, abed
}

func buildWrappingResponse(t *testing.T, svc *webApp, mode string, faults faultOptions) *etree.Document {
	t.Helper()
	state, troy, _ := twoUserGreendaleSAMLState()
	state.Apps[0].SAMLSigningMode = mode
	posted, err := svc.buildSignedSAMLResponse(state, state.Config.IDPBaseURL, state.Apps[0], troy, samlResponseContext{ACSURL: state.Apps[0].SAMLACSURL}, nil, faults)
	require.NoError(t, err)
	return mustParseXML(t, posted.XML)
}

// directChildAssertions returns el's immediate Assertion children.
func directChildAssertions(el *etree.Element) []*etree.Element {
	var out []*etree.Element
	for _, child := range el.ChildElements() {
		if elementLocalName(child) == "Assertion" {
			out = append(out, child)
		}
	}
	return out
}

// nameIDFullText concatenates every text node of the first NameID, the value a
// strict SP reading the whole node sees.
func nameIDFullText(el *etree.Element) string {
	nameID := findElementByLocalName(el, "NameID")
	if nameID == nil {
		return ""
	}
	var text string
	for _, child := range nameID.Child {
		if data, ok := child.(*etree.CharData); ok {
			text += data.Data
		}
	}
	return text
}

// nameIDFirstTextNode returns only the first text node of the first NameID, the
// value a naive SP reading firstChild.nodeValue sees.
func nameIDFirstTextNode(el *etree.Element) string {
	nameID := findElementByLocalName(el, "NameID")
	if nameID == nil {
		return ""
	}
	for _, child := range nameID.Child {
		if data, ok := child.(*etree.CharData); ok {
			return data.Data
		}
	}
	return ""
}

func TestNameIDCommentInjection(t *testing.T) {
	tests := map[string]struct {
		mode          string
		validateRoot  bool
		validateAssrt bool
	}{
		"assertion": {mode: samlSigningModeAssertion, validateAssrt: true},
		"response":  {mode: samlSigningModeResponse, validateRoot: true},
		"both":      {mode: samlSigningModeBoth, validateRoot: true, validateAssrt: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			svc := newTestIDPApp(t)
			cert := activeSAMLSigningCertificate(t, svc)
			doc := buildWrappingResponse(t, svc, tc.mode, faultOptions{Tamper: []tamperFault{tamperNameIDComment}})
			root := doc.Root()
			assertion := findElementByLocalName(root, "Assertion")

			// the genuine signature still verifies with the comment present
			if tc.validateRoot {
				_, err := samlSignatureValidator(cert).Validate(root)
				r.NoError(err)
			}
			if tc.validateAssrt {
				_, err := samlSignatureValidator(cert).Validate(assertion)
				r.NoError(err)
			}

			// a naive SP reads only the first text node: the forged victim
			r.Equal("abed@greendale.edu", nameIDFirstTextNode(assertion))
			// a strict SP reads the whole node: an identifier scimtest never issues
			r.Equal("abed@greendale.edu"+samlForgedNameIDSuffix, nameIDFullText(assertion))
		})
	}
}

func TestSignatureWrappingAssertion(t *testing.T) {
	tests := map[string]string{
		"default":   "",
		"assertion": samlSigningModeAssertion,
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			svc := newTestIDPApp(t)
			cert := activeSAMLSigningCertificate(t, svc)
			doc := buildWrappingResponse(t, svc, tc, faultOptions{Tamper: []tamperFault{tamperSignatureWrappingAssertion}})
			root := doc.Root()

			assertions := directChildAssertions(root)
			r.Len(assertions, 2)
			forged, signed := assertions[0], assertions[1]

			// a naive SP reads the first assertion: the forged victim
			r.Equal("abed@greendale.edu", firstElementTextByLocalName(forged, "NameID"))
			r.Nil(childElementByLocalName(forged, "Signature"))

			// the genuine signed assertion still verifies and names the real user
			_, err := samlSignatureValidator(cert).Validate(signed)
			r.NoError(err)
			r.Equal("troy@greendale.edu", firstElementTextByLocalName(signed, "NameID"))
		})
	}
}

func TestSignatureWrappingResponse(t *testing.T) {
	for _, mode := range []string{samlSigningModeResponse, samlSigningModeBoth} {
		t.Run(mode, func(t *testing.T) {
			r := require.New(t)
			svc := newTestIDPApp(t)
			cert := activeSAMLSigningCertificate(t, svc)
			doc := buildWrappingResponse(t, svc, mode, faultOptions{Tamper: []tamperFault{tamperSignatureWrappingResponse}})
			root := doc.Root()

			// the root response is forged and unsigned; a naive SP reading the
			// first assertion in document order sees the victim
			r.Nil(childElementByLocalName(root, "Signature"))
			r.Equal("abed@greendale.edu", firstElementTextByLocalName(root, "NameID"))

			// the genuine signed response is wrapped inside and still verifies
			var signedResponse *etree.Element
			for _, child := range root.ChildElements() {
				if elementLocalName(child) == "Response" {
					signedResponse = child
				}
			}
			r.NotNil(signedResponse)
			_, err := samlSignatureValidator(cert).Validate(signedResponse)
			r.NoError(err)
			r.Equal("troy@greendale.edu", firstElementTextByLocalName(signedResponse, "NameID"))
		})
	}
}

func TestForgeryFaultsNeedAnotherUser(t *testing.T) {
	tests := map[string]tamperFault{
		"nameid_comment": tamperNameIDComment,
		"xsw_assertion":  tamperSignatureWrappingAssertion,
		"xsw_response":   tamperSignatureWrappingResponse,
	}
	for name, fault := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			svc := newTestIDPApp(t)
			state, troy := troyGreendaleSAMLState("") // Troy only
			state.Apps[0].SAMLSigningMode = samlSigningModeBoth

			posted, err := svc.buildSignedSAMLResponse(state, state.Config.IDPBaseURL, state.Apps[0], troy, samlResponseContext{ACSURL: state.Apps[0].SAMLACSURL}, nil, faultOptions{Tamper: []tamperFault{fault}})
			r.ErrorIs(err, errSAMLForgeryNoUser)
			r.Empty(posted.XML)
		})
	}
}

func TestSignatureWrappingNeedsMatchingSignature(t *testing.T) {
	tests := map[string]struct {
		mode    string
		fault   tamperFault
		wantErr string
	}{
		"assertion wrap without signed assertion": {mode: samlSigningModeResponse, fault: tamperSignatureWrappingAssertion, wantErr: "needs a signed assertion"},
		"assertion wrap with signed response":     {mode: samlSigningModeBoth, fault: tamperSignatureWrappingAssertion, wantErr: "cannot wrap a signed response"},
		"response wrap without signed response":   {mode: samlSigningModeAssertion, fault: tamperSignatureWrappingResponse, wantErr: "needs a signed response"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			svc := newTestIDPApp(t)
			state, troy, _ := twoUserGreendaleSAMLState()
			state.Apps[0].SAMLSigningMode = tc.mode

			posted, err := svc.buildSignedSAMLResponse(state, state.Config.IDPBaseURL, state.Apps[0], troy, samlResponseContext{ACSURL: state.Apps[0].SAMLACSURL}, nil, faultOptions{Tamper: []tamperFault{tc.fault}})
			r.ErrorContains(err, tc.wantErr)
			r.Empty(posted.XML)
		})
	}
}

func TestSignatureWrappingWithNameIDComment(t *testing.T) {
	tests := map[string]struct {
		mode  string
		fault tamperFault
	}{
		"assertion": {mode: samlSigningModeAssertion, fault: tamperSignatureWrappingAssertion},
		"response":  {mode: samlSigningModeResponse, fault: tamperSignatureWrappingResponse},
		"both":      {mode: samlSigningModeBoth, fault: tamperSignatureWrappingResponse},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			setTestStateFile(t)
			svc := newTestIDPApp(t)
			state, troy, abed := twoUserGreendaleSAMLState()
			state.Apps[0].SAMLSigningMode = tc.mode
			r.NoError(saveState(state))

			rec := postSAMLSSO(t, svc, url.Values{
				"user_id":      {troy.ID},
				"fault_tamper": {string(tc.fault) + ",nameid_comment"},
			})
			r.Equal(http.StatusOK, rec.Code, rec.Body.String())
			responseXML, err := base64.StdEncoding.DecodeString(hiddenInputValue(rec.Body.String(), "SAMLResponse"))
			r.NoError(err)
			root := mustParseXML(t, string(responseXML)).Root()
			r.Equal(abed.Email, nameIDFullText(root))

			var signedAssertion *etree.Element
			cert := activeSAMLSigningCertificate(t, svc)
			switch tc.fault {
			case tamperSignatureWrappingAssertion:
				assertions := directChildAssertions(root)
				r.Len(assertions, 2)
				signedAssertion = assertions[1]
			case tamperSignatureWrappingResponse:
				signedResponse := childElementByLocalName(root, "Response")
				r.NotNil(signedResponse)
				_, err := samlSignatureValidator(cert).Validate(signedResponse)
				r.NoError(err)
				signedAssertion = findElementByLocalName(signedResponse, "Assertion")
			}
			r.NotNil(signedAssertion)
			if tc.mode != samlSigningModeResponse {
				_, err := samlSignatureValidator(cert).Validate(signedAssertion)
				r.NoError(err)
			}
			r.Equal(abed.Email, nameIDFirstTextNode(signedAssertion))
			r.Equal(abed.Email+samlForgedNameIDSuffix, nameIDFullText(signedAssertion))
		})
	}
}

func TestForgeryFaultsNeedDistinctNameID(t *testing.T) {
	faults := map[string]tamperFault{
		"nameid_comment": tamperNameIDComment,
		"xsw_assertion":  tamperSignatureWrappingAssertion,
		"xsw_response":   tamperSignatureWrappingResponse,
	}
	for name, fault := range faults {
		t.Run(name, func(t *testing.T) {
			tests := map[string]struct {
				familyName string
				addAnnie   bool
				wantNameID string
			}{
				"same NameID only":   {familyName: "Barnes"},
				"empty NameID only":  {},
				"blank NameID only":  {familyName: " \t"},
				"skip same NameID":   {familyName: "Barnes", addAnnie: true, wantNameID: "Edison"},
				"skip empty NameID":  {addAnnie: true, wantNameID: "Edison"},
				"lowest distinct ID": {familyName: "Nadir", addAnnie: true, wantNameID: "Nadir"},
			}
			for name, tc := range tests {
				t.Run(name, func(t *testing.T) {
					r := require.New(t)
					svc := newTestIDPApp(t)
					state, troy, _ := twoUserGreendaleSAMLState()
					state.Apps[0].SAMLNameIDField = "lastName"
					state.Apps[0].SAMLNameIDFormat = samlNameIDFormatForField("lastName")
					state.Users[1].FamilyName = tc.familyName
					if fault == tamperSignatureWrappingResponse {
						state.Apps[0].SAMLSigningMode = samlSigningModeResponse
					}
					if tc.addAnnie {
						state.Users = append(state.Users, user{
							ID: "usr-annie", GivenName: "Annie", FamilyName: "Edison",
							Email: "annie@greendale.edu", Username: "aedison", Active: true,
						})
					}

					posted, err := svc.buildSignedSAMLResponse(state, state.Config.IDPBaseURL, state.Apps[0], troy, samlResponseContext{ACSURL: state.Apps[0].SAMLACSURL}, nil, faultOptions{Tamper: []tamperFault{fault}})
					if tc.wantNameID == "" {
						r.ErrorIs(err, errSAMLForgeryNoUser)
						r.Empty(posted.XML)
						return
					}
					r.NoError(err)
					root := mustParseXML(t, posted.XML).Root()
					r.Equal(tc.wantNameID, nameIDFirstTextNode(root))
				})
			}
		})
	}
}

func TestForgeryFaultsRejectEncryption(t *testing.T) {
	_, dest, pem := newSPEncryptionMaterial(t)
	tests := map[string]tamperFault{
		"nameid_comment": tamperNameIDComment,
		"xsw_assertion":  tamperSignatureWrappingAssertion,
		"xsw_response":   tamperSignatureWrappingResponse,
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			svc := newTestIDPApp(t)
			state, troy, _ := twoUserGreendaleSAMLState()
			state.Apps[0].SAMLSigningMode = samlSigningModeAssertion
			state.Apps[0].SAMLEncryptionCertPEM = pem

			posted, err := svc.buildSignedSAMLResponse(state, state.Config.IDPBaseURL, state.Apps[0], troy, samlResponseContext{ACSURL: state.Apps[0].SAMLACSURL}, samlTestEncryption(t, dest, defaultSAMLEncryptionAlgorithm), faultOptions{Tamper: []tamperFault{tc}})
			r.ErrorContains(err, "cannot combine with assertion encryption")
			r.Empty(posted.XML)
		})
	}
}
