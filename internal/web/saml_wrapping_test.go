package web

import (
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
	for _, mode := range []string{samlSigningModeAssertion, samlSigningModeBoth} {
		t.Run(mode, func(t *testing.T) {
			r := require.New(t)
			svc := newTestIDPApp(t)
			cert := activeSAMLSigningCertificate(t, svc)
			doc := buildWrappingResponse(t, svc, mode, faultOptions{Tamper: []tamperFault{tamperSignatureWrappingAssertion}})
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

func TestSignatureWrappingRejectsEncryption(t *testing.T) {
	r := require.New(t)
	svc := newTestIDPApp(t)
	spKey, dest, pem := newSPEncryptionMaterial(t)
	_ = spKey
	state, troy, _ := twoUserGreendaleSAMLState()
	state.Apps[0].SAMLSigningMode = samlSigningModeAssertion
	state.Apps[0].SAMLEncryptionCertPEM = pem

	posted, err := svc.buildSignedSAMLResponse(state, state.Config.IDPBaseURL, state.Apps[0], troy, samlResponseContext{ACSURL: state.Apps[0].SAMLACSURL}, samlTestEncryption(t, dest, defaultSAMLEncryptionAlgorithm), faultOptions{Tamper: []tamperFault{tamperSignatureWrappingAssertion}})
	r.ErrorContains(err, "cannot combine with assertion encryption")
	r.Empty(posted.XML)
}
