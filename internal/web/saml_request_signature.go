package web

import (
	"crypto"
	"crypto/rsa"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

const (
	rsaSHA256SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	rsaSHA384SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
	rsaSHA512SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
	xmlDSIGNamespace         = "http://www.w3.org/2000/09/xmldsig#"
)

func validateSAMLAuthnRequestSignature(r *http.Request, encodedRequest string, cert *x509.Certificate) error {
	if r.URL.Query().Get("SAMLRequest") != "" {
		return validateRedirectSAMLSignature(r.URL.RawQuery, "SAMLRequest", "AuthnRequest", cert)
	}
	return validatePOSTSAMLSignature(encodedRequest, "AuthnRequest", cert)
}

// validateRedirectSAMLSignature checks the HTTP-Redirect binding signature
// over the message in param (SAMLRequest or SAMLResponse), RelayState, and
// SigAlg. kind names the message type in errors.
func validateRedirectSAMLSignature(rawQuery, param, kind string, cert *x509.Certificate) error {
	message, _, err := uniqueRawQueryValue(rawQuery, param, true)
	if err != nil {
		return err
	}
	relayState, relayStatePresent, err := uniqueRawQueryValue(rawQuery, "RelayState", false)
	if err != nil {
		return err
	}
	sigAlgRaw, _, err := uniqueRawQueryValue(rawQuery, "SigAlg", true)
	if err != nil {
		return err
	}
	signatureRaw, _, err := uniqueRawQueryValue(rawQuery, "Signature", true)
	if err != nil {
		return err
	}

	signed := param + "=" + message
	if relayStatePresent {
		signed += "&RelayState=" + relayState
	}
	signed += "&SigAlg=" + sigAlgRaw

	sigAlg, err := url.QueryUnescape(sigAlgRaw)
	if err != nil {
		return fmt.Errorf("decode SAML Redirect SigAlg: %w", err)
	}
	signatureValue, err := url.QueryUnescape(signatureRaw)
	if err != nil {
		return fmt.Errorf("decode SAML Redirect Signature: %w", err)
	}
	signature, err := base64.StdEncoding.DecodeString(signatureValue)
	if err != nil {
		return fmt.Errorf("decode SAML Redirect Signature: %w", err)
	}

	hash, err := redirectSignatureHash(sigAlg)
	if err != nil {
		return err
	}
	digest := hash.New()
	if _, err := digest.Write([]byte(signed)); err != nil {
		return fmt.Errorf("hash SAML Redirect signature input: %w", err)
	}
	digestValue := digest.Sum(nil)

	key, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("pinned SAML request certificate must use RSA")
	}
	if err := rsa.VerifyPKCS1v15(key, hash, digestValue, signature); err != nil {
		return fmt.Errorf("invalid SAML %s signature", kind)
	}
	return nil
}

func uniqueRawQueryValue(rawQuery string, name string, required bool) (string, bool, error) {
	var value string
	found := false
	for _, part := range strings.Split(rawQuery, "&") {
		rawKey, candidate, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		key, err := url.QueryUnescape(rawKey)
		if err != nil {
			return "", false, fmt.Errorf("decode SAML Redirect parameter name: %w", err)
		}
		if key != name {
			continue
		}
		if rawKey != name {
			return "", false, fmt.Errorf("SAML Redirect parameter name %s must not be percent-encoded", name)
		}
		if found {
			return "", false, fmt.Errorf("SAML Redirect request contains duplicate %s parameters", name)
		}
		found = true
		value = candidate
	}
	if required && (!found || value == "") {
		return "", false, fmt.Errorf("signed SAML Redirect request requires %s", name)
	}
	return value, found, nil
}

func redirectSignatureHash(algorithm string) (crypto.Hash, error) {
	switch algorithm {
	case rsaSHA256SignatureMethod:
		return crypto.SHA256, nil
	case rsaSHA384SignatureMethod:
		return crypto.SHA384, nil
	case rsaSHA512SignatureMethod:
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("unsupported SAML Redirect signature algorithm %q", algorithm)
	}
}

// validatePOSTSAMLSignature checks the enveloped XML signature of a message
// sent with the HTTP-POST binding. kind names the message type in errors.
func validatePOSTSAMLSignature(encodedMessage, kind string, cert *x509.Certificate) error {
	doc, err := parseSAMLRequestDocument(encodedMessage)
	if err != nil {
		return err
	}
	root := doc.Root()
	id := strings.TrimSpace(root.SelectAttrValue("ID", ""))
	if id == "" {
		return fmt.Errorf("SAML %s ID is required before signature validation", kind)
	}

	signatures := elementsByNameAndNamespace(root, "Signature", xmlDSIGNamespace)
	if len(signatures) == 0 {
		return fmt.Errorf("SAML %s signature is required", kind)
	}
	if len(signatures) != 1 || signatures[0].Parent() != root {
		return fmt.Errorf("SAML %s must contain exactly one direct XMLDSIG signature", kind)
	}
	signature := signatures[0]
	if err := validateXMLSignatureAlgorithms(signature, id, kind); err != nil {
		return err
	}

	validator := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{cert},
	})
	if _, err := validator.Validate(root); err != nil {
		return fmt.Errorf("invalid SAML %s signature: %w", kind, err)
	}
	return nil
}

func validateXMLSignatureAlgorithms(signature *etree.Element, messageID, kind string) error {
	signedInfo := directChildByNameAndNamespace(signature, "SignedInfo", xmlDSIGNamespace)
	if signedInfo == nil {
		return fmt.Errorf("SAML %s signature has no SignedInfo", kind)
	}
	method := directChildByNameAndNamespace(signedInfo, "SignatureMethod", xmlDSIGNamespace)
	if method == nil {
		return fmt.Errorf("SAML %s signature has no SignatureMethod", kind)
	}
	if _, err := redirectSignatureHash(method.SelectAttrValue("Algorithm", "")); err != nil {
		return err
	}
	references := 0
	for _, child := range signedInfo.ChildElements() {
		if elementLocalName(child) != "Reference" || child.NamespaceURI() != xmlDSIGNamespace {
			continue
		}
		references++
		if child.SelectAttrValue("URI", "") != "#"+messageID {
			return fmt.Errorf("SAML %s signature must reference the message ID", kind)
		}
		digestMethod := directChildByNameAndNamespace(child, "DigestMethod", xmlDSIGNamespace)
		if digestMethod == nil || !strongXMLDigestMethod(digestMethod.SelectAttrValue("Algorithm", "")) {
			return fmt.Errorf("SAML %s signature must use SHA-256, SHA-384, or SHA-512", kind)
		}
	}
	if references != 1 {
		return fmt.Errorf("SAML %s signature must contain one reference", kind)
	}
	return nil
}

func directChildByNameAndNamespace(parent *etree.Element, name string, namespace string) *etree.Element {
	for _, child := range parent.ChildElements() {
		if elementLocalName(child) == name && child.NamespaceURI() == namespace {
			return child
		}
	}
	return nil
}

func elementsByNameAndNamespace(root *etree.Element, name string, namespace string) []*etree.Element {
	var found []*etree.Element
	if elementLocalName(root) == name && root.NamespaceURI() == namespace {
		found = append(found, root)
	}
	for _, child := range root.ChildElements() {
		found = append(found, elementsByNameAndNamespace(child, name, namespace)...)
	}
	return found
}

func strongXMLDigestMethod(algorithm string) bool {
	switch algorithm {
	case "http://www.w3.org/2001/04/xmlenc#sha256",
		"http://www.w3.org/2001/04/xmldsig-more#sha384",
		"http://www.w3.org/2001/04/xmlenc#sha512":
		return true
	default:
		return false
	}
}
