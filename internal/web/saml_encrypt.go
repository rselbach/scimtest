package web

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

const (
	xmlencNS   = "http://www.w3.org/2001/04/xmlenc#"
	xmlenc11NS = "http://www.w3.org/2009/xmlenc11#"
	dsigNS     = "http://www.w3.org/2000/09/xmldsig#"

	algAES256GCM      = xmlenc11NS + "aes256-gcm"
	algRSAOAEP        = xmlencNS + "rsa-oaep-mgf1p"
	xmlencElementType = xmlencNS + "Element"
	samlAssertionNS   = "urn:oasis:names:tc:SAML:2.0:assertion"
)

// encryptSAMLAssertion returns a saml:EncryptedAssertion that wraps
// signedAssertion. dest must be a parsed RSA certificate. The function
// does not mutate signedAssertion or its parent.
//
// Algorithms are fixed. AES-256-GCM over exclusive C14N 1.0 octets of the
// Assertion, RSA-OAEP with SHA-1 MGF1 wrapping a 32-byte document key.
// Data CipherValue is base64(iv || ciphertext || tag), 12-byte IV, 16-byte tag.
func encryptSAMLAssertion(signedAssertion *etree.Element, dest *x509.Certificate) (*etree.Element, error) {
	if signedAssertion == nil || dest == nil {
		return nil, fmt.Errorf("signed assertion and encryption certificate are required")
	}
	pub, ok := dest.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("certificate public key must be RSA")
	}
	encryptedData, err := encryptElement(signedAssertion, pub)
	if err != nil {
		return nil, err
	}
	if err := attachRecipientCertificate(encryptedData, dest); err != nil {
		return nil, err
	}
	wrapper := etree.NewElement("saml:EncryptedAssertion")
	wrapper.CreateAttr("xmlns:saml", samlAssertionNS)
	wrapper.AddChild(encryptedData)
	return wrapper, nil
}

func encryptElement(el *etree.Element, pub *rsa.PublicKey) (*etree.Element, error) {
	if el == nil || pub == nil {
		return nil, fmt.Errorf("element and RSA public key are required")
	}
	plaintext, err := exclusiveC14N(el)
	if err != nil {
		return nil, err
	}
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		return nil, fmt.Errorf("generate AES key: %w", err)
	}
	dataCipher, err := encryptAES256GCM(aesKey, plaintext)
	if err != nil {
		return nil, err
	}
	wrappedKey, err := wrapKeyRSAOAEP(pub, aesKey)
	if err != nil {
		return nil, err
	}

	encryptedData := etree.NewElement("xenc:EncryptedData")
	encryptedData.CreateAttr("xmlns:xenc", xmlencNS)
	encryptedData.CreateAttr("xmlns:ds", dsigNS)
	encryptedData.CreateAttr("Type", xmlencElementType)

	dataMethod := encryptedData.CreateElement("xenc:EncryptionMethod")
	dataMethod.CreateAttr("Algorithm", algAES256GCM)

	keyInfo := encryptedData.CreateElement("ds:KeyInfo")
	encryptedKey := keyInfo.CreateElement("xenc:EncryptedKey")
	keyMethod := encryptedKey.CreateElement("xenc:EncryptionMethod")
	keyMethod.CreateAttr("Algorithm", algRSAOAEP)
	keyCipherData := encryptedKey.CreateElement("xenc:CipherData")
	keyCipherValue := keyCipherData.CreateElement("xenc:CipherValue")
	keyCipherValue.SetText(base64.StdEncoding.EncodeToString(wrappedKey))

	dataCipherData := encryptedData.CreateElement("xenc:CipherData")
	dataCipherValue := dataCipherData.CreateElement("xenc:CipherValue")
	dataCipherValue.SetText(base64.StdEncoding.EncodeToString(dataCipher))
	return encryptedData, nil
}

func attachRecipientCertificate(encryptedData *etree.Element, dest *x509.Certificate) error {
	keyInfo := childElementByLocalName(encryptedData, "KeyInfo")
	encryptedKey := childElementByLocalName(keyInfo, "EncryptedKey")
	if encryptedKey == nil {
		return fmt.Errorf("encrypted data is missing EncryptedKey")
	}
	recipientInfo := etree.NewElement("ds:KeyInfo")
	x509Data := recipientInfo.CreateElement("ds:X509Data")
	certEl := x509Data.CreateElement("ds:X509Certificate")
	certEl.SetText(base64.StdEncoding.EncodeToString(dest.Raw))
	insertBeforeLocalName(encryptedKey, recipientInfo, "CipherData")
	return nil
}

func exclusiveC14N(el *etree.Element) ([]byte, error) {
	// goxmldsig exclusive C14N rewrites namespace declarations on the element.
	canonicalizer := dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	octets, err := canonicalizer.Canonicalize(el.Copy())
	if err != nil {
		return nil, fmt.Errorf("canonicalize assertion for encryption: %w", err)
	}
	return octets, nil
}

func encryptAES256GCM(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create AES-GCM: %w", err)
	}
	iv := make([]byte, aead.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("generate AES-GCM IV: %w", err)
	}
	out := make([]byte, len(iv), len(iv)+len(plaintext)+aead.Overhead())
	copy(out, iv)
	return aead.Seal(out, iv, plaintext, nil), nil
}

func wrapKeyRSAOAEP(pub *rsa.PublicKey, key []byte) ([]byte, error) {
	// rsa-oaep-mgf1p is SHA-1 MGF1; XML Encryption 1.0 names that pairing.
	wrapped, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, key, nil)
	if err != nil {
		return nil, fmt.Errorf("wrap document key: %w", err)
	}
	return wrapped, nil
}

func serializeElement(el *etree.Element) (string, error) {
	if el == nil {
		return "", fmt.Errorf("element is required")
	}
	doc := etree.NewDocument()
	doc.SetRoot(el.Copy())
	xml, err := doc.WriteToString()
	if err != nil {
		return "", fmt.Errorf("serialize element: %w", err)
	}
	return xml, nil
}

func insertBeforeLocalName(parent *etree.Element, child *etree.Element, localName string) {
	for index, token := range parent.Child {
		element, ok := token.(*etree.Element)
		if ok && elementLocalName(element) == localName {
			parent.InsertChildAt(index, child)
			return
		}
	}
	parent.AddChild(child)
}
