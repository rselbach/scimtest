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

	algRSAOAEP        = xmlencNS + "rsa-oaep-mgf1p"
	xmlencElementType = xmlencNS + "Element"
	samlAssertionNS   = "urn:oasis:names:tc:SAML:2.0:assertion"
)

type samlAssertionEncryption struct {
	destination *x509.Certificate
	algorithm   samlEncryptionAlgorithmSpec
}

type samlEncryptionAlgorithmSpec struct {
	label    string
	xmlURI   string
	keyBytes int
}

var samlEncryptionAlgorithmSpecs = map[string]samlEncryptionAlgorithmSpec{
	samlEncryptionAlgorithmAES128GCM: {
		label:    "AES-128-GCM",
		xmlURI:   xmlenc11NS + "aes128-gcm",
		keyBytes: 16,
	},
	samlEncryptionAlgorithmAES192GCM: {
		label:    "AES-192-GCM",
		xmlURI:   xmlenc11NS + "aes192-gcm",
		keyBytes: 24,
	},
	samlEncryptionAlgorithmAES256GCM: {
		label:    "AES-256-GCM",
		xmlURI:   xmlenc11NS + "aes256-gcm",
		keyBytes: 32,
	},
}

var samlEncryptionAlgorithmOrder = []string{
	samlEncryptionAlgorithmAES128GCM,
	samlEncryptionAlgorithmAES192GCM,
	samlEncryptionAlgorithmAES256GCM,
}

func samlEncryptionAlgorithmSpecFor(value string) (samlEncryptionAlgorithmSpec, error) {
	value = normalizeSAMLEncryptionAlgorithm(value)
	spec, ok := samlEncryptionAlgorithmSpecs[value]
	if !ok {
		return samlEncryptionAlgorithmSpec{}, fmt.Errorf("SAML encryption algorithm must be AES-128-GCM, AES-192-GCM, or AES-256-GCM")
	}
	return spec, nil
}

func samlAssertionEncryptionForApp(app app) (*samlAssertionEncryption, error) {
	dest, err := parseSAMLEncryptionCertificate(app.SAMLEncryptionCertPEM)
	if err != nil {
		return nil, err
	}
	if dest == nil {
		return nil, nil
	}
	algorithm, err := samlEncryptionAlgorithmSpecFor(app.SAMLEncryptionAlgorithm)
	if err != nil {
		return nil, err
	}
	return &samlAssertionEncryption{destination: dest, algorithm: algorithm}, nil
}

// The data CipherValue is base64(iv || ciphertext || tag), 12-byte IV,
// 16-byte tag.
func encryptSAMLAssertion(signedAssertion *etree.Element, encryption samlAssertionEncryption) (*etree.Element, error) {
	if signedAssertion == nil || encryption.destination == nil {
		return nil, fmt.Errorf("signed assertion and encryption certificate are required")
	}
	pub, ok := encryption.destination.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("certificate public key must be RSA")
	}
	encryptedData, err := encryptElement(signedAssertion, pub, encryption.algorithm)
	if err != nil {
		return nil, err
	}
	if err := attachRecipientCertificate(encryptedData, encryption.destination); err != nil {
		return nil, err
	}
	wrapper := etree.NewElement("saml:EncryptedAssertion")
	wrapper.CreateAttr("xmlns:saml", samlAssertionNS)
	wrapper.AddChild(encryptedData)
	return wrapper, nil
}

func encryptElement(el *etree.Element, pub *rsa.PublicKey, algorithm samlEncryptionAlgorithmSpec) (*etree.Element, error) {
	if el == nil || pub == nil {
		return nil, fmt.Errorf("element and RSA public key are required")
	}
	plaintext, err := exclusiveC14N(el)
	if err != nil {
		return nil, err
	}
	aesKey := make([]byte, algorithm.keyBytes)
	if _, err := rand.Read(aesKey); err != nil {
		return nil, fmt.Errorf("generate AES key: %w", err)
	}
	dataCipher, err := encryptAESGCM(aesKey, plaintext)
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
	dataMethod.CreateAttr("Algorithm", algorithm.xmlURI)

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

func encryptAESGCM(key, plaintext []byte) ([]byte, error) {
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
