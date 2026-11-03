package web

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// certificateValidity names the validity period of a generated signing
// certificate. The non-standard periods test how a service provider treats
// certificate dates; the signatures stay valid.
type certificateValidity string

const (
	validityStandard     certificateValidity = "standard"
	validityExpired      certificateValidity = "expired"
	validityNotYetValid  certificateValidity = "not_yet_valid"
	validityNoExpiration certificateValidity = "no_expiration"
)

// noWellDefinedExpiration is the notAfter value RFC 5280 section 4.1.2.5
// assigns to a certificate with no well-defined expiration date.
var noWellDefinedExpiration = time.Date(9999, time.December, 31, 23, 59, 59, 0, time.UTC)

// parseCertificateValidity reads a validity name. Empty means standard.
func parseCertificateValidity(raw string) (certificateValidity, error) {
	validity := certificateValidity(strings.TrimSpace(raw))
	switch validity {
	case "":
		return validityStandard, nil
	case validityStandard, validityExpired, validityNotYetValid, validityNoExpiration:
		return validity, nil
	default:
		return "", fmt.Errorf("certificate validity %q is not standard, expired, not_yet_valid, or no_expiration", raw)
	}
}

// period returns the certificate's notBefore and notAfter relative to now.
// A not-yet-valid certificate starts a year out so it stays invalid for a
// whole test session.
func (v certificateValidity) period(now time.Time) (time.Time, time.Time) {
	switch v {
	case validityExpired:
		return now.AddDate(-1, 0, 0), now.AddDate(0, 0, -1)
	case validityNotYetValid:
		return now.AddDate(1, 0, 0), now.AddDate(11, 0, 0)
	case validityNoExpiration:
		return now.Add(-time.Hour), noWellDefinedExpiration
	default:
		return now.Add(-time.Hour), now.AddDate(10, 0, 0)
	}
}

func selfSignedCert(key *rsa.PrivateKey) ([]byte, error) {
	return selfSignedCertWithValidity(key, validityStandard, time.Now())
}

func selfSignedCertWithValidity(key *rsa.PrivateKey, validity certificateValidity, now time.Time) ([]byte, error) {
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, err
	}
	notBefore, notAfter := validity.period(now)
	tmpl := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: "scimtest local signing"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	return x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
}

func loadOrCreateSigningMaterial() (*rsa.PrivateKey, []byte, error) {
	state, err := loadState()
	if err != nil {
		return nil, nil, err
	}
	if strings.TrimSpace(state.Config.SigningPrivateKeyPEM) != "" && strings.TrimSpace(state.Config.SigningCertificatePEM) != "" {
		key, err := parseRSAPrivateKeyPEM(state.Config.SigningPrivateKeyPEM)
		if err != nil {
			return nil, nil, fmt.Errorf("parse saved signing key: %w", err)
		}
		certDER, err := parseCertificatePEM(state.Config.SigningCertificatePEM)
		if err != nil {
			return nil, nil, fmt.Errorf("parse saved signing certificate: %w", err)
		}
		return key, certDER, nil
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("generate signing key: %w", err)
	}
	certDER, err := selfSignedCert(key)
	if err != nil {
		return nil, nil, fmt.Errorf("generate signing certificate: %w", err)
	}
	state.Config.SigningPrivateKeyPEM = privateKeyPEM(key)
	state.Config.SigningCertificatePEM = certificatePEM(certDER)
	if err := saveGlobalConfig(state.Config); err != nil {
		return nil, nil, err
	}
	return key, certDER, nil
}

func privateKeyPEM(key *rsa.PrivateKey) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
}

func certificatePEM(certDER []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
}

func parseRSAPrivateKeyPEM(value string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(value))
	if block == nil {
		return nil, fmt.Errorf("missing PEM block")
	}
	if block.Type == "RSA PRIVATE KEY" {
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is %T, not RSA", key)
	}
	return rsaKey, nil
}

func parseCertificatePEM(value string) ([]byte, error) {
	block, _ := pem.Decode([]byte(value))
	if block == nil {
		return nil, fmt.Errorf("missing PEM block")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("PEM block is %q, not CERTIFICATE", block.Type)
	}
	return block.Bytes, nil
}
