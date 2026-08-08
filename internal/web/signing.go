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

func selfSignedCert(key *rsa.PrivateKey) ([]byte, error) {
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: "scimtest local signing"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(10, 0, 0),
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
