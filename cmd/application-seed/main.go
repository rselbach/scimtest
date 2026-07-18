package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/ssh"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		if _, err := fmt.Fprintln(stderr, "usage: application-seed /path/to/openssh-private-key"); err != nil {
			return 1
		}
		return 2
	}

	contents, err := os.ReadFile(args[0])
	if err != nil {
		if _, writeErr := fmt.Fprintf(stderr, "read private key: %v\n", err); writeErr != nil {
			return 1
		}
		return 1
	}
	encoded, err := privateSeedBase64(contents)
	if err != nil {
		if _, writeErr := fmt.Fprintf(stderr, "convert private key: %v\n", err); writeErr != nil {
			return 1
		}
		return 1
	}
	if _, err := fmt.Fprintln(stdout, encoded); err != nil {
		if _, writeErr := fmt.Fprintf(stderr, "write encoded seed: %v\n", err); writeErr != nil {
			return 1
		}
		return 1
	}
	return 0
}

func privateSeedBase64(contents []byte) (string, error) {
	raw, err := ssh.ParseRawPrivateKey(contents)
	if err != nil {
		var passphraseMissing *ssh.PassphraseMissingError
		if errors.As(err, &passphraseMissing) {
			return "", fmt.Errorf("encrypted private keys are not supported")
		}
		return "", fmt.Errorf("invalid OpenSSH private key")
	}

	var key ed25519.PrivateKey
	switch value := raw.(type) {
	case ed25519.PrivateKey:
		key = value
	case *ed25519.PrivateKey:
		if value != nil {
			key = *value
		}
	default:
		return "", fmt.Errorf("private key must be Ed25519")
	}
	if len(key) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("Ed25519 private key must be %d bytes", ed25519.PrivateKeySize)
	}
	seed := key.Seed()
	if len(seed) != ed25519.SeedSize {
		return "", fmt.Errorf("Ed25519 private seed must be %d bytes", ed25519.SeedSize)
	}
	return base64.StdEncoding.EncodeToString(seed), nil
}
