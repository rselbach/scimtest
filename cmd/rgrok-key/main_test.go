package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestPrivateSeedBase64(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyBlock, err := ssh.MarshalPrivateKey(privateKey, "Greendale application key")
	if err != nil {
		t.Fatal(err)
	}

	encoded, err := privateSeedBase64(pem.EncodeToMemory(keyBlock))
	if err != nil {
		t.Fatal(err)
	}
	seed, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(privateKey.Seed(), seed) {
		t.Fatalf("decoded seed does not match generated key")
	}
}

func TestPrivateSeedBase64RejectsInvalidKeys(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaBlock, err := ssh.MarshalPrivateKey(rsaKey, "Greendale RSA key")
	if err != nil {
		t.Fatal(err)
	}
	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encryptedBlock, err := ssh.MarshalPrivateKeyWithPassphrase(ed25519Key, "Greendale encrypted key", []byte("chang-me"))
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]struct {
		contents []byte
		want     string
	}{
		"wrong key type": {contents: pem.EncodeToMemory(rsaBlock), want: "must be Ed25519"},
		"malformed":      {contents: []byte("not a private key"), want: "invalid OpenSSH private key"},
		"encrypted":      {contents: pem.EncodeToMemory(encryptedBlock), want: "encrypted private keys are not supported"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := privateSeedBase64(tc.contents)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want error containing %q", err, tc.want)
			}
		})
	}
}

func TestRunUsageAndReadErrors(t *testing.T) {
	tests := map[string]struct {
		args     []string
		wantCode int
		wantErr  string
	}{
		"missing argument": {wantCode: 2, wantErr: "usage:"},
		"extra argument":   {args: []string{"one", "two"}, wantCode: 2, wantErr: "usage:"},
		"read error":       {args: []string{filepath.Join(t.TempDir(), "missing")}, wantCode: 1, wantErr: "read private key:"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if got := run(tc.args, &stdout, &stderr); got != tc.wantCode {
				t.Fatalf("exit code = %d, want %d", got, tc.wantCode)
			}
			if stdout.Len() != 0 {
				t.Fatalf("stdout = %q, want empty", stdout.String())
			}
			if !strings.Contains(stderr.String(), tc.wantErr) {
				t.Fatalf("stderr = %q, want text containing %q", stderr.String(), tc.wantErr)
			}
		})
	}
}

func TestRunWritesOnlySeed(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(privateKey, "Human Being mascot")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if got := run([]string{path}, &stdout, &stderr); got != 0 {
		t.Fatalf("exit code = %d, stderr = %q", got, stderr.String())
	}
	want := base64.StdEncoding.EncodeToString(privateKey.Seed()) + "\n"
	if stdout.String() != want {
		t.Fatalf("stdout did not contain the generated seed")
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}
