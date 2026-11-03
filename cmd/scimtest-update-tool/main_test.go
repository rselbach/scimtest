package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/rselbach/scimtest/internal/update"
)

const releaseURL = "https://github.com/rselbach/scimtest/releases/download/v2.6.0/"

func useTestKey(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	previous := pinnedPublicKey
	pinnedPublicKey = base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	t.Cleanup(func() { pinnedPublicKey = previous })
	return key, base64.StdEncoding.EncodeToString(key.Seed()) + "\n"
}

func TestSignFeedWritesAFeedTheAppOpens(t *testing.T) {
	r := require.New(t)
	key, seed := useTestKey(t)
	dir := t.TempDir()
	zip := filepath.Join(dir, "scimtest.zip")
	r.NoError(os.WriteFile(zip, []byte("scimtest.app"), 0o644))
	notes := filepath.Join(dir, "notes.md")
	r.NoError(os.WriteFile(notes, []byte("# scimtest 2.6.0\n\n## Changes\n\n- **Signing keys** rotate with validity presets\n* SAML wrapping faults\n- `go` 1.26.10\n"), 0o644))
	out := filepath.Join(dir, "update.json")

	err := run([]string{
		"sign-feed", "--version", "2.6.0", "--build", "42",
		"--published-at", "2026-11-03T12:00:00Z",
		"--notes-url", "https://github.com/rselbach/scimtest/releases/tag/v2.6.0",
		"--notes", notes,
		"--artifact", "macos,arm64,app-zip,26.0," + zip + "," + releaseURL + "scimtest.zip",
		"--out", out,
	}, strings.NewReader(seed))
	r.NoError(err)

	feed, err := os.ReadFile(out)
	r.NoError(err)
	release, err := update.Open(feed, key.Public().(ed25519.PublicKey))
	r.NoError(err)
	r.Equal(uint64(42), release.Build)
	r.Equal([]string{"Signing keys rotate with validity presets", "SAML wrapping faults", "go 1.26.10"}, release.Highlights)
	r.Len(release.Artifacts, 1)
	r.Equal(int64(len("scimtest.app")), release.Artifacts[0].Size)
}

func TestSignFeedRefusesBadInput(t *testing.T) {
	tests := map[string]struct {
		args []string
		seed func(t *testing.T) string
	}{
		"unpinned key": {
			args: []string{"--version", "2.6.0", "--build", "42"},
			seed: func(*testing.T) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)) },
		},
		"artifact elsewhere": {
			args: []string{"--version", "2.6.0", "--build", "42", "--artifact", "macos,arm64,app-zip,26.0,ZIP,https://example.com/scimtest.zip"},
		},
		"no build": {
			args: []string{"--version", "2.6.0"},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			_, seed := useTestKey(t)
			if tc.seed != nil {
				seed = tc.seed(t)
			}
			dir := t.TempDir()
			zip := filepath.Join(dir, "scimtest.zip")
			r.NoError(os.WriteFile(zip, []byte("scimtest.app"), 0o644))
			args := []string{"sign-feed", "--published-at", "2026-11-03T12:00:00Z", "--out", filepath.Join(dir, "update.json")}
			for _, arg := range tc.args {
				args = append(args, strings.ReplaceAll(arg, "ZIP", zip))
			}

			r.Error(run(args, strings.NewReader(seed)))
			r.NoFileExists(filepath.Join(dir, "update.json"))
		})
	}
}

func TestAppcastSignsArchiveForSparkle(t *testing.T) {
	r := require.New(t)
	key, seed := useTestKey(t)
	dir := t.TempDir()
	zip := filepath.Join(dir, "scimtest.zip")
	r.NoError(os.WriteFile(zip, []byte("scimtest.app"), 0o644))
	out := filepath.Join(dir, "appcast.xml")

	err := run([]string{
		"appcast", "--version", "2.6.0", "--build", "42", "--minimum-os", "26.0",
		"--published-at", "2026-11-03T12:00:00Z", "--archive", zip,
		"--url", releaseURL + "scimtest.zip", "--out", out,
	}, strings.NewReader(seed))
	r.NoError(err)

	data, err := os.ReadFile(out)
	r.NoError(err)
	var feed struct {
		Item struct {
			Version   string `xml:"http://www.andymatuschak.org/xml-namespaces/sparkle version"`
			Enclosure struct {
				URL       string `xml:"url,attr"`
				Length    int    `xml:"length,attr"`
				Signature string `xml:"http://www.andymatuschak.org/xml-namespaces/sparkle edSignature,attr"`
			} `xml:"enclosure"`
		} `xml:"channel>item"`
	}
	r.NoError(xml.Unmarshal(data, &feed))
	r.Equal("42", feed.Item.Version)
	r.Equal(releaseURL+"scimtest.zip", feed.Item.Enclosure.URL)
	r.Equal(len("scimtest.app"), feed.Item.Enclosure.Length)
	signature, err := base64.StdEncoding.DecodeString(feed.Item.Enclosure.Signature)
	r.NoError(err)
	r.True(ed25519.Verify(key.Public().(ed25519.PublicKey), []byte("scimtest.app"), signature))
}
