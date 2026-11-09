package update

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const testSHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func testKey(seed byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
}

func testRelease() Release {
	return Release{
		Schema:      feedSchema,
		App:         BundleID,
		Channel:     feedChannel,
		Version:     "2.6.0",
		Build:       42,
		PublishedAt: "2026-11-01T12:00:00Z",
		NotesURL:    "https://github.com/rselbach/scimtest/releases/tag/v2.6.0",
		Highlights:  []string{"Certificate validity presets when rotating signing keys"},
		Artifacts: []Artifact{{
			OS:        "macos",
			Arch:      "arm64",
			Kind:      KindAppZip,
			MinimumOS: "26.0",
			URL:       artifactPrefix + "v2.6.0/scimtest-desktop_2.6.0_arm64.zip",
			Size:      1024,
			SHA256:    testSHA,
		}},
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	r := require.New(t)
	key := testKey(1)
	feed, err := Seal(testRelease(), key)
	r.NoError(err)

	got, err := Open(feed, key.Public().(ed25519.PublicKey))
	r.NoError(err)
	r.Equal(testRelease(), got)
}

func TestOpenRejects(t *testing.T) {
	tests := map[string]struct {
		change func(*Release)
		key    ed25519.PrivateKey
	}{
		"another key":          {key: testKey(2)},
		"another app":          {change: func(r *Release) { r.App = "com.rselbach.onda" }},
		"another channel":      {change: func(r *Release) { r.Channel = "beta" }},
		"another schema":       {change: func(r *Release) { r.Schema = 2 }},
		"pre-release version":  {change: func(r *Release) { r.Version = "2.6.0-rc1" }},
		"path in version":      {change: func(r *Release) { r.Version = "../2" }},
		"build zero":           {change: func(r *Release) { r.Build = 0 }},
		"notes elsewhere":      {change: func(r *Release) { r.NotesURL = "https://example.com/notes" }},
		"newline in highlight": {change: func(r *Release) { r.Highlights = []string{"one\ntwo"} }},
		"too many highlights":  {change: func(r *Release) { r.Highlights = make([]string, maxHighlights+1) }},
		"artifact elsewhere":   {change: func(r *Release) { r.Artifacts[0].URL = "https://example.com/scimtest.zip" }},
		"artifact over http": {change: func(r *Release) {
			r.Artifacts[0].URL = "http://github.com/rselbach/scimtest/releases/download/v2.6.0/a.zip"
		}},
		"artifact query":        {change: func(r *Release) { r.Artifacts[0].URL += "?x=1" }},
		"artifact parent":       {change: func(r *Release) { r.Artifacts[0].URL = artifactPrefix + "../../onda/a.zip" }},
		"artifact bad SHA":      {change: func(r *Release) { r.Artifacts[0].SHA256 = strings.ToUpper(testSHA) }},
		"artifact empty":        {change: func(r *Release) { r.Artifacts[0].Size = 0 }},
		"artifact too large":    {change: func(r *Release) { r.Artifacts[0].Size = maxArtifactBytes + 1 }},
		"artifact bad minimum":  {change: func(r *Release) { r.Artifacts[0].MinimumOS = "twenty-six" }},
		"artifact long minimum": {change: func(r *Release) { r.Artifacts[0].MinimumOS = "26.0.0.1" }},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			release := testRelease()
			if tc.change != nil {
				tc.change(&release)
			}
			key := tc.key
			if key == nil {
				key = testKey(1)
			}
			feed, err := Seal(release, key)
			r.NoError(err)

			_, err = Open(feed, testKey(1).Public().(ed25519.PublicKey))
			r.Error(err)
		})
	}
}

func TestOpenRejectsTamperedPayload(t *testing.T) {
	r := require.New(t)
	key := testKey(1)
	feed, err := Seal(testRelease(), key)
	r.NoError(err)
	var envelope Envelope
	r.NoError(json.Unmarshal(feed, &envelope))
	tampered := testRelease()
	tampered.Build = 43
	payload, err := json.Marshal(tampered)
	r.NoError(err)
	envelope.Payload = base64.StdEncoding.EncodeToString(payload)
	feed, err = json.Marshal(envelope)
	r.NoError(err)

	_, err = Open(feed, key.Public().(ed25519.PublicKey))
	r.ErrorContains(err, "signature does not verify")
}

func TestOpenRejectsOversizedFeed(t *testing.T) {
	r := require.New(t)
	_, err := Open(bytes.Repeat([]byte(" "), maxFeedBytes+1), testKey(1).Public().(ed25519.PublicKey))
	r.ErrorContains(err, "too large")
}

func TestSparkleSignatureSignsArchiveBytes(t *testing.T) {
	r := require.New(t)
	key := testKey(1)
	archive := []byte("scimtest.app")
	signature, err := base64.StdEncoding.DecodeString(SparkleSignature(archive, key))
	r.NoError(err)
	r.True(ed25519.Verify(key.Public().(ed25519.PublicKey), archive, signature))
}

func TestParseOSVersion(t *testing.T) {
	tests := map[string]struct {
		text   string
		want   OSVersion
		wantOK bool
	}{
		"major":         {text: "26", want: OSVersion{26}, wantOK: true},
		"major minor":   {text: "26.1", want: OSVersion{26, 1}, wantOK: true},
		"full":          {text: "26.1.2", want: OSVersion{26, 1, 2}, wantOK: true},
		"too many":      {text: "26.1.2.3"},
		"empty part":    {text: "26..1"},
		"not a version": {text: "Tahoe"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			got, ok := ParseOSVersion(tc.text)
			r.Equal(tc.wantOK, ok)
			r.Equal(tc.want, got)
		})
	}
}

func TestMachOHasARM64(t *testing.T) {
	thinARM64 := []byte{0xcf, 0xfa, 0xed, 0xfe, 0x0c, 0x00, 0x00, 0x01}
	thinAMD64 := []byte{0xcf, 0xfa, 0xed, 0xfe, 0x07, 0x00, 0x00, 0x01}
	fat := append([]byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2}, make([]byte, 40)...)
	copy(fat[8:], []byte{0x01, 0x00, 0x00, 0x07})
	copy(fat[28:], []byte{0x01, 0x00, 0x00, 0x0c})
	tests := map[string]struct {
		head []byte
		want bool
	}{
		"thin arm64": {head: thinARM64, want: true},
		"thin amd64": {head: thinAMD64},
		"universal":  {head: fat, want: true},
		"script":     {head: []byte("#!/bin/sh\n")},
		"short":      {head: []byte{0xcf}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			require.New(t).Equal(tc.want, machOHasARM64(tc.head))
		})
	}
}
