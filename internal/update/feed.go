package update

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// signingContext prefixes every signed feed message, so a feed signature can
// never pass for a Sparkle archive signature made with the same key.
const signingContext = "scimtest-update-feed-v1\n"

const (
	feedSchema       = 1
	feedChannel      = "stable"
	maxFeedBytes     = 64 * 1024
	maxArtifactBytes = 2 << 30
	maxHighlights    = 8
	maxHighlightLen  = 200
)

// Artifact kinds published in the feed.
const (
	KindAppZip = "app-zip"
	KindDMG    = "dmg"
	KindDeb    = "deb"
	KindRPM    = "rpm"
	KindArch   = "pkg.tar.zst"
)

// Envelope is the published feed: a base64 release and its signature.
type Envelope struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// Release describes one published scimtest release.
type Release struct {
	Schema      int    `json:"schema"`
	App         string `json:"app"`
	Channel     string `json:"channel"`
	Version     string `json:"version"`
	Build       uint64 `json:"build"`
	PublishedAt string `json:"published_at"`
	NotesURL    string `json:"notes_url,omitempty"`
	// Highlights are a few one-line release notes the update prompt lists.
	Highlights []string   `json:"highlights,omitempty"`
	Artifacts  []Artifact `json:"artifacts"`
}

// Artifact is one downloadable file of a release.
type Artifact struct {
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	Kind      string `json:"kind"`
	MinimumOS string `json:"minimum_os"`
	URL       string `json:"url"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
}

// Artifact returns the release's file of kind for os and arch.
func (r Release) Artifact(os, arch, kind string) (Artifact, bool) {
	for _, artifact := range r.Artifacts {
		if artifact.OS == os && artifact.Arch == arch && artifact.Kind == kind {
			return artifact, true
		}
	}
	return Artifact{}, false
}

// ParsePublicKey decodes a base64 Ed25519 public key.
func ParsePublicKey(text string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(text))
	if err != nil {
		return nil, fmt.Errorf("public key is not base64: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("public key is not 32 bytes")
	}
	return ed25519.PublicKey(raw), nil
}

// ParseSigningKey decodes a base64 32-byte Ed25519 seed, the format the
// release workflow's Sparkle key secret holds.
func ParseSigningKey(text string) (ed25519.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(text))
	if err != nil {
		return nil, errors.New("signing key is not base64")
	}
	if len(raw) != ed25519.SeedSize {
		return nil, errors.New("signing key is not a 32-byte Ed25519 seed")
	}
	return ed25519.NewKeyFromSeed(raw), nil
}

// Seal signs release and returns the feed bytes to publish.
func Seal(release Release, key ed25519.PrivateKey) ([]byte, error) {
	payload, err := json.Marshal(release)
	if err != nil {
		return nil, fmt.Errorf("encode release: %w", err)
	}
	envelope := Envelope{
		Payload:   base64.StdEncoding.EncodeToString(payload),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, signedMessage(payload))),
	}
	feed, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode feed: %w", err)
	}
	return append(feed, '\n'), nil
}

// SparkleSignature returns the base64 Ed25519 signature Sparkle expects over
// an archive's bytes.
func SparkleSignature(archive []byte, key ed25519.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(key, archive))
}

// Open verifies feed with key and returns its release, checked against
// scimtest's identity and artifact origin. Nothing in an unverified payload
// is parsed.
func Open(feed []byte, key ed25519.PublicKey) (Release, error) {
	if len(feed) > maxFeedBytes {
		return Release{}, errors.New("update feed is too large")
	}
	var envelope Envelope
	if err := json.Unmarshal(feed, &envelope); err != nil {
		return Release{}, errors.New("update feed is not an envelope")
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return Release{}, errors.New("update feed payload is not base64")
	}
	signature, err := base64.StdEncoding.DecodeString(envelope.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return Release{}, errors.New("update feed signature is not 64 base64 bytes")
	}
	if !ed25519.Verify(key, signedMessage(payload), signature) {
		return Release{}, errors.New("update feed signature does not verify")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	var release Release
	if err := decoder.Decode(&release); err != nil {
		return Release{}, fmt.Errorf("update feed release is malformed: %w", err)
	}
	if err := checkRelease(release); err != nil {
		return Release{}, err
	}
	return release, nil
}

func signedMessage(payload []byte) []byte {
	return append([]byte(signingContext), payload...)
}

func checkRelease(release Release) error {
	switch {
	case release.Schema != feedSchema:
		return fmt.Errorf("update feed has schema %d", release.Schema)
	case release.App != BundleID:
		return fmt.Errorf("update feed is for %q", release.App)
	case release.Channel != feedChannel:
		return fmt.Errorf("update feed is for channel %q", release.Channel)
	case !isVersion(release.Version):
		return fmt.Errorf("update feed has version %q", release.Version)
	case release.Build == 0:
		return errors.New("update feed has build 0")
	case release.NotesURL != "" && !strings.HasPrefix(release.NotesURL, notesPrefix):
		return fmt.Errorf("update feed has notes URL %q", release.NotesURL)
	case len(release.Highlights) > maxHighlights:
		return fmt.Errorf("update feed has %d highlights", len(release.Highlights))
	}
	for _, highlight := range release.Highlights {
		if highlight == "" || len(highlight) > maxHighlightLen || strings.ContainsAny(highlight, "\r\n") {
			return fmt.Errorf("update feed has highlight %q", highlight)
		}
	}
	for _, artifact := range release.Artifacts {
		switch {
		case !isSHA256(artifact.SHA256):
			return fmt.Errorf("update feed has a bad SHA-256 for %s", artifact.URL)
		case artifact.Size <= 0 || artifact.Size > maxArtifactBytes:
			return fmt.Errorf("update feed has a bad size for %s", artifact.URL)
		case !validOSVersion(artifact.MinimumOS):
			return fmt.Errorf("update feed has minimum OS %q", artifact.MinimumOS)
		case !allowedArtifactURL(artifact.URL):
			return fmt.Errorf("update feed has artifact URL %q", artifact.URL)
		}
	}
	return nil
}

// isVersion accepts dotted numeric versions; they name staging folders and
// are compared on Linux, so nothing else is allowed.
func isVersion(text string) bool {
	parts := strings.Split(text, ".")
	if len(text) > 32 || len(parts) > 3 {
		return false
	}
	for _, part := range parts {
		if _, err := strconv.ParseUint(part, 10, 32); err != nil {
			return false
		}
	}
	return true
}

func isSHA256(text string) bool {
	if len(text) != 64 {
		return false
	}
	for _, c := range text {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func allowedArtifactURL(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.String() != raw || parsed.Scheme != "https" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	rest, ok := strings.CutPrefix(raw, artifactPrefix)
	if !ok || rest == "" {
		return false
	}
	for _, segment := range strings.Split(rest, "/") {
		if segment == ".." || segment == "." {
			return false
		}
	}
	return true
}

// OSVersion is a dotted version such as 26.0.1; missing parts are zero.
type OSVersion [3]uint64

// ParseOSVersion parses "26", "26.1", or "26.1.2".
func ParseOSVersion(text string) (OSVersion, bool) {
	var version OSVersion
	parts := strings.Split(strings.TrimSpace(text), ".")
	if len(parts) > len(version) {
		return OSVersion{}, false
	}
	for i, part := range parts {
		value, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return OSVersion{}, false
		}
		version[i] = value
	}
	return version, true
}

func validOSVersion(text string) bool {
	_, ok := ParseOSVersion(text)
	return ok
}

// Less reports whether v is older than other.
func (v OSVersion) Less(other OSVersion) bool {
	for i := range v {
		if v[i] != other[i] {
			return v[i] < other[i]
		}
	}
	return false
}
