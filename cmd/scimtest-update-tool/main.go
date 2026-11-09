// Command scimtest-update-tool writes scimtest's signed update feed and the
// legacy Sparkle appcast that releases from before the feed still read. Both
// commands read the base64 Ed25519 seed from standard input and refuse a key
// whose public half is not the one scimtest pins.
//
//	scimtest-update-tool sign-feed --version V --build N --published-at RFC3339
//	    --notes-url URL --notes FILE
//	    --artifact os,arch,kind,minimum_os,FILE,URL [--artifact ...] --out FILE
//	scimtest-update-tool appcast --version V --build N --minimum-os X
//	    --published-at RFC3339 --archive FILE --url URL --out FILE
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/rselbach/scimtest/internal/update"
)

const maxHighlights = 5

// pinnedPublicKey is the key every signing command must hold the private
// half of.
var pinnedPublicKey = update.PublicKey

func main() {
	if err := run(os.Args[1:], os.Stdin); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader) error {
	if len(args) == 0 {
		return errors.New("usage: scimtest-update-tool sign-feed|appcast ...")
	}
	switch args[0] {
	case "sign-feed":
		return signFeed(args[1:], stdin)
	case "appcast":
		return appcast(args[1:], stdin)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

type artifactFlags []string

func (a *artifactFlags) String() string { return strings.Join(*a, " ") }

func (a *artifactFlags) Set(value string) error {
	*a = append(*a, value)
	return nil
}

func signFeed(args []string, stdin io.Reader) error {
	flags := flag.NewFlagSet("sign-feed", flag.ContinueOnError)
	version := flags.String("version", "", "release version")
	build := flags.Uint64("build", 0, "release build number")
	publishedAt := flags.String("published-at", "", "RFC 3339 publication time")
	notesURL := flags.String("notes-url", "", "GitHub release page")
	notes := flags.String("notes", "", "release notes Markdown")
	out := flags.String("out", "", "feed file to write")
	var artifacts artifactFlags
	flags.Var(&artifacts, "artifact", "os,arch,kind,minimum_os,FILE,URL")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *out == "" || *publishedAt == "" {
		return errors.New("sign-feed needs --out and --published-at")
	}
	if _, err := time.Parse(time.RFC3339, *publishedAt); err != nil {
		return fmt.Errorf("--published-at: %w", err)
	}
	key, err := readSigningKey(stdin)
	if err != nil {
		return err
	}
	release := update.Release{
		Schema:      1,
		App:         update.BundleID,
		Channel:     "stable",
		Version:     *version,
		Build:       *build,
		PublishedAt: *publishedAt,
		NotesURL:    *notesURL,
	}
	if *notes != "" {
		markdown, err := os.ReadFile(*notes)
		if err != nil {
			return fmt.Errorf("read release notes: %w", err)
		}
		release.Highlights = highlights(string(markdown))
	}
	for _, spec := range artifacts {
		artifact, err := describeArtifact(spec)
		if err != nil {
			return err
		}
		release.Artifacts = append(release.Artifacts, artifact)
	}
	feed, err := update.Seal(release, key)
	if err != nil {
		return err
	}
	// open it exactly as the app does, so a bad field fails the release
	if _, err := update.Open(feed, key.Public().(ed25519.PublicKey)); err != nil {
		return fmt.Errorf("the signed feed does not open: %w", err)
	}
	return os.WriteFile(*out, feed, 0o644)
}

func describeArtifact(spec string) (update.Artifact, error) {
	parts := strings.Split(spec, ",")
	if len(parts) != 6 {
		return update.Artifact{}, fmt.Errorf("--artifact %q needs os,arch,kind,minimum_os,FILE,URL", spec)
	}
	data, err := os.ReadFile(parts[4])
	if err != nil {
		return update.Artifact{}, fmt.Errorf("read artifact: %w", err)
	}
	sum := sha256.Sum256(data)
	return update.Artifact{
		OS:        parts[0],
		Arch:      parts[1],
		Kind:      parts[2],
		MinimumOS: parts[3],
		URL:       parts[5],
		Size:      int64(len(data)),
		SHA256:    hex.EncodeToString(sum[:]),
	}, nil
}

// highlights returns the first few Markdown bullet lines of notes as plain
// text.
func highlights(notes string) []string {
	var found []string
	for line := range strings.Lines(notes) {
		text, ok := strings.CutPrefix(strings.TrimSpace(line), "- ")
		if !ok {
			text, ok = strings.CutPrefix(strings.TrimSpace(line), "* ")
		}
		text = strings.TrimSpace(strings.NewReplacer("**", "", "`", "").Replace(text))
		if !ok || text == "" || len(text) > 200 {
			continue
		}
		found = append(found, text)
		if len(found) == maxHighlights {
			break
		}
	}
	return found
}

func appcast(args []string, stdin io.Reader) error {
	flags := flag.NewFlagSet("appcast", flag.ContinueOnError)
	version := flags.String("version", "", "release version")
	build := flags.Uint64("build", 0, "release build number")
	minimumOS := flags.String("minimum-os", "", "minimum macOS version")
	publishedAt := flags.String("published-at", "", "RFC 3339 publication time")
	archive := flags.String("archive", "", "application ZIP")
	archiveURL := flags.String("url", "", "download URL of the ZIP")
	out := flags.String("out", "", "appcast file to write")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *version == "" || *build == 0 || *minimumOS == "" || *archive == "" || *archiveURL == "" || *out == "" {
		return errors.New("appcast needs --version, --build, --minimum-os, --archive, --url, and --out")
	}
	published, err := time.Parse(time.RFC3339, *publishedAt)
	if err != nil {
		return fmt.Errorf("--published-at: %w", err)
	}
	key, err := readSigningKey(stdin)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(*archive)
	if err != nil {
		return fmt.Errorf("read archive: %w", err)
	}
	var feed bytes.Buffer
	feed.WriteString(xml.Header)
	feed.WriteString(`<rss version="2.0" xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle">` + "\n")
	feed.WriteString("  <channel>\n    <title>scimtest</title>\n    <link>https://github.com/rselbach/scimtest</link>\n    <item>\n")
	fmt.Fprintf(&feed, "      <title>%s</title>\n", escape(*version))
	fmt.Fprintf(&feed, "      <pubDate>%s</pubDate>\n", published.UTC().Format(time.RFC1123Z))
	fmt.Fprintf(&feed, "      <sparkle:version>%d</sparkle:version>\n", *build)
	fmt.Fprintf(&feed, "      <sparkle:shortVersionString>%s</sparkle:shortVersionString>\n", escape(*version))
	fmt.Fprintf(&feed, "      <sparkle:minimumSystemVersion>%s</sparkle:minimumSystemVersion>\n", escape(*minimumOS))
	feed.WriteString("      <sparkle:hardwareRequirements>arm64</sparkle:hardwareRequirements>\n")
	fmt.Fprintf(&feed, "      <enclosure url=\"%s\" length=\"%d\" type=\"application/octet-stream\" sparkle:edSignature=\"%s\"/>\n",
		escape(*archiveURL), len(data), update.SparkleSignature(data, key))
	feed.WriteString("    </item>\n  </channel>\n</rss>\n")
	return os.WriteFile(*out, feed.Bytes(), 0o644)
}

func escape(text string) string {
	var escaped strings.Builder
	if err := xml.EscapeText(&escaped, []byte(text)); err != nil {
		return ""
	}
	return escaped.String()
}

// readSigningKey reads the seed from stdin and checks it against the pinned
// public key, so a wrong secret fails the release instead of publishing a
// feed no client accepts.
func readSigningKey(stdin io.Reader) (ed25519.PrivateKey, error) {
	text, err := io.ReadAll(io.LimitReader(stdin, 4096))
	if err != nil {
		return nil, fmt.Errorf("read signing key: %w", err)
	}
	key, err := update.ParseSigningKey(string(text))
	if err != nil {
		return nil, err
	}
	pinned, err := update.ParsePublicKey(pinnedPublicKey)
	if err != nil {
		return nil, err
	}
	if !pinned.Equal(key.Public()) {
		return nil, errors.New("the signing key does not match scimtest's pinned public key")
	}
	return key, nil
}
