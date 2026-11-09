// Package update keeps the scimtest desktop app current.
//
// GitHub Pages serves one signed JSON feed ([FeedURL]); GitHub Releases serve
// the files it names. The feed's Ed25519 signature, made with the release key
// ([PublicKey]), covers the release JSON. A newer release is downloaded,
// checked against the signed size and SHA-256, and on macOS unpacked beside
// the installed app, verified as a notarized scimtest, and swapped in when
// the user restarts or quits. Linux builds only offer the matching package
// for download; the package manager installs it.
package update

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

const (
	// FeedURL is the signed release feed.
	FeedURL = "https://rselbach.github.io/scimtest/update.json"
	// PublicKey is the release key's base64 Ed25519 public key. The same key
	// signs the legacy Sparkle appcast's archives.
	PublicKey = "2obyIySbPw8xSuXQwzSw2sCbOixUww08jk95se82unc="
	// BundleID is scimtest's bundle identifier, which the feed must name.
	BundleID = "com.rselbach.scimtest"

	artifactPrefix = "https://github.com/rselbach/scimtest/releases/download/"
	notesPrefix    = "https://github.com/rselbach/scimtest/"
)

// Status is what the updater offers.
type Status int

// Updater states.
const (
	// StatusIdle means there is nothing to offer.
	StatusIdle Status = iota
	// StatusReady means a verified update is staged and waits for a restart.
	StatusReady
	// StatusAvailable means a newer release exists that this copy cannot
	// install itself; the user downloads it.
	StatusAvailable
	// StatusFailed means a newer release could not be installed.
	StatusFailed
	// StatusRestarting means the update is in place and scimtest is quitting.
	StatusRestarting
)

// Snapshot is what the UI shows.
type Snapshot struct {
	Status         Status
	CurrentVersion string
	// Version is the release on offer, if any.
	Version     string
	NotesURL    string
	Highlights  []string
	DownloadURL string
	// Failure is a sentence explaining StatusFailed.
	Failure string
}

// Install describes the running copy.
type Install struct {
	Version   string
	Build     uint64
	OSVersion OSVersion
}

// Platform names this build's files in the feed.
type Platform struct {
	OS   string
	Arch string
	// Kind is the package kind Linux builds offer for download.
	Kind string
}

// Staged is a verified update waiting to be applied.
type Staged interface {
	Version() string
	Build() uint64
}

// Installer stages and applies macOS updates.
type Installer interface {
	// Replaceable reports whether the installed app can replace itself.
	Replaceable() bool
	// RemoveLeftovers deletes what earlier updates left behind.
	RemoveLeftovers()
	// Stage unpacks and verifies zip, the archive of release.
	Stage(zip string, release Release) (Staged, error)
	// Apply checks staged again and swaps it in. With relaunch, the new app
	// opens once this process exits.
	Apply(staged Staged, relaunch bool) error
	// Discard removes staged without installing it.
	Discard(staged Staged)
}

// Config sets up an Updater.
type Config struct {
	FeedURL   string
	PublicKey ed25519.PublicKey
	Current   Install
	Platform  Platform
	// StateDir holds updater.json and downloads.
	StateDir string
	// Installer is nil for builds that only offer downloads.
	Installer Installer
	// Terminate quits the app after a restart is arranged.
	Terminate func()
	Client    *http.Client
	// LaunchDelay is how long after Start the first check runs.
	LaunchDelay time.Duration
	// Interval is how often automatic checks run.
	Interval time.Duration
}

// ErrNotReady means there is no staged update to restart into.
var ErrNotReady = errors.New("no update is ready")

// StrandedError means the update was swapped in but the relaunch could not
// be arranged and the swap could not be undone. The previous app stays at
// Previous until the next launch removes it.
type StrandedError struct {
	Previous string
	Err      error
}

func (e *StrandedError) Error() string {
	return fmt.Sprintf("%v; the update is installed and the previous app is at %s", e.Err, e.Previous)
}

func (e *StrandedError) Unwrap() error {
	return e.Err
}

// Updater checks for, downloads, and installs updates.
type Updater struct {
	cfg     Config
	checks  chan chan error
	updated string

	prefsMu sync.Mutex
	prefs   prefs

	// installMu serializes staging and applying.
	installMu sync.Mutex

	mu         sync.Mutex
	status     Status
	offer      Release
	download   string
	failure    string
	staged     Staged
	restarting bool
	guard      func() error
}

// New returns an Updater for cfg. It does not check until Start.
func New(cfg Config) (*Updater, error) {
	if cfg.Client == nil {
		cfg.Client = newHTTPClient()
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 24 * time.Hour
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return nil, fmt.Errorf("create update state directory: %w", err)
	}
	u := &Updater{cfg: cfg, checks: make(chan chan error)}
	u.prefs = loadPrefs(u.prefsPath())
	if u.prefs.LastVersion != "" && u.prefs.LastVersion != cfg.Current.Version {
		u.updated = cfg.Current.Version
	}
	if u.prefs.LastVersion != cfg.Current.Version {
		u.prefs.LastVersion = cfg.Current.Version
		u.savePrefs()
	}
	return u, nil
}

// Start runs automatic checks until ctx ends.
func (u *Updater) Start(ctx context.Context) {
	go u.run(ctx)
}

// Snapshot returns the current state.
func (u *Updater) Snapshot() Snapshot {
	u.mu.Lock()
	defer u.mu.Unlock()
	return Snapshot{
		Status:         u.status,
		CurrentVersion: u.cfg.Current.Version,
		Version:        u.offer.Version,
		NotesURL:       u.offer.NotesURL,
		Highlights:     u.offer.Highlights,
		DownloadURL:    u.download,
		Failure:        u.failure,
	}
}

// TakeUpdatedTo returns the running version once if this is the first
// launch since an update, and an empty string otherwise.
func (u *Updater) TakeUpdatedTo() string {
	u.mu.Lock()
	defer u.mu.Unlock()
	version := u.updated
	u.updated = ""
	return version
}

// CheckNow runs a check and waits for it. It returns an error when the check
// could not reach a verified feed or could not install a newer release.
func (u *Updater) CheckNow(ctx context.Context) error {
	done := make(chan error, 1)
	select {
	case u.checks <- done:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// SetRestartGuard sets a check that must pass before a restart, such as no
// sync running.
func (u *Updater) SetRestartGuard(guard func() error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.guard = guard
}

// Restart installs the staged update, arranges for the new version to open,
// and quits.
func (u *Updater) Restart() error {
	u.installMu.Lock()
	defer u.installMu.Unlock()
	u.mu.Lock()
	staged, guard := u.staged, u.guard
	u.mu.Unlock()
	if staged == nil {
		return ErrNotReady
	}
	if guard != nil {
		if err := guard(); err != nil {
			return err
		}
	}
	if err := u.cfg.Installer.Apply(staged, true); err != nil {
		var stranded *StrandedError
		u.mu.Lock()
		u.staged = nil
		u.status = StatusFailed
		u.failure = fmt.Sprintf("scimtest couldn't replace itself: %v", err)
		if errors.As(err, &stranded) {
			// the new version is in place; nothing more can be installed
			u.restarting = true
			u.failure = fmt.Sprintf("scimtest %s is installed, but scimtest couldn't restart itself. Quit scimtest and open it again.", staged.Version())
		}
		u.mu.Unlock()
		if stranded == nil {
			u.cfg.Installer.Discard(staged)
		}
		return err
	}
	u.mu.Lock()
	u.staged = nil
	u.restarting = true
	u.status = StatusRestarting
	u.mu.Unlock()
	if u.cfg.Terminate != nil {
		u.cfg.Terminate()
	}
	return nil
}

// InstallOnQuit swaps in a staged update without relaunching. Call it once
// the app has shut down.
func (u *Updater) InstallOnQuit() {
	u.installMu.Lock()
	defer u.installMu.Unlock()
	u.mu.Lock()
	staged := u.staged
	u.staged = nil
	u.restarting = true
	u.mu.Unlock()
	if staged == nil {
		return
	}
	if err := u.cfg.Installer.Apply(staged, false); err != nil {
		log.Printf("install update %s on quit: %v", staged.Version(), err)
	}
}

func (u *Updater) run(ctx context.Context) {
	if u.cfg.Installer != nil {
		u.cfg.Installer.RemoveLeftovers()
	}
	timer := time.NewTimer(u.cfg.LaunchDelay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			if u.checkDue() {
				if err := u.check(ctx); err != nil {
					log.Printf("update check: %v", err)
				}
			}
			timer.Reset(time.Hour)
		case done := <-u.checks:
			done <- u.check(ctx)
		}
	}
}

func (u *Updater) checkDue() bool {
	u.prefsMu.Lock()
	defer u.prefsMu.Unlock()
	return time.Since(u.prefs.LastCheck) >= u.cfg.Interval
}

// check fetches the feed and acts on it. Failing to reach the feed leaves
// what the UI shows alone; failing to install a newer release is shown.
func (u *Updater) check(ctx context.Context) error {
	u.mu.Lock()
	restarting := u.restarting
	u.mu.Unlock()
	if restarting {
		return nil
	}
	release, err := u.fetch(ctx)
	if err != nil {
		return err
	}
	u.prefsMu.Lock()
	u.prefs.LastCheck = time.Now()
	u.prefsMu.Unlock()
	u.savePrefs()

	if u.cfg.Installer == nil {
		u.offerDownload(release)
		return nil
	}
	zip, hasZip := release.Artifact(u.cfg.Platform.OS, u.cfg.Platform.Arch, KindAppZip)
	minimum, _ := ParseOSVersion(zip.MinimumOS)
	if release.Build <= u.cfg.Current.Build || !hasZip || u.cfg.Current.OSVersion.Less(minimum) {
		u.upToDate()
		return nil
	}
	manual := zip.URL
	if dmg, ok := release.Artifact(u.cfg.Platform.OS, u.cfg.Platform.Arch, KindDMG); ok {
		manual = dmg.URL
	}
	if !u.cfg.Installer.Replaceable() {
		u.setOffer(release, manual, StatusAvailable)
		return nil
	}
	u.mu.Lock()
	current := u.staged != nil && u.staged.Build() >= release.Build
	u.mu.Unlock()
	if current {
		return nil
	}
	return u.stage(ctx, release, zip, manual)
}

func (u *Updater) fetch(ctx context.Context) (Release, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.cfg.FeedURL, nil)
	if err != nil {
		return Release{}, err
	}
	response, err := u.cfg.Client.Do(request)
	if err != nil {
		return Release{}, fmt.Errorf("fetch update feed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return Release{}, fmt.Errorf("fetch update feed: %s", response.Status)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxFeedBytes+1))
	if err != nil {
		return Release{}, fmt.Errorf("read update feed: %w", err)
	}
	return Open(body, u.cfg.PublicKey)
}

func (u *Updater) offerDownload(release Release) {
	artifact, ok := release.Artifact(u.cfg.Platform.OS, u.cfg.Platform.Arch, u.cfg.Platform.Kind)
	current, currentOK := ParseOSVersion(u.cfg.Current.Version)
	offered, offeredOK := ParseOSVersion(release.Version)
	if !ok || !currentOK || !offeredOK || !current.Less(offered) {
		u.upToDate()
		return
	}
	u.setOffer(release, artifact.URL, StatusAvailable)
}

func (u *Updater) stage(ctx context.Context, release Release, zip Artifact, manual string) error {
	path, err := download(ctx, u.cfg.Client, zip, filepath.Join(u.cfg.StateDir, "downloads"))
	if err != nil {
		if ctx.Err() == nil {
			u.failRelease(release, manual, downloadFailure(err))
		}
		return err
	}
	u.installMu.Lock()
	defer u.installMu.Unlock()
	staged, err := u.cfg.Installer.Stage(path, release)
	removeFile(path)
	if err != nil {
		u.failRelease(release, manual, "The update didn't pass its signature checks, so scimtest deleted it. It will try again at the next check.")
		return err
	}
	u.mu.Lock()
	if u.restarting {
		u.mu.Unlock()
		u.cfg.Installer.Discard(staged)
		return nil
	}
	previous := u.staged
	u.staged = staged
	u.offer = release
	u.download = manual
	u.failure = ""
	u.status = StatusReady
	u.mu.Unlock()
	if previous != nil {
		u.cfg.Installer.Discard(previous)
	}
	return nil
}

func downloadFailure(err error) string {
	var mismatch *integrityError
	if errors.As(err, &mismatch) {
		return "The download didn't match the signed release, so scimtest deleted it. It will try again at the next check."
	}
	return "The download didn't finish. scimtest will try again at the next check."
}

// upToDate clears an offer a check found no longer applies. A staged update
// stays ready.
func (u *Updater) upToDate() {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.restarting || u.staged != nil {
		return
	}
	u.offer = Release{}
	u.download = ""
	u.failure = ""
	u.status = StatusIdle
}

func (u *Updater) setOffer(release Release, download string, status Status) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.offer = release
	u.download = download
	u.failure = ""
	u.status = status
}

// failRelease shows that release could not be installed, unless an older
// update is already staged and can still be installed.
func (u *Updater) failRelease(release Release, download, failure string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.staged != nil {
		return
	}
	u.offer = release
	u.download = download
	u.failure = failure
	u.status = StatusFailed
}

func (u *Updater) prefsPath() string {
	return filepath.Join(u.cfg.StateDir, "updater.json")
}

func (u *Updater) savePrefs() {
	u.prefsMu.Lock()
	defer u.prefsMu.Unlock()
	if err := u.prefs.save(u.prefsPath()); err != nil {
		log.Printf("save update state: %v", err)
	}
}

// Arch is this build's architecture in feed terms.
func Arch() string {
	if runtime.GOARCH == "amd64" {
		return "x86_64"
	}
	return runtime.GOARCH
}
