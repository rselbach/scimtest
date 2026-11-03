package update

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type fakeStaged struct {
	version string
	build   uint64
}

func (s *fakeStaged) Version() string { return s.version }
func (s *fakeStaged) Build() uint64   { return s.build }

type fakeInstaller struct {
	mu          sync.Mutex
	replaceable bool
	stageErr    error
	applyErr    error
	applied     []bool
	discarded   int
}

func (f *fakeInstaller) Replaceable() bool { return f.replaceable }
func (f *fakeInstaller) RemoveLeftovers()  {}

func (f *fakeInstaller) Stage(zip string, release Release) (Staged, error) {
	if _, err := os.Stat(zip); err != nil {
		return nil, err
	}
	if f.stageErr != nil {
		return nil, f.stageErr
	}
	return &fakeStaged{version: release.Version, build: release.Build}, nil
}

func (f *fakeInstaller) Apply(_ Staged, relaunch bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applied = append(f.applied, relaunch)
	return f.applyErr
}

func (f *fakeInstaller) Discard(Staged) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.discarded++
}

// testServer serves a signed feed for release and its files.
type testServer struct {
	mu      sync.Mutex
	feed    []byte
	files   map[string][]byte
	failing bool
}

func (s *testServer) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failing {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	if request.URL.String() == FeedURL {
		http.ServeContent(w, request, "update.json", time.Time{}, bytes.NewReader(s.feed))
		return
	}
	body, ok := s.files[request.URL.String()]
	if !ok {
		http.NotFound(w, request)
		return
	}
	http.ServeContent(w, request, "file", time.Time{}, bytes.NewReader(body))
}

func (s *testServer) publish(t *testing.T, release Release) {
	t.Helper()
	feed, err := Seal(release, testKey(1))
	require.New(t).NoError(err)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.feed = feed
}

func (s *testServer) setFailing(failing bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failing = failing
}

// releaseWith returns a release offering files, each served by server.
func releaseWith(server *testServer, version string, build uint64, artifacts ...Artifact) Release {
	release := testRelease()
	release.Version = version
	release.Build = build
	release.Artifacts = nil
	for _, artifact := range artifacts {
		body := []byte(artifact.Kind + " " + version)
		artifact.Size = int64(len(body))
		described := artifactFor(body)
		artifact.SHA256 = described.SHA256
		server.files[artifact.URL] = body
		release.Artifacts = append(release.Artifacts, artifact)
	}
	return release
}

func macArtifact(kind string) Artifact {
	return Artifact{OS: "macos", Arch: "arm64", Kind: kind, MinimumOS: "26.0", URL: artifactPrefix + "v2.6.0/scimtest." + kind}
}

func linuxArtifact(kind string) Artifact {
	return Artifact{OS: "linux", Arch: "x86_64", Kind: kind, MinimumOS: "0", URL: artifactPrefix + "v2.6.0/scimtest." + kind}
}

type updaterHarness struct {
	updater    *Updater
	server     *testServer
	installer  *fakeInstaller
	terminated int
}

func newHarness(t *testing.T, installer *fakeInstaller, platform Platform) *updaterHarness {
	t.Helper()
	h := &updaterHarness{server: &testServer{files: map[string][]byte{}}, installer: installer}
	cfg := Config{
		FeedURL:     FeedURL,
		PublicKey:   testKey(1).Public().(ed25519.PublicKey),
		Current:     Install{Version: "2.5.1", Build: 41, OSVersion: OSVersion{26, 1}},
		Platform:    platform,
		StateDir:    t.TempDir(),
		Terminate:   func() { h.terminated++ },
		Client:      testClient(h.server),
		LaunchDelay: time.Hour,
	}
	if installer != nil {
		cfg.Installer = installer
	}
	updater, err := New(cfg)
	require.New(t).NoError(err)
	h.updater = updater
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	updater.Start(ctx)
	return h
}

func macPlatform() Platform {
	return Platform{OS: "macos", Arch: "arm64"}
}

func TestCheckStagesNewerRelease(t *testing.T) {
	r := require.New(t)
	h := newHarness(t, &fakeInstaller{replaceable: true}, macPlatform())
	release := releaseWith(h.server, "2.6.0", 42, macArtifact(KindAppZip), macArtifact(KindDMG))
	h.server.publish(t, release)

	r.NoError(h.updater.CheckNow(context.Background()))
	got := h.updater.Snapshot()
	r.Equal(StatusReady, got.Status)
	r.Equal("2.6.0", got.Version)
	r.Equal(release.Highlights, got.Highlights)
	r.Equal(macArtifact(KindDMG).URL, got.DownloadURL)
}

func TestCheckOffers(t *testing.T) {
	tests := map[string]struct {
		installer  *fakeInstaller
		platform   Platform
		version    string
		build      uint64
		artifacts  []Artifact
		wantStatus Status
		wantURL    string
	}{
		"same build": {
			installer: &fakeInstaller{replaceable: true}, platform: macPlatform(),
			version: "2.5.1", build: 41, artifacts: []Artifact{macArtifact(KindAppZip)},
			wantStatus: StatusIdle,
		},
		"newer macOS required": {
			installer: &fakeInstaller{replaceable: true}, platform: macPlatform(),
			version: "2.6.0", build: 42,
			artifacts:  []Artifact{{OS: "macos", Arch: "arm64", Kind: KindAppZip, MinimumOS: "27.0", URL: macArtifact(KindAppZip).URL}},
			wantStatus: StatusIdle,
		},
		"copy cannot replace itself": {
			installer: &fakeInstaller{}, platform: macPlatform(),
			version: "2.6.0", build: 42, artifacts: []Artifact{macArtifact(KindAppZip), macArtifact(KindDMG)},
			wantStatus: StatusAvailable, wantURL: macArtifact(KindDMG).URL,
		},
		"newer Linux package": {
			platform: Platform{OS: "linux", Arch: "x86_64", Kind: KindDeb},
			version:  "2.6.0", build: 42, artifacts: []Artifact{linuxArtifact(KindDeb), linuxArtifact(KindRPM)},
			wantStatus: StatusAvailable, wantURL: linuxArtifact(KindDeb).URL,
		},
		"same Linux version": {
			platform: Platform{OS: "linux", Arch: "x86_64", Kind: KindDeb},
			version:  "2.5.1", build: 42, artifacts: []Artifact{linuxArtifact(KindDeb)},
			wantStatus: StatusIdle,
		},
		"no package of this kind": {
			platform: Platform{OS: "linux", Arch: "x86_64", Kind: KindArch},
			version:  "2.6.0", build: 42, artifacts: []Artifact{linuxArtifact(KindDeb)},
			wantStatus: StatusIdle,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			h := newHarness(t, tc.installer, tc.platform)
			h.server.publish(t, releaseWith(h.server, tc.version, tc.build, tc.artifacts...))

			r.NoError(h.updater.CheckNow(context.Background()))
			got := h.updater.Snapshot()
			r.Equal(tc.wantStatus, got.Status)
			r.Equal(tc.wantURL, got.DownloadURL)
		})
	}
}

func TestCheckShowsInstallFailures(t *testing.T) {
	tests := map[string]struct {
		installer   *fakeInstaller
		corrupt     bool
		wantFailure string
	}{
		"download mismatch": {
			installer: &fakeInstaller{replaceable: true}, corrupt: true,
			wantFailure: "The download didn't match the signed release, so scimtest deleted it. It will try again at the next check.",
		},
		"bundle rejected": {
			installer:   &fakeInstaller{replaceable: true, stageErr: errors.New("unsigned")},
			wantFailure: "The update didn't pass its signature checks, so scimtest deleted it. It will try again at the next check.",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			h := newHarness(t, tc.installer, macPlatform())
			release := releaseWith(h.server, "2.6.0", 42, macArtifact(KindAppZip))
			if tc.corrupt {
				h.server.files[macArtifact(KindAppZip).URL] = []byte("app-zip 9.9.9")
			}
			h.server.publish(t, release)

			r.Error(h.updater.CheckNow(context.Background()))
			got := h.updater.Snapshot()
			r.Equal(StatusFailed, got.Status)
			r.Equal("2.6.0", got.Version)
			r.Equal(tc.wantFailure, got.Failure)
		})
	}
}

func TestUnreachableFeedKeepsOffer(t *testing.T) {
	r := require.New(t)
	h := newHarness(t, nil, Platform{OS: "linux", Arch: "x86_64", Kind: KindDeb})
	h.server.publish(t, releaseWith(h.server, "2.6.0", 42, linuxArtifact(KindDeb)))
	r.NoError(h.updater.CheckNow(context.Background()))
	h.server.setFailing(true)

	r.Error(h.updater.CheckNow(context.Background()))
	r.Equal(StatusAvailable, h.updater.Snapshot().Status)
}

func stagedHarness(t *testing.T, installer *fakeInstaller) *updaterHarness {
	t.Helper()
	h := newHarness(t, installer, macPlatform())
	h.server.publish(t, releaseWith(h.server, "2.6.0", 42, macArtifact(KindAppZip)))
	require.New(t).NoError(h.updater.CheckNow(context.Background()))
	return h
}

func TestRestartAppliesAndQuits(t *testing.T) {
	r := require.New(t)
	h := stagedHarness(t, &fakeInstaller{replaceable: true})

	r.NoError(h.updater.Restart())
	r.Equal([]bool{true}, h.installer.applied)
	r.Equal(1, h.terminated)
	r.Equal(StatusRestarting, h.updater.Snapshot().Status)
	h.updater.InstallOnQuit()
	r.Equal([]bool{true}, h.installer.applied)
}

func TestRestartRespectsGuard(t *testing.T) {
	r := require.New(t)
	h := stagedHarness(t, &fakeInstaller{replaceable: true})
	h.updater.SetRestartGuard(func() error { return errors.New("a sync is running") })

	r.ErrorContains(h.updater.Restart(), "a sync is running")
	r.Empty(h.installer.applied)
	r.Zero(h.terminated)
	r.Equal(StatusReady, h.updater.Snapshot().Status)
}

func TestRestartFailure(t *testing.T) {
	tests := map[string]struct {
		applyErr      error
		wantDiscarded int
		wantFailure   string
	}{
		"not applied": {
			applyErr:      errors.New("another scimtest is updating this copy"),
			wantDiscarded: 1,
			wantFailure:   "scimtest couldn't replace itself: another scimtest is updating this copy",
		},
		"stranded": {
			applyErr:    &StrandedError{Previous: "/Applications/.scimtest-update-42/scimtest.app", Err: errors.New("start the relauncher")},
			wantFailure: "scimtest 2.6.0 is installed, but scimtest couldn't restart itself. Quit scimtest and open it again.",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			installer := &fakeInstaller{replaceable: true}
			h := stagedHarness(t, installer)
			installer.applyErr = tc.applyErr

			r.Error(h.updater.Restart())
			got := h.updater.Snapshot()
			r.Equal(StatusFailed, got.Status)
			r.Equal(tc.wantFailure, got.Failure)
			r.Equal(tc.wantDiscarded, installer.discarded)
			r.Zero(h.terminated)
			r.ErrorIs(h.updater.Restart(), ErrNotReady)
		})
	}
}

func TestInstallOnQuitAppliesWithoutRelaunch(t *testing.T) {
	r := require.New(t)
	h := stagedHarness(t, &fakeInstaller{replaceable: true})

	h.updater.InstallOnQuit()
	r.Equal([]bool{false}, h.installer.applied)
	r.Zero(h.terminated)
}

func TestNewerReleaseReplacesStagedUpdate(t *testing.T) {
	r := require.New(t)
	h := stagedHarness(t, &fakeInstaller{replaceable: true})
	newer := releaseWith(h.server, "2.7.0", 43, Artifact{OS: "macos", Arch: "arm64", Kind: KindAppZip, MinimumOS: "26.0", URL: artifactPrefix + "v2.7.0/scimtest.zip"})
	h.server.publish(t, newer)

	r.NoError(h.updater.CheckNow(context.Background()))
	r.Equal("2.7.0", h.updater.Snapshot().Version)
	r.Equal(1, h.installer.discarded)
}

func TestTakeUpdatedToAfterVersionChange(t *testing.T) {
	r := require.New(t)
	dir := t.TempDir()
	r.NoError(prefs{LastVersion: "2.5.1"}.save(filepath.Join(dir, "updater.json")))
	cfg := Config{Current: Install{Version: "2.6.0"}, StateDir: dir}

	updater, err := New(cfg)
	r.NoError(err)
	r.Equal("2.6.0", updater.TakeUpdatedTo())
	r.Empty(updater.TakeUpdatedTo())

	again, err := New(cfg)
	r.NoError(err)
	r.Empty(again.TakeUpdatedTo())
}
