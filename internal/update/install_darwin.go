//go:build darwin

package update

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// CodeRequirement is what an update's code signature must satisfy: a
// notarized Developer ID application from scimtest's team, identified as
// scimtest. The release workflow checks release builds against the same file.
//
//go:embed requirement.txt
var CodeRequirement string

const (
	stagingPrefix = ".scimtest-update-"
	receiptName   = "receipt.json"
	appName       = "scimtest.app"
	lockTries     = 10
	// relaunchWaitTenths is how long, in tenths of a second, the relauncher
	// waits for this process to exit.
	relaunchWaitTenths = 600
)

// waiter polls the old process, then runs the given command. Its arguments
// arrive as positional parameters, never as shell text.
const waiter = `pid="$1"; shift; i=0
while /bin/kill -0 "$pid" 2>/dev/null; do
  i=$((i + 1))
  if [ "$i" -gt "$WAIT_TENTHS" ]; then exit 1; fi
  /bin/sleep 0.1
done
exec "$@"`

// MacInstaller replaces the running scimtest.app.
type MacInstaller struct {
	bundle    string
	build     uint64
	osVersion OSVersion
	// verify checks an unpacked app; tests replace it.
	verify func(app string, want expectedBundle) error
	// relaunch arranges for the bundle to open after this process exits;
	// tests replace it.
	relaunch func(bundle string) error
}

// NewMacInstaller returns an installer for bundle, which runs as build on
// osVersion.
func NewMacInstaller(bundle string, build uint64, osVersion OSVersion) *MacInstaller {
	return &MacInstaller{
		bundle:    bundle,
		build:     build,
		osVersion: osVersion,
		verify:    verifyBundle,
		relaunch:  relaunchAfterExit,
	}
}

// expectedBundle is what an unpacked app must be.
type expectedBundle struct {
	version     string
	build       uint64
	osVersion   OSVersion
	requirement string
}

// receipt records which install a staging folder belongs to.
type receipt struct {
	Installed string `json:"installed"`
	Build     uint64 `json:"build"`
}

// stagedBundle is a verified app beside the installed one. Its receipt stays
// locked by this process for as long as the value is referenced.
type stagedBundle struct {
	folder    string
	app       string
	installed string
	expected  expectedBundle
	receipt   *os.File
}

func (s *stagedBundle) Version() string { return s.expected.version }

func (s *stagedBundle) Build() uint64 { return s.expected.build }

// Replaceable reports whether the app can replace itself: not translocated,
// and both the bundle and its folder are writable by this user. Anything
// else gets the download instead of an escalation.
func (m *MacInstaller) Replaceable() bool {
	if !filepath.IsAbs(m.bundle) || strings.Contains(m.bundle, "/AppTranslocation/") {
		return false
	}
	return unix.Access(filepath.Dir(m.bundle), unix.W_OK) == nil && unix.Access(m.bundle, unix.W_OK) == nil
}

// Stage unpacks zip into a new staging folder beside the installed app and
// verifies the app inside. A failure removes the new folder.
func (m *MacInstaller) Stage(zip string, release Release) (Staged, error) {
	installed, err := filepath.EvalSymlinks(m.bundle)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", m.bundle, err)
	}
	folder, lock, err := claimFolder(filepath.Dir(installed), installed, release.Build)
	if err != nil {
		return nil, err
	}
	staged := &stagedBundle{
		folder:    folder,
		app:       filepath.Join(folder, appName),
		installed: installed,
		expected: expectedBundle{
			version:     release.Version,
			build:       release.Build,
			osVersion:   m.osVersion,
			requirement: CodeRequirement,
		},
		receipt: lock,
	}
	if err := unpack(zip, folder); err != nil {
		m.Discard(staged)
		return nil, err
	}
	if err := m.verify(staged.app, staged.expected); err != nil {
		m.Discard(staged)
		return nil, err
	}
	return staged, nil
}

// Apply checks staged again, holding a lock on the installed bundle, and
// swaps the two bundles in one rename. With relaunch, a detached waiter opens
// the new app once this process exits; if it cannot start, the swap is undone.
func (m *MacInstaller) Apply(update Staged, relaunch bool) error {
	staged, ok := update.(*stagedBundle)
	if !ok {
		return errors.New("not a staged scimtest update")
	}
	bundleLock, err := lockInstalled(staged.installed, m.build)
	if err != nil {
		return err
	}
	defer bundleLock.Close()
	if err := checkOwned(staged); err != nil {
		return err
	}
	if err := m.verify(staged.app, staged.expected); err != nil {
		return err
	}
	if err := swap(staged.app, staged.installed); err != nil {
		return err
	}
	if !relaunch {
		return nil
	}
	relaunchErr := m.relaunch(staged.installed)
	if relaunchErr == nil {
		return nil
	}
	if err := swap(staged.app, staged.installed); err != nil {
		return &StrandedError{Previous: staged.app, Err: fmt.Errorf("%w, and undoing the swap failed: %v", relaunchErr, err)}
	}
	return relaunchErr
}

// Discard removes a staged update that will not be installed.
func (m *MacInstaller) Discard(update Staged) {
	staged, ok := update.(*stagedBundle)
	if !ok {
		return
	}
	if err := checkOwned(staged); err != nil {
		fmt.Fprintf(os.Stderr, "leave staged update %s: %v\n", staged.folder, err)
		return
	}
	if err := removeStagingFolder(staged.folder); err != nil {
		fmt.Fprintf(os.Stderr, "remove staged update: %v\n", err)
	}
	if err := staged.receipt.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "close staged update receipt: %v\n", err)
	}
}

// RemoveLeftovers removes this install's staging folders that no process
// holds: the previous bundle after an update, or an update never applied.
// Folders of other copies, folders in use, and anything without this
// install's receipt stay.
func (m *MacInstaller) RemoveLeftovers() {
	installed, err := filepath.EvalSymlinks(m.bundle)
	if err != nil {
		return
	}
	parent := filepath.Dir(installed)
	entries, err := os.ReadDir(parent)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), stagingPrefix) {
			continue
		}
		folder := filepath.Join(parent, entry.Name())
		lock := ownedAndFree(folder, installed)
		if lock == nil {
			continue
		}
		if err := removeStagingFolder(folder); err != nil {
			fmt.Fprintf(os.Stderr, "remove earlier update: %v\n", err)
		}
		if err := lock.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "close earlier update receipt: %v\n", err)
		}
	}
}

// claimFolder creates a new staging folder in parent with a locked receipt.
func claimFolder(parent, installed string, build uint64) (string, *os.File, error) {
	data, err := json.Marshal(receipt{Installed: installed, Build: build})
	if err != nil {
		return "", nil, fmt.Errorf("encode update receipt: %w", err)
	}
	folder, err := os.MkdirTemp(parent, fmt.Sprintf("%s%d-", stagingPrefix, build))
	if err != nil {
		return "", nil, fmt.Errorf("create staging folder: %w", err)
	}
	path := filepath.Join(folder, receiptName)
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		// lock before writing: a reader that finds the receipt empty or
		// locked leaves the folder alone
		err = unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			_, err = file.Write(data)
		}
		if err == nil {
			err = file.Sync()
		}
		if err != nil {
			err = errors.Join(err, file.Close())
		}
	}
	if err != nil {
		if removeErr := removeStagingFolder(folder); removeErr != nil {
			err = errors.Join(err, removeErr)
		}
		return "", nil, fmt.Errorf("write update receipt: %w", err)
	}
	return folder, file, nil
}

// ownedAndFree opens and locks folder's receipt and returns it if it names
// installed: the folder belongs to this install and no process holds it.
func ownedAndFree(folder, installed string) *os.File {
	path := filepath.Join(folder, receiptName)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	var found receipt
	if !tryLock(file) || json.NewDecoder(file).Decode(&found) != nil || found.Installed != installed {
		if err := file.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "close update receipt: %v\n", err)
		}
		return nil
	}
	return file
}

// tryLock takes an exclusive flock on file. A child spawned at the wrong
// moment holds a copy of every lock until it execs, so contention gets a
// moment to clear first.
func tryLock(file *os.File) bool {
	for range lockTries {
		if unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB) == nil {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// lockInstalled locks the installed bundle against another process applying
// an update to it and checks that it is still the running build: if
// something already replaced it, installing would go backwards.
func lockInstalled(installed string, runningBuild uint64) (*os.File, error) {
	bundle, err := os.Open(installed)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", installed, err)
	}
	fail := func(err error) (*os.File, error) {
		return nil, errors.Join(err, bundle.Close())
	}
	if !tryLock(bundle) {
		return fail(errors.New("another scimtest is updating this copy"))
	}
	locked, err := bundle.Stat()
	if err != nil {
		return fail(fmt.Errorf("inspect %s: %w", installed, err))
	}
	current, err := os.Lstat(installed)
	if err != nil {
		return fail(fmt.Errorf("inspect %s: %w", installed, err))
	}
	build, err := plistValue(filepath.Join(installed, "Contents", "Info.plist"), "CFBundleVersion")
	if err != nil || !os.SameFile(locked, current) || build != strconv.FormatUint(runningBuild, 10) {
		return fail(fmt.Errorf("%s is no longer build %d", installed, runningBuild))
	}
	return bundle, nil
}

// checkOwned confirms the staging folder is still the one this process
// staged and locked, with a receipt naming the installed bundle.
func checkOwned(staged *stagedBundle) error {
	held, err := staged.receipt.Stat()
	if err != nil {
		return fmt.Errorf("inspect staged update: %w", err)
	}
	path := filepath.Join(staged.folder, receiptName)
	onDisk, err := os.Lstat(path)
	if err != nil || !os.SameFile(held, onDisk) {
		return fmt.Errorf("the staged update at %s lost its receipt", staged.folder)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read staged update receipt: %w", err)
	}
	var found receipt
	if json.Unmarshal(data, &found) != nil || found != (receipt{Installed: staged.installed, Build: staged.expected.build}) {
		return fmt.Errorf("the staged update at %s belongs to another install", staged.folder)
	}
	return nil
}

// relaunchAfterExit starts a detached waiter that opens bundle once this
// process exits, or gives up after a minute.
func relaunchAfterExit(bundle string) error {
	command := exec.Command("/bin/sh", "-c", waiter, "scimtest-relaunch", strconv.Itoa(os.Getpid()), "/usr/bin/open", bundle)
	command.Env = append(os.Environ(), "WAIT_TENTHS="+strconv.Itoa(relaunchWaitTenths))
	// its own process group, so nothing aimed at scimtest reaches it
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		return fmt.Errorf("start the relauncher: %w", err)
	}
	if err := command.Process.Release(); err != nil {
		return fmt.Errorf("release the relauncher: %w", err)
	}
	return nil
}

// swap exchanges two paths in one step.
func swap(a, b string) error {
	if err := unix.RenameatxNp(unix.AT_FDCWD, a, unix.AT_FDCWD, b, unix.RENAME_SWAP); err != nil {
		return fmt.Errorf("swap %s and %s: %w", a, b, err)
	}
	return nil
}

func unpack(zip, folder string) error {
	output, err := exec.Command("/usr/bin/ditto", "-x", "-k", zip, folder).CombinedOutput()
	if err != nil {
		return fmt.Errorf("unpack the update: %v: %s", err, bytes.TrimSpace(output))
	}
	return nil
}

// verifyBundle checks an unpacked app before anything runs from it.
func verifyBundle(app string, want expectedBundle) error {
	info, err := os.Lstat(app)
	if err != nil || !info.IsDir() {
		return errors.New("the update has no scimtest.app folder")
	}
	plist := filepath.Join(app, "Contents", "Info.plist")
	values := map[string]string{}
	for _, key := range []string{"CFBundleIdentifier", "CFBundleShortVersionString", "CFBundleVersion", "LSMinimumSystemVersion", "CFBundleExecutable"} {
		value, err := plistValue(plist, key)
		if err != nil {
			return err
		}
		values[key] = value
	}
	minimum, ok := ParseOSVersion(values["LSMinimumSystemVersion"])
	executable := values["CFBundleExecutable"]
	switch {
	case values["CFBundleIdentifier"] != BundleID:
		return fmt.Errorf("the update is %s, not %s", values["CFBundleIdentifier"], BundleID)
	case values["CFBundleShortVersionString"] != want.version:
		return fmt.Errorf("the update is version %s, not %s", values["CFBundleShortVersionString"], want.version)
	case values["CFBundleVersion"] != strconv.FormatUint(want.build, 10):
		return fmt.Errorf("the update is build %s, not %d", values["CFBundleVersion"], want.build)
	case !ok || want.osVersion.Less(minimum):
		return fmt.Errorf("the update needs macOS %s", values["LSMinimumSystemVersion"])
	case executable == "" || strings.Contains(executable, "/") || strings.HasPrefix(executable, "."):
		return fmt.Errorf("the update's executable is %q", executable)
	}
	if !hasARM64(filepath.Join(app, "Contents", "MacOS", executable)) {
		return errors.New("the update has no arm64 executable")
	}
	output, err := exec.Command("/usr/bin/codesign", "--verify", "--deep", "--strict", "-R="+strings.TrimSpace(want.requirement), app).CombinedOutput()
	if err != nil {
		return fmt.Errorf("the update's code signature is not scimtest's notarized Developer ID: %s", bytes.TrimSpace(output))
	}
	return nil
}

func plistValue(plist, key string) (string, error) {
	output, err := exec.Command("/usr/bin/plutil", "-extract", key, "raw", "-o", "-", plist).Output()
	if err != nil {
		return "", fmt.Errorf("the update's Info.plist has no %s", key)
	}
	return strings.TrimSpace(string(output)), nil
}

// hasARM64 reports whether the Mach-O file at path, thin or universal, has
// an arm64 slice.
func hasARM64(path string) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()
	head := make([]byte, 4096)
	n, err := file.Read(head)
	if err != nil {
		return false
	}
	return machOHasARM64(head[:n])
}

// removeStagingFolder removes a folder, which must be named like one.
func removeStagingFolder(folder string) error {
	if !strings.HasPrefix(filepath.Base(folder), stagingPrefix) {
		return fmt.Errorf("refuse to remove %s", folder)
	}
	return os.RemoveAll(folder)
}

// BundleInstall describes the scimtest.app at bundle on this Mac.
func BundleInstall(bundle string) (Install, error) {
	plist := filepath.Join(bundle, "Contents", "Info.plist")
	identifier, err := plistValue(plist, "CFBundleIdentifier")
	if err != nil {
		return Install{}, err
	}
	if identifier != BundleID {
		return Install{}, fmt.Errorf("%s is %s, not %s", bundle, identifier, BundleID)
	}
	version, err := plistValue(plist, "CFBundleShortVersionString")
	if err != nil {
		return Install{}, err
	}
	buildText, err := plistValue(plist, "CFBundleVersion")
	if err != nil {
		return Install{}, err
	}
	build, err := strconv.ParseUint(buildText, 10, 64)
	if err != nil {
		return Install{}, fmt.Errorf("%s has build %q", bundle, buildText)
	}
	productVersion, err := unix.Sysctl("kern.osproductversion")
	if err != nil {
		return Install{}, fmt.Errorf("read the macOS version: %w", err)
	}
	osVersion, ok := ParseOSVersion(productVersion)
	if !ok {
		return Install{}, fmt.Errorf("unrecognized macOS version %q", productVersion)
	}
	return Install{Version: version, Build: build, OSVersion: osVersion}, nil
}
