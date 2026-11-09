//go:build darwin

package update

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// writeBundle creates a scimtest.app at path whose marker file holds label.
func writeBundle(t *testing.T, path string, build uint64, label string) {
	t.Helper()
	r := require.New(t)
	r.NoError(os.MkdirAll(filepath.Join(path, "Contents", "MacOS"), 0o755))
	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>%s</string>
<key>CFBundleVersion</key><string>%d</string>
</dict></plist>
`, BundleID, build)
	r.NoError(os.WriteFile(filepath.Join(path, "Contents", "Info.plist"), []byte(plist), 0o644))
	r.NoError(os.WriteFile(filepath.Join(path, "Contents", "MacOS", "marker"), []byte(label), 0o644))
}

func marker(t *testing.T, bundle string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(bundle, "Contents", "MacOS", "marker"))
	require.New(t).NoError(err)
	return string(data)
}

type installFixture struct {
	installer *MacInstaller
	installed string
	zip       string
	relaunch  []string
	release   Release
}

func newInstallFixture(t *testing.T) *installFixture {
	t.Helper()
	r := require.New(t)
	root, err := filepath.EvalSymlinks(t.TempDir())
	r.NoError(err)
	f := &installFixture{installed: filepath.Join(root, "Applications", appName)}
	writeBundle(t, f.installed, 41, "old")

	source := filepath.Join(root, "source", appName)
	writeBundle(t, source, 42, "new")
	f.zip = filepath.Join(root, "update.zip")
	output, err := exec.Command("/usr/bin/ditto", "-c", "-k", "--keepParent", source, f.zip).CombinedOutput()
	r.NoError(err, string(output))

	f.release = testRelease()
	f.release.Build = 42
	f.installer = NewMacInstaller(f.installed, 41, OSVersion{26})
	f.installer.verify = func(app string, want expectedBundle) error {
		if marker(t, app) != "new" || want.build != 42 {
			return errors.New("not the update")
		}
		return nil
	}
	f.installer.relaunch = func(bundle string) error {
		f.relaunch = append(f.relaunch, bundle)
		return nil
	}
	return f
}

func stagingFolders(t *testing.T, installed string) []string {
	t.Helper()
	found, err := filepath.Glob(filepath.Join(filepath.Dir(installed), stagingPrefix+"*"))
	require.New(t).NoError(err)
	return found
}

func TestStageAndApplySwapsBundles(t *testing.T) {
	r := require.New(t)
	f := newInstallFixture(t)

	staged, err := f.installer.Stage(f.zip, f.release)
	r.NoError(err)
	r.NoError(f.installer.Apply(staged, true))
	r.Equal("new", marker(t, f.installed))
	r.Equal([]string{f.installed}, f.relaunch)

	previous := staged.(*stagedBundle)
	r.Equal("old", marker(t, previous.app))
	// the folder stays while this process holds its receipt
	f.installer.RemoveLeftovers()
	r.Len(stagingFolders(t, f.installed), 1)
	r.NoError(previous.receipt.Close())
	f.installer.RemoveLeftovers()
	r.Empty(stagingFolders(t, f.installed))
}

func TestApplyUndoesSwapWhenRelaunchFails(t *testing.T) {
	r := require.New(t)
	f := newInstallFixture(t)
	f.installer.relaunch = func(string) error { return errors.New("no relauncher") }
	staged, err := f.installer.Stage(f.zip, f.release)
	r.NoError(err)

	err = f.installer.Apply(staged, true)
	r.ErrorContains(err, "no relauncher")
	var stranded *StrandedError
	r.False(errors.As(err, &stranded))
	r.Equal("old", marker(t, f.installed))
}

func TestApplyRefusesChangedInstall(t *testing.T) {
	r := require.New(t)
	f := newInstallFixture(t)
	staged, err := f.installer.Stage(f.zip, f.release)
	r.NoError(err)
	writeBundle(t, f.installed, 40, "replaced")

	r.ErrorContains(f.installer.Apply(staged, false), "no longer build 41")
	r.Equal("replaced", marker(t, f.installed))
}

func TestStageRemovesRejectedUpdate(t *testing.T) {
	r := require.New(t)
	f := newInstallFixture(t)
	f.installer.verify = func(string, expectedBundle) error { return errors.New("unsigned") }

	_, err := f.installer.Stage(f.zip, f.release)
	r.ErrorContains(err, "unsigned")
	r.Empty(stagingFolders(t, f.installed))
}

func TestDiscardRemovesStagedUpdate(t *testing.T) {
	r := require.New(t)
	f := newInstallFixture(t)
	staged, err := f.installer.Stage(f.zip, f.release)
	r.NoError(err)

	f.installer.Discard(staged)
	r.Empty(stagingFolders(t, f.installed))
	r.Equal("old", marker(t, f.installed))
}

func TestRemoveLeftoversKeepsOtherInstalls(t *testing.T) {
	r := require.New(t)
	f := newInstallFixture(t)
	other := filepath.Join(filepath.Dir(f.installed), stagingPrefix+"other")
	r.NoError(os.MkdirAll(other, 0o755))
	r.NoError(os.WriteFile(filepath.Join(other, receiptName), []byte(`{"installed":"/Applications/elsewhere.app","build":42}`), 0o600))
	unowned := filepath.Join(filepath.Dir(f.installed), stagingPrefix+"unowned")
	r.NoError(os.MkdirAll(unowned, 0o755))

	f.installer.RemoveLeftovers()
	r.DirExists(other)
	r.DirExists(unowned)
}

func TestReplaceable(t *testing.T) {
	tests := map[string]struct {
		bundle func(t *testing.T) string
		want   bool
	}{
		"writable": {
			bundle: func(t *testing.T) string { return newInstallFixture(t).installed },
			want:   true,
		},
		"translocated": {
			bundle: func(*testing.T) string {
				return "/private/var/folders/x/AppTranslocation/ABC/d/scimtest.app"
			},
		},
		"relative": {
			bundle: func(*testing.T) string { return "scimtest.app" },
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			installer := NewMacInstaller(tc.bundle(t), 41, OSVersion{26})
			require.New(t).Equal(tc.want, installer.Replaceable())
		})
	}
}

func TestVerifyBundleRequiresScimtestSignature(t *testing.T) {
	r := require.New(t)
	app := filepath.Join(t.TempDir(), appName)
	writeBundle(t, app, 42, "new")
	plist := filepath.Join(app, "Contents", "Info.plist")
	for key, value := range map[string]string{
		"CFBundleShortVersionString": "2.6.0",
		"LSMinimumSystemVersion":     "26.0",
		"CFBundleExecutable":         "scimtest",
	} {
		output, err := exec.Command("/usr/bin/plutil", "-insert", key, "-string", value, plist).CombinedOutput()
		r.NoError(err, string(output))
	}
	// an Apple-signed arm64 binary passes every check but the requirement
	executable, err := os.ReadFile("/usr/bin/true")
	r.NoError(err)
	r.NoError(os.WriteFile(filepath.Join(app, "Contents", "MacOS", "scimtest"), executable, 0o755))

	err = verifyBundle(app, expectedBundle{version: "2.6.0", build: 42, osVersion: OSVersion{26}, requirement: CodeRequirement})
	r.ErrorContains(err, "code signature is not scimtest's")
}
