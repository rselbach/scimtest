//go:build desktop && linux

package main

import (
	"errors"

	"github.com/rselbach/scimtest/internal/update"
)

// Release builds set these with -ldflags -X.
var (
	desktopVersion     string
	desktopPackageKind string
)

// newDesktopUpdater offers newer packages for download; the package manager
// installs them.
func newDesktopUpdater(terminate func()) (*update.Updater, error) {
	if desktopPackageKind == "" {
		return nil, errors.New("build has no package kind")
	}
	platform := update.Platform{OS: "linux", Arch: update.Arch(), Kind: desktopPackageKind}
	return newUpdater(update.Install{Version: desktopVersion}, platform, nil, terminate)
}

func setDesktopUpdater(*update.Updater) {}
