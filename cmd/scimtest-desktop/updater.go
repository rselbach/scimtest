//go:build desktop

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/rselbach/scimtest/internal/update"
)

// updateLaunchDelay keeps the first update check out of the way of startup.
const updateLaunchDelay = 10 * time.Second

// newUpdater returns an updater for install, or an error when this build
// cannot check for updates.
func newUpdater(install update.Install, platform update.Platform, installer update.Installer, terminate func()) (*update.Updater, error) {
	if install.Version == "" || install.Version == "0.0.0" {
		return nil, fmt.Errorf("preview build %q does not update", install.Version)
	}
	key, err := update.ParsePublicKey(update.PublicKey)
	if err != nil {
		return nil, err
	}
	configDir, err := os.UserConfigDir()
	if err != nil {
		return nil, fmt.Errorf("get user config dir: %w", err)
	}
	return update.New(update.Config{
		FeedURL:     update.FeedURL,
		PublicKey:   key,
		Current:     install,
		Platform:    platform,
		StateDir:    filepath.Join(configDir, "scimtest", "updates"),
		Installer:   installer,
		Terminate:   terminate,
		LaunchDelay: updateLaunchDelay,
	})
}
