//go:build desktop && darwin

package main

/*
#include <stdlib.h>

void scimtest_show_update_alert(const char *title, const char *message);
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"github.com/rselbach/scimtest/internal/update"
)

// update menu states the native menu understands
const (
	updateMenuUnavailable = 0
	updateMenuCheck       = 1
	updateMenuRestart     = 2
	updateMenuBusy        = 3
)

const menuCheckTimeout = 5 * time.Minute

// desktopUpdater is set before the menu is installed and never changes.
var desktopUpdater *update.Updater

// newDesktopUpdater updates the running scimtest.app in place.
func newDesktopUpdater(terminate func()) (*update.Updater, error) {
	bundle, err := runningBundle()
	if err != nil {
		return nil, err
	}
	install, err := update.BundleInstall(bundle)
	if err != nil {
		return nil, err
	}
	platform := update.Platform{OS: "macos", Arch: update.Arch()}
	installer := update.NewMacInstaller(bundle, install.Build, install.OSVersion)
	return newUpdater(install, platform, installer, terminate)
}

// runningBundle is the scimtest.app holding this executable.
func runningBundle() (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("find the executable: %w", err)
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return "", fmt.Errorf("resolve the executable: %w", err)
	}
	macOS := filepath.Dir(executable)
	contents := filepath.Dir(macOS)
	bundle := filepath.Dir(contents)
	if filepath.Base(macOS) != "MacOS" || filepath.Base(contents) != "Contents" || !strings.HasSuffix(bundle, ".app") {
		return "", errors.New("scimtest is not running from an application bundle")
	}
	return bundle, nil
}

func updateMenuState(updater *update.Updater) int {
	if updater == nil {
		return updateMenuUnavailable
	}
	switch updater.Snapshot().Status {
	case update.StatusReady:
		return updateMenuRestart
	case update.StatusRestarting:
		return updateMenuBusy
	default:
		return updateMenuCheck
	}
}

//export scimtestUpdateMenuState
func scimtestUpdateMenuState() C.int {
	return C.int(updateMenuState(desktopUpdater))
}

// scimtestUpdateMenuVersion returns the offered version; the caller frees it.
//
//export scimtestUpdateMenuVersion
func scimtestUpdateMenuVersion() *C.char {
	if desktopUpdater == nil {
		return C.CString("")
	}
	return C.CString(desktopUpdater.Snapshot().Version)
}

//export scimtestInstallUpdateOnQuit
func scimtestInstallUpdateOnQuit() {
	if desktopUpdater != nil {
		desktopUpdater.InstallOnQuit()
	}
}

//export scimtestUpdateMenuAction
func scimtestUpdateMenuAction() {
	go runUpdateMenuAction(desktopUpdater)
}

// runUpdateMenuAction restarts into a ready update, or checks and reports
// what it found.
func runUpdateMenuAction(updater *update.Updater) {
	switch updateMenuState(updater) {
	case updateMenuRestart:
		if err := updater.Restart(); err != nil {
			showUpdateAlert("scimtest couldn't restart to update", sentence(err))
		}
		return
	case updateMenuCheck:
	default:
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), menuCheckTimeout)
	defer cancel()
	if err := updater.CheckNow(ctx); err != nil {
		snapshot := updater.Snapshot()
		if snapshot.Status == update.StatusFailed {
			showUpdateAlert(fmt.Sprintf("scimtest %s couldn't be installed", snapshot.Version), snapshot.Failure)
			return
		}
		showUpdateAlert("scimtest couldn't check for updates", sentence(err))
		return
	}
	snapshot := updater.Snapshot()
	switch snapshot.Status {
	case update.StatusReady:
		showUpdateAlert(fmt.Sprintf("scimtest %s is ready", snapshot.Version), "Choose Restart to Update in the scimtest menu or the toolbar to finish updating.")
	case update.StatusAvailable:
		showUpdateAlert(fmt.Sprintf("scimtest %s is available", snapshot.Version), "This copy of scimtest can't replace itself. Use Update available in the toolbar to download the new version.")
	case update.StatusFailed:
		showUpdateAlert(fmt.Sprintf("scimtest %s couldn't be installed", snapshot.Version), snapshot.Failure)
	default:
		showUpdateAlert("You're up to date", fmt.Sprintf("scimtest %s is the newest version.", snapshot.CurrentVersion))
	}
}

func sentence(err error) string {
	text := err.Error()
	if text == "" {
		return text
	}
	return strings.ToUpper(text[:1]) + text[1:] + "."
}

func showUpdateAlert(title, message string) {
	cTitle := C.CString(title)
	defer C.free(unsafe.Pointer(cTitle))
	cMessage := C.CString(message)
	defer C.free(unsafe.Pointer(cMessage))
	C.scimtest_show_update_alert(cTitle, cMessage)
}

func setDesktopUpdater(updater *update.Updater) {
	desktopUpdater = updater
}
