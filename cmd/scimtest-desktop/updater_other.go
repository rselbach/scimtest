//go:build desktop && !darwin && !linux

package main

import (
	"errors"

	"github.com/rselbach/scimtest/internal/update"
)

func newDesktopUpdater(func()) (*update.Updater, error) {
	return nil, errors.New("updates are not available on this platform")
}

func setDesktopUpdater(*update.Updater) {}
