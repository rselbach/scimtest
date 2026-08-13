//go:build desktop && darwin

package main

import (
	"os"
	"testing"
)

var installedMenuHasQuitItem bool
var installedMenuIsStandard bool

func TestMain(m *testing.M) {
	installApplicationMenu()
	installedMenuHasQuitItem = applicationMenuHasQuitItem()
	installedMenuIsStandard = applicationMenuIsStandard()
	os.Exit(m.Run())
}

func TestInstallApplicationMenuAddsQuitShortcut(t *testing.T) {
	if !installedMenuHasQuitItem {
		t.Fatal("scimtest application menu has no Command-Q quit item")
	}
}

func TestInstallApplicationMenuAddsStandardMenus(t *testing.T) {
	if !installedMenuIsStandard {
		t.Fatal("scimtest has an incomplete macOS menu bar")
	}
}
