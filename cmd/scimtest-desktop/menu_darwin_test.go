//go:build desktop && darwin

package main

import (
	"os"
	"testing"
)

var installedMenuHasQuitItem bool

func TestMain(m *testing.M) {
	installApplicationMenu()
	installedMenuHasQuitItem = applicationMenuHasQuitItem()
	os.Exit(m.Run())
}

func TestInstallApplicationMenuAddsQuitShortcut(t *testing.T) {
	if !installedMenuHasQuitItem {
		t.Fatal("scimtest application menu has no Command-Q quit item")
	}
}
