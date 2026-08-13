//go:build desktop && darwin

package main

import (
	"os"
	"testing"
)

var installedMenuHasQuitItem bool
var installedMenuHasUpdateItem bool
var installedMenuIsStandard bool

func TestMain(m *testing.M) {
	installApplicationMenu()
	installedMenuHasQuitItem = applicationMenuHasQuitItem()
	installedMenuHasUpdateItem = applicationMenuHasUpdateItem()
	installedMenuIsStandard = applicationMenuIsStandard()
	os.Exit(m.Run())
}

func TestInstallApplicationMenuAddsUpdateItem(t *testing.T) {
	if !installedMenuHasUpdateItem {
		t.Fatal("scimtest application menu has no update item")
	}
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
