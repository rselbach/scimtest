//go:build desktop && darwin

package main

import (
	"errors"
	"os"
	"testing"
)

var installedMenuHasQuitItem bool
var installedMenuHasUpdateItem bool
var installedMenuHasReleaseNotesItem bool
var installedMenuIsStandard bool

func TestMain(m *testing.M) {
	installApplicationMenu()
	installedMenuHasQuitItem = applicationMenuHasQuitItem()
	installedMenuHasUpdateItem = applicationMenuHasUpdateItem()
	installedMenuHasReleaseNotesItem = applicationMenuHasReleaseNotesItem()
	installedMenuIsStandard = applicationMenuIsStandard()
	os.Exit(m.Run())
}

func TestInstallApplicationMenuAddsUpdateItem(t *testing.T) {
	if !installedMenuHasUpdateItem {
		t.Fatal("scimtest application menu has no update item")
	}
}

func TestInstallApplicationMenuAddsReleaseNotesItem(t *testing.T) {
	if !installedMenuHasReleaseNotesItem {
		t.Fatal("scimtest application menu has no release notes item")
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

func TestNativeQuitInstallsStagedUpdate(t *testing.T) {
	if !applicationDelegateInstallsOnQuit() {
		t.Fatal("the application delegate does not install a staged update on quit")
	}
}

func TestSentenceHandlesMultibyteAndInvalidUTF8(t *testing.T) {
	tests := map[string]struct {
		in   string
		want string
	}{
		"ascii":        {in: "network unreachable", want: "Network unreachable."},
		"multibyte":    {in: "érror from Greendale", want: "Érror from Greendale."},
		"empty":        {in: "", want: ""},
		"invalid utf8": {in: "\xffbad", want: "\xffbad."},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := sentence(errors.New(tc.in)); got != tc.want {
				t.Fatalf("sentence(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
