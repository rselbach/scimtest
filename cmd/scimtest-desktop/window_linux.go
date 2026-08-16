//go:build desktop && linux

package main

/*
#cgo pkg-config: gtk+-3.0
#include <gtk/gtk.h>
*/
import "C"

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

import webview "github.com/webview/webview_go"

func initializeDesktopWindowing() error {
	if err := configureLinuxWebKit(); err != nil {
		return err
	}
	if C.gtk_init_check(nil, nil) == C.FALSE {
		return errors.New("could not initialize GTK; a graphical desktop session is required")
	}
	return nil
}

func configureLinuxWebKit() error {
	if strings.TrimSpace(os.Getenv("WAYLAND_DISPLAY")) == "" ||
		strings.TrimSpace(os.Getenv("HYPRLAND_INSTANCE_SIGNATURE")) == "" ||
		strings.TrimSpace(os.Getenv("WEBKIT_DISABLE_DMABUF_RENDERER")) != "" {
		return nil
	}
	if err := os.Setenv("WEBKIT_DISABLE_DMABUF_RENDERER", "1"); err != nil {
		return fmt.Errorf("configure WebKit for Hyprland: %w", err)
	}
	return nil
}

func hasNativeWindow(window webview.WebView) bool {
	// New wraps a null C handle when GTK initialization fails, and Window then
	// dereferences that handle. initializeDesktopWindowing checked GTK first.
	return window != nil
}
