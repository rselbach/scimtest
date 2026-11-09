//go:build desktop && linux

package main

import (
	"os"
	"testing"
)

func TestConfigureLinuxWebKit(t *testing.T) {
	tests := map[string]struct {
		wayland  string
		hyprland string
		preset   string
		want     string
	}{
		"Hyprland Wayland": {wayland: "wayland-1", hyprland: "instance", want: "1"},
		"other compositor": {wayland: "wayland-1"},
		"X11":              {hyprland: "instance"},
		"existing setting": {wayland: "wayland-1", hyprland: "instance", preset: "custom", want: "custom"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Setenv("WAYLAND_DISPLAY", tc.wayland)
			t.Setenv("HYPRLAND_INSTANCE_SIGNATURE", tc.hyprland)
			t.Setenv("WEBKIT_DISABLE_DMABUF_RENDERER", tc.preset)

			if err := configureLinuxWebKit(); err != nil {
				t.Fatalf("configure Linux WebKit: %v", err)
			}
			if got := os.Getenv("WEBKIT_DISABLE_DMABUF_RENDERER"); got != tc.want {
				t.Errorf("WEBKIT_DISABLE_DMABUF_RENDERER = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestInitializeDesktopWindowingRequiresDisplay(t *testing.T) {
	t.Setenv("DISPLAY", "")
	t.Setenv("WAYLAND_DISPLAY", "")

	if err := initializeDesktopWindowing(); err == nil {
		t.Fatal("initialize desktop windowing without a display succeeded")
	}
}
