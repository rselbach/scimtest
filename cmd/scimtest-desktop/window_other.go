//go:build desktop && !linux

package main

import webview "github.com/webview/webview_go"

func initializeDesktopWindowing() error {
	return nil
}

func hasNativeWindow(window webview.WebView) bool {
	return window != nil && window.Window() != nil
}
