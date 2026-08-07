//go:build windows

package web

import (
	"errors"

	"golang.org/x/sys/windows"
)

// syscall.EADDRINUSE is a synthetic errno on Windows and never matches the
// WSAEADDRINUSE that a failed bind actually returns.
func isAddrInUse(err error) bool {
	return errors.Is(err, windows.WSAEADDRINUSE)
}
