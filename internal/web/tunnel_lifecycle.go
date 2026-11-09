package web

import (
	"errors"
	"sync"
)

type tunnelPhase string

const (
	tunnelIdle        tunnelPhase = ""
	tunnelConnecting  tunnelPhase = "connecting"
	tunnelAuthorizing tunnelPhase = "authorizing"
	tunnelConnected   tunnelPhase = "connected"
	tunnelFailed      tunnelPhase = "failed"
)

type tunnelMode uint8

const (
	tunnelOpen tunnelMode = iota
	tunnelResetting
	tunnelClosed
)

// tunnelLifecycle owns connection progress and admission. Its fields and
// transitions require mu; shutdown stays terminal even when a reset finishes.
type tunnelLifecycle struct {
	mu             sync.Mutex
	phase          tunnelPhase
	mode           tunnelMode
	active         *activeTunnel
	starting       *automaticTunnelStart
	lastError      string
	enrollmentURL  string
	enrollmentCode string
}

func (t *tunnelLifecycle) start(attempt *automaticTunnelStart) bool {
	if t.mode != tunnelOpen || t.starting != nil || t.active != nil {
		return false
	}
	t.starting = attempt
	t.phase = tunnelConnecting
	t.lastError = ""
	t.clearEnrollment()
	return true
}

func (t *tunnelLifecycle) finishStart(attempt *automaticTunnelStart) {
	if t.starting == attempt {
		t.starting = nil
	}
}

func (t *tunnelLifecycle) connect(entry *activeTunnel) {
	t.active = entry
	t.phase = tunnelConnected
	t.lastError = ""
	t.clearEnrollment()
}

func (t *tunnelLifecycle) fail(message string) {
	if t.mode == tunnelClosed {
		return
	}
	t.lastError = message
	t.clearEnrollment()
	if t.active == nil {
		t.phase = tunnelFailed
	}
}

func (t *tunnelLifecycle) accepts(attempt *automaticTunnelStart) bool {
	return t.mode == tunnelOpen && (t.starting == attempt ||
		(t.active != nil && t.active.attempt == attempt))
}

func (t *tunnelLifecycle) enroll(url, code string) {
	t.enrollmentURL = url
	t.enrollmentCode = code
	if t.active == nil {
		t.phase = tunnelAuthorizing
	}
}

func (t *tunnelLifecycle) clearEnrollment() {
	t.enrollmentURL = ""
	t.enrollmentCode = ""
	if t.phase == tunnelAuthorizing {
		t.phase = tunnelConnecting
	}
}

func (t *tunnelLifecycle) disconnect(entry *activeTunnel, message string) {
	if t.active != entry {
		return
	}
	t.active = nil
	t.fail(message)
}

func (t *tunnelLifecycle) beginReset() (*automaticTunnelStart, error) {
	switch t.mode {
	case tunnelClosed:
		return nil, errors.New("scimtest is shutting down")
	case tunnelResetting:
		return nil, errors.New("GitHub account sign-out is already in progress")
	}
	t.mode = tunnelResetting
	return t.starting, nil
}

func (t *tunnelLifecycle) endReset() {
	if t.mode == tunnelResetting {
		t.mode = tunnelOpen
	}
}

func (t *tunnelLifecycle) reset() *activeTunnel {
	entry := t.active
	t.active = nil
	t.phase = tunnelIdle
	t.lastError = ""
	t.clearEnrollment()
	t.endReset()
	return entry
}

func (t *tunnelLifecycle) close() (*automaticTunnelStart, *activeTunnel) {
	t.mode = tunnelClosed
	entry := t.active
	t.active = nil
	t.phase = tunnelIdle
	t.clearEnrollment()
	return t.starting, entry
}

func (t *tunnelLifecycle) retryAvailable() bool {
	return t.mode == tunnelOpen && t.phase == tunnelFailed && t.starting == nil
}

func (t *tunnelLifecycle) displayState(supported bool) string {
	if t.phase != tunnelIdle {
		return string(t.phase)
	}
	if supported {
		return string(tunnelConnecting)
	}
	return "unavailable"
}
