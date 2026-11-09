package web

import (
	"context"
	"encoding/json"
)

type syncJobPhase string

const (
	syncJobRunning   syncJobPhase = "running"
	syncJobStopping  syncJobPhase = "stopping"
	syncJobSucceeded syncJobPhase = "succeeded"
	syncJobFailed    syncJobPhase = "failed"
	syncJobCanceled  syncJobPhase = "canceled"
)

type syncJob struct {
	syncJobSnapshot
	cancel context.CancelFunc
}

// Running reports whether the job still owns sync admission.
func (j syncJobSnapshot) Running() bool {
	return j.Phase == syncJobRunning || j.Phase == syncJobStopping
}

// Done reports whether the worker has finished.
func (j syncJobSnapshot) Done() bool {
	switch j.Phase {
	case syncJobSucceeded, syncJobFailed, syncJobCanceled:
		return true
	default:
		return false
	}
}

// Success reports whether the worker completed without failures or cancellation.
func (j syncJobSnapshot) Success() bool {
	return j.Phase == syncJobSucceeded
}

// MarshalJSON derives the existing lifecycle fields for API clients.
func (j syncJobSnapshot) MarshalJSON() ([]byte, error) {
	type snapshot syncJobSnapshot
	return json.Marshal(struct {
		snapshot
		Running bool `json:"running"`
		Done    bool `json:"done"`
		Success bool `json:"success"`
	}{snapshot(j), j.Running(), j.Done(), j.Success()})
}
