package web

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestResilienceEndpointRunAppliesConfiguredCount(t *testing.T) {
	r := require.New(t)
	svc := &webApp{}
	now := time.Date(2026, time.August, 14, 10, 0, 0, 0, time.UTC)

	run, err := svc.armResilienceRun("greendale", "token-outage", 2, now)
	r.NoError(err)
	r.Equal(resilienceRunArmed, run.State)

	for range 2 {
		action, ok := svc.takeResilienceEndpointAction("greendale", "token", now)
		r.True(ok)
		r.Equal(503, action.Status)
	}
	_, ok := svc.takeResilienceEndpointAction("greendale", "token", now)
	r.False(ok)

	run, ok = svc.resilienceRun("greendale", now)
	r.True(ok)
	r.Equal(resilienceRunCompleted, run.State)
	r.Equal("2 of 2 injections applied", run.progress())
	r.Len(run.Decisions, 2)
}

func TestResilienceFlowFaultAppliesOnce(t *testing.T) {
	r := require.New(t)
	svc := &webApp{}
	now := time.Date(2026, time.August, 14, 10, 0, 0, 0, time.UTC)

	_, err := svc.armResilienceRun("greendale", "expired-token", 0, now)
	r.NoError(err)
	r.True(svc.takeResilienceFlowFaults("greendale", now).IDTokenTTLSet)
	r.False(svc.takeResilienceFlowFaults("greendale", now).active())
}

func TestResilienceRunExpires(t *testing.T) {
	r := require.New(t)
	svc := &webApp{}
	now := time.Date(2026, time.August, 14, 10, 0, 0, 0, time.UTC)

	_, err := svc.armResilienceRun("greendale", "slow-token", 0, now)
	r.NoError(err)
	run, ok := svc.resilienceRun("greendale", now.Add(resilienceRunLifetime))
	r.True(ok)
	r.Equal(resilienceRunExpired, run.State)
	r.False(run.active())
	r.Len(run.Decisions, 1)
}

func TestExpiredResilienceRunCanBeReplaced(t *testing.T) {
	r := require.New(t)
	svc := &webApp{}
	now := time.Date(2026, time.August, 14, 10, 0, 0, 0, time.UTC)

	_, err := svc.armResilienceRun("greendale", "slow-token", 0, now)
	r.NoError(err)
	run, err := svc.armResilienceRun("greendale", "expired-token", 0, now.Add(resilienceRunLifetime))
	r.NoError(err)
	r.Equal("expired-token", run.PresetID)
}

func TestResilienceRejectsConcurrentRun(t *testing.T) {
	r := require.New(t)
	svc := &webApp{}
	now := time.Date(2026, time.August, 14, 10, 0, 0, 0, time.UTC)

	_, err := svc.armResilienceRun("greendale", "slow-token", 0, now)
	r.NoError(err)
	_, err = svc.armResilienceRun("greendale", "expired-token", 0, now)
	r.EqualError(err, "a resilience scenario is already active")
}

func TestResiliencePresetsMatchApplicationProtocols(t *testing.T) {
	tests := map[string]struct {
		app      app
		wantIDs  []string
		rejectID string
	}{
		"OIDC": {
			app:      app{Protocol: "oidc"},
			wantIDs:  []string{"token-outage", "slow-token", "expired-token", "broken-signature", "missing-email"},
			rejectID: "saml-auth-failed",
		},
		"SAML": {
			app:      app{Protocol: "saml"},
			wantIDs:  []string{"broken-signature", "saml-auth-failed"},
			rejectID: "token-outage",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var ids []string
			for _, preset := range resiliencePresetsForApp(tc.app) {
				ids = append(ids, preset.ID)
			}
			require.ElementsMatch(t, tc.wantIDs, ids)
			require.NotContains(t, ids, tc.rejectID)
		})
	}
}
