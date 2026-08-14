package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	resilienceRunLifetime  = 15 * time.Minute
	maxResilienceDecisions = 20
)

type resilienceRunState string

const (
	resilienceRunArmed     resilienceRunState = "armed"
	resilienceRunRunning   resilienceRunState = "running"
	resilienceRunCompleted resilienceRunState = "completed"
	resilienceRunDisarmed  resilienceRunState = "disarmed"
	resilienceRunExpired   resilienceRunState = "expired"
)

type resilienceAction struct {
	Faults     faultOptions
	Status     int
	OAuthError string
	RetryAfter string
	Delay      time.Duration
}

func (a resilienceAction) describe() string {
	switch {
	case a.Status != 0:
		detail := fmt.Sprintf("HTTP %d", a.Status)
		if a.RetryAfter != "" {
			detail += " with Retry-After " + a.RetryAfter
		}
		return detail
	case a.Delay != 0:
		return "delay " + a.Delay.String()
	case a.Faults.active():
		return a.Faults.describe()
	default:
		return "healthy response"
	}
}

type resiliencePreset struct {
	ID           string
	Name         string
	Summary      string
	Protocol     string
	Phase        string
	Action       resilienceAction
	DefaultCount int
	AllowCount   bool
}

var resiliencePresets = []resiliencePreset{
	{
		ID:       "token-outage",
		Name:     "Token endpoint outage",
		Summary:  "Return a temporary error before recovering normally.",
		Protocol: "oidc",
		Phase:    "token",
		Action: resilienceAction{
			Status:     http.StatusServiceUnavailable,
			OAuthError: "temporarily_unavailable",
			RetryAfter: "5",
		},
		DefaultCount: 2,
		AllowCount:   true,
	},
	{
		ID:           "slow-token",
		Name:         "Slow token endpoint",
		Summary:      "Delay token redemption long enough to expose timeout handling.",
		Protocol:     "oidc",
		Phase:        "token",
		Action:       resilienceAction{Delay: 3 * time.Second},
		DefaultCount: 1,
	},
	{
		ID:       "expired-token",
		Name:     "Expired ID token",
		Summary:  "Issue a correctly formed ID token that is already expired.",
		Protocol: "oidc",
		Phase:    "flow",
		Action: resilienceAction{Faults: faultOptions{
			IDTokenTTL:    -time.Minute,
			IDTokenTTLSet: true,
		}},
		DefaultCount: 1,
	},
	{
		ID:           "broken-signature",
		Name:         "Invalid signature",
		Summary:      "Corrupt the token or assertion signature without changing its shape.",
		Protocol:     "both",
		Phase:        "flow",
		Action:       resilienceAction{Faults: faultOptions{BreakSignature: true}},
		DefaultCount: 1,
	},
	{
		ID:           "missing-email",
		Name:         "Missing email claim",
		Summary:      "Omit email from the ID token and userinfo response.",
		Protocol:     "oidc",
		Phase:        "flow",
		Action:       resilienceAction{Faults: faultOptions{DropClaims: []string{"email"}}},
		DefaultCount: 1,
	},
	{
		ID:       "saml-auth-failed",
		Name:     "SAML authentication failure",
		Summary:  "Return an AuthnFailed status instead of a signed assertion.",
		Protocol: "saml",
		Phase:    "flow",
		Action: resilienceAction{Faults: faultOptions{
			SAMLStatus: "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed",
		}},
		DefaultCount: 1,
	},
}

func resiliencePresetByID(id string) (resiliencePreset, bool) {
	for _, preset := range resiliencePresets {
		if preset.ID == id {
			return preset, true
		}
	}
	return resiliencePreset{}, false
}

func resiliencePresetsForApp(foundApp app) []resiliencePreset {
	presets := make([]resiliencePreset, 0, len(resiliencePresets))
	for _, preset := range resiliencePresets {
		if preset.Protocol == "both" || preset.Protocol == foundApp.Protocol ||
			(preset.Protocol == "oidc" && supportsOIDC(foundApp)) ||
			(preset.Protocol == "saml" && supportsSAML(foundApp)) {
			presets = append(presets, preset)
		}
	}
	return presets
}

type resilienceDecision struct {
	Time    string
	Phase   string
	Outcome string
	Detail  string
}

type resilienceRun struct {
	ID        string
	PresetID  string
	Name      string
	Summary   string
	Protocol  string
	Phase     string
	State     resilienceRunState
	Action    resilienceAction
	Total     int
	Remaining int
	ArmedAt   time.Time
	ExpiresAt time.Time
	Decisions []resilienceDecision
}

func (r resilienceRun) active() bool {
	return r.State == resilienceRunArmed || r.State == resilienceRunRunning
}

func (r resilienceRun) progress() string {
	applied := r.Total - r.Remaining
	return fmt.Sprintf("%d of %d injections applied", applied, r.Total)
}

func (a *webApp) armResilienceRun(slug, presetID string, count int, now time.Time) (resilienceRun, error) {
	preset, ok := resiliencePresetByID(strings.TrimSpace(presetID))
	if !ok {
		return resilienceRun{}, errors.New("unknown resilience scenario")
	}
	if !preset.AllowCount || count == 0 {
		count = preset.DefaultCount
	}
	if count < 1 || count > 20 {
		return resilienceRun{}, errors.New("failure count must be between 1 and 20")
	}
	id, err := randomSecret(12)
	if err != nil {
		return resilienceRun{}, fmt.Errorf("create resilience run: %w", err)
	}
	run := resilienceRun{
		ID:        id,
		PresetID:  preset.ID,
		Name:      preset.Name,
		Summary:   preset.Summary,
		Protocol:  preset.Protocol,
		Phase:     preset.Phase,
		State:     resilienceRunArmed,
		Action:    preset.Action,
		Total:     count,
		Remaining: count,
		ArmedAt:   now,
		ExpiresAt: now.Add(resilienceRunLifetime),
	}
	a.resilienceMu.Lock()
	defer a.resilienceMu.Unlock()
	if a.resilienceRuns == nil {
		a.resilienceRuns = make(map[string]resilienceRun)
	}
	if current, found := a.resilienceRuns[slug]; found && current.active() {
		if now.Before(current.ExpiresAt) {
			return resilienceRun{}, errors.New("a resilience scenario is already active")
		}
		current.expire(now)
		a.resilienceRuns[slug] = current
	}
	a.resilienceRuns[slug] = run
	return run, nil
}

func (a *webApp) resilienceRun(slug string, now time.Time) (resilienceRun, bool) {
	a.resilienceMu.Lock()
	defer a.resilienceMu.Unlock()
	run, ok := a.resilienceRuns[slug]
	if !ok {
		return resilienceRun{}, false
	}
	if run.active() && !now.Before(run.ExpiresAt) {
		run.expire(now)
		a.resilienceRuns[slug] = run
	}
	return cloneResilienceRun(run), true
}

func (a *webApp) takeResilienceFlowFaults(slug string, now time.Time) faultOptions {
	a.resilienceMu.Lock()
	defer a.resilienceMu.Unlock()
	run, ok := a.resilienceRuns[slug]
	if !ok || !run.active() || run.Phase != "flow" || !now.Before(run.ExpiresAt) {
		return faultOptions{}
	}
	run.State = resilienceRunCompleted
	run.Remaining = 0
	run.addDecision("flow", "injected", run.Action.describe(), now)
	a.resilienceRuns[slug] = run
	return run.Action.Faults
}

func (a *webApp) takeResilienceEndpointAction(slug, phase string, now time.Time) (resilienceAction, bool) {
	a.resilienceMu.Lock()
	defer a.resilienceMu.Unlock()
	run, ok := a.resilienceRuns[slug]
	if !ok || !run.active() || run.Phase != phase || !now.Before(run.ExpiresAt) {
		return resilienceAction{}, false
	}
	run.State = resilienceRunRunning
	run.Remaining--
	run.addDecision(phase, "injected", run.Action.describe(), now)
	if run.Remaining == 0 {
		run.State = resilienceRunCompleted
	}
	a.resilienceRuns[slug] = run
	return run.Action, true
}

func (a *webApp) resilienceEndpoint(protocol, phase string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slug := r.PathValue("slug")
		action, ok := a.takeResilienceEndpointAction(slug, phase, time.Now())
		if !ok {
			next(w, r)
			return
		}
		if action.Delay > 0 {
			a.recordFlowEvent(slug, protocol, phase, "ok", "", "Injected "+action.describe())
			if !waitForResilienceDelay(r.Context(), action.Delay) {
				return
			}
		}
		if action.Status == 0 {
			next(w, r)
			return
		}
		if action.RetryAfter != "" {
			w.Header().Set("Retry-After", action.RetryAfter)
		}
		detail := action.describe()
		if action.OAuthError != "" {
			detail = action.OAuthError + ": injected " + detail
			a.recordFlowEvent(slug, protocol, phase, "failed", "", detail)
			writeOAuthError(w, action.Status, action.OAuthError, "injected resilience scenario")
			return
		}
		a.recordFlowEvent(slug, protocol, phase, "failed", "", "Injected "+detail)
		http.Error(w, "injected resilience scenario", action.Status)
	}
}

func waitForResilienceDelay(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func (r *resilienceRun) addDecision(phase, outcome, detail string, now time.Time) {
	r.Decisions = append(r.Decisions, resilienceDecision{
		Time:    now.Format(time.RFC3339),
		Phase:   phase,
		Outcome: outcome,
		Detail:  detail,
	})
	if len(r.Decisions) > maxResilienceDecisions {
		r.Decisions = r.Decisions[len(r.Decisions)-maxResilienceDecisions:]
	}
}

func (r *resilienceRun) expire(now time.Time) {
	r.State = resilienceRunExpired
	r.Remaining = 0
	r.addDecision("scenario", "expired", "No matching flow arrived before the safety timeout", now)
}

func cloneResilienceRun(run resilienceRun) resilienceRun {
	run.Decisions = append([]resilienceDecision(nil), run.Decisions...)
	run.Action.Faults.DropClaims = append([]string(nil), run.Action.Faults.DropClaims...)
	return run
}
