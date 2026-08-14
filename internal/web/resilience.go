package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
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
	RunID      string
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
	InFlight  int
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

func (a *webApp) reserveResilienceEndpointAction(slug, phase string, now time.Time) (resilienceAction, bool) {
	a.resilienceMu.Lock()
	defer a.resilienceMu.Unlock()
	run, ok := a.resilienceRuns[slug]
	if !ok || !run.active() || run.Phase != phase || !now.Before(run.ExpiresAt) || run.Remaining-run.InFlight < 1 {
		return resilienceAction{}, false
	}
	run.State = resilienceRunRunning
	run.InFlight++
	a.resilienceRuns[slug] = run
	action := run.Action
	action.RunID = run.ID
	return action, true
}

func (a *webApp) disarmResilienceRun(slug string, now time.Time) bool {
	a.resilienceMu.Lock()
	defer a.resilienceMu.Unlock()
	run, ok := a.resilienceRuns[slug]
	if !ok || !run.active() {
		return false
	}
	run.State = resilienceRunDisarmed
	// Reserved endpoint actions have not been delivered yet. Disarming makes
	// their later completion a no-op and leaves progress unchanged.
	run.InFlight = 0
	run.addDecision("scenario", "disarmed", "Disarmed by the developer", now)
	a.resilienceRuns[slug] = run
	return true
}

func (a *webApp) completeResilienceEndpointAction(slug, phase string, action resilienceAction, now time.Time) bool {
	a.resilienceMu.Lock()
	defer a.resilienceMu.Unlock()
	run, ok := a.resilienceRuns[slug]
	if !ok || !run.active() || run.ID != action.RunID || run.InFlight < 1 || run.Remaining < 1 {
		return false
	}
	run.InFlight--
	run.Remaining--
	run.addDecision(phase, "injected", action.describe(), now)
	if run.Remaining == 0 && run.InFlight == 0 {
		run.State = resilienceRunCompleted
	}
	a.resilienceRuns[slug] = run
	return true
}

func (a *webApp) cancelResilienceEndpointAction(slug, phase string, action resilienceAction, now time.Time) {
	a.resilienceMu.Lock()
	defer a.resilienceMu.Unlock()
	run, ok := a.resilienceRuns[slug]
	if !ok || run.ID != action.RunID || run.InFlight < 1 {
		return
	}
	run.InFlight--
	if run.Remaining == run.Total && run.InFlight == 0 {
		run.State = resilienceRunArmed
	}
	run.addDecision(phase, "canceled", "Request ended before the fault was delivered", now)
	a.resilienceRuns[slug] = run
}

func (a *webApp) writeResilienceEndpointFailure(w http.ResponseWriter, slug, protocol, phase string, action resilienceAction) {
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
	r.InFlight = 0
	r.addDecision("scenario", "expired", "No matching flow arrived before the safety timeout", now)
}

func cloneResilienceRun(run resilienceRun) resilienceRun {
	run.Decisions = append([]resilienceDecision(nil), run.Decisions...)
	run.Action.Faults.DropClaims = append([]string(nil), run.Action.Faults.DropClaims...)
	return run
}

type resiliencePresetView struct {
	ID         string
	Name       string
	Summary    string
	Protocol   string
	Behavior   string
	Count      int
	AllowCount bool
}

type resilienceRunView struct {
	Name        string
	Summary     string
	State       string
	StatusClass string
	Active      bool
	Progress    string
	Behavior    string
	ArmedAt     string
	ExpiresAt   string
	Decisions   []resilienceDecision
}

type resiliencePageData struct {
	App             app
	Presets         []resiliencePresetView
	Run             *resilienceRunView
	CanChoose       bool
	Error           string
	OIDC            bool
	SAML            bool
	OIDCInspector   string
	SAMLInspector   string
	PlaygroundURL   string
	PlaygroundReady bool
	SetupURL        string
}

func (a *webApp) handleResilience(w http.ResponseWriter, r *http.Request) {
	_, foundApp, ok := appForProtocol(w, r, supportsAnyIDP)
	if !ok {
		return
	}
	http.Redirect(w, r, resilienceDashboardURL(foundApp, nil), http.StatusSeeOther)
}

func (a *webApp) buildResiliencePageData(foundApp app, pageError string) *resiliencePageData {
	presets := resiliencePresetsForApp(foundApp)
	presetViews := make([]resiliencePresetView, 0, len(presets))
	for _, preset := range presets {
		presetViews = append(presetViews, resiliencePresetView{
			ID:         preset.ID,
			Name:       preset.Name,
			Summary:    preset.Summary,
			Protocol:   strings.ToUpper(preset.Protocol),
			Behavior:   preset.Action.describe(),
			Count:      preset.DefaultCount,
			AllowCount: preset.AllowCount,
		})
	}
	slug := url.PathEscape(foundApp.Slug)
	data := &resiliencePageData{
		App:           foundApp,
		Presets:       presetViews,
		Error:         strings.TrimSpace(pageError),
		OIDC:          supportsOIDC(foundApp),
		SAML:          supportsSAML(foundApp),
		OIDCInspector: "/inspect/oidc/" + slug,
		SAMLInspector: "/inspect/saml/" + slug,
		PlaygroundURL: "/inspect/oidc/" + slug + "/playground",
		PlaygroundReady: supportsOIDC(foundApp) && strings.TrimSpace(foundApp.OIDCClientID) != "" &&
			(foundApp.OIDCPublicClient || strings.TrimSpace(foundApp.OIDCClientSecret) != ""),
		SetupURL: dashboardURL("apps", map[string]string{
			"environment": foundApp.ID,
			"id":          foundApp.ID,
			"modal":       "app",
		}),
	}
	if run, found := a.resilienceRun(foundApp.Slug, time.Now()); found {
		data.Run = newResilienceRunView(run)
	}
	data.CanChoose = data.Run == nil || !data.Run.Active
	return data
}

func (a *webApp) handleResilienceArm(w http.ResponseWriter, r *http.Request) {
	_, foundApp, ok := appForProtocol(w, r, supportsAnyIDP)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		redirectResilienceError(w, r, foundApp, err)
		return
	}
	presetID := strings.TrimSpace(r.FormValue("preset"))
	if !resiliencePresetAvailable(foundApp, presetID) {
		redirectResilienceError(w, r, foundApp, errors.New("scenario is not available for this environment"))
		return
	}
	count := 0
	if raw := strings.TrimSpace(r.FormValue("count")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			redirectResilienceError(w, r, foundApp, errors.New("failure count must be a number"))
			return
		}
		count = parsed
	}
	run, err := a.armResilienceRun(foundApp.Slug, presetID, count, time.Now())
	if err != nil {
		redirectResilienceError(w, r, foundApp, err)
		return
	}
	// A scenario and a quick fault must never compete for the next flow.
	a.disarmFaults(foundApp.Slug)
	a.recordFlowEvent(foundApp.Slug, "fault", "scenario", "ok", "", "Armed: "+run.Name)
	http.Redirect(w, r, resilienceDashboardURL(foundApp, nil), http.StatusSeeOther)
}

func (a *webApp) handleResilienceDisarm(w http.ResponseWriter, r *http.Request) {
	_, foundApp, ok := appForProtocol(w, r, supportsAnyIDP)
	if !ok {
		return
	}
	if a.disarmResilienceRun(foundApp.Slug, time.Now()) {
		a.recordFlowEvent(foundApp.Slug, "fault", "scenario", "ok", "", "Disarmed")
	}
	http.Redirect(w, r, resilienceDashboardURL(foundApp, nil), http.StatusSeeOther)
}

func resiliencePresetAvailable(foundApp app, presetID string) bool {
	for _, preset := range resiliencePresetsForApp(foundApp) {
		if preset.ID == presetID {
			return true
		}
	}
	return false
}

func resilienceDashboardURL(foundApp app, extra map[string]string) string {
	values := map[string]string{"environment": foundApp.ID}
	for key, value := range extra {
		values[key] = value
	}
	return dashboardURL("resilience", values)
}

func redirectResilienceError(w http.ResponseWriter, r *http.Request, foundApp app, err error) {
	http.Redirect(w, r, resilienceDashboardURL(foundApp, map[string]string{"error": err.Error()}), http.StatusSeeOther)
}

func newResilienceRunView(run resilienceRun) *resilienceRunView {
	state := string(run.State)
	statusClass := "deleted"
	switch run.State {
	case resilienceRunArmed, resilienceRunRunning:
		statusClass = "pending"
	case resilienceRunCompleted:
		statusClass = "synced"
	case resilienceRunExpired, resilienceRunDisarmed:
		statusClass = "deleted"
	}
	decisions := make([]resilienceDecision, len(run.Decisions))
	for i, decision := range run.Decisions {
		decisions[len(run.Decisions)-1-i] = decision
	}
	return &resilienceRunView{
		Name:        run.Name,
		Summary:     run.Summary,
		State:       state,
		StatusClass: statusClass,
		Active:      run.active(),
		Progress:    run.progress(),
		Behavior:    run.Action.describe(),
		ArmedAt:     run.ArmedAt.Format(time.RFC3339),
		ExpiresAt:   run.ExpiresAt.Format(time.RFC3339),
		Decisions:   decisions,
	}
}
