package web

import (
	"net/http"
	"net/url"
	"time"
)

// flowEvent is one hop of an OIDC or SAML flow. The inspectors show these so
// a developer can see failed attempts, not just the latest success.
type flowEvent struct {
	Time     string
	Protocol string
	Stage    string
	Outcome  string // "ok" or "failed"
	User     string
	Detail   string
}

func (e flowEvent) Failed() bool { return e.Outcome == "failed" }

const maxFlowEvents = 20

func (a *webApp) recordFlowEvent(slug, protocol, stage, outcome, user, detail string) {
	a.flowLogMu.Lock()
	defer a.flowLogMu.Unlock()
	if a.flowLog == nil {
		a.flowLog = make(map[string][]flowEvent)
	}
	events := append(a.flowLog[slug], flowEvent{
		Time:     time.Now().Format(time.RFC3339),
		Protocol: protocol,
		Stage:    stage,
		Outcome:  outcome,
		User:     user,
		Detail:   detail,
	})
	if len(events) > maxFlowEvents {
		events = events[len(events)-maxFlowEvents:]
	}
	a.flowLog[slug] = events
}

// flowEvents returns the recorded events for one environment, newest first.
func (a *webApp) flowEvents(slug string) []flowEvent {
	a.flowLogMu.Lock()
	defer a.flowLogMu.Unlock()
	stored := a.flowLog[slug]
	events := make([]flowEvent, len(stored))
	for i, event := range stored {
		events[len(stored)-1-i] = event
	}
	return events
}

// failFlow records a failed flow hop and writes the plain-text error the
// handler would have written anyway.
func (a *webApp) failFlow(w http.ResponseWriter, app app, protocol, stage string, status int, message string) {
	a.recordFlowEvent(app.Slug, protocol, stage, "failed", "", message)
	http.Error(w, message, status)
}

// failOAuth records a failed token or userinfo hop and writes the OAuth
// error response.
func (a *webApp) failOAuth(w http.ResponseWriter, app app, stage string, status int, code, description string) {
	a.recordFlowEvent(app.Slug, "oidc", stage, "failed", "", code+": "+description)
	writeOAuthError(w, status, code, description)
}

// failAuthorize records a failed authorize hop and delivers the error to the
// RP redirect URI when possible.
func (a *webApp) failAuthorize(w http.ResponseWriter, r *http.Request, app app, values url.Values, err error) {
	a.recordFlowEvent(app.Slug, "oidc", "authorize", "failed", "", err.Error())
	redirectAuthorizeError(w, r, values, err)
}
