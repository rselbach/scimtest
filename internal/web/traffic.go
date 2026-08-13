package web

import (
	"net/http"
	"sync"
)

const maxTrafficEntries = 100

// trafficLog is a bounded ring of rendered RP interaction transcripts backing
// the in-app Traffic view.
type trafficLog struct {
	mu      sync.Mutex
	entries []string
}

func (t *trafficLog) add(entry string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.entries = append(t.entries, entry)
	if len(t.entries) > maxTrafficEntries {
		t.entries = t.entries[len(t.entries)-maxTrafficEntries:]
	}
}

// snapshot returns the recorded transcripts, newest first.
func (t *trafficLog) snapshot() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]string, len(t.entries))
	for i, entry := range t.entries {
		out[len(t.entries)-1-i] = entry
	}
	return out
}

func (t *trafficLog) clear() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.entries = nil
}

func (a *webApp) handleTraffic(w http.ResponseWriter, r *http.Request) {
	globalState, err := loadState()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	environmentID, err := requestEnvironmentID(r, globalState)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	state := globalState
	var activeEnvironment app
	if environmentID != "" {
		activeEnvironment, _ = appByID(globalState.Apps, environmentID)
		state, err = loadStateForApp(environmentID)
		if err == nil {
			state, err = stateForApp(state, environmentID)
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		rememberEnvironment(w, environmentID)
	} else {
		state.Config.SCIMDisabled = true
	}

	stats := buildStats(state)
	stats.Apps = len(globalState.Apps)
	data := trafficPageData{
		Entries:                a.traffic.snapshot(),
		RecordOn:               a.trafficRecordEnabled(),
		SecretsOn:              a.debugSecretsEnabled(),
		Stats:                  stats,
		BaseURL:                configuredBaseURL(state.Config.BaseURL),
		IDPBaseURL:             a.effectiveIDPBaseURL(r, state),
		SCIMEnabled:            activeEnvironment.SCIMEnabled,
		UsersURL:               addEnvironmentToURL(dashboardURL("users", nil), environmentID),
		GroupsURL:              addEnvironmentToURL(dashboardURL("groups", nil), environmentID),
		AppsURL:                addEnvironmentToURL(dashboardURL("apps", nil), environmentID),
		EnvironmentSettingsURL: addEnvironmentToURL(dashboardURL("apps", map[string]string{"modal": "app", "id": environmentID}), environmentID),
		ConfigURL:              addEnvironmentToURL(dashboardURL("apps", map[string]string{"modal": "config"}), environmentID),
		ToolsURL:               addEnvironmentToURL(dashboardURL("apps", map[string]string{"modal": "tools"}), environmentID),
		TraceURL:               addEnvironmentToURL(dashboardURL("users", map[string]string{"showTrace": "1"}), environmentID),
		HasTrace:               a.hasTrace(environmentID),
		Environments:           globalState.Apps,
		ActiveEnvironment:      activeEnvironment,
		GitHubAccount:          a.githubAccountView(),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := pageTemplate.ExecuteTemplate(w, "traffic.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

type trafficPageData struct {
	Entries                []string
	RecordOn               bool
	SecretsOn              bool
	Stats                  statsView
	BaseURL                string
	IDPBaseURL             string
	SCIMEnabled            bool
	UsersURL               string
	GroupsURL              string
	AppsURL                string
	EnvironmentSettingsURL string
	ConfigURL              string
	ToolsURL               string
	TraceURL               string
	HasTrace               bool
	Environments           []app
	ActiveEnvironment      app
	GitHubAccount          githubAccountView
}

func (a *webApp) handleTrafficSettings(w http.ResponseWriter, r *http.Request) {
	a.trafficRecord.Store(r.FormValue("record") == "on")
	// Raw credentials are only ever exposed when recording is also on.
	a.debugSecrets.Store(r.FormValue("record") == "on" && r.FormValue("record_secrets") == "on")
	http.Redirect(w, r, "/traffic", http.StatusSeeOther)
}

func (a *webApp) handleTrafficClear(w http.ResponseWriter, r *http.Request) {
	a.traffic.clear()
	http.Redirect(w, r, "/traffic", http.StatusSeeOther)
}
