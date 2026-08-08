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
	data := struct {
		Entries   []string
		DebugOn   bool
		SecretsOn bool
	}{
		Entries:   a.traffic.snapshot(),
		DebugOn:   a.debugRPEnabled(),
		SecretsOn: a.debugSecretsEnabled(),
	}
	if err := pageTemplate.ExecuteTemplate(w, "traffic.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (a *webApp) handleTrafficSettings(w http.ResponseWriter, r *http.Request) {
	a.debugRP.Store(r.FormValue("debug") == "on")
	// Raw credentials are only ever exposed when tracing is also on.
	a.debugSecrets.Store(r.FormValue("debug") == "on" && r.FormValue("debug_secrets") == "on")
	http.Redirect(w, r, "/traffic", http.StatusSeeOther)
}

func (a *webApp) handleTrafficClear(w http.ResponseWriter, r *http.Request) {
	a.traffic.clear()
	http.Redirect(w, r, "/traffic", http.StatusSeeOther)
}
