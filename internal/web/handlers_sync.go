package web

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func (a *webApp) handleSync(w http.ResponseWriter, r *http.Request) {
	a.startSyncRequest(w, r, "sync")
}

func (a *webApp) handleReconcile(w http.ResponseWriter, r *http.Request) {
	a.startSyncRequest(w, r, "reconcile")
}

func (a *webApp) startSyncRequest(w http.ResponseWriter, r *http.Request, kind string) {
	tab := normalizedTab(r.FormValue("tab"))
	a.mu.Lock()
	state, err := loadRequestState(r)
	a.mu.Unlock()
	if err != nil {
		a.respondSyncStartError(w, r, tab, err)
		return
	}
	appID := requestSyncAppID(r, state)
	if appID == "" {
		a.respondSyncStartError(w, r, tab, fmt.Errorf("SCIM is not enabled for the active environment"))
		return
	}
	activeEnvironment, _ := appByID(state.Apps, appID)
	if job := a.currentSyncJob(appID); job != nil && job.Running {
		a.respondSyncStartError(w, r, tab, fmt.Errorf("sync already running"))
		return
	}
	job, err := a.startSyncJob(appID, activeEnvironment.Name, kind)
	if err != nil {
		a.respondSyncStartError(w, r, tab, err)
		return
	}

	if wantsJSON(r) {
		writeJSON(w, job)
		return
	}

	redirectWithFlash(w, r, dashboardURLWithPage(tab, formPage(r), formPageSize(r), formSearch(r), nil), flashMessage{Kind: "success", Message: kind + " started"})
}

func (a *webApp) handleSyncStatus(w http.ResponseWriter, r *http.Request) {
	state, err := loadRequestState(r)
	if err != nil {
		writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	after, err := syncEventSequence(r.URL.Query().Get("after"))
	if err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, a.currentSyncJobAfter(requestSyncAppID(r, state), after))
}

func syncEventSequence(value string) (int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, nil
	}
	sequence, err := strconv.Atoi(value)
	if err != nil || sequence < 0 {
		return 0, fmt.Errorf("sync event sequence must be a non-negative integer")
	}
	return sequence, nil
}

func (a *webApp) respondSyncStartError(w http.ResponseWriter, r *http.Request, tab string, err error) {
	if wantsJSON(r) {
		writeJSONStatus(w, http.StatusConflict, syncJobSnapshot{Done: true, Error: err.Error(), Message: err.Error()})
		return
	}

	a.redirectError(w, r, tab, err)
}

func (a *webApp) startSyncJob(appID string, environmentName string, kind string) (*syncJobSnapshot, error) {
	a.syncJobMu.Lock()
	defer a.syncJobMu.Unlock()

	if a.syncJobs == nil {
		a.syncJobs = make(map[string]*syncJobSnapshot)
	}
	for jobAppID, job := range a.syncJobs {
		if job == nil || !job.Running {
			continue
		}
		if jobAppID == appID {
			return nil, fmt.Errorf("sync already running")
		}
		return nil, fmt.Errorf("a sync is already running for %s; wait for it to finish", job.EnvironmentName)
	}

	job := &syncJobSnapshot{
		ID:              strconvFormatInt(time.Now().UnixNano()),
		EnvironmentName: environmentName,
		Running:         true,
		Message:         "Starting " + kind + " for " + environmentName,
		StartedAt:       time.Now().UTC().Format(time.RFC3339),
	}
	a.syncJobs[appID] = job
	go a.runSyncJob(job.ID, appID, kind)

	return cloneSyncJob(job), nil
}

func (a *webApp) runSyncJob(id string, appID string, kind string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	state, err := loadState()
	if err != nil {
		a.finishSyncJob(appID, id, false, err.Error(), false)
		return
	}
	projected, err := stateForApp(state, appID)
	if err != nil {
		a.finishSyncJob(appID, id, false, err.Error(), false)
		return
	}

	run := syncDirtyStateWithProgress
	if kind == "reconcile" {
		run = reconcileStateWithProgress
	}
	result := run(projected, func(progress syncProgress) {
		a.updateSyncJobProgress(appID, id, progress)
	})
	a.rememberTrace(appID, result.Traces)
	if result.Fatal != nil {
		a.finishSyncJob(appID, id, false, result.Fatal.Error(), len(result.Traces) > 0)
		return
	}

	mergeAppSyncState(&state, appID, result.State)
	appendOperationLogs(&state, appID, result.Traces)
	purgeFullySyncedDeletions(&state)
	if err := saveState(state); err != nil {
		a.finishSyncJob(appID, id, false, err.Error(), len(result.Traces) > 0)
		return
	}

	success := result.Stopped == nil
	a.finishSyncJob(appID, id, success, result.Status, len(result.Traces) > 0)
}

func (a *webApp) updateSyncJobProgress(appID string, id string, progress syncProgress) {
	a.syncJobMu.Lock()
	defer a.syncJobMu.Unlock()

	job := a.syncJobs[appID]
	if job == nil || job.ID != id {
		return
	}
	job.Total = progress.Total
	job.Processed = progress.Processed
	job.Percent = syncProgressPercent(progress.Processed, progress.Total, false)
	if progress.Label != "" {
		job.Current = strings.TrimSpace(strings.Join([]string{progress.Operation, progress.ResourceType, progress.Label}, " "))
		if progress.Phase != "" {
			job.LatestSequence++
			job.Events = append(job.Events, syncJobEvent{
				Sequence:     job.LatestSequence,
				ID:           progress.ResourceType + ":" + progress.ResourceID,
				ResourceType: progress.ResourceType,
				ResourceID:   progress.ResourceID,
				Label:        progress.Label,
				Operation:    progress.Operation,
				Phase:        progress.Phase,
				Detail:       progress.Detail,
			})
		}
	}
	job.RateLimited = progress.RateLimited
	if progress.Status != "" {
		job.Message = progress.Status
	}
}

func (a *webApp) finishSyncJob(appID string, id string, success bool, message string, traceAvailable bool) {
	a.syncJobMu.Lock()
	defer a.syncJobMu.Unlock()

	job := a.syncJobs[appID]
	if job == nil || job.ID != id {
		return
	}
	job.Running = false
	job.Done = true
	job.Success = success
	job.TraceAvailable = traceAvailable
	job.RateLimited = false
	job.Message = message
	job.Percent = syncProgressPercent(job.Processed, job.Total, true)
	job.FinishedAt = time.Now().UTC().Format(time.RFC3339)
	if !success {
		job.Error = message
	}
}

func (a *webApp) currentSyncJob(appID string) *syncJobSnapshot {
	a.syncJobMu.Lock()
	defer a.syncJobMu.Unlock()

	return cloneSyncJob(a.syncJobs[appID])
}

func (a *webApp) currentSyncJobAfter(appID string, sequence int) *syncJobSnapshot {
	a.syncJobMu.Lock()
	defer a.syncJobMu.Unlock()

	job := cloneSyncJob(a.syncJobs[appID])
	if job == nil || sequence == 0 {
		return job
	}
	events := make([]syncJobEvent, 0, len(job.Events))
	for _, event := range job.Events {
		if event.Sequence > sequence {
			events = append(events, event)
		}
	}
	job.Events = events
	return job
}

func cloneSyncJob(job *syncJobSnapshot) *syncJobSnapshot {
	if job == nil {
		return nil
	}

	cloned := *job
	cloned.Events = append([]syncJobEvent(nil), job.Events...)
	return &cloned
}

func syncProgressPercent(processed int, total int, done bool) int {
	if total <= 0 {
		if done {
			return 100
		}
		return 0
	}

	percent := processed * 100 / total
	if done {
		return 100
	}
	if percent > 99 {
		return 99
	}

	return percent
}

func wantsJSON(r *http.Request) bool {
	return r.Header.Get("X-Requested-With") == "fetch" || strings.Contains(r.Header.Get("Accept"), "application/json")
}

func (a *webApp) handleImport(w http.ResponseWriter, r *http.Request) {
	tab := normalizedTab(r.FormValue("tab"))
	a.mu.Lock()
	defer a.mu.Unlock()

	state, err := loadRequestState(r)
	if err != nil {
		a.redirectError(w, r, tab, err)
		return
	}
	appID := requestSyncAppID(r, state)
	if appID == "" {
		a.redirectError(w, r, tab, fmt.Errorf("SCIM is not enabled for the active environment"))
		return
	}
	projected, err := stateForApp(state, appID)
	if err != nil {
		a.redirectError(w, r, tab, err)
		return
	}

	result := importStateFromSCIM(projected)
	a.rememberTrace(appID, result.Traces)
	if result.Fatal != nil {
		if len(result.Traces) > 0 && projected.Config.AutoOpenSyncTrace {
			setShowTraceCookie(w)
		}
		redirectWithFlash(w, r, dashboardURLWithPage(tab, formPage(r), formPageSize(r), formSearch(r), nil), flashMessage{Kind: "error", Message: result.Fatal.Error()})
		return
	}

	mergeAppImportState(&state, appID, result.State)
	appendOperationLogs(&state, appID, result.Traces)
	purgeFullySyncedDeletions(&state)
	if err := saveState(state); err != nil {
		a.redirectError(w, r, tab, err)
		return
	}

	if result.State.Config.AutoOpenSyncTrace {
		setShowTraceCookie(w)
	}
	redirectWithFlash(w, r, dashboardURLWithPage(tab, formPage(r), formPageSize(r), formSearch(r), nil), flashMessage{Kind: "success", Message: result.Status})
}

func (a *webApp) handleReset(w http.ResponseWriter, r *http.Request) {
	tab := normalizedTab(r.FormValue("tab"))
	a.mu.Lock()
	defer a.mu.Unlock()

	state, err := loadRequestState(r)
	if err != nil {
		a.redirectError(w, r, tab, err)
		return
	}
	appID := requestSyncAppID(r, state)
	if appID == "" {
		a.redirectError(w, r, tab, fmt.Errorf("SCIM is not enabled for the active environment"))
		return
	}
	if _, err := stateForApp(state, appID); err != nil {
		a.redirectError(w, r, tab, err)
		return
	}

	if len(state.Users) == 0 && len(state.Groups) == 0 {
		a.redirectError(w, r, tab, fmt.Errorf("no users or groups to reset"))
		return
	}

	resetUsers := len(state.Users)
	resetGroups := len(state.Groups)
	initializeAppSync(&state, appID)

	if err := saveState(state); err != nil {
		a.redirectError(w, r, tab, err)
		return
	}

	message := fmt.Sprintf("reset sync status for %d users and %d groups", resetUsers, resetGroups)
	redirectWithFlash(w, r, dashboardURLWithPage(tab, formPage(r), formPageSize(r), formSearch(r), nil), flashMessage{Kind: "success", Message: message})
}
