package web

import (
	"net/http"
)

func apiInternalRequest(r *http.Request, environmentID string) *http.Request {
	clone := r.Clone(r.Context())
	clone.Header = r.Header.Clone()
	clone.Header.Set("Accept", "application/json")
	clone.Header.Set("X-Requested-With", "fetch")
	values := clone.URL.Query()
	values.Set("environment", environmentID)
	clone.URL.RawQuery = values.Encode()
	return clone
}

func (a *webApp) handleAPISyncPlan(w http.ResponseWriter, r *http.Request) {
	a.handleSyncPlan(w, apiInternalRequest(r, r.PathValue("environment_id")))
}
func (a *webApp) handleAPISyncStatus(w http.ResponseWriter, r *http.Request) {
	a.handleSyncStatus(w, apiInternalRequest(r, r.PathValue("environment_id")))
}
func (a *webApp) handleAPISyncStart(w http.ResponseWriter, r *http.Request) {
	if _, err := a.loadAPIEnvironment(r.PathValue("environment_id")); err != nil {
		apiError(w, http.StatusNotFound, err.Error())
		return
	}
	request := apiInternalRequest(r, r.PathValue("environment_id"))
	request = request.WithContext(withAPIProtocolResponse(request.Context()))
	a.handleSync(w, request)
}
func (a *webApp) handleAPISyncCancel(w http.ResponseWriter, r *http.Request) {
	a.handleSyncCancel(w, apiInternalRequest(r, r.PathValue("environment_id")))
}
func (a *webApp) handleAPIReconcile(w http.ResponseWriter, r *http.Request) {
	request := apiInternalRequest(r, r.PathValue("environment_id"))
	request = request.WithContext(withAPIProtocolResponse(request.Context()))
	a.handleReconcile(w, request)
}
func (a *webApp) handleAPIUserPush(w http.ResponseWriter, r *http.Request) {
	request := apiInternalRequest(r, r.PathValue("environment_id"))
	request = request.WithContext(withAPIProtocolResponse(request.Context()))
	request.SetPathValue("id", r.PathValue("user_id"))
	a.handleUserPush(w, request)
}
func (a *webApp) handleAPIGroupPush(w http.ResponseWriter, r *http.Request) {
	request := apiInternalRequest(r, r.PathValue("environment_id"))
	request = request.WithContext(withAPIProtocolResponse(request.Context()))
	request.SetPathValue("id", r.PathValue("group_id"))
	a.handleGroupPush(w, request)
}

func (a *webApp) handleAPIReset(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	state, err := a.loadAPIEnvironment(r.PathValue("environment_id"))
	if err != nil {
		apiError(w, http.StatusNotFound, err.Error())
		return
	}
	if !scimEnabled(state) {
		apiError(w, http.StatusBadRequest, "SCIM is not enabled for the environment")
		return
	}
	initializeAppSync(&state, r.PathValue("environment_id"))
	if err := a.saveRequestState(state); err != nil {
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, map[string]int{"users": len(state.Users), "groups": len(state.Groups)})
}

func (a *webApp) handleAPITrace(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("environment_id")
	if _, err := a.loadAPIEnvironment(id); err != nil {
		apiError(w, http.StatusNotFound, err.Error())
		return
	}
	a.traceMu.Lock()
	traces := append([]syncTraceEntry{}, a.lastTraces[id]...)
	a.traceMu.Unlock()
	writeJSON(w, traces)
}
