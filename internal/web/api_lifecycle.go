package web

import (
	"fmt"
	"net/http"
)

type apiJoinerRequest struct {
	GivenName  *string  `json:"given_name"`
	FamilyName *string  `json:"family_name"`
	Email      *string  `json:"email"`
	Username   *string  `json:"username"`
	GroupIDs   []string `json:"group_ids"`
}

type apiMoverRequest struct {
	UserID         string   `json:"user_id"`
	AddGroupIDs    []string `json:"add_group_ids"`
	RemoveGroupIDs []string `json:"remove_group_ids"`
}

type apiLeaverRequest struct {
	UserID string `json:"user_id"`
}

func (a *webApp) handleAPILifecycleJoiner(w http.ResponseWriter, r *http.Request) {
	var request apiJoinerRequest
	if decodeAPIJSON(w, r, &request) != nil {
		return
	}
	run, err := a.startJoiner(r.PathValue("environment_id"), apiUserRequest{
		GivenName:  request.GivenName,
		FamilyName: request.FamilyName,
		Email:      request.Email,
		Username:   request.Username,
	}, request.GroupIDs)
	a.writeAPILifecycleStart(w, r, run, err)
}

func (a *webApp) handleAPILifecycleMover(w http.ResponseWriter, r *http.Request) {
	var request apiMoverRequest
	if decodeAPIJSON(w, r, &request) != nil {
		return
	}
	run, err := a.startMover(r.PathValue("environment_id"), request.UserID, request.AddGroupIDs, request.RemoveGroupIDs)
	a.writeAPILifecycleStart(w, r, run, err)
}

func (a *webApp) handleAPILifecycleLeaver(w http.ResponseWriter, r *http.Request) {
	var request apiLeaverRequest
	if decodeAPIJSON(w, r, &request) != nil {
		return
	}
	run, err := a.startLeaver(r.PathValue("environment_id"), request.UserID)
	a.writeAPILifecycleStart(w, r, run, err)
}

// writeAPILifecycleStart answers a scenario request with 202 and the run as
// it stands. Its SCIM pushes and the app's answers arrive later; poll the run
// to see them.
func (a *webApp) writeAPILifecycleStart(w http.ResponseWriter, r *http.Request, run lifecycleRun, err error) {
	if err != nil {
		apiError(w, apiMutationStatus(err), err.Error())
		return
	}
	writeJSONStatus(w, http.StatusAccepted, apiLifecycleRun(r, r.PathValue("environment_id"), run))
}

func (a *webApp) handleAPILifecycleRuns(w http.ResponseWriter, r *http.Request) {
	found, ok := a.apiEnvironmentApp(w, r)
	if !ok {
		return
	}
	runs := a.lifecycleRunsFor(found.Slug)
	for i := range runs {
		runs[i] = apiLifecycleRun(r, found.ID, runs[i])
	}
	writeJSON(w, map[string]any{"runs": runs})
}

func (a *webApp) handleAPILifecycleRun(w http.ResponseWriter, r *http.Request) {
	found, ok := a.apiEnvironmentApp(w, r)
	if !ok {
		return
	}
	run, ok := a.lifecycleRun(found.Slug, r.PathValue("run_id"))
	if !ok {
		apiError(w, http.StatusNotFound, fmt.Sprintf("lifecycle run %q not found", r.PathValue("run_id")))
		return
	}
	writeJSON(w, apiLifecycleRun(r, found.ID, run))
}

// apiLifecycleRun gives each step that needs a browser the admin URL where
// the tester sends its message.
func apiLifecycleRun(r *http.Request, environmentID string, run lifecycleRun) lifecycleRun {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	for i := range run.Steps {
		if run.Steps[i].Status == lifecycleNeedsBrowser {
			run.Steps[i].BrowserURL = scheme + "://" + r.Host + lifecycleDashboardURL(app{ID: environmentID}, run.ID, "")
		}
	}
	return run
}
