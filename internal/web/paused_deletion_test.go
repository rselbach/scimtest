package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestPausedSCIMDeletionsResume(t *testing.T) {
	for name, tc := range map[string]struct {
		apiMethod string
		apiPath   string
		apiBody   string
		formPath  string
		form      url.Values
		resource  string
		id        string
		remote    string
	}{
		"user": {
			apiMethod: http.MethodDelete, apiPath: "/users/troy",
			formPath: "/users/troy/delete", resource: "user", id: "troy", remote: "/Users/remote-troy",
		},
		"group": {
			apiMethod: http.MethodDelete, apiPath: "/groups/study-group",
			formPath: "/groups/study-group/delete", resource: "group", id: "study-group", remote: "/Groups/remote-study-group",
		},
		"bulk users": {
			apiMethod: http.MethodPost, apiPath: "/users/bulk-delete", apiBody: `{"ids":["troy"]}`,
			formPath: "/users/delete", form: url.Values{"user_ids": {"troy"}}, resource: "user", id: "troy", remote: "/Users/remote-troy",
		},
		"bulk groups": {
			apiMethod: http.MethodPost, apiPath: "/groups/bulk-delete", apiBody: `{"ids":["study-group"]}`,
			formPath: "/groups/delete", form: url.Values{"group_ids": {"study-group"}}, resource: "group", id: "study-group", remote: "/Groups/remote-study-group",
		},
		"delete all": {
			apiMethod: http.MethodPost, apiPath: "/tools/delete-all",
			formPath: "/tools/delete-all", resource: "user", id: "troy", remote: "/Users/remote-troy",
		},
	} {
		for _, entryPoint := range []string{"API", "form"} {
			t.Run(name+"/"+entryPoint, func(t *testing.T) {
				r := require.New(t)
				setTestStateFile(t)
				var remoteMu sync.Mutex
				resources := map[string]bool{"/Users/remote-troy": true, "/Groups/remote-study-group": true}
				remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					if req.Method != http.MethodDelete {
						t.Errorf("unexpected SCIM request %s %s", req.Method, req.URL.Path)
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					remoteMu.Lock()
					delete(resources, req.URL.Path)
					remoteMu.Unlock()
					w.WriteHeader(http.StatusNoContent)
				}))
				defer remote.Close()
				r.NoError(saveState(appState{
					Users:     []user{{ID: "troy", GivenName: "Troy", FamilyName: "Barnes", Username: "troy", Email: "troy@greendale.edu", Active: true}},
					Groups:    []group{{ID: "study-group", DisplayName: "Study Group"}},
					Apps:      []app{{ID: "greendale", Name: "Greendale", Slug: "greendale", Protocol: "scim", SCIMEnabled: true, SCIMBaseURL: remote.URL, SCIMBearerToken: "secret"}},
					UserSync:  map[string]map[string]resourceSyncState{"greendale": {"troy": {RemoteID: "remote-troy"}}},
					GroupSync: map[string]map[string]resourceSyncState{"greendale": {"study-group": {RemoteID: "remote-study-group"}}},
				}))
				svc := newTestIDPApp(t)
				svc.instanceToken = "greendale-local-instance"
				handler := svc.routes()
				base := "/api/v1/environments/greendale"
				acceptanceRequest(t, handler, http.MethodPatch, base, `{"scim_bearer_token":""}`, http.StatusOK)
				if entryPoint == "API" {
					acceptanceRequest(t, handler, tc.apiMethod, base+tc.apiPath, tc.apiBody, http.StatusOK)
				} else {
					page := httptest.NewRecorder()
					handler.ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/?tab=users&environment=greendale", nil))
					r.Equal(http.StatusOK, page.Code)
					r.Contains(page.Body.String(), `data-has-scim-environments="true"`)
					form := url.Values{"environment": {"greendale"}}
					for key, values := range tc.form {
						form[key] = values
					}
					req := httptest.NewRequest(http.MethodPost, tc.formPath, strings.NewReader(form.Encode()))
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					rec := httptest.NewRecorder()
					handler.ServeHTTP(rec, req)
					r.Equal(http.StatusSeeOther, rec.Code, rec.Body.String())
				}
				state, err := loadStateForApp("greendale")
				r.NoError(err)
				r.False(state.Apps[0].SCIMEnabled)
				rows := state.UserSync["greendale"]
				if tc.resource == "group" {
					rows = state.GroupSync["greendale"]
					r.Len(state.Groups, 1)
				} else {
					r.Len(state.Users, 1)
				}
				r.True(rows[tc.id].Deleted)
				r.True(rows[tc.id].Dirty)
				acceptanceRequest(t, handler, http.MethodPatch, base, `{"scim_bearer_token":"secret"}`, http.StatusOK)
				state, err = loadStateForApp("greendale")
				r.NoError(err)
				r.True(state.Apps[0].SCIMEnabled)
				projected, err := stateForApp(state, "greendale")
				r.NoError(err)
				r.Equal([]syncPlanEntry{{ResourceType: tc.resource, ResourceID: tc.id, Label: map[string]string{"user": "Troy Barnes", "group": "Study Group"}[tc.resource], Operation: "delete"}}, planSync(projected))
				acceptanceRequest(t, handler, http.MethodPost, base+"/sync/start", "", http.StatusAccepted)
				r.Eventually(func() bool { job := svc.currentSyncJob("greendale"); return job != nil && job.Done }, 3*time.Second, 10*time.Millisecond)
				r.True(svc.currentSyncJob("greendale").Success)
				remoteMu.Lock()
				deleted := !resources[tc.remote]
				remaining := len(resources)
				remoteMu.Unlock()
				r.True(deleted, "the remembered remote resource must be deleted")
				r.Equal(1, remaining)
			})
		}
	}
}
