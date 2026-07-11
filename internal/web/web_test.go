package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	rgrokclient "github.com/rselbach/rgrok/client"
	"github.com/stretchr/testify/require"
)

func TestIndexRendersDashboard(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)

	state := appState{
		Config: config{BaseURL: "https://example.com/scim"},
		Users: []user{{
			ID:         "u1",
			GivenName:  "Troy",
			FamilyName: "Barnes",
			Username:   "tbarnes",
			Email:      "troy@example.com",
			Active:     true,
		}},
		Groups: []group{{
			ID:          "g1",
			DisplayName: "Greendale Study Group",
			MemberIDs:   []string{"u1"},
		}},
		UserOperations:  map[string][]operationLog{},
		GroupOperations: map[string][]operationLog{},
	}
	r.NoError(saveState(state))

	app := &webApp{}

	userReq := httptest.NewRequest(http.MethodGet, "/?tab=users", nil)
	userRec := httptest.NewRecorder()
	app.routes().ServeHTTP(userRec, userReq)
	r.Equal(http.StatusOK, userRec.Code)
	userBody := userRec.Body.String()
	r.Contains(userBody, "tbarnes")
	r.Contains(userBody, "https://example.com/scim")
	r.Contains(userBody, "SCIM Control Surface")
	r.Contains(userBody, "window.location.reload()")

	groupReq := httptest.NewRequest(http.MethodGet, "/?tab=groups", nil)
	groupRec := httptest.NewRecorder()
	app.routes().ServeHTTP(groupRec, groupReq)
	r.Equal(http.StatusOK, groupRec.Code)
	r.Contains(groupRec.Body.String(), "Greendale Study Group")
}

func TestIDPRoutesExcludeAdminEndpoints(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{
		Config: config{BearerToken: "chang-secret"},
		Users: []user{{
			ID:         "u1",
			GivenName:  "Troy",
			FamilyName: "Barnes",
			Username:   "tbarnes",
			Email:      "troy@greendale.edu",
			Active:     true,
		}},
		Apps: []app{{
			ID:               "app-1",
			Name:             "Greendale",
			Slug:             "greendale",
			Protocol:         "oidc",
			OIDCClientID:     "greendale-client",
			OIDCClientSecret: "secret-dean",
		}},
	}))

	app := &webApp{}
	public := app.idpRoutes()

	for _, target := range []string{"/", "/?modal=config", "/sync/status"} {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		rec := httptest.NewRecorder()
		public.ServeHTTP(rec, req)
		r.Equal(http.StatusNotFound, rec.Code, target)
		r.NotContains(rec.Body.String(), "chang-secret", target)
		r.NotContains(rec.Body.String(), "secret-dean", target)
	}

	deleteReq := httptest.NewRequest(http.MethodPost, "/tools/delete-all", nil)
	deleteRec := httptest.NewRecorder()
	public.ServeHTTP(deleteRec, deleteReq)
	r.Equal(http.StatusNotFound, deleteRec.Code)

	discoveryReq := httptest.NewRequest(http.MethodGet, "/oidc/greendale/.well-known/openid-configuration", nil)
	discoveryReq.Host = "idp.greendale.test"
	discoveryRec := httptest.NewRecorder()
	public.ServeHTTP(discoveryRec, discoveryReq)
	r.Equal(http.StatusOK, discoveryRec.Code)
	r.Contains(discoveryRec.Body.String(), "http://idp.greendale.test/oidc/greendale")

	state, err := loadState()
	r.NoError(err)
	r.Len(state.Users, 1)
}

func TestAdminRoutesRejectCrossOriginMutations(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{
		Config: config{SCIMDisabled: true},
		Users: []user{{
			ID:         "u1",
			GivenName:  "Britta",
			FamilyName: "Perry",
			Username:   "bperry",
			Email:      "britta@greendale.edu",
			Active:     true,
		}},
	}))

	app := &webApp{}
	req := httptest.NewRequest(http.MethodPost, "/tools/delete-all", nil)
	req.Host = "admin.greendale.test"
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	rec := httptest.NewRecorder()
	app.routes().ServeHTTP(rec, req)

	r.Equal(http.StatusForbidden, rec.Code)
	state, err := loadState()
	r.NoError(err)
	r.Len(state.Users, 1)
}

func TestAdminRoutesAllowSameOriginMutations(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{
		Config: config{SCIMDisabled: true},
		Users: []user{{
			ID:         "u1",
			GivenName:  "Britta",
			FamilyName: "Perry",
			Username:   "bperry",
			Email:      "britta@greendale.edu",
			Active:     true,
		}},
	}))

	app := &webApp{}
	req := httptest.NewRequest(http.MethodPost, "/tools/delete-all", nil)
	req.Host = "admin.greendale.test"
	req.Header.Set("Origin", "http://admin.greendale.test")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()
	app.routes().ServeHTTP(rec, req)

	r.Equal(http.StatusSeeOther, rec.Code)
	state, err := loadState()
	r.NoError(err)
	r.Empty(state.Users)
}

func TestIDPPostRoutesAllowCrossOriginRequests(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{}))

	app := &webApp{}
	req := httptest.NewRequest(http.MethodPost, "/saml/missing/sso", nil)
	req.Header.Set("Origin", "https://sp.greendale.test")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	rec := httptest.NewRecorder()
	app.routes().ServeHTTP(rec, req)

	r.Equal(http.StatusNotFound, rec.Code)
}

func TestIndexPaginatesUsersAndGroups(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)

	users := make([]user, 0, 30)
	for i := 1; i <= 30; i++ {
		users = append(users, user{
			ID:         fmt.Sprintf("u%03d", i),
			GivenName:  "Troy",
			FamilyName: fmt.Sprintf("Barnes %03d", i),
			Username:   fmt.Sprintf("student%03d", i),
			Email:      fmt.Sprintf("student%03d@greendale.edu", i),
			Active:     true,
		})
	}
	groups := make([]group, 0, 28)
	for i := 1; i <= 28; i++ {
		groups = append(groups, group{
			ID:          fmt.Sprintf("g%03d", i),
			DisplayName: fmt.Sprintf("Greendale Group %03d", i),
		})
	}

	state := appState{
		Users:           users,
		Groups:          groups,
		UserOperations:  map[string][]operationLog{},
		GroupOperations: map[string][]operationLog{},
	}
	r.NoError(saveState(state))

	app := &webApp{}
	userReq := httptest.NewRequest(http.MethodGet, "/?tab=users&page=2", nil)
	userRec := httptest.NewRecorder()
	app.routes().ServeHTTP(userRec, userReq)

	r.Equal(http.StatusOK, userRec.Code)
	userBody := userRec.Body.String()
	r.Contains(userBody, "Showing 16–30 of 30")
	r.Contains(userBody, "student016@greendale.edu")
	r.NotContains(userBody, "student015@greendale.edu")
	r.Contains(userBody, `name="page" value="2"`)
	r.Contains(userBody, `name="pageSize" value="15"`)
	r.Contains(userBody, `value="15" selected`)

	groupReq := httptest.NewRequest(http.MethodGet, "/?tab=groups&page=2&pageSize=25", nil)
	groupRec := httptest.NewRecorder()
	app.routes().ServeHTTP(groupRec, groupReq)

	r.Equal(http.StatusOK, groupRec.Code)
	groupBody := groupRec.Body.String()
	r.Contains(groupBody, "Showing 26–28 of 28")
	r.Contains(groupBody, "Greendale Group 026")
	r.NotContains(groupBody, "Greendale Group 025")
	r.Contains(groupBody, `name="page" value="2"`)
	r.Contains(groupBody, `name="pageSize" value="25"`)
	r.Contains(groupBody, `value="25" selected`)
}

func TestIndexSearchesUsersAndGroups(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)

	state := appState{
		Users: []user{{
			ID:         "u1",
			GivenName:  "Troy",
			FamilyName: "Barnes",
			Username:   "tbarnes",
			Email:      "troy@greendale.edu",
			Active:     true,
		}, {
			ID:         "u2",
			GivenName:  "Abed",
			FamilyName: "Nadir",
			Username:   "coolabed",
			Email:      "abed@greendale.edu",
			Active:     true,
		}, {
			ID:         "u3",
			GivenName:  "Annie",
			FamilyName: "Edison",
			Username:   "aedison",
			Email:      "humanbeing@greendale.edu",
			Active:     true,
		}},
		Groups: []group{{
			ID:          "g1",
			DisplayName: "Study Group",
		}, {
			ID:          "g2",
			DisplayName: "Paintball Squad",
		}},
		UserOperations:  map[string][]operationLog{},
		GroupOperations: map[string][]operationLog{},
	}
	r.NoError(saveState(state))

	app := &webApp{}
	tests := map[string]struct {
		path    string
		want    string
		notWant string
	}{
		"user name": {
			path:    "/?tab=users&q=nadir",
			want:    "Abed Nadir",
			notWant: "Troy Barnes",
		},
		"user username": {
			path:    "/?tab=users&q=coolabed",
			want:    "abed@greendale.edu",
			notWant: "aedison",
		},
		"user email": {
			path:    "/?tab=users&q=humanbeing",
			want:    "Annie Edison",
			notWant: "Abed Nadir",
		},
		"group name": {
			path:    "/?tab=groups&q=paintball",
			want:    "Paintball Squad",
			notWant: "Study Group",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			rec := httptest.NewRecorder()
			app.routes().ServeHTTP(rec, req)

			r.Equal(http.StatusOK, rec.Code)
			body := rec.Body.String()
			r.Contains(body, "Showing 1–1 of 1")
			r.Contains(body, tc.want)
			r.NotContains(body, tc.notWant)
			r.Contains(body, `name="q"`)
		})
	}
}

func TestIndexRendersListPartial(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)

	state := appState{
		Users: []user{{
			ID:         "u1",
			GivenName:  "Abed",
			FamilyName: "Nadir",
			Username:   "coolabed",
			Email:      "abed@greendale.edu",
			Active:     true,
		}},
		UserOperations:  map[string][]operationLog{},
		GroupOperations: map[string][]operationLog{},
	}
	r.NoError(saveState(state))

	app := &webApp{}
	req := httptest.NewRequest(http.MethodGet, "/?tab=users&q=abed&partial=list", nil)
	rec := httptest.NewRecorder()
	app.routes().ServeHTTP(rec, req)

	r.Equal(http.StatusOK, rec.Code)
	body := rec.Body.String()
	r.Contains(body, `data-list-card`)
	r.Contains(body, "Abed Nadir")
	r.NotContains(body, "<!DOCTYPE html>")
	r.NotContains(body, `class="topbar"`)
}

func TestUserActionPreservesPage(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)

	users := make([]user, 0, 30)
	for i := 1; i <= 30; i++ {
		users = append(users, user{
			ID:         fmt.Sprintf("u%03d", i),
			GivenName:  "Annie",
			FamilyName: fmt.Sprintf("Edison %03d", i),
			Username:   fmt.Sprintf("student%03d", i),
			Email:      fmt.Sprintf("student%03d@greendale.edu", i),
			Active:     true,
		})
	}
	r.NoError(saveState(appState{
		Users:           users,
		UserOperations:  map[string][]operationLog{},
		GroupOperations: map[string][]operationLog{},
	}))

	app := &webApp{}
	form := url.Values{"tab": {"users"}, "page": {"2"}, "pageSize": {"25"}, "q": {"student026"}}
	req := httptest.NewRequest(http.MethodPost, "/users/u026/toggle-active", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	r.Equal(http.StatusSeeOther, rec.Code)
	r.Equal("/?page=2&pageSize=25&q=student026&tab=users", rec.Header().Get("Location"))
}

func TestToggleActiveUpdatesStateAndHistory(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)

	state := appState{
		Users: []user{{
			ID:         "u1",
			GivenName:  "Annie",
			FamilyName: "Edison",
			Username:   "aedison",
			Email:      "annie@example.com",
			Active:     true,
		}},
		UserOperations:  map[string][]operationLog{},
		GroupOperations: map[string][]operationLog{},
	}
	r.NoError(saveState(state))

	app := &webApp{}
	form := url.Values{"tab": {"users"}}
	req := httptest.NewRequest(http.MethodPost, "/users/u1/toggle-active", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	r.Equal(http.StatusSeeOther, rec.Code)
	updated, err := loadState()
	r.NoError(err)
	r.Len(updated.Users, 1)
	r.False(updated.Users[0].Active)
	r.True(updated.Users[0].Dirty)
	r.Equal("", updated.Users[0].LastError)
	r.Equal("Deactivated", updated.UserOperations["u1"][0].Summary)
}

func TestIndexRendersToolsModal(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{}))

	app := &webApp{}
	req := httptest.NewRequest(http.MethodGet, "/?tab=users&modal=tools", nil)
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	r.Equal(http.StatusOK, rec.Code)
	body := rec.Body.String()
	r.Contains(body, "Tools")
	r.Contains(body, `/tools/create-users`)
	r.Contains(body, `name="count"`)
	r.Contains(body, `name="email_domain"`)
	r.Contains(body, `/tools/delete-all`)
	r.Contains(body, "Activate All")
	r.Contains(body, "Deactivate All")
}

func TestToolsCreateUsers(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)

	r.NoError(saveState(appState{
		Users: []user{{
			ID:         "u1",
			GivenName:  "Troy",
			FamilyName: "Barnes",
			Username:   "user001",
			Email:      "user001@greendale.edu",
			Active:     true,
		}},
		UserOperations:  map[string][]operationLog{},
		GroupOperations: map[string][]operationLog{},
	}))

	app := &webApp{}
	form := url.Values{"tab": {"users"}, "count": {"3"}, "email_domain": {"@greendale.edu"}}
	req := httptest.NewRequest(http.MethodPost, "/tools/create-users", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	r.Equal(http.StatusSeeOther, rec.Code)
	r.Equal("/?tab=users", rec.Header().Get("Location"))
	updated, err := loadState()
	r.NoError(err)
	r.Len(updated.Users, 4)

	created := updated.Users[1:]
	r.Equal("user002", created[0].Username)
	r.Equal("user002@greendale.edu", created[0].Email)
	r.Equal("user003", created[1].Username)
	r.Equal("user004", created[2].Username)
	for _, u := range created {
		r.True(u.Active)
		r.True(u.Dirty)
		r.Equal("Created by tools", updated.UserOperations[u.ID][0].Summary)
	}
}

func TestToolsActivateAndDeactivateAll(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)

	r.NoError(saveState(appState{
		Users: []user{{
			ID:         "u1",
			GivenName:  "Abed",
			FamilyName: "Nadir",
			Username:   "coolabed",
			Email:      "abed@greendale.edu",
		}, {
			ID:         "u2",
			GivenName:  "Annie",
			FamilyName: "Edison",
			Username:   "aedison",
			Email:      "annie@greendale.edu",
			Active:     true,
		}, {
			ID:         "u3",
			GivenName:  "Señor",
			FamilyName: "Chang",
			Username:   "chang",
			Email:      "chang@greendale.edu",
			Deleted:    true,
		}},
		UserOperations:  map[string][]operationLog{},
		GroupOperations: map[string][]operationLog{},
	}))

	app := &webApp{}
	activate := url.Values{"tab": {"users"}}
	activateReq := httptest.NewRequest(http.MethodPost, "/tools/activate-all", strings.NewReader(activate.Encode()))
	activateReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	activateRec := httptest.NewRecorder()

	app.routes().ServeHTTP(activateRec, activateReq)

	r.Equal(http.StatusSeeOther, activateRec.Code)
	updated, err := loadState()
	r.NoError(err)
	r.True(updated.Users[0].Active)
	r.True(updated.Users[0].Dirty)
	r.True(updated.Users[1].Active)
	r.False(updated.Users[1].Dirty)
	r.False(updated.Users[2].Active)
	r.False(updated.Users[2].Dirty)
	r.Equal("Activated", updated.UserOperations["u1"][0].Summary)

	deactivate := url.Values{"tab": {"users"}}
	deactivateReq := httptest.NewRequest(http.MethodPost, "/tools/deactivate-all", strings.NewReader(deactivate.Encode()))
	deactivateReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	deactivateRec := httptest.NewRecorder()

	app.routes().ServeHTTP(deactivateRec, deactivateReq)

	r.Equal(http.StatusSeeOther, deactivateRec.Code)
	updated, err = loadState()
	r.NoError(err)
	r.False(updated.Users[0].Active)
	r.True(updated.Users[0].Dirty)
	r.False(updated.Users[1].Active)
	r.True(updated.Users[1].Dirty)
	r.False(updated.Users[2].Active)
	r.False(updated.Users[2].Dirty)
	r.Equal("Deactivated", updated.UserOperations["u2"][0].Summary)
}

func TestToolsDeleteAll(t *testing.T) {
	t.Run("SCIM enabled marks users for deletion", func(t *testing.T) {
		r := require.New(t)
		setTestStateFile(t)
		r.NoError(saveState(appState{
			Users: []user{{
				ID:         "u1",
				GivenName:  "Jeff",
				FamilyName: "Winger",
				Username:   "jwinger",
				Email:      "jeff@greendale.edu",
				Active:     true,
			}, {
				ID:         "u2",
				GivenName:  "Britta",
				FamilyName: "Perry",
				Username:   "bperry",
				Email:      "britta@greendale.edu",
				Active:     true,
				Deleted:    true,
			}},
			UserOperations:  map[string][]operationLog{},
			GroupOperations: map[string][]operationLog{},
		}))

		app := &webApp{}
		form := url.Values{"tab": {"users"}}
		req := httptest.NewRequest(http.MethodPost, "/tools/delete-all", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()

		app.routes().ServeHTTP(rec, req)

		r.Equal(http.StatusSeeOther, rec.Code)
		updated, err := loadState()
		r.NoError(err)
		r.True(updated.Users[0].Deleted)
		r.True(updated.Users[0].Dirty)
		r.True(updated.Users[1].Deleted)
		r.False(updated.Users[1].Dirty)
		r.Equal("Marked for deletion by tools", updated.UserOperations["u1"][0].Summary)
	})

	t.Run("SCIM disabled removes users locally", func(t *testing.T) {
		r := require.New(t)
		setTestStateFile(t)
		r.NoError(saveState(appState{
			Config: config{SCIMDisabled: true},
			Users: []user{{
				ID:         "u1",
				GivenName:  "Shirley",
				FamilyName: "Bennett",
				Username:   "sbennett",
				Email:      "shirley@greendale.edu",
				Active:     true,
			}},
			Groups: []group{{
				ID:          "g1",
				DisplayName: "Study Group",
				MemberIDs:   []string{"u1"},
			}},
			UserOperations:  map[string][]operationLog{},
			GroupOperations: map[string][]operationLog{},
		}))

		app := &webApp{}
		form := url.Values{"tab": {"users"}}
		req := httptest.NewRequest(http.MethodPost, "/tools/delete-all", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()

		app.routes().ServeHTTP(rec, req)

		r.Equal(http.StatusSeeOther, rec.Code)
		updated, err := loadState()
		r.NoError(err)
		r.Empty(updated.Users)
		r.Empty(updated.Groups[0].MemberIDs)
	})
}

func TestSyncPersistsRemoteStateAndTraceCookie(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.Equal(http.MethodPost, req.Method)
		r.Equal("/Users", req.URL.Path)
		w.Header().Set("Content-Type", "application/scim+json")
		_, err := fmt.Fprint(w, `{"id":"remote-user-1"}`)
		r.NoError(err)
	}))
	defer server.Close()

	state := appState{
		Config: config{
			BaseURL:           server.URL,
			BearerToken:       "token",
			AutoOpenSyncTrace: true,
		},
		Users: []user{{
			ID:         "u1",
			GivenName:  "Shirley",
			FamilyName: "Bennett",
			Username:   "sbennett",
			Email:      "shirley@example.com",
			Active:     true,
			Dirty:      true,
		}},
		UserOperations:  map[string][]operationLog{},
		GroupOperations: map[string][]operationLog{},
	}
	r.NoError(saveState(state))

	app := &webApp{}
	form := url.Values{"tab": {"users"}}
	req := httptest.NewRequest(http.MethodPost, "/sync", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	r.Equal(http.StatusSeeOther, rec.Code)
	job := waitForSyncDone(t, app)
	r.True(job.Success)
	r.True(job.TraceAvailable)
	updated, err := loadState()
	r.NoError(err)
	r.Equal("remote-user-1", updated.Users[0].RemoteID)
	r.False(updated.Users[0].Dirty)
	r.NotEmpty(updated.UserOperations["u1"])
	r.Contains(app.traceContent(), "POST /Users")
}

func TestSyncStartsAsyncAndReportsStatus(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)

	started := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.Equal(http.MethodPost, req.Method)
		r.Equal("/Users", req.URL.Path)
		close(started)
		<-release
		w.Header().Set("Content-Type", "application/scim+json")
		_, err := fmt.Fprint(w, `{"id":"remote-user-1"}`)
		r.NoError(err)
	}))
	defer server.Close()

	r.NoError(saveState(appState{
		Config: config{
			BaseURL:     server.URL,
			BearerToken: "token",
		},
		Users: []user{{
			ID:         "u1",
			GivenName:  "Shirley",
			FamilyName: "Bennett",
			Username:   "sbennett",
			Email:      "shirley@example.com",
			Active:     true,
			Dirty:      true,
		}},
		UserOperations:  map[string][]operationLog{},
		GroupOperations: map[string][]operationLog{},
	}))

	app := &webApp{}
	form := url.Values{"tab": {"users"}}
	req := httptest.NewRequest(http.MethodPost, "/sync", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Requested-With", "fetch")
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	r.Equal(http.StatusOK, rec.Code)
	var startedJob syncJobSnapshot
	r.NoError(json.NewDecoder(rec.Body).Decode(&startedJob))
	r.True(startedJob.Running)

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("sync request did not start")
	}

	statusReq := httptest.NewRequest(http.MethodGet, "/sync/status", nil)
	statusRec := httptest.NewRecorder()
	app.routes().ServeHTTP(statusRec, statusReq)

	r.Equal(http.StatusOK, statusRec.Code)
	var runningJob syncJobSnapshot
	r.NoError(json.NewDecoder(statusRec.Body).Decode(&runningJob))
	r.True(runningJob.Running)
	r.Equal(1, runningJob.Total)
	r.Equal(0, runningJob.Processed)

	updated, err := loadState()
	r.NoError(err)
	r.Empty(updated.Users[0].RemoteID)

	close(release)
	finishedJob := waitForSyncDone(t, app)
	r.True(finishedJob.Success)
	r.Equal(100, finishedJob.Percent)
	r.Equal("create user Shirley Bennett (sbennett)", finishedJob.Current)
}

func TestMutationIsRejectedWhileSyncRuns(t *testing.T) {
	r := require.New(t)
	app := &webApp{syncJob: &syncJobSnapshot{Running: true}}
	called := false
	handler := app.rejectWhileSyncing(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})
	req := httptest.NewRequest(http.MethodPost, "/users/save", strings.NewReader("tab=users"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()

	handler(rec, req)

	r.False(called)
	r.Equal(http.StatusConflict, rec.Code)
	r.JSONEq(`{"error":"sync is running; wait for it to finish"}`, rec.Body.String())
}

func TestSyncRateLimitRendersReadableError(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.Equal(http.MethodPut, req.Method)
		r.Equal("/Users/remote-dean", req.URL.Path)
		w.Header().Set("Content-Type", "application/scim+json")
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusTooManyRequests)
		_, err := fmt.Fprint(w, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"detail":"Too many requests. Please retry after the rate limit resets.","status":"429"}`)
		r.NoError(err)
	}))
	defer server.Close()

	state := appState{
		Config: config{
			BaseURL:     server.URL,
			BearerToken: "token",
		},
		Users: []user{{
			ID:         "u1",
			GivenName:  "Dean",
			FamilyName: "Pelton",
			Username:   "deanp",
			Email:      "dean@example.com",
			Active:     true,
			RemoteID:   "remote-dean",
			Dirty:      true,
		}},
		UserOperations:  map[string][]operationLog{},
		GroupOperations: map[string][]operationLog{},
	}
	r.NoError(saveState(state))

	app := &webApp{}
	form := url.Values{"tab": {"users"}}
	syncReq := httptest.NewRequest(http.MethodPost, "/sync", strings.NewReader(form.Encode()))
	syncReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	syncRec := httptest.NewRecorder()

	app.routes().ServeHTTP(syncRec, syncReq)

	r.Equal(http.StatusSeeOther, syncRec.Code)
	job := waitForSyncDone(t, app)
	r.False(job.Success)
	r.True(job.TraceAvailable)
	updated, err := loadState()
	r.NoError(err)
	r.Contains(updated.Users[0].LastError, "Try again now")
	r.NotContains(updated.Users[0].LastError, "schemas")
	r.Equal("0", updated.UserOperations["u1"][0].ResponseRetryAfter)
	r.Contains(app.traceContent(), "Retry-After: 0")

	indexReq := httptest.NewRequest(http.MethodGet, "/?tab=users", nil)
	indexRec := httptest.NewRecorder()
	app.routes().ServeHTTP(indexRec, indexReq)

	r.Equal(http.StatusOK, indexRec.Code)
	body := indexRec.Body.String()
	r.Contains(body, "user Dean Pelton: SCIM server rate limit hit (429 Too Many Requests). Try again now.")
	r.NotContains(body, "schemas")

	historyReq := httptest.NewRequest(http.MethodGet, "/?tab=users&historyType=user&historyID=u1", nil)
	historyRec := httptest.NewRecorder()
	app.routes().ServeHTTP(historyRec, historyReq)

	r.Equal(http.StatusOK, historyRec.Code)
	r.Contains(historyRec.Body.String(), "Retry-After: 0")
}

func TestIndexRendersLegacyRateLimitErrorReadable(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)

	state := appState{
		Config: config{BaseURL: "https://example.com/scim"},
		Users: []user{{
			ID:         "u1",
			GivenName:  "Dean",
			FamilyName: "Pelton",
			Username:   "deanp",
			Email:      "dean@example.com",
			Active:     true,
			RemoteID:   "remote-dean",
			Dirty:      true,
			LastError:  `SCIM PUT /Users/remote-dean returned 429 Too Many Requests; rate limited; retry after 1m0s: {"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"detail":"Too many requests.","status":"429"}`,
		}},
		UserOperations:  map[string][]operationLog{},
		GroupOperations: map[string][]operationLog{},
	}
	r.NoError(saveState(state))

	app := &webApp{}
	req := httptest.NewRequest(http.MethodGet, "/?tab=users", nil)
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	r.Equal(http.StatusOK, rec.Code)
	body := rec.Body.String()
	r.Contains(body, "user Dean Pelton: SCIM server rate limit hit (429 Too Many Requests). Try again in 1 minute.")
	r.NotContains(body, "schemas")
	r.NotContains(body, "1m0s")
}

func TestSCIMDisabledHidesSyncControlsAndColumns(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)

	state := appState{
		Config: config{
			BaseURL:      "https://example.com/scim",
			SCIMDisabled: true,
		},
		Users: []user{{
			ID:         "u1",
			GivenName:  "Troy",
			FamilyName: "Barnes",
			Username:   "tbarnes",
			Email:      "troy@example.com",
			Active:     true,
			RemoteID:   "remote-u1",
			Dirty:      true,
			LastError:  "sync failed",
		}},
		Groups: []group{{
			ID:          "g1",
			DisplayName: "Greendale Study Group",
			MemberIDs:   []string{"u1"},
			RemoteID:    "remote-g1",
			Dirty:       true,
		}},
		UserOperations:  map[string][]operationLog{},
		GroupOperations: map[string][]operationLog{},
	}
	r.NoError(saveState(state))

	app := &webApp{}
	userReq := httptest.NewRequest(http.MethodGet, "/?tab=users", nil)
	userRec := httptest.NewRecorder()
	app.routes().ServeHTTP(userRec, userReq)

	r.Equal(http.StatusOK, userRec.Code)
	userBody := userRec.Body.String()
	r.Contains(userBody, "SCIM")
	r.Contains(userBody, "disabled")
	r.NotContains(userBody, ">Sync<")
	r.NotContains(userBody, ">Import<")
	r.NotContains(userBody, ">Reset<")
	r.NotContains(userBody, "<th>Status</th>")
	r.NotContains(userBody, "<th>Remote ID</th>")
	r.NotContains(userBody, "remote-u1")
	r.NotContains(userBody, "sync failed")

	groupReq := httptest.NewRequest(http.MethodGet, "/?tab=groups", nil)
	groupRec := httptest.NewRecorder()
	app.routes().ServeHTTP(groupRec, groupReq)

	r.Equal(http.StatusOK, groupRec.Code)
	groupBody := groupRec.Body.String()
	r.Contains(groupBody, "Greendale Study Group")
	r.NotContains(groupBody, "<th>Status</th>")
	r.NotContains(groupBody, "<th>Remote ID</th>")
	r.NotContains(groupBody, "remote-g1")
}

func TestSCIMDisabledRejectsSync(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)

	state := appState{
		Config:          config{SCIMDisabled: true},
		UserOperations:  map[string][]operationLog{},
		GroupOperations: map[string][]operationLog{},
	}
	r.NoError(saveState(state))

	app := &webApp{}
	form := url.Values{"tab": {"users"}}
	req := httptest.NewRequest(http.MethodPost, "/sync", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	r.Equal(http.StatusSeeOther, rec.Code)
	r.Contains(rec.Header().Get("Set-Cookie"), "SCIM+is+disabled")
}

func TestConfigRendersRgrokSetupLink(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{}))

	app := &webApp{}
	req := httptest.NewRequest(http.MethodGet, "/?tab=users&modal=config", nil)
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	r.Equal(http.StatusOK, rec.Code)
	body := rec.Body.String()
	r.Contains(body, "Set up rgrok tunnel")
	r.Contains(body, "/?modal=config&amp;rgrok=1&amp;tab=users")
	r.Contains(body, `name="idp_base_url"`)
	r.NotContains(body, `name="idp_base_url" value="" placeholder="http://example.com" autocomplete="off" disabled`)
}

func TestConfigRendersEstablishedRgrokTunnel(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{}))

	app := &webApp{
		rgrokTunnel: &activeRgrokTunnel{
			Name:      "demo",
			PublicURL: "https://demo.rgrok.rselbach.com",
			Tunnel:    &fakeTunnel{},
		},
	}
	req := httptest.NewRequest(http.MethodGet, "/?tab=users&modal=config", nil)
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	r.Equal(http.StatusOK, rec.Code)
	body := rec.Body.String()
	r.Contains(body, "Tunnel established.")
	r.Contains(body, `form="rgrok-cancel-form">Cancel</button>`)
	r.Contains(body, `value="https://demo.rgrok.rselbach.com"`)
	r.Contains(body, `autocomplete="off" disabled`)
	r.NotContains(body, "Set up rgrok tunnel")
}

func TestRgrokSetupStartsTunnel(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{}))

	var got rgrokclient.Config
	var gotCtx context.Context
	tunnel := &fakeTunnel{}
	app := &webApp{
		localPort: 8080,
		rgrokStart: func(ctx context.Context, cfg rgrokclient.Config) (*startedRgrokTunnel, error) {
			gotCtx = ctx
			got = cfg
			return &startedRgrokTunnel{
				PublicURL: "https://demo.rgrok.rselbach.com",
				Tunnel:    tunnel,
			}, nil
		},
	}
	form := url.Values{
		"tab":         {"apps"},
		"rgrok_name":  {"Demo"},
		"rgrok_token": {"token-123"},
	}
	req := httptest.NewRequest(http.MethodPost, "/rgrok/setup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	r.Equal(http.StatusSeeOther, rec.Code)
	r.Contains(rec.Header().Get("Location"), "modal=config")
	r.Equal("https://rgrok.rselbach.com", got.ServerBaseURL)
	r.Equal("token-123", got.Token)
	r.Equal("demo", got.Name)
	r.Equal(8080, got.LocalPort)
	r.Equal("https://demo.rgrok.rselbach.com", app.rgrokPublicURL())
	r.False(tunnel.closed)
	r.NoError(gotCtx.Err())

	state, err := loadState()
	r.NoError(err)
	r.Equal("demo", state.Config.RgrokName)
	r.Equal("token-123", state.Config.RgrokToken)
	r.Equal("https://demo.rgrok.rselbach.com", state.Config.IDPBaseURL)
}

func TestRgrokSetupDoesNotBlockConfigSave(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{}))

	started := make(chan struct{})
	release := make(chan struct{})
	app := &webApp{
		localPort: 8080,
		rgrokStart: func(context.Context, rgrokclient.Config) (*startedRgrokTunnel, error) {
			close(started)
			<-release
			return &startedRgrokTunnel{
				PublicURL: "https://demo.rgrok.rselbach.com",
				Tunnel:    &fakeTunnel{},
			}, nil
		},
	}

	setupForm := url.Values{
		"tab":         {"apps"},
		"rgrok_name":  {"demo"},
		"rgrok_token": {"token-123"},
	}
	setupReq := httptest.NewRequest(http.MethodPost, "/rgrok/setup", strings.NewReader(setupForm.Encode()))
	setupReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setupRec := httptest.NewRecorder()
	setupDone := make(chan struct{})
	go func() {
		app.routes().ServeHTTP(setupRec, setupReq)
		close(setupDone)
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("rgrok setup did not start")
	}

	configForm := url.Values{
		"tab":          {"apps"},
		"base_url":     {"https://scim.greendale.test"},
		"bearer_token": {"chang-secret"},
	}
	configReq := httptest.NewRequest(http.MethodPost, "/config/save", strings.NewReader(configForm.Encode()))
	configReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	configRec := httptest.NewRecorder()
	configDone := make(chan struct{})
	go func() {
		app.routes().ServeHTTP(configRec, configReq)
		close(configDone)
	}()

	select {
	case <-configDone:
		r.Equal(http.StatusSeeOther, configRec.Code)
	case <-time.After(time.Second):
		t.Fatal("config save blocked on rgrok setup")
	}

	close(release)
	select {
	case <-setupDone:
		r.Equal(http.StatusSeeOther, setupRec.Code)
	case <-time.After(time.Second):
		t.Fatal("rgrok setup did not finish")
	}

	state, err := loadState()
	r.NoError(err)
	r.Equal("https://scim.greendale.test", state.Config.BaseURL)
	r.Equal("demo", state.Config.RgrokName)
}

func TestRgrokSetupRedirectsBackToDialogOnError(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)

	app := &webApp{localPort: 8080}
	form := url.Values{
		"tab":         {"users"},
		"rgrok_name":  {"bad_name"},
		"rgrok_token": {"token-123"},
	}
	req := httptest.NewRequest(http.MethodPost, "/rgrok/setup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	r.Equal(http.StatusSeeOther, rec.Code)
	location := rec.Header().Get("Location")
	r.Contains(location, "modal=config")
	r.Contains(location, "rgrok=1")
	r.Contains(location, "rgrok_error=")
	r.Empty(app.rgrokPublicURL())
}

func TestRgrokCancelClosesTunnel(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{
		Config: config{
			IDPBaseURL: "https://demo.rgrok.rselbach.com",
			RgrokName:  "demo",
			RgrokToken: "token-123",
		},
	}))

	tunnel := &fakeTunnel{}
	app := &webApp{
		rgrokTunnel: &activeRgrokTunnel{
			Name:      "demo",
			PublicURL: "https://demo.rgrok.rselbach.com",
			Tunnel:    tunnel,
		},
	}
	form := url.Values{"tab": {"users"}}
	req := httptest.NewRequest(http.MethodPost, "/rgrok/cancel", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	r.Equal(http.StatusSeeOther, rec.Code)
	r.True(tunnel.closed)
	r.Empty(app.rgrokPublicURL())

	state, err := loadState()
	r.NoError(err)
	r.Empty(state.Config.RgrokName)
	r.Empty(state.Config.RgrokToken)
	r.Empty(state.Config.IDPBaseURL)
}

func TestRestoreSavedRgrokTunnel(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{
		Config: config{
			RgrokName:  "demo",
			RgrokToken: "token-123",
		},
	}))

	var got rgrokclient.Config
	tunnel := &fakeTunnel{}
	app := &webApp{
		localPort: 8080,
		rgrokStart: func(ctx context.Context, cfg rgrokclient.Config) (*startedRgrokTunnel, error) {
			got = cfg
			return &startedRgrokTunnel{
				PublicURL: "https://demo.rgrok.rselbach.com",
				Tunnel:    tunnel,
			}, nil
		},
	}

	app.restoreSavedRgrokTunnel()

	r.Equal("https://rgrok.rselbach.com", got.ServerBaseURL)
	r.Equal("token-123", got.Token)
	r.Equal("demo", got.Name)
	r.Equal(8080, got.LocalPort)
	r.Equal("https://demo.rgrok.rselbach.com", app.rgrokPublicURL())
	r.False(tunnel.closed)

	state, err := loadState()
	r.NoError(err)
	r.Equal("demo", state.Config.RgrokName)
	r.Equal("token-123", state.Config.RgrokToken)
	r.Equal("https://demo.rgrok.rselbach.com", state.Config.IDPBaseURL)
}

func TestRgrokCancelWaitsForRestore(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{
		Config: config{
			RgrokName:  "demo",
			RgrokToken: "token-123",
		},
	}))

	started := make(chan struct{})
	release := make(chan struct{})
	tunnel := &fakeTunnel{}
	app := &webApp{
		localPort: 8080,
		rgrokStart: func(context.Context, rgrokclient.Config) (*startedRgrokTunnel, error) {
			close(started)
			<-release
			return &startedRgrokTunnel{
				PublicURL: "https://demo.rgrok.rselbach.com",
				Tunnel:    tunnel,
			}, nil
		},
	}
	restoreDone := make(chan struct{})
	go func() {
		app.restoreSavedRgrokTunnel()
		close(restoreDone)
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("rgrok restore did not start")
	}

	cancelForm := url.Values{"tab": {"users"}}
	cancelReq := httptest.NewRequest(http.MethodPost, "/rgrok/cancel", strings.NewReader(cancelForm.Encode()))
	cancelReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	cancelRec := httptest.NewRecorder()
	cancelDone := make(chan struct{})
	go func() {
		app.routes().ServeHTTP(cancelRec, cancelReq)
		close(cancelDone)
	}()

	close(release)
	select {
	case <-restoreDone:
	case <-time.After(time.Second):
		t.Fatal("rgrok restore did not finish")
	}
	select {
	case <-cancelDone:
	case <-time.After(time.Second):
		t.Fatal("rgrok cancel did not finish")
	}

	r.Equal(http.StatusSeeOther, cancelRec.Code)
	r.True(tunnel.closed)
	r.Empty(app.rgrokPublicURL())
	state, err := loadState()
	r.NoError(err)
	r.Empty(state.Config.RgrokName)
	r.Empty(state.Config.RgrokToken)
	r.Empty(state.Config.IDPBaseURL)
}

type fakeTunnel struct {
	closed bool
}

func (f *fakeTunnel) Close() error {
	f.closed = true
	return nil
}

func waitForSyncDone(t *testing.T, app *webApp) syncJobSnapshot {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		job := app.currentSyncJob()
		if job != nil && job.Done {
			return *job
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("sync job did not finish")
	return syncJobSnapshot{}
}

func setTestStateFile(t *testing.T) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.db")
	t.Setenv("SCIMTEST_STATE_FILE", path)
	r := require.New(t)
	r.NoError(os.RemoveAll(path))
}
