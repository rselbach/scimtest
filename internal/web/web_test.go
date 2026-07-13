package web

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
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
	r.Contains(dashboardAsset(t, app, "/assets/app.js"), "window.location.reload()")

	groupReq := httptest.NewRequest(http.MethodGet, "/?tab=groups", nil)
	groupRec := httptest.NewRecorder()
	app.routes().ServeHTTP(groupRec, groupReq)
	r.Equal(http.StatusOK, groupRec.Code)
	r.Contains(groupRec.Body.String(), "Greendale Study Group")
}

func TestIndexRendersConciseSCIMActionsAndUsernameHint(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{
		Apps: []app{{
			ID:              "app-1",
			Name:            "Greendale",
			Slug:            "greendale",
			Protocol:        "scim",
			SCIMEnabled:     true,
			SCIMBaseURL:     "https://example.test/scim",
			SCIMBearerToken: "token",
		}},
		UserOperations:  map[string][]operationLog{},
		GroupOperations: map[string][]operationLog{},
	}))

	app := &webApp{}
	rec := httptest.NewRecorder()
	app.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/?tab=users&environment=app-1&modal=user", nil))

	r.Equal(http.StatusOK, rec.Code)
	body := rec.Body.String()
	r.Contains(body, `data-sync-submit >Sync</button>`)
	r.Contains(body, `type="submit">Preview import</button>`)
	r.Contains(body, `type="submit">Reset</button>`)
	r.Contains(body, `Uses email when left blank`)
}

func TestDashboardDialogsAreLabelledAndFocusEditableFields(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{
		Users:  []user{{ID: "troy", GivenName: "Troy", FamilyName: "Barnes", Username: "troy", Email: "troy@greendale.edu", Active: true}},
		Groups: []group{{ID: "study-group", DisplayName: "Study Group", MemberIDs: []string{"troy"}}},
		Apps: []app{{
			ID:              "app-1",
			Name:            "Greendale",
			Slug:            "greendale",
			Protocol:        "scim",
			SCIMEnabled:     true,
			SCIMBaseURL:     "https://greendale.test/scim",
			SCIMBearerToken: "chang-secret",
		}},
		UserOperations: map[string][]operationLog{
			"troy": {{Kind: "local", Summary: "Created", CreatedAt: "2026-07-12T00:00:00Z"}},
		},
	}))
	appService := newTestIDPApp(t)
	appService.rememberTrace("app-1", []syncTraceEntry{{Operation: "create", Method: http.MethodPost, Path: "/Users"}})
	assetJS := dashboardAsset(t, appService, "/assets/app.js")
	r.Contains(assetJS, "document.querySelectorAll('.topbar, .app, .footer')")
	r.Contains(assetJS, "region.setAttribute('aria-hidden', 'true')")
	tests := map[string]struct {
		path         string
		titleID      string
		focusPattern string
	}{
		"user": {
			path:         "/?tab=users&modal=user",
			titleID:      "user-dialog-title",
			focusPattern: `name="username"[^>]*data-autofocus`,
		},
		"group": {
			path:         "/?tab=groups&modal=group",
			titleID:      "group-dialog-title",
			focusPattern: `name="display_name"[^>]*data-autofocus`,
		},
		"environment": {
			path:         "/?tab=apps&modal=app",
			titleID:      "app-dialog-title",
			focusPattern: `name="name"[^>]*data-autofocus`,
		},
		"config": {
			path:         "/?tab=users&modal=config",
			titleID:      "config-dialog-title",
			focusPattern: `name="idp_base_url"[^>]*data-autofocus`,
		},
		"tools": {
			path:         "/?tab=users&modal=tools",
			titleID:      "tools-dialog-title",
			focusPattern: `name="count"[^>]*data-autofocus`,
		},
		"history": {
			path:    "/?tab=users&historyType=user&historyID=troy",
			titleID: "history-dialog-title",
		},
		"trace": {
			path:    "/?tab=users&showTrace=1",
			titleID: "trace-dialog-title",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			rec := httptest.NewRecorder()
			appService.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, nil))

			r.Equal(http.StatusOK, rec.Code)
			body := rec.Body.String()
			r.Contains(body, `aria-labelledby="`+tc.titleID+`"`)
			r.Contains(body, `id="`+tc.titleID+`"`)
			if tc.focusPattern != "" {
				r.Regexp(tc.focusPattern, body)
			}
		})
	}
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

func TestIndexRendersBulkUserSelection(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{
		Users: []user{
			{ID: "u1", GivenName: "Troy", FamilyName: "Barnes", Username: "troy", Email: "troy@greendale.edu"},
			{ID: "u2", GivenName: "Pierce", FamilyName: "Hawthorne", Username: "pierce", Email: "pierce@greendale.edu", Deleted: true},
		},
		UserOperations:  map[string][]operationLog{},
		GroupOperations: map[string][]operationLog{},
	}))

	app := &webApp{}
	rec := httptest.NewRecorder()
	app.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/?tab=users", nil))

	r.Equal(http.StatusOK, rec.Code)
	body := rec.Body.String()
	r.Contains(body, `action="/users/delete"`)
	r.Contains(body, `data-select-all`)
	r.Contains(body, `name="user_ids" value="u1"`)
	r.NotContains(body, `name="user_ids" value="u2"`)
}

func TestBulkDeleteUsers(t *testing.T) {
	tests := map[string]struct {
		state        appState
		userIDs      []string
		wantUsers    []string
		wantDeleted  []string
		wantMembers  []string
		wantSCIMApps []string
	}{
		"SCIM enabled marks selected users for deletion": {
			state: appState{
				Apps: []app{
					{ID: "app-1", Name: "Study App", Slug: "study-app", Protocol: "scim", SCIMEnabled: true, SCIMBaseURL: "https://study.example.test/scim", SCIMBearerToken: "token"},
					{ID: "app-2", Name: "Library App", Slug: "library-app", Protocol: "scim", SCIMEnabled: true, SCIMBaseURL: "https://library.example.test/scim", SCIMBearerToken: "token"},
					{ID: "app-3", Name: "Cafeteria App", Slug: "cafeteria-app", Protocol: "oidc"},
				},
				Users: []user{
					{ID: "u1", GivenName: "Troy", FamilyName: "Barnes", Username: "troy", Email: "troy@greendale.edu"},
					{ID: "u2", GivenName: "Abed", FamilyName: "Nadir", Username: "abed", Email: "abed@greendale.edu"},
					{ID: "u3", GivenName: "Annie", FamilyName: "Edison", Username: "annie", Email: "annie@greendale.edu"},
				},
				UserOperations:  map[string][]operationLog{},
				GroupOperations: map[string][]operationLog{},
			},
			userIDs:      []string{"u1", "u3"},
			wantUsers:    []string{"u1", "u2", "u3"},
			wantDeleted:  []string{"u1", "u3"},
			wantSCIMApps: []string{"app-1", "app-2"},
		},
		"SCIM disabled removes selected users and memberships": {
			state: appState{
				Config: config{SCIMDisabled: true},
				Users: []user{
					{ID: "u1", GivenName: "Troy", FamilyName: "Barnes", Username: "troy", Email: "troy@greendale.edu"},
					{ID: "u2", GivenName: "Abed", FamilyName: "Nadir", Username: "abed", Email: "abed@greendale.edu"},
					{ID: "u3", GivenName: "Annie", FamilyName: "Edison", Username: "annie", Email: "annie@greendale.edu"},
				},
				Groups:          []group{{ID: "g1", DisplayName: "Study Group", MemberIDs: []string{"u1", "u2", "u3"}}},
				UserOperations:  map[string][]operationLog{},
				GroupOperations: map[string][]operationLog{},
			},
			userIDs:     []string{"u1", "u3"},
			wantUsers:   []string{"u2"},
			wantDeleted: []string{},
			wantMembers: []string{"u2"},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			setTestStateFile(t)
			r.NoError(saveState(tc.state))

			form := url.Values{"tab": {"users"}, "user_ids": tc.userIDs}
			req := httptest.NewRequest(http.MethodPost, "/users/delete", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()
			(&webApp{}).routes().ServeHTTP(rec, req)

			r.Equal(http.StatusSeeOther, rec.Code)
			updated, err := loadState()
			r.NoError(err)
			userIDs := make([]string, 0, len(updated.Users))
			deletedIDs := make([]string, 0, len(updated.Users))
			for _, u := range updated.Users {
				userIDs = append(userIDs, u.ID)
				if u.Deleted {
					deletedIDs = append(deletedIDs, u.ID)
				}
			}
			r.Equal(tc.wantUsers, userIDs)
			r.Equal(tc.wantDeleted, deletedIDs)
			if tc.wantMembers != nil {
				r.Equal(tc.wantMembers, updated.Groups[0].MemberIDs)
			}
			for _, appID := range tc.wantSCIMApps {
				for _, userID := range tc.wantDeleted {
					r.True(updated.UserSync[appID][userID].Dirty)
					r.True(updated.UserSync[appID][userID].Deleted)
				}
				r.False(updated.UserSync[appID]["u2"].Dirty)
			}
			r.NotContains(updated.UserSync, "app-3")
		})
	}
}

func TestBulkDeleteUsersRejectsInvalidSelectionAtomically(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{
		Users: []user{
			{ID: "u1", GivenName: "Troy", FamilyName: "Barnes", Username: "troy", Email: "troy@greendale.edu"},
			{ID: "u2", GivenName: "Abed", FamilyName: "Nadir", Username: "abed", Email: "abed@greendale.edu"},
		},
		UserOperations:  map[string][]operationLog{},
		GroupOperations: map[string][]operationLog{},
	}))

	form := url.Values{"tab": {"users"}, "user_ids": {"u1", "missing"}}
	req := httptest.NewRequest(http.MethodPost, "/users/delete", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	(&webApp{}).routes().ServeHTTP(rec, req)

	r.Equal(http.StatusSeeOther, rec.Code)
	updated, err := loadState()
	r.NoError(err)
	r.Len(updated.Users, 2)
	r.False(updated.Users[0].Deleted)
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
	r.False(updated.Users[0].Dirty)
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
		r.False(u.Dirty)
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
	r.False(updated.Users[0].Dirty)
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
	r.False(updated.Users[0].Dirty)
	r.False(updated.Users[1].Active)
	r.False(updated.Users[1].Dirty)
	r.False(updated.Users[2].Active)
	r.False(updated.Users[2].Dirty)
	r.Equal("Deactivated", updated.UserOperations["u2"][0].Summary)
}

func TestToolsDeleteAll(t *testing.T) {
	t.Run("SCIM enabled marks users for deletion", func(t *testing.T) {
		r := require.New(t)
		setTestStateFile(t)
		r.NoError(saveState(appState{
			Apps: []app{{ID: "app-1", Name: "Study App", Slug: "study-app", Protocol: "scim", SCIMEnabled: true, SCIMBaseURL: "https://example.test/scim", SCIMBearerToken: "token"}},
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
		r.False(updated.Users[0].Dirty)
		r.True(updated.UserSync["app-1"]["u1"].Dirty)
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

func TestToolsClearUsersLocalNeverContactsSCIM(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests++
	}))
	defer server.Close()
	r.NoError(saveState(appState{
		Config: config{BaseURL: server.URL, BearerToken: "chang-secret"},
		Users: []user{
			{ID: "u1", GivenName: "Troy", FamilyName: "Barnes", Username: "troy", Email: "troy@greendale.edu", Active: true, RemoteID: "remote-troy"},
			{ID: "u2", GivenName: "Abed", FamilyName: "Nadir", Username: "abed", Email: "abed@greendale.edu", Active: true, RemoteID: "remote-abed"},
		},
		Groups: []group{
			{ID: "g1", DisplayName: "Study Group", MemberIDs: []string{"u1", "u2"}, RemoteID: "remote-group"},
			{ID: "g2", DisplayName: "Empty Group", RemoteID: "remote-empty"},
		},
		UserOperations: map[string][]operationLog{
			"u1": {{Kind: "sync", Summary: "Created"}},
		},
		GroupOperations: map[string][]operationLog{},
	}))
	app := &webApp{}
	form := url.Values{"tab": {"users"}}
	req := httptest.NewRequest(http.MethodPost, "/tools/clear-users-local", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	r.Equal(http.StatusSeeOther, rec.Code)
	r.Zero(requests)
	updated, err := loadState()
	r.NoError(err)
	r.Empty(updated.Users)
	r.Empty(updated.UserOperations)
	r.Empty(updated.Groups[0].MemberIDs)
	r.False(updated.Groups[0].Dirty)
	r.True(updated.GroupSync["app_legacy_scim"]["g1"].Dirty)
	r.Empty(updated.Groups[0].LastError)
	r.False(updated.Groups[1].Dirty)
	r.Contains(rec.Header().Get("Set-Cookie"), "cleared")
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
	r.Equal("remote-user-1", updated.UserSync["app_legacy_scim"]["u1"].RemoteID)
	r.False(updated.UserSync["app_legacy_scim"]["u1"].Dirty)
	r.NotEmpty(updated.UserOperations["u1"])
	r.Contains(app.traceContent("app_legacy_scim"), "POST /Users")
}

func TestReconcileRepairsDriftedSyncedUser(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)

	requests := make([]string, 0, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		requests = append(requests, req.Method+" "+req.URL.Path)
		switch req.Method + " " + req.URL.Path {
		case "GET /Users/remote-user-1":
			w.Header().Set("Content-Type", "application/scim+json")
			_, err := fmt.Fprint(w, `{"id":"remote-user-1","externalId":"u1","userName":"sbennett-old"}`)
			r.NoError(err)
		case "PUT /Users/remote-user-1":
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected request: %s %s", req.Method, req.URL.Path)
		}
	}))
	defer server.Close()

	state := appState{
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
			RemoteID:   "remote-user-1",
		}},
		UserOperations:  map[string][]operationLog{},
		GroupOperations: map[string][]operationLog{},
	}
	r.NoError(saveState(state))

	app := &webApp{}
	form := url.Values{"tab": {"users"}}
	req := httptest.NewRequest(http.MethodPost, "/reconcile", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, req)

	r.Equal(http.StatusSeeOther, rec.Code)
	job := waitForSyncDone(t, app)
	r.True(job.Success)
	r.Contains(job.Message, "1 updated")
	r.Equal([]string{
		"GET /Users/remote-user-1",
		"PUT /Users/remote-user-1",
	}, requests)
	updated, err := loadState()
	r.NoError(err)
	r.Equal("remote-user-1", updated.UserSync["app_legacy_scim"]["u1"].RemoteID)
	r.False(updated.UserSync["app_legacy_scim"]["u1"].Dirty)
	r.NotEmpty(updated.UserOperations["u1"])
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
	r.Equal(1, runningJob.LatestSequence)
	r.Equal([]syncJobEvent{{
		Sequence:     1,
		ID:           "user:u1",
		ResourceType: "user",
		ResourceID:   "u1",
		Label:        "Shirley Bennett (sbennett)",
		Operation:    "create",
		Phase:        "running",
	}}, runningJob.Events)

	updated, err := loadState()
	r.NoError(err)
	r.Empty(updated.Users[0].RemoteID)

	close(release)
	finishedJob := waitForSyncDone(t, app)
	r.True(finishedJob.Success)
	r.Equal(100, finishedJob.Percent)
	r.Equal("create user Shirley Bennett (sbennett)", finishedJob.Current)
	r.Equal(2, finishedJob.LatestSequence)
	r.Len(finishedJob.Events, 2)
	r.Equal("done", finishedJob.Events[1].Phase)

	incrementalReq := httptest.NewRequest(http.MethodGet, "/sync/status?after=1", nil)
	incrementalRec := httptest.NewRecorder()
	app.routes().ServeHTTP(incrementalRec, incrementalReq)
	r.Equal(http.StatusOK, incrementalRec.Code)
	var incrementalJob syncJobSnapshot
	r.NoError(json.NewDecoder(incrementalRec.Body).Decode(&incrementalJob))
	r.Len(incrementalJob.Events, 1)
	r.Equal(2, incrementalJob.Events[0].Sequence)
	r.Equal("done", incrementalJob.Events[0].Phase)
}

func TestSyncStatusRejectsInvalidEventSequence(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{}))
	rec := httptest.NewRecorder()

	newTestIDPApp(t).routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/sync/status?after=-1", nil))

	r.Equal(http.StatusBadRequest, rec.Code)
	r.Equal("application/json", rec.Header().Get("Content-Type"))
	r.JSONEq(`{"error":"sync event sequence must be a non-negative integer"}`, rec.Body.String())
}

func TestCurrentSyncJobAfterDoesNotResendLargeActivityHistory(t *testing.T) {
	r := require.New(t)
	events := make([]syncJobEvent, 10000)
	for i := range events {
		events[i] = syncJobEvent{
			Sequence: i + 1,
			ID:       fmt.Sprintf("user-%d", i+1),
			Label:    "Human Being mascot",
			Phase:    "done",
		}
	}
	app := &webApp{syncJobs: map[string]*syncJobSnapshot{
		"app-greendale": {LatestSequence: len(events), Events: events},
	}}

	job := app.currentSyncJobAfter("app-greendale", 9999)

	r.Len(job.Events, 1)
	r.Equal(10000, job.Events[0].Sequence)
	r.Len(app.syncJobs["app-greendale"].Events, 10000)
}

func TestMutationIsRejectedWhileSyncRuns(t *testing.T) {
	r := require.New(t)
	app := &webApp{syncJobs: map[string]*syncJobSnapshot{"app-1": {Running: true}}}
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
	r.Equal("application/json", rec.Header().Get("Content-Type"))
	r.JSONEq(`{"error":"sync is running; wait for it to finish"}`, rec.Body.String())
}

func TestInvalidUserFormPreservesSubmittedValues(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{}))
	app := &webApp{}
	form := url.Values{
		"tab":         {"users"},
		"email":       {"troy@greendale.edu"},
		"username":    {"troy"},
		"family_name": {"Barnes"},
	}
	post := httptest.NewRequest(http.MethodPost, "/users/save", strings.NewReader(form.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postRec := httptest.NewRecorder()
	app.routes().ServeHTTP(postRec, post)

	r.Equal(http.StatusSeeOther, postRec.Code)
	cookies := postRec.Result().Cookies()
	r.NotEmpty(cookies)
	get := httptest.NewRequest(http.MethodGet, postRec.Header().Get("Location"), nil)
	for _, cookie := range cookies {
		get.AddCookie(cookie)
	}
	getRec := httptest.NewRecorder()
	app.routes().ServeHTTP(getRec, get)

	r.Equal(http.StatusOK, getRec.Code)
	r.Contains(getRec.Body.String(), "given name is required")
	r.Contains(getRec.Body.String(), `value="troy@greendale.edu"`)
	r.Contains(getRec.Body.String(), `value="Barnes"`)
}

func TestDashboardRendersCriticalFlowAffordances(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{
		Users: []user{{ID: "troy", GivenName: "Troy", FamilyName: "Barnes", Username: "troy", Email: "troy@greendale.edu", Active: true}},
		Apps: []app{{
			ID:               "app-1",
			Name:             "Greendale Portal",
			Slug:             "greendale",
			Protocol:         "both",
			OIDCClientID:     "greendale-client",
			OIDCRedirectURIs: []string{"http://localhost:3000/callback"},
			SAMLACSURL:       "http://localhost:3000/saml/acs",
			SAMLNameIDField:  "email",
			SAMLNameIDFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		}},
	}))
	app := newTestIDPApp(t)
	state, err := loadState()
	r.NoError(err)
	state.Apps[0].SCIMEnabled = true
	state.Apps[0].SCIMBaseURL = "https://scim.example.test"
	state.Apps[0].SCIMBearerToken = "token"
	initializeAppSync(&state, "app-1")
	r.NoError(saveState(state))
	app.syncJobs = map[string]*syncJobSnapshot{"app-1": {Running: true, Percent: 42, Message: "Creating Troy"}}
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/?tab=apps", nil))

	r.Equal(http.StatusOK, rec.Code)
	body := rec.Body.String()
	r.Contains(body, ">Discovery</a>")
	r.Contains(body, ">Test OIDC</a>")
	r.Contains(body, ">Metadata</a>")
	r.Contains(body, ">Test SAML</a>")
	r.NotContains(body, "Get ready to test")
	listRec := httptest.NewRecorder()
	app.routes().ServeHTTP(listRec, httptest.NewRequest(http.MethodGet, "/?tab=apps&partial=list", nil))
	r.Equal(http.StatusOK, listRec.Code)
	r.NotContains(listRec.Body.String(), "https://scim.example.test")

	editRec := httptest.NewRecorder()
	app.routes().ServeHTTP(editRec, httptest.NewRequest(http.MethodGet, "/?tab=apps&modal=app&id=app-1", nil))
	r.Equal(http.StatusOK, editRec.Code)
	r.Contains(editRec.Body.String(), `value="https://scim.example.test"`)

	progressRec := httptest.NewRecorder()
	app.routes().ServeHTTP(progressRec, httptest.NewRequest(http.MethodGet, "/?tab=users", nil))
	r.Contains(progressRec.Body.String(), `role="progressbar"`)
	r.Contains(progressRec.Body.String(), `aria-valuenow="42"`)
	r.Contains(progressRec.Body.String(), `aria-live="polite"`)
	r.Contains(progressRec.Body.String(), `data-sync-details`)
	r.Contains(progressRec.Body.String(), `data-sync-activity-list`)
	r.Contains(progressRec.Body.String(), `data-sync-details-open>View details</button>`)
	r.Contains(dashboardAsset(t, app, "/assets/app.js"), `statusURL.searchParams.set('after', String(syncEventSequence))`)
}

func TestDashboardJavaScriptDoesNotContainStyles(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{}))
	app := newTestIDPApp(t)
	rec := httptest.NewRecorder()
	app.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/assets/app.js", nil))
	r.Equal(http.StatusOK, rec.Code)
	r.Equal("public, max-age=3600", rec.Header().Get("Cache-Control"))
	r.NotContains(rec.Body.String(), ".section-label")
	r.NotContains(rec.Body.String(), "grid-column:")
	r.Contains(dashboardAsset(t, app, "/assets/app.css"), ".section-label")
}

func TestNewEnvironmentFormGeneratesSlugLocally(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{}))
	app := newTestIDPApp(t)
	rec := httptest.NewRecorder()
	app.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/?tab=apps&modal=app", nil))

	r.Equal(http.StatusOK, rec.Code)
	body := rec.Body.String()
	r.Contains(body, `data-environment-form`)
	r.Contains(body, `data-environment-name`)
	r.Contains(body, `data-environment-slug`)
	assetJS := dashboardAsset(t, app, "/assets/app.js")
	r.Contains(assetJS, `if (environmentForm && !environmentForm.elements.id.value)`)
	r.Contains(assetJS, `.replace(/[^a-z0-9]+/g, '-')`)
}

func TestDashboardUsesOneGlobalDirectory(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{Users: []user{
		{ID: "troy", GivenName: "Troy", FamilyName: "Barnes", Email: "troy@greendale.edu", Username: "troy", Active: true},
		{ID: "abed", GivenName: "Abed", FamilyName: "Nadir", Email: "abed@greendale.edu", Username: "abed", Active: true},
	}}))
	app := newTestIDPApp(t)

	rec := httptest.NewRecorder()
	app.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/?tab=users&environment=obsolete", nil))

	r.Equal(http.StatusOK, rec.Code)
	body := rec.Body.String()
	r.Contains(body, "Abed Nadir")
	r.Contains(body, "Troy Barnes")
	r.NotContains(body, "Edit environment")
}

func TestEnvironmentSelectorRendersInTopbar(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{Apps: []app{
		{
			ID: "app-1", Name: "Greendale SCIM", Slug: "greendale-scim", Protocol: "scim",
			SCIMEnabled: true, SCIMBaseURL: "https://greendale.test/scim", SCIMBearerToken: "token",
		},
		{ID: "app-2", Name: "Greendale OIDC", Slug: "greendale-oidc", Protocol: "oidc"},
	}}))
	appService := newTestIDPApp(t)

	for _, tab := range []string{"users", "groups"} {
		rec := httptest.NewRecorder()
		appService.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/?tab="+tab+"&environment=app-1", nil))

		r.Equal(http.StatusOK, rec.Code)
		body := rec.Body.String()
		selectorIndex := strings.Index(body, `id="environment-selector"`)
		topbarEnd := strings.Index(body, `</header>`)
		r.Greater(selectorIndex, 0)
		r.Less(selectorIndex, topbarEnd)
		r.Equal(1, strings.Count(body, `id="environment-selector"`))
		r.Contains(body, "Active environment")
		r.Contains(body, "Greendale SCIM")
		r.Contains(body, "Greendale OIDC")
		r.Contains(body, "data-sync-submit >Sync</button>")
		r.NotContains(body, "Sync Greendale SCIM")
		r.NotContains(body, "Sync target")
	}
}

func TestEnvironmentContextIsExplicitAndIndependentPerRequest(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{
		Users: []user{{ID: "troy", GivenName: "Troy", FamilyName: "Barnes", Email: "troy@greendale.edu", Username: "troy", Active: true}},
		Apps: []app{
			{ID: "app-local", Name: "dev-local", Slug: "dev-local", Protocol: "scim", SCIMEnabled: true, SCIMBaseURL: "https://local.test/scim", SCIMBearerToken: "local-token"},
			{ID: "app-staging", Name: "staging", Slug: "staging", Protocol: "scim", SCIMEnabled: true, SCIMBaseURL: "https://staging.test/scim", SCIMBearerToken: "staging-token"},
		},
		UserSync: map[string]map[string]resourceSyncState{
			"app-local":   {"troy": {RemoteID: "remote-local"}},
			"app-staging": {"troy": {RemoteID: "remote-staging"}},
		},
	}))
	appService := newTestIDPApp(t)

	localRec := httptest.NewRecorder()
	appService.routes().ServeHTTP(localRec, httptest.NewRequest(http.MethodGet, "/?tab=users&environment=app-local", nil))
	r.Equal(http.StatusOK, localRec.Code)
	r.Contains(localRec.Body.String(), "remote-local")
	r.NotContains(localRec.Body.String(), "remote-staging")
	r.Contains(localRec.Body.String(), "environment=app-local")

	stagingRec := httptest.NewRecorder()
	appService.routes().ServeHTTP(stagingRec, httptest.NewRequest(http.MethodGet, "/?tab=users&environment=app-staging", nil))
	r.Equal(http.StatusOK, stagingRec.Code)
	r.Contains(stagingRec.Body.String(), "remote-staging")
	r.NotContains(stagingRec.Body.String(), "remote-local")
	r.Contains(stagingRec.Body.String(), "environment=app-staging")
}

func TestAuthenticationOnlyEnvironmentHidesSCIMActions(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{
		Users: []user{{ID: "abed", GivenName: "Abed", FamilyName: "Nadir", Email: "abed@greendale.edu", Username: "abed", Active: true}},
		Apps: []app{
			{ID: "app-scim", Name: "SCIM", Slug: "scim", Protocol: "scim", SCIMEnabled: true, SCIMBaseURL: "https://scim.test", SCIMBearerToken: "token"},
			{ID: "app-oidc", Name: "OIDC only", Slug: "oidc-only", Protocol: "oidc"},
		},
	}))
	appService := newTestIDPApp(t)
	rec := httptest.NewRecorder()
	appService.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/?tab=users&environment=app-oidc", nil))

	r.Equal(http.StatusOK, rec.Code)
	body := rec.Body.String()
	r.Contains(body, `<option value="app-oidc" selected>OIDC only</option>`)
	r.NotContains(body, "Sync OIDC only")
	r.NotContains(body, "Remote ID")
}

func TestAppSaveStoresSCIMSettingsAndInitializesSyncState(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{
		Users:  []user{{ID: "troy", GivenName: "Troy", FamilyName: "Barnes", Email: "troy@greendale.edu", Username: "troy", Active: true}},
		Groups: []group{{ID: "study-group", DisplayName: "Study Group", MemberIDs: []string{"troy"}}},
	}))
	appService := newTestIDPApp(t)
	form := url.Values{
		"tab":                     {"apps"},
		"name":                    {"Greendale Portal"},
		"slug":                    {"greendale-portal"},
		"protocol":                {"oidc"},
		"allow_any_oidc_redirect": {"on"},
		"scim_enabled":            {"on"},
		"scim_base_url":           {"https://portal.test/scim/v2"},
		"scim_bearer_token":       {"chang-secret"},
		"scim_auto_open_trace":    {"on"},
	}
	req := httptest.NewRequest(http.MethodPost, "/apps/save", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	appService.routes().ServeHTTP(rec, req)

	r.Equal(http.StatusSeeOther, rec.Code)
	state, err := loadState()
	r.NoError(err)
	r.Len(state.Apps, 1)
	savedApp := state.Apps[0]
	r.Contains(rec.Header().Get("Location"), "environment="+savedApp.ID)
	r.True(savedApp.SCIMEnabled)
	r.Equal("https://portal.test/scim/v2", savedApp.SCIMBaseURL)
	r.Equal("chang-secret", savedApp.SCIMBearerToken)
	r.True(savedApp.SCIMAutoOpenTrace)
	r.True(state.UserSync[savedApp.ID]["troy"].Dirty)
	r.True(state.GroupSync[savedApp.ID]["study-group"].Dirty)
	state.UserSync[savedApp.ID]["troy"] = resourceSyncState{RemoteID: "remote-troy", LastError: "old user error"}
	state.GroupSync[savedApp.ID]["study-group"] = resourceSyncState{RemoteID: "remote-study-group", LastError: "old group error"}
	r.NoError(saveState(state))

	form.Set("id", savedApp.ID)
	form.Set("name", "Greendale Portal Updated")
	form.Del("scim_bearer_token")
	req = httptest.NewRequest(http.MethodPost, "/apps/save", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	appService.routes().ServeHTTP(rec, req)
	r.Equal(http.StatusSeeOther, rec.Code)
	state, err = loadState()
	r.NoError(err)
	r.Equal("chang-secret", state.Apps[0].SCIMBearerToken)
	r.Equal("remote-troy", state.UserSync[savedApp.ID]["troy"].RemoteID)
	r.Equal("remote-study-group", state.GroupSync[savedApp.ID]["study-group"].RemoteID)

	form.Set("scim_base_url", "https://new-portal.test/scim/v2/")
	req = httptest.NewRequest(http.MethodPost, "/apps/save", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	appService.routes().ServeHTTP(rec, req)
	r.Equal(http.StatusSeeOther, rec.Code)
	state, err = loadState()
	r.NoError(err)
	r.Equal("https://new-portal.test/scim/v2", state.Apps[0].SCIMBaseURL)
	r.Equal(resourceSyncState{Dirty: true}, state.UserSync[savedApp.ID]["troy"])
	r.Equal(resourceSyncState{Dirty: true}, state.GroupSync[savedApp.ID]["study-group"])
}

func TestDeletingActiveEnvironmentSelectsNextEnvironment(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{Apps: []app{
		{ID: "app-local", Name: "dev-local", Slug: "dev-local", Protocol: "oidc"},
		{ID: "app-staging", Name: "staging", Slug: "staging", Protocol: "oidc"},
	}}))
	appService := newTestIDPApp(t)
	form := url.Values{"environment": {"app-local"}}
	req := httptest.NewRequest(http.MethodPost, "/apps/app-local/delete", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	appService.routes().ServeHTTP(rec, req)

	r.Equal(http.StatusSeeOther, rec.Code)
	r.Contains(rec.Header().Get("Location"), "environment=app-staging")
	state, err := loadState()
	r.NoError(err)
	r.Len(state.Apps, 1)
	r.Equal("app-staging", state.Apps[0].ID)
}

func TestEnvironmentRoutesAreRemoved(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{}))
	app := newTestIDPApp(t)
	form := url.Values{"tab": {"users"}, "name": {"Greendale Staging"}}
	createReq := httptest.NewRequest(http.MethodPost, "/environments/save", strings.NewReader(form.Encode()))
	createReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	createRec := httptest.NewRecorder()
	app.routes().ServeHTTP(createRec, createReq)
	r.Equal(http.StatusMethodNotAllowed, createRec.Code)

	deleteForm := url.Values{"tab": {"users"}, "confirmation": {"wrong"}}
	deleteReq := httptest.NewRequest(http.MethodPost, "/environments/obsolete/delete", strings.NewReader(deleteForm.Encode()))
	deleteReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	deleteRec := httptest.NewRecorder()
	app.routes().ServeHTTP(deleteRec, deleteReq)
	r.Equal(http.StatusMethodNotAllowed, deleteRec.Code)
}

func TestSyncOnlyMutatesSelectedApp(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.Equal("/Users", req.URL.Path)
		w.Header().Set("Content-Type", "application/scim+json")
		_, err := fmt.Fprint(w, `{"id":"remote-troy-b"}`)
		r.NoError(err)
	}))
	defer server.Close()
	r.NoError(saveState(appState{
		Users: []user{{ID: "troy", GivenName: "Troy", FamilyName: "Barnes", Email: "troy@greendale.edu", Username: "troy", Active: true}},
		Apps: []app{
			{ID: "app-a", Name: "App A", Slug: "app-a", Protocol: "scim", SCIMEnabled: true, SCIMBaseURL: server.URL, SCIMBearerToken: "token-a"},
			{ID: "app-b", Name: "App B", Slug: "app-b", Protocol: "scim", SCIMEnabled: true, SCIMBaseURL: server.URL, SCIMBearerToken: "token-b"},
		},
		UserSync: map[string]map[string]resourceSyncState{
			"app-a": {"troy": {Dirty: true}},
			"app-b": {"troy": {Dirty: true}},
		},
	}))
	app := newTestIDPApp(t)
	form := url.Values{"tab": {"users"}, "environment": {"app-b"}}
	req := httptest.NewRequest(http.MethodPost, "/sync", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()
	app.routes().ServeHTTP(rec, req)
	r.Equal(http.StatusOK, rec.Code)

	deadline := time.Now().Add(2 * time.Second)
	for {
		job := app.currentSyncJob("app-b")
		if job != nil && job.Done {
			r.True(job.Success)
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("app sync did not finish")
		}
		time.Sleep(5 * time.Millisecond)
	}

	state, err := loadState()
	r.NoError(err)
	r.True(state.UserSync["app-a"]["troy"].Dirty)
	r.Empty(state.UserSync["app-a"]["troy"].RemoteID)
	r.False(state.UserSync["app-b"]["troy"].Dirty)
	r.Equal("remote-troy-b", state.UserSync["app-b"]["troy"].RemoteID)
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
	r.Contains(updated.UserSync["app_legacy_scim"]["u1"].LastError, "Try again now")
	r.NotContains(updated.UserSync["app_legacy_scim"]["u1"].LastError, "schemas")
	r.Equal("0", updated.UserOperations["u1"][0].ResponseRetryAfter)
	r.Contains(app.traceContent("app_legacy_scim"), "Retry-After: 0")

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
	r.Contains(rec.Header().Get("Set-Cookie"), "SCIM+is+not+enabled+for+the+active+environment")
}

func TestConfigRendersAutomaticRgrokStatus(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{}))
	rec := httptest.NewRecorder()

	newTestIDPApp(t).routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/?tab=users&modal=config", nil))

	r.Equal(http.StatusOK, rec.Code)
	r.Contains(rec.Body.String(), "Automatic tunnel:")
	r.NotContains(rec.Body.String(), "rgrok_token")
	r.NotContains(rec.Body.String(), "rgrok_name")
}

func TestLoadRgrokApplicationIdentity(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	_ = publicKey
	seed := privateKey.Seed()

	tests := map[string]struct {
		profileID string
		seed      string
		required  string
		wantNil   bool
		wantErr   string
	}{
		"development build without identity": {wantNil: true},
		"release missing identity":           {required: "true", wantErr: "profile id"},
		"invalid profile":                    {profileID: "not-a-profile", seed: base64.StdEncoding.EncodeToString(seed), wantErr: "profile id"},
		"missing seed":                       {profileID: strings.Repeat("a", 32), wantErr: "private seed is required"},
		"invalid base64":                     {profileID: strings.Repeat("a", 32), seed: "%%%", wantErr: "invalid base64"},
		"wrong seed size":                    {profileID: strings.Repeat("a", 32), seed: base64.StdEncoding.EncodeToString([]byte("short")), wantErr: "32 bytes"},
		"valid identity":                     {profileID: strings.Repeat("a", 32), seed: base64.StdEncoding.EncodeToString(seed)},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			oldProfileID, oldSeed, oldRequired := rgrokApplicationProfileID, rgrokApplicationPrivateSeed, rgrokReleaseIdentityRequired
			t.Cleanup(func() {
				rgrokApplicationProfileID, rgrokApplicationPrivateSeed, rgrokReleaseIdentityRequired = oldProfileID, oldSeed, oldRequired
			})
			rgrokApplicationProfileID, rgrokApplicationPrivateSeed, rgrokReleaseIdentityRequired = tc.profileID, tc.seed, tc.required

			identity, err := loadRgrokApplicationIdentity()
			if tc.wantErr != "" {
				r.ErrorContains(err, tc.wantErr)
				return
			}
			r.NoError(err)
			if tc.wantNil {
				r.Nil(identity)
				return
			}
			r.Equal(tc.profileID, identity.profileID)
			r.Equal(privateKey, identity.privateKey)
		})
	}
}

func TestAutomaticRgrokTunnelUsesApplicationIdentity(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{}))
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	r.NoError(err)
	var got rgrokclient.Config
	tunnel := &fakeTunnel{}
	app := &webApp{
		localPort: 8080,
		rgrokStart: func(_ context.Context, cfg rgrokclient.Config) (*startedRgrokTunnel, error) {
			got = cfg
			return &startedRgrokTunnel{PublicURL: "https://random.rgrok.rselbach.com", Tunnel: tunnel}, nil
		},
	}

	app.startAutomaticRgrokTunnel(rgrokApplicationIdentity{profileID: strings.Repeat("a", 32), privateKey: privateKey})

	r.Equal("https://rgrok.rselbach.com", got.ServerBaseURL)
	r.Equal(strings.Repeat("a", 32), got.ApplicationProfileID)
	r.NotEmpty(got.InstanceID)
	r.Equal(privateKey, got.ApplicationPrivateKey)
	r.Empty(got.Token)
	r.Empty(got.Name)
	r.Equal(8080, got.LocalPort)
	r.Equal("https://random.rgrok.rselbach.com", app.rgrokPublicURL())
	r.NoError(app.closeAutomaticRgrokTunnel())
	r.True(tunnel.closed)
	r.Empty(app.rgrokPublicURL())
}

func TestAutomaticRgrokTunnelSurfacesRegistrationError(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{}))
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	r.NoError(err)
	app := &webApp{
		localPort: 8080,
		rgrokStart: func(context.Context, rgrokclient.Config) (*startedRgrokTunnel, error) {
			return nil, fmt.Errorf("application profile rejected")
		},
	}

	app.startAutomaticRgrokTunnel(rgrokApplicationIdentity{profileID: strings.Repeat("a", 32), privateKey: privateKey})

	r.Equal("start automatic tunnel: application profile rejected", app.rgrokError())
}

func TestAutomaticRgrokTunnelClosesInvalidTunnel(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{}))
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	r.NoError(err)
	tunnel := &fakeTunnel{}
	app := &webApp{
		localPort: 8080,
		rgrokStart: func(context.Context, rgrokclient.Config) (*startedRgrokTunnel, error) {
			return &startedRgrokTunnel{Tunnel: tunnel}, nil
		},
	}

	app.startAutomaticRgrokTunnel(rgrokApplicationIdentity{profileID: strings.Repeat("a", 32), privateKey: privateKey})

	r.True(tunnel.closed)
	r.Equal("rgrok did not return a public URL", app.rgrokError())
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
		app.syncJobMu.Lock()
		var job *syncJobSnapshot
		for _, candidate := range app.syncJobs {
			job = cloneSyncJob(candidate)
			break
		}
		app.syncJobMu.Unlock()
		if job != nil && job.Done {
			return *job
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("sync job did not finish")
	return syncJobSnapshot{}
}

func TestBulkDeleteGroups(t *testing.T) {
	tests := map[string]struct {
		apps        []app
		wantDeleted bool
	}{
		"SCIM enabled marks selected groups for deletion": {
			apps:        []app{{ID: "app-1", Name: "Study App", Slug: "study-app", Protocol: "scim", SCIMEnabled: true, SCIMBaseURL: "https://study.example.test/scim", SCIMBearerToken: "token"}},
			wantDeleted: true,
		},
		"SCIM disabled removes selected groups": {
			apps: []app{{ID: "app-1", Name: "Study App", Slug: "study-app", Protocol: "oidc"}},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			setTestStateFile(t)
			r.NoError(saveState(appState{
				Apps: tc.apps,
				Groups: []group{
					{ID: "g1", DisplayName: "Study Group"},
					{ID: "g2", DisplayName: "Glee Club"},
				},
			}))
			appService := newTestIDPApp(t)
			form := url.Values{"tab": {"groups"}, "group_ids": {"g1"}}
			req := httptest.NewRequest(http.MethodPost, "/groups/delete", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()

			appService.routes().ServeHTTP(rec, req)

			r.Equal(http.StatusSeeOther, rec.Code)
			state, err := loadState()
			r.NoError(err)
			if !tc.wantDeleted {
				r.Len(state.Groups, 1)
				r.Equal("g2", state.Groups[0].ID)
				return
			}
			r.Len(state.Groups, 2)
			deleted := map[string]bool{}
			for _, g := range state.Groups {
				deleted[g.ID] = g.Deleted
			}
			r.True(deleted["g1"])
			r.False(deleted["g2"])
			r.True(state.GroupSync["app-1"]["g1"].Deleted)
		})
	}
}

func TestIndexRendersBulkGroupSelection(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{
		Groups: []group{
			{ID: "g1", DisplayName: "Study Group"},
			{ID: "g2", DisplayName: "Glee Club", Deleted: true},
		},
		Apps: []app{{ID: "app-1", Name: "Study App", Slug: "study-app", Protocol: "scim", SCIMEnabled: true, SCIMBaseURL: "https://study.example.test/scim", SCIMBearerToken: "token"}},
	}))
	appService := newTestIDPApp(t)
	rec := httptest.NewRecorder()
	appService.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/?tab=groups", nil))

	r.Equal(http.StatusOK, rec.Code)
	body := rec.Body.String()
	r.Contains(body, `action="/groups/delete"`)
	r.Contains(body, `name="group_ids" value="g1"`)
	r.NotContains(body, `name="group_ids" value="g2"`)
}

func TestAppsTabRendersPKCETestLinkForPublicClients(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{
		Config: config{IDPBaseURL: "http://idp.test"},
		Apps: []app{{
			ID:               "app-1",
			Name:             "Public SPA",
			Slug:             "public-spa",
			Protocol:         "oidc",
			OIDCClientID:     "spa-client",
			OIDCPublicClient: true,
			OIDCRedirectURIs: []string{"http://client.test/callback"},
		}},
	}))
	appService := newTestIDPApp(t)
	rec := httptest.NewRecorder()
	appService.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/?tab=apps", nil))

	r.Equal(http.StatusOK, rec.Code)
	body := rec.Body.String()
	r.Contains(body, "data-pkce-test")
	r.Contains(body, "http://idp.test/oidc/public-spa/authorize?")
}

func TestAppFormShowsOIDCSetupPanel(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{
		Config: config{IDPBaseURL: "http://idp.test"},
		Apps: []app{{
			ID:               "app-1",
			Name:             "Example",
			Slug:             "example",
			Protocol:         "oidc",
			OIDCClientID:     "example-client",
			OIDCClientSecret: "generated-secret",
			OIDCRedirectURIs: []string{"http://client.test/callback"},
		}},
	}))
	appService := newTestIDPApp(t)
	rec := httptest.NewRecorder()
	appService.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/?tab=apps&modal=app&id=app-1", nil))

	r.Equal(http.StatusOK, rec.Code)
	body := rec.Body.String()
	r.Contains(body, "http://idp.test/oidc/example/.well-known/openid-configuration")
	r.Contains(body, "http://idp.test/oidc/example/token")
	r.Contains(body, "http://idp.test/oidc/example/jwks")
	r.Contains(body, "example-client")
	r.Contains(body, "generated-secret")
}

func TestUserSaveRejectsDuplicateEmailAndUsername(t *testing.T) {
	tests := map[string]struct {
		form    url.Values
		wantErr string
	}{
		"duplicate email": {
			form:    url.Values{"given_name": {"Kevin"}, "family_name": {"Chang"}, "email": {"TROY@greendale.edu"}, "username": {"kevin"}},
			wantErr: "already used by Troy Barnes",
		},
		"duplicate username": {
			form:    url.Values{"given_name": {"Kevin"}, "family_name": {"Chang"}, "email": {"kevin@greendale.edu"}, "username": {"Troy"}},
			wantErr: "already used by Troy Barnes",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			setTestStateFile(t)
			r.NoError(saveState(appState{
				Users: []user{{ID: "troy", GivenName: "Troy", FamilyName: "Barnes", Email: "troy@greendale.edu", Username: "troy", Active: true}},
			}))
			appService := newTestIDPApp(t)
			tc.form.Set("tab", "users")
			req := httptest.NewRequest(http.MethodPost, "/users/save", strings.NewReader(tc.form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()

			appService.routes().ServeHTTP(rec, req)

			r.Equal(http.StatusSeeOther, rec.Code)
			r.Contains(rec.Header().Get("Location"), "modal=user")
			state, err := loadState()
			r.NoError(err)
			r.Len(state.Users, 1)
			appService.formDraftMu.Lock()
			defer appService.formDraftMu.Unlock()
			for _, draft := range appService.formDrafts {
				r.Contains(draft.Error, tc.wantErr)
			}
		})
	}
}

func TestDeletingEnvironmentDropsItsOperationLogs(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{
		Users: []user{{ID: "troy", GivenName: "Troy", FamilyName: "Barnes", Email: "troy@greendale.edu", Username: "troy", Active: true}},
		Apps: []app{
			{ID: "app-a", Name: "Alpha", Slug: "alpha", Protocol: "scim", SCIMEnabled: true, SCIMBaseURL: "https://alpha.test", SCIMBearerToken: "token"},
			{ID: "app-b", Name: "Beta", Slug: "beta", Protocol: "scim", SCIMEnabled: true, SCIMBaseURL: "https://beta.test", SCIMBearerToken: "token"},
		},
		UserOperations: map[string][]operationLog{"troy": {
			{AppID: "app-a", Kind: "sync", Summary: "Created", Operation: "create", CreatedAt: "2026-07-12T00:00:00Z"},
			{AppID: "app-b", Kind: "sync", Summary: "Created", Operation: "create", CreatedAt: "2026-07-12T00:00:00Z"},
			{Kind: "local", Summary: "Created", CreatedAt: "2026-07-12T00:00:00Z"},
		}},
	}))
	appService := newTestIDPApp(t)
	req := httptest.NewRequest(http.MethodPost, "/apps/app-a/delete", nil)
	rec := httptest.NewRecorder()

	appService.routes().ServeHTTP(rec, req)

	r.Equal(http.StatusSeeOther, rec.Code)
	state, err := loadState()
	r.NoError(err)
	entries := state.UserOperations["troy"]
	r.Len(entries, 2)
	for _, entry := range entries {
		r.NotEqual("app-a", entry.AppID)
	}
}

func TestSyncRejectedWhileAnotherEnvironmentSyncs(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{Apps: []app{
		{ID: "app-a", Name: "Alpha", Slug: "alpha", Protocol: "scim", SCIMEnabled: true, SCIMBaseURL: "https://alpha.test", SCIMBearerToken: "token"},
		{ID: "app-b", Name: "Beta", Slug: "beta", Protocol: "scim", SCIMEnabled: true, SCIMBaseURL: "https://beta.test", SCIMBearerToken: "token"},
	}}))
	appService := newTestIDPApp(t)
	appService.syncJobs = map[string]*syncJobSnapshot{
		"app-a": {ID: "job-a", EnvironmentName: "Alpha", Running: true},
	}
	form := url.Values{"tab": {"users"}, "environment": {"app-b"}}
	req := httptest.NewRequest(http.MethodPost, "/sync", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()

	appService.routes().ServeHTTP(rec, req)

	r.Equal(http.StatusConflict, rec.Code)
	r.Equal("application/json", rec.Header().Get("Content-Type"))
	r.Contains(rec.Body.String(), "a sync is already running for Alpha")
}

func TestFormDraftRedactsSecrets(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{}))
	appService := newTestIDPApp(t)
	form := url.Values{
		"tab":                {"apps"},
		"name":               {"Greendale Portal"},
		"protocol":           {"oidc"},
		"scim_enabled":       {"on"},
		"scim_bearer_token":  {"chang-secret"},
		"oidc_client_secret": {"winger-secret"},
	}
	req := httptest.NewRequest(http.MethodPost, "/apps/save", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	appService.routes().ServeHTTP(rec, req)

	r.Equal(http.StatusSeeOther, rec.Code)
	appService.formDraftMu.Lock()
	defer appService.formDraftMu.Unlock()
	r.Len(appService.formDrafts, 1)
	for _, draft := range appService.formDrafts {
		r.Empty(draft.Values.Get("scim_bearer_token"))
		r.Empty(draft.Values.Get("oidc_client_secret"))
		r.Equal("Greendale Portal", draft.Values.Get("name"))
	}
}

func dashboardAsset(t *testing.T, app *webApp, path string) string {
	t.Helper()
	r := require.New(t)
	rec := httptest.NewRecorder()
	app.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	r.Equal(http.StatusOK, rec.Code)
	return rec.Body.String()
}

func setTestStateFile(t *testing.T) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.db")
	t.Setenv("SCIMTEST_STATE_FILE", path)
	r := require.New(t)
	r.NoError(os.RemoveAll(path))
}
