package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestImportPreviewAppliesCachedStateAndCreatesUndoSnapshot(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/scim+json")
		switch req.URL.Path {
		case "/Users":
			_, err := fmt.Fprint(w, `{"totalResults":1,"startIndex":1,"itemsPerPage":1,"Resources":[{"id":"remote-troy","externalId":"troy","userName":"troy","name":{"givenName":"Troy","familyName":"Barnes"},"emails":[{"value":"troy.barnes@greendale.edu"}],"active":true}]}`)
			r.NoError(err)
		case "/Groups":
			_, err := fmt.Fprint(w, `{"totalResults":0,"startIndex":1,"itemsPerPage":0,"Resources":[]}`)
			r.NoError(err)
		default:
			t.Fatalf("unexpected import path %s", req.URL.Path)
		}
	}))
	defer server.Close()
	r.NoError(saveState(appState{
		Users: []user{{ID: "troy", GivenName: "Troy", FamilyName: "Barnes", Email: "old@greendale.edu", Username: "troy", Active: true}},
		Apps:  []app{{ID: "app-1", Name: "Greendale", Slug: "greendale", Protocol: "scim", SCIMEnabled: true, SCIMBaseURL: server.URL, SCIMBearerToken: "chang-secret"}},
	}))
	app := newTestIDPApp(t)
	form := url.Values{"tab": {"users"}, "environment": {"app-1"}}
	preview := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/import", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	app.routes().ServeHTTP(preview, req)
	r.Equal(http.StatusSeeOther, preview.Code)
	state, err := loadState()
	r.NoError(err)
	r.Equal("old@greendale.edu", state.Users[0].Email)

	page := httptest.NewRecorder()
	app.routes().ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/?tab=users&environment=app-1", nil))
	r.Contains(page.Body.String(), "Apply import (+0 ~1 -0)")

	form.Set("apply", "on")
	apply := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/import", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	app.routes().ServeHTTP(apply, req)
	r.Equal(http.StatusSeeOther, apply.Code)
	state, err = loadState()
	r.NoError(err)
	r.Equal("troy.barnes@greendale.edu", state.Users[0].Email)
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(os.Getenv("SCIMTEST_STATE_FILE")), "backups", "pre-restore-*.json"))
	r.NoError(err)
	r.Len(matches, 1)
}

func TestImportPreviewRejectsChangedDirectory(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/scim+json")
		_, err := fmt.Fprint(w, `{"totalResults":0,"startIndex":1,"itemsPerPage":0,"Resources":[]}`)
		r.NoError(err)
	}))
	defer server.Close()
	r.NoError(saveState(appState{Apps: []app{{
		ID: "app-1", Name: "Greendale", Slug: "greendale", Protocol: "scim",
		SCIMEnabled: true, SCIMBaseURL: server.URL, SCIMBearerToken: "chang-secret",
	}}}))
	app := newTestIDPApp(t)
	form := url.Values{"tab": {"users"}, "environment": {"app-1"}}
	preview := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/import", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	app.routes().ServeHTTP(preview, req)
	r.Equal(http.StatusSeeOther, preview.Code)

	state, err := loadStateForApp("app-1")
	r.NoError(err)
	state.Users = append(state.Users, user{
		ID: "troy", GivenName: "Troy", FamilyName: "Barnes",
		Email: "troy@greendale.edu", Username: "troy", Active: true,
	})
	r.NoError(saveEnvironmentState(state))

	form.Set("apply", "on")
	apply := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/import", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	app.routes().ServeHTTP(apply, req)
	r.Equal(http.StatusSeeOther, apply.Code)
	r.Nil(app.cachedImportPreview("app-1"))

	state, err = loadStateForApp("app-1")
	r.NoError(err)
	r.Len(state.Users, 1)
	r.Equal("troy", state.Users[0].ID)
	r.False(state.Users[0].Deleted)
}
