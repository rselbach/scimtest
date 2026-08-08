package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPushSyncsOnlyTheTargetResource(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)

	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/scim+json")
			_, err := fmt.Fprint(w, `{"totalResults":0,"Resources":[]}`)
			r.NoError(err)
			return
		}
		r.Equal(http.MethodPost, req.Method)
		r.Equal("/Users", req.URL.Path)
		posts.Add(1)
		w.Header().Set("Content-Type", "application/scim+json")
		_, err := fmt.Fprint(w, `{"id":"remote-user-1"}`)
		r.NoError(err)
	}))
	defer server.Close()

	r.NoError(saveState(appState{
		Users: []user{
			{ID: "u1", GivenName: "Troy", FamilyName: "Barnes", Username: "tbarnes", Email: "troy@greendale.edu", Active: true, Dirty: true},
			{ID: "u2", GivenName: "Abed", FamilyName: "Nadir", Username: "anadir", Email: "abed@greendale.edu", Active: true, Dirty: true},
		},
		Apps: []app{{
			ID: "app-1", Name: "Greendale", Slug: "greendale", Protocol: "scim",
			SCIMEnabled: true, SCIMBaseURL: server.URL, SCIMBearerToken: "token",
		}},
	}))

	svc := &webApp{}
	form := url.Values{"tab": {"users"}, "environment": {"app-1"}}
	req := httptest.NewRequest(http.MethodPost, "/users/u1/sync", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	svc.routes().ServeHTTP(rec, req)

	r.Equal(http.StatusSeeOther, rec.Code, rec.Body.String())
	job := waitForSyncDone(t, svc)
	r.True(job.Success, job.Error)
	r.Equal(int32(1), posts.Load(), "only the pushed user may reach the remote")

	updated, err := loadStateForApp("app-1")
	r.NoError(err)
	r.Equal("remote-user-1", updated.UserSync["app-1"]["u1"].RemoteID)
	r.False(updated.UserSync["app-1"]["u1"].Dirty)
	// The other user's pending state is untouched: no row still means dirty.
	_, tracked := updated.UserSync["app-1"]["u2"]
	r.False(tracked)
	r.NotEmpty(updated.UserOperations["u1"])
}

func TestPushUnknownResource(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{
		Apps: []app{{
			ID: "app-1", Name: "Greendale", Slug: "greendale", Protocol: "scim",
			SCIMEnabled: true, SCIMBaseURL: "http://scim.test", SCIMBearerToken: "token",
		}},
	}))

	svc := &webApp{}
	form := url.Values{"tab": {"users"}, "environment": {"app-1"}}
	req := httptest.NewRequest(http.MethodPost, "/users/nope/sync", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	svc.routes().ServeHTTP(rec, req)

	r.Equal(http.StatusSeeOther, rec.Code)
	r.Contains(rec.Header().Get("Set-Cookie"), "user+not+found")
}
