package web

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type blockedMutationReader struct {
	io.Reader
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (r *blockedMutationReader) Read(p []byte) (int, error) {
	r.once.Do(func() {
		close(r.entered)
		<-r.release
	})
	return r.Reader.Read(p)
}

func TestSyncWaitsForAdmittedMutation(t *testing.T) {
	for name, tc := range map[string]struct {
		method      string
		path        string
		contentType string
		body        string
		wantStatus  int
	}{
		"API": {
			method: http.MethodPatch, path: "/api/v1/environments/greendale/users/troy",
			contentType: "application/json",
			body:        `{"given_name":"Abed","family_name":"Nadir"}`,
			wantStatus:  http.StatusOK,
		},
		"form": {
			method: http.MethodPost, path: "/users/save",
			contentType: "application/x-www-form-urlencoded",
			body: url.Values{
				"environment": {"greendale"}, "id": {"troy"},
				"given_name": {"Abed"}, "family_name": {"Nadir"},
				"email": {"troy@greendale.edu"}, "username": {"troy"},
			}.Encode(),
			wantStatus: http.StatusSeeOther,
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			setTestStateFile(t)
			requests := make(chan string, 1)
			remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				var payload struct {
					DisplayName string `json:"displayName"`
				}
				if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
					t.Error(err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				requests <- payload.DisplayName
				w.WriteHeader(http.StatusNoContent)
			}))
			defer remote.Close()
			r.NoError(saveState(appState{
				Users:    []user{{ID: "troy", GivenName: "Troy", FamilyName: "Barnes", Email: "troy@greendale.edu", Username: "troy", Active: true}},
				Apps:     []app{{ID: "greendale", Name: "Greendale", Slug: "greendale", Protocol: "scim", SCIMEnabled: true, SCIMBaseURL: remote.URL, SCIMBearerToken: "secret"}},
				UserSync: map[string]map[string]resourceSyncState{"greendale": {"troy": {RemoteID: "remote-troy", Dirty: true}}},
			}))
			svc := newTestIDPApp(t)
			svc.instanceToken = "greendale-local-instance"
			handler := svc.routes()
			body := &blockedMutationReader{Reader: strings.NewReader(tc.body), entered: make(chan struct{}), release: make(chan struct{})}
			var releaseOnce sync.Once
			releaseMutation := func() { releaseOnce.Do(func() { close(body.release) }) }
			defer releaseMutation()
			req := httptest.NewRequest(tc.method, "http://127.0.0.1:8080"+tc.path, body)
			req.Header.Set("Content-Type", tc.contentType)
			req.Header.Set(instanceTokenHeader, svc.instanceToken)
			mutation := httptest.NewRecorder()
			mutationDone := make(chan struct{})
			go func() {
				defer close(mutationDone)
				handler.ServeHTTP(mutation, req)
			}()
			select {
			case <-body.entered:
			case <-time.After(time.Second):
				t.Fatal("mutation did not start reading its body")
			}
			syncDone := make(chan struct{})
			started := make(chan struct{})
			start := httptest.NewRecorder()
			go func() {
				defer close(syncDone)
				close(started)
				startReq := httptest.NewRequest(http.MethodPost, "/sync?environment=greendale", nil)
				startReq.Header.Set("Accept", "application/json")
				handler.ServeHTTP(start, startReq)
			}()
			<-started
			select {
			case <-syncDone:
				t.Error("sync started before the admitted mutation finished")
			case <-time.After(50 * time.Millisecond):
			}
			releaseMutation()
			select {
			case <-mutationDone:
			case <-time.After(time.Second):
				t.Fatal("mutation did not finish")
			}
			select {
			case <-syncDone:
			case <-time.After(time.Second):
				t.Fatal("sync did not start after the mutation finished")
			}
			r.Equal(tc.wantStatus, mutation.Code, mutation.Body.String())
			r.Equal(http.StatusOK, start.Code, start.Body.String())
			r.Eventually(func() bool { job := svc.currentSyncJob("greendale"); return job != nil && job.Done }, 3*time.Second, 10*time.Millisecond)
			r.True(svc.currentSyncJob("greendale").Success)
			r.Equal("Abed Nadir", <-requests)
			state, err := loadStateForApp("greendale")
			r.NoError(err)
			r.Equal("Abed", state.Users[0].GivenName)
			r.False(state.UserSync["greendale"]["troy"].Dirty)
		})
	}
}
