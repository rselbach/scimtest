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

	groupReq := httptest.NewRequest(http.MethodGet, "/?tab=groups", nil)
	groupRec := httptest.NewRecorder()
	app.routes().ServeHTTP(groupRec, groupReq)
	r.Equal(http.StatusOK, groupRec.Code)
	r.Contains(groupRec.Body.String(), "Greendale Study Group")
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
	updated, err := loadState()
	r.NoError(err)
	r.Equal("remote-user-1", updated.Users[0].RemoteID)
	r.False(updated.Users[0].Dirty)
	r.NotEmpty(updated.UserOperations["u1"])
	r.Contains(rec.Header().Get("Set-Cookie"), "scimtest_trace=")
	r.Contains(app.traceContent(), "POST /Users")
}

func setTestStateFile(t *testing.T) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.db")
	t.Setenv("SCIMTEST_STATE_FILE", path)
	r := require.New(t)
	r.NoError(os.RemoveAll(path))
}
