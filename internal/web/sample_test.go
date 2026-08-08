package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAppendSampleDirectory(t *testing.T) {
	r := require.New(t)
	state := appState{}

	usersAdded, groupsAdded, err := appendSampleDirectory(&state)
	r.NoError(err)
	r.Equal(len(sampleUsers), usersAdded)
	r.Equal(len(sampleGroups), groupsAdded)
	r.Len(state.Users, len(sampleUsers))
	r.Len(state.Groups, len(sampleGroups))

	byUsername := make(map[string]user, len(state.Users))
	for _, u := range state.Users {
		byUsername[u.Username] = u
	}
	r.Equal("troy.barnes@greendale.edu", byUsername["tbarnes"].Email)
	r.False(byUsername["schang"].Active, "Señor Chang must load inactive")
	r.True(byUsername["tbarnes"].Dirty)

	byName := make(map[string]group, len(state.Groups))
	for _, g := range state.Groups {
		byName[g.DisplayName] = g
	}
	r.Len(byName["Study Group"].MemberIDs, 6)
	r.Len(byName["Faculty"].MemberIDs, 2)
	// Troy overlaps Study Group and the Annex so membership diffs are exercised.
	r.Contains(byName["Air Conditioning Repair Annex"].MemberIDs, byUsername["tbarnes"].ID)

	// Loading again adds nothing.
	usersAdded, groupsAdded, err = appendSampleDirectory(&state)
	r.NoError(err)
	r.Zero(usersAdded)
	r.Zero(groupsAdded)
	r.Len(state.Users, len(sampleUsers))
	r.Len(state.Groups, len(sampleGroups))
}

func TestAppendSampleDirectorySkipsExistingUsers(t *testing.T) {
	r := require.New(t)
	state := appState{
		Users:  []user{{ID: "usr-1", GivenName: "Troy", Email: "troy.barnes@greendale.edu", Username: "tbarnes", Active: true}},
		Groups: []group{{ID: "grp-1", DisplayName: "Faculty"}},
	}

	usersAdded, groupsAdded, err := appendSampleDirectory(&state)
	r.NoError(err)
	r.Equal(len(sampleUsers)-1, usersAdded)
	r.Equal(len(sampleGroups)-1, groupsAdded)

	// The existing Troy joins the new groups instead of being duplicated.
	for _, g := range state.Groups {
		if g.DisplayName == "Air Conditioning Repair Annex" {
			r.Contains(g.MemberIDs, "usr-1")
		}
	}
}

func TestToolsSeedSampleEndpoint(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{
		Apps: []app{{ID: "app-1", Name: "Example", Slug: "example", Protocol: "oidc"}},
	}))
	svc := newTestIDPApp(t)

	form := url.Values{"environment": {"app-1"}, "tab": {"users"}}
	req := httptest.NewRequest(http.MethodPost, "/tools/seed-sample", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	svc.routes().ServeHTTP(rec, req)

	r.Equal(http.StatusSeeOther, rec.Code)
	r.Contains(rec.Header().Get("Set-Cookie"), "Greendale")

	state, err := loadStateForApp("app-1")
	r.NoError(err)
	r.Len(state.Users, len(sampleUsers))
	r.Len(state.Groups, len(sampleGroups))
}
