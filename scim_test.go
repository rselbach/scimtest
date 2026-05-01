package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSyncDirtyState(t *testing.T) {
	r := require.New(t)

	requests := make([]string, 0, 5)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		requests = append(requests, req.Method+" "+req.URL.Path)
		if req.Header.Get("Authorization") != "Bearer chang-secret" {
			t.Fatalf("unexpected auth header: %q", req.Header.Get("Authorization"))
		}

		switch req.Method + " " + req.URL.Path {
		case "POST /Users":
			var body scimUserResource
			r.NoError(json.NewDecoder(req.Body).Decode(&body))
			r.Equal("shirleyb", body.UserName)
			r.Equal("Shirley Bennett", body.DisplayName)
			r.NotNil(body.Active)
			r.True(*body.Active)
			w.Header().Set("Content-Type", "application/scim+json")
			w.WriteHeader(http.StatusCreated)
			r.NoError(json.NewEncoder(w).Encode(scimUserResource{ID: "remote-user-created"}))
		case "PUT /Users/remote-user-updated":
			var body scimUserResource
			r.NoError(json.NewDecoder(req.Body).Decode(&body))
			r.Equal("anniee", body.UserName)
			r.NotNil(body.Active)
			r.False(*body.Active)
			w.WriteHeader(http.StatusOK)
		case "POST /Groups":
			var body scimGroupResource
			r.NoError(json.NewDecoder(req.Body).Decode(&body))
			r.Equal("Study Group", body.DisplayName)
			r.Len(body.Members, 2)
			r.Equal("remote-user-created", body.Members[0].Value)
			r.Equal("remote-user-updated", body.Members[1].Value)
			w.Header().Set("Content-Type", "application/scim+json")
			w.WriteHeader(http.StatusCreated)
			r.NoError(json.NewEncoder(w).Encode(scimGroupResource{ID: "remote-group-created"}))
		case "PUT /Groups/remote-group-updated":
			var body scimGroupResource
			r.NoError(json.NewDecoder(req.Body).Decode(&body))
			r.Equal("Spanish Class", body.DisplayName)
			r.Len(body.Members, 1)
			r.Equal("remote-user-updated", body.Members[0].Value)
			w.WriteHeader(http.StatusOK)
		case "DELETE /Users/remote-user-deleted":
			w.WriteHeader(http.StatusNoContent)
		case "DELETE /Groups/remote-group-deleted":
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected request: %s %s", req.Method, req.URL.Path)
		}
	}))
	defer server.Close()

	state := appState{
		Config: config{
			BaseURL:     server.URL,
			BearerToken: "chang-secret",
		},
		Users: []user{
			{ID: "user-1", GivenName: "Shirley", FamilyName: "Bennett", Username: "shirleyb", Email: "shirley@greendale.edu", Active: true, Dirty: true},
			{ID: "user-2", GivenName: "Annie", FamilyName: "Edison", Username: "anniee", Email: "annie@greendale.edu", Active: false, RemoteID: "remote-user-updated", Dirty: true},
			{ID: "user-3", GivenName: "Señor", FamilyName: "Chang", Username: "chang", Email: "chang@greendale.edu", Active: true, RemoteID: "remote-user-deleted", Dirty: true, Deleted: true},
		},
		Groups: []group{
			{ID: "group-1", DisplayName: "Study Group", MemberIDs: []string{"user-1", "user-2"}, Dirty: true},
			{ID: "group-2", DisplayName: "Spanish Class", MemberIDs: []string{"user-2"}, RemoteID: "remote-group-updated", Dirty: true},
			{ID: "group-3", DisplayName: "Paintball Squad", RemoteID: "remote-group-deleted", Dirty: true, Deleted: true},
		},
	}

	result := syncDirtyState(state)
	r.NoError(result.fatal)
	r.Equal(
		"sync finished: users 1 created, 1 updated, 1 deleted, 0 failed; groups 1 created, 1 updated, 1 deleted, 0 failed",
		result.status,
	)
	r.Equal(
		[]string{
			"POST /Users",
			"PUT /Users/remote-user-updated",
			"DELETE /Users/remote-user-deleted",
			"POST /Groups",
			"PUT /Groups/remote-group-updated",
			"DELETE /Groups/remote-group-deleted",
		},
		requests,
	)
	r.Len(result.state.Users, 2)
	r.Equal("remote-user-created", result.state.Users[0].RemoteID)
	r.False(result.state.Users[0].Dirty)
	r.False(result.state.Users[1].Dirty)
	r.Len(result.state.Groups, 2)
	r.Equal("remote-group-created", result.state.Groups[0].RemoteID)
	r.False(result.state.Groups[0].Dirty)
	r.False(result.state.Groups[1].Dirty)
}

func TestSyncDirtyStateFailsGroupWhenMemberNotSynced(t *testing.T) {
	r := require.New(t)

	state := appState{
		Config: config{
			BaseURL:     "https://example.com/scim/v2",
			BearerToken: "chang-secret",
		},
		Users: []user{{
			ID:         "user-1",
			GivenName:  "Abed",
			FamilyName: "Nadir",
			Username:   "abed",
			Email:      "abed@greendale.edu",
			Active:     true,
		}},
		Groups: []group{{
			ID:          "group-1",
			DisplayName: "Dreamatorium",
			MemberIDs:   []string{"user-1"},
			Dirty:       true,
		}},
	}

	result := syncDirtyState(state)
	r.NoError(result.fatal)
	r.Len(result.state.Groups, 1)
	r.Contains(result.state.Groups[0].LastError, "has not been synced yet")
	r.True(result.state.Groups[0].Dirty)
}

func TestPrettyJSONHighlightsOutput(t *testing.T) {
	r := require.New(t)

	formatted := prettyJSON(`{"active":true,"count":2,"name":"Troy","meta":null,"items":["a"]}`)

	r.Contains(formatted, "\x1b[")
	r.Contains(formatted, `"active"`)
	r.Contains(formatted, `"name"`)
	r.Contains(formatted, `"Troy"`)
	r.Contains(formatted, "true")
	r.Contains(formatted, "null")
	r.Contains(formatted, "\n")
	r.True(strings.Index(formatted, `"active"`) < strings.Index(formatted, `"count"`))
}

func TestImportStateFromSCIM(t *testing.T) {
	r := require.New(t)

	requests := make([]string, 0, 4)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		requests = append(requests, req.Method+" "+req.URL.RequestURI())
		r.Equal("Bearer chang-secret", req.Header.Get("Authorization"))

		switch req.URL.Path + "?" + req.URL.RawQuery {
		case "/Users?startIndex=1&count=100":
			w.Header().Set("Content-Type", "application/scim+json")
			r.NoError(json.NewEncoder(w).Encode(scimListResponse[scimUserResource]{
				TotalResults: 2,
				StartIndex:   1,
				ItemsPerPage: 1,
				Resources: []scimUserResource{{
					ID:          "remote-user-1",
					ExternalID:  "local-1",
					UserName:    "abed",
					DisplayName: "Abed Nadir",
					Active:      boolPtr(true),
					Name: &scimName{
						GivenName:  "Abed",
						FamilyName: "Nadir",
					},
					Emails: []scimEmail{{Value: "abed@greendale.edu"}},
				}},
			}))
		case "/Users?startIndex=2&count=100":
			w.Header().Set("Content-Type", "application/scim+json")
			r.NoError(json.NewEncoder(w).Encode(scimListResponse[scimUserResource]{
				TotalResults: 2,
				StartIndex:   2,
				ItemsPerPage: 1,
				Resources: []scimUserResource{{
					ID:          "remote-user-2",
					UserName:    "anniee",
					DisplayName: "Annie Edison",
					Active:      boolPtr(false),
					Name: &scimName{
						GivenName:  "Annie",
						FamilyName: "Edison",
					},
					Emails: []scimEmail{{Value: "annie@greendale.edu"}},
				}},
			}))
		case "/Groups?startIndex=1&count=100":
			w.Header().Set("Content-Type", "application/scim+json")
			r.NoError(json.NewEncoder(w).Encode(scimListResponse[scimGroupResource]{
				TotalResults: 1,
				StartIndex:   1,
				ItemsPerPage: 1,
				Resources: []scimGroupResource{{
					ID:          "remote-group-1",
					ExternalID:  "local-group-1",
					DisplayName: "Study Group",
					Members: []scimMember{{
						Value: "remote-user-1",
						Type:  "User",
					}, {
						Value: "remote-user-2",
						Type:  "User",
					}},
				}},
			}))
		default:
			t.Fatalf("unexpected import request: %s", req.URL.RequestURI())
		}
	}))
	defer server.Close()

	state := appState{
		Config: config{
			BaseURL:     server.URL,
			BearerToken: "chang-secret",
		},
		Users: []user{{
			ID:         "old-user",
			GivenName:  "Old",
			FamilyName: "Name",
			Username:   "old-abed",
			Email:      "old@greendale.edu",
			Active:     false,
			RemoteID:   "stale-remote",
			Dirty:      true,
			LastError:  "boom",
		}},
		Groups: []group{{
			ID:          "old-group",
			DisplayName: "Old Group",
			MemberIDs:   []string{"old-user"},
			RemoteID:    "stale-group",
			Dirty:       true,
		}},
		UserOperations: map[string][]operationLog{
			"old-user": {{Kind: "local", Summary: "Created", CreatedAt: "2026-05-01T10:00:00Z"}},
		},
		GroupOperations: map[string][]operationLog{
			"old-group": {{Kind: "local", Summary: "Created", CreatedAt: "2026-05-01T10:00:00Z"}},
		},
	}

	result := importStateFromSCIM(state)
	r.NoError(result.fatal)
	r.Equal("imported 2 users and 1 groups from SCIM", result.status)
	r.Len(result.state.Users, 2)
	r.Len(result.state.Groups, 1)
	r.Equal([]string{
		"GET /Users?startIndex=1&count=100",
		"GET /Users?startIndex=2&count=100",
		"GET /Groups?startIndex=1&count=100",
	}, requests)

	r.Equal("local-1", result.state.Users[0].ID)
	r.Equal("remote-user-1", result.state.Users[0].RemoteID)
	r.Equal("Abed", result.state.Users[0].GivenName)
	r.Equal("Nadir", result.state.Users[0].FamilyName)
	r.Equal("abed", result.state.Users[0].Username)
	r.Equal("abed@greendale.edu", result.state.Users[0].Email)
	r.True(result.state.Users[0].Active)
	r.False(result.state.Users[0].Dirty)
	r.Empty(result.state.Users[0].LastError)

	r.Equal("remote-user-2", result.state.Users[1].RemoteID)
	r.Equal("anniee", result.state.Users[1].Username)
	r.Equal("annie@greendale.edu", result.state.Users[1].Email)
	r.False(result.state.Users[1].Active)
	r.False(result.state.Users[1].Dirty)
	r.NotEmpty(result.state.Users[1].ID)
	r.NotEqual("old-user", result.state.Users[1].ID)

	r.Equal("local-group-1", result.state.Groups[0].ID)
	r.Equal("Study Group", result.state.Groups[0].DisplayName)
	r.Equal("remote-group-1", result.state.Groups[0].RemoteID)
	r.False(result.state.Groups[0].Dirty)
	r.Equal([]string{result.state.Users[0].ID, result.state.Users[1].ID}, result.state.Groups[0].MemberIDs)

	_, oldUserStillExists := result.state.UserOperations["old-user"]
	r.False(oldUserStillExists)
	_, oldGroupStillExists := result.state.GroupOperations["old-group"]
	r.False(oldGroupStillExists)

	r.Len(result.state.UserOperations[result.state.Users[0].ID], 1)
	r.Equal("Imported from SCIM", result.state.UserOperations[result.state.Users[0].ID][0].Summary)
	r.Len(result.state.UserOperations[result.state.Users[1].ID], 1)
	r.Equal("Imported from SCIM", result.state.UserOperations[result.state.Users[1].ID][0].Summary)
	r.Len(result.state.GroupOperations[result.state.Groups[0].ID], 1)
	r.Equal("Imported from SCIM", result.state.GroupOperations[result.state.Groups[0].ID][0].Summary)
	r.Len(result.traces, 3)
	r.Equal("import", result.traces[0].Operation)
	r.Equal("GET", result.traces[0].Method)
}

func boolPtr(v bool) *bool {
	return &v
}
