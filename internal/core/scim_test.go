package core

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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
			var body SCIMUserResource
			r.NoError(json.NewDecoder(req.Body).Decode(&body))
			r.Equal("shirleyb", body.UserName)
			r.Equal("Shirley Bennett", body.DisplayName)
			r.NotNil(body.Active)
			r.True(*body.Active)
			w.Header().Set("Content-Type", "application/scim+json")
			w.WriteHeader(http.StatusCreated)
			r.NoError(json.NewEncoder(w).Encode(SCIMUserResource{ID: "remote-user-created"}))
		case "PUT /Users/remote-user-updated":
			var body SCIMUserResource
			r.NoError(json.NewDecoder(req.Body).Decode(&body))
			r.Equal("anniee", body.UserName)
			r.NotNil(body.Active)
			r.False(*body.Active)
			w.WriteHeader(http.StatusOK)
		case "POST /Groups":
			var body SCIMGroupResource
			r.NoError(json.NewDecoder(req.Body).Decode(&body))
			r.Equal("Study Group", body.DisplayName)
			r.Len(body.Members, 2)
			r.Equal("remote-user-created", body.Members[0].Value)
			r.Equal("remote-user-updated", body.Members[1].Value)
			w.Header().Set("Content-Type", "application/scim+json")
			w.WriteHeader(http.StatusCreated)
			r.NoError(json.NewEncoder(w).Encode(SCIMGroupResource{ID: "remote-group-created"}))
		case "PUT /Groups/remote-group-updated":
			var body SCIMGroupResource
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

	state := AppState{
		Config: Config{
			BaseURL:     server.URL,
			BearerToken: "chang-secret",
		},
		Users: []User{
			{ID: "user-1", GivenName: "Shirley", FamilyName: "Bennett", Username: "shirleyb", Email: "shirley@greendale.edu", Active: true, Dirty: true},
			{ID: "user-2", GivenName: "Annie", FamilyName: "Edison", Username: "anniee", Email: "annie@greendale.edu", Active: false, RemoteID: "remote-user-updated", Dirty: true},
			{ID: "user-3", GivenName: "Señor", FamilyName: "Chang", Username: "chang", Email: "chang@greendale.edu", Active: true, RemoteID: "remote-user-deleted", Dirty: true, Deleted: true},
		},
		Groups: []Group{
			{ID: "group-1", DisplayName: "Study Group", MemberIDs: []string{"user-1", "user-2"}, Dirty: true},
			{ID: "group-2", DisplayName: "Spanish Class", MemberIDs: []string{"user-2"}, RemoteID: "remote-group-updated", Dirty: true},
			{ID: "group-3", DisplayName: "Paintball Squad", RemoteID: "remote-group-deleted", Dirty: true, Deleted: true},
		},
	}

	result := SyncDirtyState(state)
	r.NoError(result.Fatal)
	r.Equal(
		"sync finished: users 1 created, 1 updated, 1 deleted, 0 failed; groups 1 created, 1 updated, 1 deleted, 0 failed",
		result.Status,
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
	r.Len(result.State.Users, 2)
	r.Equal("remote-user-created", result.State.Users[0].RemoteID)
	r.False(result.State.Users[0].Dirty)
	r.False(result.State.Users[1].Dirty)
	r.Len(result.State.Groups, 2)
	r.Equal("remote-group-created", result.State.Groups[0].RemoteID)
	r.False(result.State.Groups[0].Dirty)
	r.False(result.State.Groups[1].Dirty)
}

func TestSyncDirtyStateRetriesRateLimit(t *testing.T) {
	r := require.New(t)
	sleeps := captureRateLimitSleeps(t)

	attempts := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.Equal("Bearer chang-secret", req.Header.Get("Authorization"))
		r.Equal(http.MethodPost, req.Method)
		r.Equal("/Users", req.URL.Path)

		var body SCIMUserResource
		r.NoError(json.NewDecoder(req.Body).Decode(&body))
		attempts[body.UserName]++
		if body.UserName == "abedn" && attempts[body.UserName] == 1 {
			w.Header().Set("Retry-After", "2")
			http.Error(w, "slow down, Professor Professorson", http.StatusTooManyRequests)
			return
		}

		w.Header().Set("Content-Type", "application/scim+json")
		w.WriteHeader(http.StatusCreated)
		r.NoError(json.NewEncoder(w).Encode(SCIMUserResource{ID: "remote-" + body.UserName}))
	}))
	defer server.Close()

	state := AppState{
		Config: Config{
			BaseURL:     server.URL,
			BearerToken: "chang-secret",
		},
		Users: []User{
			{ID: "user-1", GivenName: "Troy", FamilyName: "Barnes", Username: "troys", Email: "troy@greendale.edu", Active: true, Dirty: true},
			{ID: "user-2", GivenName: "Abed", FamilyName: "Nadir", Username: "abedn", Email: "abed@greendale.edu", Active: true, Dirty: true},
		},
	}

	var progressEvents []SyncProgress
	result := SyncDirtyStateWithProgress(state, func(progress SyncProgress) {
		progressEvents = append(progressEvents, progress)
	})
	r.NoError(result.Fatal)
	r.NoError(result.Stopped)
	r.True(result.Changed)
	r.Equal([]time.Duration{2 * time.Second}, *sleeps)
	r.Equal(1, attempts["troys"])
	r.Equal(2, attempts["abedn"])
	r.Len(result.State.Users, 2)
	r.Equal("remote-troys", result.State.Users[0].RemoteID)
	r.Equal("remote-abedn", result.State.Users[1].RemoteID)
	r.False(result.State.Users[0].Dirty)
	r.False(result.State.Users[1].Dirty)
	r.Empty(result.State.Users[1].LastError)
	r.Len(result.Traces, 3)
	r.Equal("429 Too Many Requests", result.Traces[1].Status)
	r.Equal("201 Created", result.Traces[2].Status)
	r.Contains(progressLabels(progressEvents), "Troy Barnes (troys)")
	r.Contains(progressLabels(progressEvents), "Abed Nadir (abedn)")
	r.Contains(progressStatuses(progressEvents), "Rate limited; waiting 2 seconds")
	r.True(hasRateLimitedProgress(progressEvents))
}

func TestSyncDirtyStateStopsOnRateLimitAfterRetries(t *testing.T) {
	r := require.New(t)
	sleeps := captureRateLimitSleeps(t)

	requests := make([]string, 0, 5)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		requests = append(requests, req.Method+" "+req.URL.Path)
		r.Equal("Bearer chang-secret", req.Header.Get("Authorization"))

		if req.Method != http.MethodPost || req.URL.Path != "/Users" {
			t.Fatalf("unexpected request after rate limit: %s %s", req.Method, req.URL.Path)
		}

		var body SCIMUserResource
		r.NoError(json.NewDecoder(req.Body).Decode(&body))
		switch body.UserName {
		case "troys":
			w.Header().Set("Content-Type", "application/scim+json")
			w.WriteHeader(http.StatusCreated)
			r.NoError(json.NewEncoder(w).Encode(SCIMUserResource{ID: "remote-user-1"}))
		case "abedn":
			w.Header().Set("Retry-After", "45")
			http.Error(w, "slow down, Professor Professorson", http.StatusTooManyRequests)
		default:
			t.Fatalf("unexpected user create: %s", body.UserName)
		}
	}))
	defer server.Close()

	state := AppState{
		Config: Config{
			BaseURL:     server.URL,
			BearerToken: "chang-secret",
		},
		Users: []User{
			{ID: "user-1", GivenName: "Troy", FamilyName: "Barnes", Username: "troys", Email: "troy@greendale.edu", Active: true, Dirty: true},
			{ID: "user-2", GivenName: "Abed", FamilyName: "Nadir", Username: "abedn", Email: "abed@greendale.edu", Active: true, Dirty: true},
			{ID: "user-3", GivenName: "Annie", FamilyName: "Edison", Username: "anniee", Email: "annie@greendale.edu", Active: true, Dirty: true},
		},
		Groups: []Group{{
			ID:          "group-1",
			DisplayName: "Study Group",
			MemberIDs:   []string{"user-1"},
			Dirty:       true,
		}},
	}

	result := SyncDirtyState(state)
	r.NoError(result.Fatal)
	r.Error(result.Stopped)
	r.True(result.Changed)
	r.Contains(result.Status, "sync stopped")
	r.Contains(result.Status, "Try again in 45 seconds")
	r.Equal([]string{"POST /Users", "POST /Users", "POST /Users", "POST /Users", "POST /Users"}, requests)
	r.Equal([]time.Duration{45 * time.Second, 45 * time.Second, 45 * time.Second}, *sleeps)

	var rateLimitErr *RateLimitError
	r.True(errors.As(result.Stopped, &rateLimitErr))
	r.Equal("in 45 seconds", rateLimitErr.RetryAfter)

	r.Len(result.State.Users, 3)
	r.Equal("remote-user-1", result.State.Users[0].RemoteID)
	r.False(result.State.Users[0].Dirty)
	r.True(result.State.Users[1].Dirty)
	r.Contains(result.State.Users[1].LastError, "429 Too Many Requests")
	r.Contains(result.State.Users[1].LastError, "Try again in 45 seconds")
	r.NotContains(result.State.Users[1].LastError, "schemas")
	r.True(result.State.Users[2].Dirty)
	r.Empty(result.State.Users[2].RemoteID)
	r.Empty(result.State.Users[2].LastError)
	r.Len(result.State.Groups, 1)
	r.True(result.State.Groups[0].Dirty)
	r.Empty(result.State.Groups[0].RemoteID)

	r.Len(result.Traces, 5)
	r.Equal("429 Too Many Requests", result.Traces[4].Status)
	r.Equal("45", result.Traces[4].ResponseRetryAfter)
	r.Contains(result.Traces[4].Err, "Try again in 45 seconds")
}

func TestSyncDirtyStateFailsGroupWhenMemberNotSynced(t *testing.T) {
	r := require.New(t)

	state := AppState{
		Config: Config{
			BaseURL:     "https://example.com/scim/v2",
			BearerToken: "chang-secret",
		},
		Users: []User{{
			ID:         "user-1",
			GivenName:  "Abed",
			FamilyName: "Nadir",
			Username:   "abed",
			Email:      "abed@greendale.edu",
			Active:     true,
		}},
		Groups: []Group{{
			ID:          "group-1",
			DisplayName: "Dreamatorium",
			MemberIDs:   []string{"user-1"},
			Dirty:       true,
		}},
	}

	result := SyncDirtyState(state)
	r.NoError(result.Fatal)
	r.Len(result.State.Groups, 1)
	r.Contains(result.State.Groups[0].LastError, "has not been synced yet")
	r.True(result.State.Groups[0].Dirty)
}

func TestImportStateFromSCIMRateLimitParsesHTTPDateRetryAfter(t *testing.T) {
	r := require.New(t)
	sleeps := captureRateLimitSleeps(t)

	fixedNow := time.Date(2026, 5, 15, 20, 0, 0, 0, time.UTC)
	originalCurrentTime := currentTime
	currentTime = func() time.Time { return fixedNow }
	t.Cleanup(func() { currentTime = originalCurrentTime })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.Equal(http.MethodGet, req.Method)
		r.Equal("/Users", req.URL.Path)
		w.Header().Set("Retry-After", fixedNow.Add(45*time.Second).Format(http.TimeFormat))
		http.Error(w, "cool it, Leonard", http.StatusTooManyRequests)
	}))
	defer server.Close()

	state := AppState{
		Config: Config{
			BaseURL:     server.URL,
			BearerToken: "chang-secret",
		},
	}

	result := ImportStateFromSCIM(state)
	r.Error(result.Fatal)
	r.Contains(result.Fatal.Error(), "Try again in 45 seconds")
	r.Equal([]time.Duration{45 * time.Second, 45 * time.Second, 45 * time.Second}, *sleeps)

	var rateLimitErr *RateLimitError
	r.True(errors.As(result.Fatal, &rateLimitErr))
	r.Equal("in 45 seconds", rateLimitErr.RetryAfter)
	r.Len(result.Traces, 4)
	r.Equal("429 Too Many Requests", result.Traces[3].Status)
	r.Equal(fixedNow.Add(45*time.Second).Format(http.TimeFormat), result.Traces[3].ResponseRetryAfter)
	r.Contains(result.Traces[3].Err, "Try again in 45 seconds")
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
			r.NoError(json.NewEncoder(w).Encode(SCIMListResponse[SCIMUserResource]{
				TotalResults: 2,
				StartIndex:   1,
				ItemsPerPage: 1,
				Resources: []SCIMUserResource{{
					ID:          "remote-user-1",
					ExternalID:  "local-1",
					UserName:    "abed",
					DisplayName: "Abed Nadir",
					Active:      boolPtr(true),
					Name: &SCIMName{
						GivenName:  "Abed",
						FamilyName: "Nadir",
					},
					Emails: []SCIMEmail{{Value: "abed@greendale.edu"}},
				}},
			}))
		case "/Users?startIndex=2&count=100":
			w.Header().Set("Content-Type", "application/scim+json")
			r.NoError(json.NewEncoder(w).Encode(SCIMListResponse[SCIMUserResource]{
				TotalResults: 2,
				StartIndex:   2,
				ItemsPerPage: 1,
				Resources: []SCIMUserResource{{
					ID:          "remote-user-2",
					UserName:    "anniee",
					DisplayName: "Annie Edison",
					Active:      boolPtr(false),
					Name: &SCIMName{
						GivenName:  "Annie",
						FamilyName: "Edison",
					},
					Emails: []SCIMEmail{{Value: "annie@greendale.edu"}},
				}},
			}))
		case "/Groups?startIndex=1&count=100":
			w.Header().Set("Content-Type", "application/scim+json")
			r.NoError(json.NewEncoder(w).Encode(SCIMListResponse[SCIMGroupResource]{
				TotalResults: 1,
				StartIndex:   1,
				ItemsPerPage: 1,
				Resources: []SCIMGroupResource{{
					ID:          "remote-group-1",
					ExternalID:  "local-group-1",
					DisplayName: "Study Group",
					Members: []SCIMMember{{
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

	state := AppState{
		Config: Config{
			BaseURL:     server.URL,
			BearerToken: "chang-secret",
		},
		Users: []User{{
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
		Groups: []Group{{
			ID:          "old-group",
			DisplayName: "Old Group",
			MemberIDs:   []string{"old-user"},
			RemoteID:    "stale-group",
			Dirty:       true,
		}},
		UserOperations: map[string][]OperationLog{
			"old-user": {{Kind: "local", Summary: "Created", CreatedAt: "2026-05-01T10:00:00Z"}},
		},
		GroupOperations: map[string][]OperationLog{
			"old-group": {{Kind: "local", Summary: "Created", CreatedAt: "2026-05-01T10:00:00Z"}},
		},
	}

	result := ImportStateFromSCIM(state)
	r.NoError(result.Fatal)
	r.Equal("imported 2 users and 1 groups from SCIM", result.Status)
	r.Len(result.State.Users, 2)
	r.Len(result.State.Groups, 1)
	r.Equal([]string{
		"GET /Users?startIndex=1&count=100",
		"GET /Users?startIndex=2&count=100",
		"GET /Groups?startIndex=1&count=100",
	}, requests)

	r.Equal("local-1", result.State.Users[0].ID)
	r.Equal("remote-user-1", result.State.Users[0].RemoteID)
	r.Equal("Abed", result.State.Users[0].GivenName)
	r.Equal("Nadir", result.State.Users[0].FamilyName)
	r.Equal("abed", result.State.Users[0].Username)
	r.Equal("abed@greendale.edu", result.State.Users[0].Email)
	r.True(result.State.Users[0].Active)
	r.False(result.State.Users[0].Dirty)
	r.Empty(result.State.Users[0].LastError)

	r.Equal("remote-user-2", result.State.Users[1].RemoteID)
	r.Equal("anniee", result.State.Users[1].Username)
	r.Equal("annie@greendale.edu", result.State.Users[1].Email)
	r.False(result.State.Users[1].Active)
	r.False(result.State.Users[1].Dirty)
	r.NotEmpty(result.State.Users[1].ID)
	r.NotEqual("old-user", result.State.Users[1].ID)

	r.Equal("local-group-1", result.State.Groups[0].ID)
	r.Equal("Study Group", result.State.Groups[0].DisplayName)
	r.Equal("remote-group-1", result.State.Groups[0].RemoteID)
	r.False(result.State.Groups[0].Dirty)
	r.Equal([]string{result.State.Users[0].ID, result.State.Users[1].ID}, result.State.Groups[0].MemberIDs)

	_, oldUserStillExists := result.State.UserOperations["old-user"]
	r.False(oldUserStillExists)
	_, oldGroupStillExists := result.State.GroupOperations["old-group"]
	r.False(oldGroupStillExists)

	r.Len(result.State.UserOperations[result.State.Users[0].ID], 1)
	r.Equal("Imported from SCIM", result.State.UserOperations[result.State.Users[0].ID][0].Summary)
	r.Len(result.State.UserOperations[result.State.Users[1].ID], 1)
	r.Equal("Imported from SCIM", result.State.UserOperations[result.State.Users[1].ID][0].Summary)
	r.Len(result.State.GroupOperations[result.State.Groups[0].ID], 1)
	r.Equal("Imported from SCIM", result.State.GroupOperations[result.State.Groups[0].ID][0].Summary)
	r.Len(result.Traces, 3)
	r.Equal("import", result.Traces[0].Operation)
	r.Equal("GET", result.Traces[0].Method)
}

func captureRateLimitSleeps(t *testing.T) *[]time.Duration {
	t.Helper()

	sleeps := []time.Duration{}
	originalRateLimitSleep := rateLimitSleep
	rateLimitSleep = func(delay time.Duration) {
		sleeps = append(sleeps, delay)
	}
	t.Cleanup(func() { rateLimitSleep = originalRateLimitSleep })

	return &sleeps
}

func progressLabels(events []SyncProgress) []string {
	labels := make([]string, 0, len(events))
	for _, event := range events {
		if event.Label != "" {
			labels = append(labels, event.Label)
		}
	}

	return labels
}

func progressStatuses(events []SyncProgress) []string {
	statuses := make([]string, 0, len(events))
	for _, event := range events {
		if event.Status != "" {
			statuses = append(statuses, event.Status)
		}
	}

	return statuses
}

func hasRateLimitedProgress(events []SyncProgress) bool {
	for _, event := range events {
		if event.RateLimited {
			return true
		}
	}

	return false
}

func boolPtr(v bool) *bool {
	return &v
}
