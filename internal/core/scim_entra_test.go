package core

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEntraUserOperations(t *testing.T) {
	active, inactive := true, false
	remote := SCIMUserResource{
		ID: "remote-troy", ExternalID: "troy", UserName: "tbarnes", DisplayName: "Troy Barnes", Active: &active,
		Name:       &SCIMName{GivenName: "Troy", FamilyName: "Barnes"},
		Emails:     []SCIMEmail{{Value: "troy.barnes@greendale.edu", Type: "work", Primary: true}},
		Enterprise: &SCIMEnterpriseUser{Department: "Air Conditioning Repair"},
	}
	desired := func(change func(*SCIMUserResource)) SCIMUserResource {
		resource := remote
		resource.ID = ""
		resource.Active = &active
		enterprise := *remote.Enterprise
		resource.Enterprise = &enterprise
		change(&resource)
		return resource
	}
	tests := map[string]struct {
		desired SCIMUserResource
		remote  SCIMUserResource
		want    string
	}{
		"matching user sends nothing": {
			desired: desired(func(*SCIMUserResource) {}),
			remote:  remote,
			want:    `null`,
		},
		"deactivation sends active as a capitalized string": {
			desired: desired(func(resource *SCIMUserResource) { resource.Active = &inactive }),
			remote:  remote,
			want:    `[{"op":"Replace","path":"active","value":"False"}]`,
		},
		"reactivation sends True": {
			desired: desired(func(*SCIMUserResource) {}),
			remote: func() SCIMUserResource {
				resource := remote
				resource.Active = &inactive
				return resource
			}(),
			want: `[{"op":"Replace","path":"active","value":"True"}]`,
		},
		"changed attributes use one path operation each": {
			desired: desired(func(resource *SCIMUserResource) {
				resource.DisplayName = "Troy and Abed"
				resource.Name = &SCIMName{GivenName: "Troy", FamilyName: "Nadir"}
				resource.Emails = []SCIMEmail{{Value: "troy@greendale.edu", Type: "work", Primary: true}}
			}),
			remote: remote,
			want:   `[{"op":"Replace","path":"displayName","value":"Troy and Abed"},{"op":"Replace","path":"name.familyName","value":"Nadir"},{"op":"Replace","path":"emails[type eq \"work\"].value","value":"troy@greendale.edu"}]`,
		},
		"cleared enterprise value is removed and the manager is a bare ID": {
			desired: desired(func(resource *SCIMUserResource) {
				resource.Enterprise = &SCIMEnterpriseUser{Manager: &SCIMManager{Value: "remote-dean"}}
			}),
			remote: remote,
			want:   `[{"op":"Remove","path":"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department"},{"op":"Replace","path":"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager","value":"remote-dean"}]`,
		},
		"directory without enterprise values leaves the extension alone": {
			desired: desired(func(resource *SCIMUserResource) { resource.Enterprise = nil }),
			remote:  remote,
			want:    `null`,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			data, err := json.Marshal(entraUserOperations(tc.desired, tc.remote))
			require.NoError(t, err)
			require.JSONEq(t, tc.want, string(data))
		})
	}
}

func TestEntraGroupOperations(t *testing.T) {
	remote := SCIMGroupResource{ID: "remote-study", ExternalID: "study", DisplayName: "Study Group", Members: []SCIMMember{{Value: "remote-troy"}, {Value: "remote-abed", Type: "User"}}}
	tests := map[string]struct {
		desired SCIMGroupResource
		want    string
	}{
		"matching group sends nothing": {
			desired: SCIMGroupResource{DisplayName: "Study Group", Members: []SCIMMember{{Value: "remote-abed"}, {Value: "remote-troy"}}},
			want:    `null`,
		},
		"membership changes add and remove only the difference": {
			desired: SCIMGroupResource{DisplayName: "Study Group", Members: []SCIMMember{{Value: "remote-abed", Type: "User"}, {Value: "remote-annie", Type: "User"}}},
			want:    `[{"op":"Add","path":"members","value":[{"value":"remote-annie"}]},{"op":"Remove","path":"members","value":[{"value":"remote-troy"}]}]`,
		},
		"rename": {
			desired: SCIMGroupResource{DisplayName: "Study Group F", Members: remote.Members},
			want:    `[{"op":"Replace","path":"displayName","value":"Study Group F"}]`,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			data, err := json.Marshal(entraGroupOperations(tc.desired, remote))
			require.NoError(t, err)
			require.JSONEq(t, tc.want, string(data))
		})
	}
}

// entraSCIMServer is a SCIM target that records requests and answers
// externalId filters from the resources it holds.
type entraSCIMServer struct {
	t            *testing.T
	requests     []string
	bodies       map[string]string
	users        []SCIMUserResource
	groups       []SCIMGroupResource
	filterStatus int
}

func (s *entraSCIMServer) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	body, err := io.ReadAll(req.Body)
	require.NoError(s.t, err)
	target := req.Method + " " + req.URL.Path
	if req.URL.RawQuery != "" {
		target += "?" + req.URL.RawQuery
	}
	s.requests = append(s.requests, target)
	s.bodies[req.Method+" "+req.URL.Path] = string(body)
	w.Header().Set("Content-Type", "application/scim+json")
	filter := req.URL.Query().Get("filter")
	switch {
	case req.Method == http.MethodGet && filter != "" && s.filterStatus != 0:
		w.WriteHeader(s.filterStatus)
	case req.Method == http.MethodGet && req.URL.Path == "/Users" && filter != "":
		matches := []SCIMUserResource{}
		for _, resource := range s.users {
			if filter == `externalId eq "`+resource.ExternalID+`"` {
				matches = append(matches, resource)
			}
		}
		require.NoError(s.t, json.NewEncoder(w).Encode(SCIMListResponse[SCIMUserResource]{TotalResults: len(matches), Resources: matches}))
	case req.Method == http.MethodGet && req.URL.Path == "/Groups" && filter != "":
		matches := []SCIMGroupResource{}
		for _, resource := range s.groups {
			if filter == `externalId eq "`+resource.ExternalID+`"` {
				matches = append(matches, resource)
			}
		}
		require.NoError(s.t, json.NewEncoder(w).Encode(SCIMListResponse[SCIMGroupResource]{TotalResults: len(matches), Resources: matches}))
	case req.Method == http.MethodGet:
		writeEmptySCIMListResponse(w)
	case req.Method == http.MethodPost:
		var resource struct {
			ExternalID string `json:"externalId"`
		}
		require.NoError(s.t, json.Unmarshal(body, &resource))
		w.WriteHeader(http.StatusCreated)
		require.NoError(s.t, json.NewEncoder(w).Encode(map[string]string{"id": "remote-" + resource.ExternalID}))
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func newEntraSCIMServer(t *testing.T) (*entraSCIMServer, *httptest.Server) {
	t.Helper()
	fake := &entraSCIMServer{t: t, bodies: map[string]string{}}
	server := httptest.NewServer(fake)
	t.Cleanup(server.Close)
	return fake, server
}

func TestEntraDialectSync(t *testing.T) {
	active := true
	troy := User{ID: "troy", GivenName: "Troy", FamilyName: "Barnes", Username: "tbarnes", Email: "troy.barnes@greendale.edu", Active: true}
	remoteTroy := SCIMUserResource{
		ID: "remote-troy", ExternalID: "troy", UserName: "tbarnes", DisplayName: "Troy Barnes", Active: &active,
		Name:   &SCIMName{GivenName: "Troy", FamilyName: "Barnes"},
		Emails: []SCIMEmail{{Value: "troy.barnes@greendale.edu", Type: "work"}},
	}
	abed := User{ID: "abed", GivenName: "Abed", FamilyName: "Nadir", Username: "anadir", Email: "abed.nadir@greendale.edu", Active: true, RemoteID: "remote-abed"}
	tests := map[string]struct {
		users        []User
		groups       []Group
		remoteUsers  []SCIMUserResource
		remoteGroups []SCIMGroupResource
		filterStatus int
		wantRequests []string
		wantBodies   map[string]string
		wantError    string
	}{
		"new user is matched by externalId alone before the create": {
			users:        []User{func() User { u := troy; u.Dirty = true; return u }()},
			wantRequests: []string{`GET /Users?filter=externalId+eq+%22troy%22`, "POST /Users"},
		},
		"deactivated user is matched again and patched": {
			users:        []User{func() User { u := troy; u.RemoteID, u.Active, u.Dirty = "remote-troy", false, true; return u }()},
			remoteUsers:  []SCIMUserResource{remoteTroy},
			wantRequests: []string{`GET /Users?filter=externalId+eq+%22troy%22`, "PATCH /Users/remote-troy"},
			wantBodies: map[string]string{
				"PATCH /Users/remote-troy": `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"Replace","path":"active","value":"False"}]}`,
			},
		},
		"existing remote user found while creating is patched, not replaced": {
			users:        []User{func() User { u := troy; u.FamilyName, u.Dirty = "Nadir", true; return u }()},
			remoteUsers:  []SCIMUserResource{remoteTroy},
			wantRequests: []string{`GET /Users?filter=externalId+eq+%22troy%22`, "PATCH /Users/remote-troy"},
			wantBodies: map[string]string{
				"PATCH /Users/remote-troy": `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"Replace","path":"displayName","value":"Troy Nadir"},{"op":"Replace","path":"name.familyName","value":"Nadir"}]}`,
			},
		},
		"group membership change adds and removes members": {
			users:        []User{func() User { u := troy; u.RemoteID = "remote-troy"; return u }(), abed},
			groups:       []Group{{ID: "study", DisplayName: "Study Group", MemberIDs: []string{"abed"}, RemoteID: "remote-study", Dirty: true}},
			remoteGroups: []SCIMGroupResource{{ID: "remote-study", ExternalID: "study", DisplayName: "Study Group", Members: []SCIMMember{{Value: "remote-troy"}}}},
			wantRequests: []string{`GET /Groups?filter=externalId+eq+%22study%22`, "PATCH /Groups/remote-study"},
			wantBodies: map[string]string{
				"PATCH /Groups/remote-study": `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"Add","path":"members","value":[{"value":"remote-abed"}]},{"op":"Remove","path":"members","value":[{"value":"remote-troy"}]}]}`,
			},
		},
		"failed filter does not fall back to listing": {
			users:        []User{func() User { u := troy; u.Dirty = true; return u }()},
			filterStatus: http.StatusBadRequest,
			wantRequests: []string{`GET /Users?filter=externalId+eq+%22troy%22`},
			wantError:    "400 Bad Request",
		},
		"user missing from the remote fails the update": {
			users:        []User{func() User { u := troy; u.RemoteID, u.Dirty = "remote-troy", true; return u }()},
			wantRequests: []string{`GET /Users?filter=externalId+eq+%22troy%22`},
			wantError:    `SCIM user with externalId "troy": resource not found`,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			fake, server := newEntraSCIMServer(t)
			fake.users, fake.groups, fake.filterStatus = tc.remoteUsers, tc.remoteGroups, tc.filterStatus

			result := SyncDirtyState(AppState{
				Config: Config{BaseURL: server.URL, BearerToken: "chang-secret", Persona: PersonaEntra},
				Users:  tc.users,
				Groups: tc.groups,
			})

			r.NoError(result.Fatal)
			r.Equal(tc.wantRequests, fake.requests)
			for request, want := range tc.wantBodies {
				r.JSONEq(want, fake.bodies[request], request)
			}
			lastErrors := make([]string, 0, len(result.State.Users))
			for _, u := range result.State.Users {
				lastErrors = append(lastErrors, u.LastError)
			}
			if tc.wantError == "" {
				r.Empty(strings.Join(lastErrors, ""))
				return
			}
			r.Contains(strings.Join(lastErrors, "\n"), tc.wantError)
		})
	}
}

func TestGenericDialectKeepsLookupAndReplace(t *testing.T) {
	r := require.New(t)
	fake, server := newEntraSCIMServer(t)
	fake.filterStatus = http.StatusBadRequest

	result := SyncDirtyState(AppState{
		Config: Config{BaseURL: server.URL, BearerToken: "chang-secret", PatchSupported: true},
		Users: []User{
			{ID: "troy", GivenName: "Troy", Username: "tbarnes", Email: "troy.barnes@greendale.edu", Active: true, Dirty: true},
			{ID: "abed", GivenName: "Abed", Username: "anadir", Email: "abed.nadir@greendale.edu", RemoteID: "remote-abed", Dirty: true},
		},
	})

	r.NoError(result.Fatal)
	r.Equal([]string{
		`GET /Users?count=2&filter=externalId+eq+%22troy%22`,
		"GET /Users?startIndex=1&count=100",
		"POST /Users",
		"PATCH /Users/remote-abed",
	}, fake.requests)
	r.Contains(fake.bodies["PATCH /Users/remote-abed"], `"Operations":[{"op":"replace","value":{`)
	r.Contains(fake.bodies["PATCH /Users/remote-abed"], `"active":false`)
}

func TestEntraClearsLastEnterpriseValue(t *testing.T) {
	r := require.New(t)
	fake, server := newEntraSCIMServer(t)
	troy := User{ID: "troy", GivenName: "Troy", Username: "troy", Email: "troy@greendale.edu", Active: true, RemoteID: "remote-troy", Dirty: true, Department: "Air Conditioning Repair"}
	remote := newSCIMUserResource(troy, newSCIMUserDirectory([]User{troy}))
	remote.ID = troy.RemoteID
	fake.users = []SCIMUserResource{remote}
	first := SyncDirtyState(AppState{
		Config: Config{BaseURL: server.URL, BearerToken: "study-group-secret", Persona: PersonaEntra},
		Users:  []User{troy},
	})
	r.NoError(first.Fatal)
	r.False(first.Failed)
	state := first.State
	state.Users[0].Department = ""
	state.Users[0].Dirty = true
	cleared := SyncDirtyState(state)
	r.NoError(cleared.Fatal)
	r.False(cleared.Failed)
	r.False(cleared.State.Users[0].Dirty)
	r.JSONEq(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"Remove","path":"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department"}]}`, fake.bodies["PATCH /Users/remote-troy"])
}
