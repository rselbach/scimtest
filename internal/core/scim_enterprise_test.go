package core

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSCIMUserPayloadCarriesEnterpriseExtension(t *testing.T) {
	plain := User{ID: "abed", GivenName: "Abed", Username: "abed", Email: "abed@greendale.edu", Active: true}
	dean := User{ID: "dean", GivenName: "Craig", Username: "dean", Email: "dean@greendale.edu", Active: true, RemoteID: "remote-dean", Department: "Office of the Dean"}
	troy := User{
		ID: "troy", GivenName: "Troy", Username: "troy", Email: "troy@greendale.edu", Active: true,
		EmployeeNumber: "GC-1001", CostCenter: "3100", Organization: "Greendale Community College",
		Division: "Facilities", Department: "Air Conditioning Repair", ManagerID: "dean",
		Attributes: map[string]string{"role": "student"},
	}
	tests := map[string]struct {
		user      User
		directory []User
		want      []string
		wantNot   []string
	}{
		"directory without enterprise values sends only the core schema": {
			user:      plain,
			directory: []User{plain},
			want:      []string{`"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"]`},
			wantNot:   []string{"enterprise", "manager"},
		},
		"values and a provisioned manager": {
			user:      troy,
			directory: []User{troy, dean},
			want: []string{
				`"schemas":["urn:ietf:params:scim:schemas:core:2.0:User","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"]`,
				`"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"employeeNumber":"GC-1001","costCenter":"3100","organization":"Greendale Community College","division":"Facilities","department":"Air Conditioning Repair","manager":{"value":"remote-dean"}}`,
			},
			wantNot: []string{"role", "student"},
		},
		"cleared values are explicit once the directory uses the extension": {
			user:      plain,
			directory: []User{plain, dean},
			want:      []string{`"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"employeeNumber":"","costCenter":"","organization":"","division":"","department":"","manager":null}`},
		},
		"manager without a remote ID is null": {
			user:      troy,
			directory: []User{troy, {ID: "dean", Email: "dean@greendale.edu"}},
			want:      []string{`"manager":null`},
		},
		"deleted manager is null": {
			user:      troy,
			directory: []User{troy, {ID: "dean", Email: "dean@greendale.edu", RemoteID: "remote-dean", Deleted: true}},
			want:      []string{`"manager":null`},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			data, err := json.Marshal(newSCIMUserResource(tc.user, newSCIMUserDirectory(tc.directory)))
			r.NoError(err)
			for _, want := range tc.want {
				r.Contains(string(data), want)
			}
			for _, wantNot := range tc.wantNot {
				r.NotContains(string(data), wantNot)
			}
		})
	}
}

func TestSyncDirtyStateSendsManagerOnceItIsCreated(t *testing.T) {
	r := require.New(t)
	var requests []string
	managers := map[string]string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if isSCIMExternalIDProbe(req) {
			writeEmptySCIMListResponse(w)
			return
		}
		requests = append(requests, req.Method+" "+req.URL.Path)
		var resource SCIMUserResource
		r.NoError(json.NewDecoder(req.Body).Decode(&resource))
		r.Contains(resource.Schemas, scimEnterpriseUserSchema)
		r.NotNil(resource.Enterprise)
		managers[req.Method+" "+resource.ExternalID] = scimManagerValue(resource.Enterprise.Manager)
		w.Header().Set("Content-Type", "application/scim+json")
		if req.Method == http.MethodPost {
			w.WriteHeader(http.StatusCreated)
			r.NoError(json.NewEncoder(w).Encode(SCIMUserResource{ID: "remote-" + resource.ExternalID}))
		}
	}))
	defer server.Close()

	var progress []SyncProgress
	result := SyncDirtyStateWithProgress(AppState{
		Config: Config{BaseURL: server.URL, BearerToken: "chang-secret", FilterSupported: true},
		Users: []User{
			{ID: "troy", GivenName: "Troy", Username: "troy", Email: "troy@greendale.edu", Active: true, ManagerID: "dean", Dirty: true},
			{ID: "dean", GivenName: "Craig", Username: "dean", Email: "dean@greendale.edu", Active: true, Department: "Office of the Dean", Dirty: true},
		},
	}, func(event SyncProgress) { progress = append(progress, event) })

	r.NoError(result.Fatal)
	r.NoError(result.Stopped)
	r.Equal([]string{"POST /Users", "POST /Users", "PUT /Users/remote-troy"}, requests)
	r.Equal(map[string]string{"POST troy": "", "POST dean": "", "PUT troy": "remote-dean"}, managers)
	r.Contains(result.Status, "users 2 created, 1 updated")
	r.False(result.State.Users[0].Dirty)
	r.False(result.State.Users[1].Dirty)
	last := progress[len(progress)-1]
	r.Equal(last.Total, last.Processed)
}

func TestSyncDirtyStateRetriesManagerReferenceWhenManagerFails(t *testing.T) {
	r := require.New(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if isSCIMExternalIDProbe(req) {
			writeEmptySCIMListResponse(w)
			return
		}
		var resource SCIMUserResource
		r.NoError(json.NewDecoder(req.Body).Decode(&resource))
		if resource.ExternalID == "dean" {
			http.Error(w, "the Dean is out of the office", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/scim+json")
		w.WriteHeader(http.StatusCreated)
		r.NoError(json.NewEncoder(w).Encode(SCIMUserResource{ID: "remote-" + resource.ExternalID}))
	}))
	defer server.Close()

	result := SyncDirtyState(AppState{
		Config: Config{BaseURL: server.URL, BearerToken: "chang-secret", FilterSupported: true},
		Users: []User{
			{ID: "troy", GivenName: "Troy", Username: "troy", Email: "troy@greendale.edu", Active: true, ManagerID: "dean", Dirty: true},
			{ID: "dean", GivenName: "Craig", Username: "dean", Email: "dean@greendale.edu", Active: true, Dirty: true},
		},
	})

	r.NoError(result.Fatal)
	r.True(result.Failed)
	r.Equal("remote-troy", result.State.Users[0].RemoteID)
	r.True(result.State.Users[0].Dirty, "troy's manager reference is still unsent")
	r.Empty(result.State.Users[0].LastError)
	r.True(result.State.Users[1].Dirty)
	r.NotEmpty(result.State.Users[1].LastError)
}

func TestReconcileComparesEnterpriseExtension(t *testing.T) {
	troy := User{
		ID: "troy", GivenName: "Troy", FamilyName: "Barnes", Username: "troy", Email: "troy@greendale.edu",
		Active: true, RemoteID: "remote-troy", Department: "Air Conditioning Repair", ManagerID: "dean",
	}
	dean := User{ID: "dean", GivenName: "Craig", FamilyName: "Pelton", Username: "dean", Email: "dean@greendale.edu", Active: true, RemoteID: "remote-dean"}
	tests := map[string]struct {
		remoteTroy *SCIMEnterpriseUser
		want       []string
	}{
		"matching extension is in sync": {
			remoteTroy: &SCIMEnterpriseUser{Department: "Air Conditioning Repair", Manager: &SCIMManager{Value: "remote-dean"}},
			want:       []string{"GET /Users/remote-troy", "GET /Users/remote-dean"},
		},
		"changed department is replaced": {
			remoteTroy: &SCIMEnterpriseUser{Department: "Study Room F", Manager: &SCIMManager{Value: "remote-dean"}},
			want:       []string{"GET /Users/remote-troy", "PUT /Users/remote-troy", "GET /Users/remote-dean"},
		},
		"missing manager is replaced": {
			remoteTroy: &SCIMEnterpriseUser{Department: "Air Conditioning Repair"},
			want:       []string{"GET /Users/remote-troy", "PUT /Users/remote-troy", "GET /Users/remote-dean"},
		},
		"missing extension is replaced": {
			want: []string{"GET /Users/remote-troy", "PUT /Users/remote-troy", "GET /Users/remote-dean"},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			var requests []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				requests = append(requests, req.Method+" "+req.URL.Path)
				w.Header().Set("Content-Type", "application/scim+json")
				switch req.Method + " " + req.URL.Path {
				case "GET /Users/remote-troy":
					remote := newSCIMUserResource(troy, scimUserDirectory{})
					remote.ID = "remote-troy"
					remote.Enterprise = tc.remoteTroy
					r.NoError(json.NewEncoder(w).Encode(remote))
				case "GET /Users/remote-dean":
					remote := newSCIMUserResource(dean, newSCIMUserDirectory([]User{troy, dean}))
					remote.ID = "remote-dean"
					r.NoError(json.NewEncoder(w).Encode(remote))
				case "PUT /Users/remote-troy":
					var resource SCIMUserResource
					r.NoError(json.NewDecoder(req.Body).Decode(&resource))
					r.Equal("Air Conditioning Repair", resource.Enterprise.Department)
					r.Equal("remote-dean", scimManagerValue(resource.Enterprise.Manager))
				default:
					t.Fatalf("unexpected SCIM request %s %s", req.Method, req.URL.Path)
				}
			}))
			defer server.Close()

			result := ReconcileState(AppState{
				Config: Config{BaseURL: server.URL, BearerToken: "chang-secret"},
				Users:  []User{troy, dean},
			})

			r.NoError(result.Fatal)
			r.NoError(result.Stopped)
			r.Equal(tc.want, requests)
		})
	}
}

func TestImportStateFromSCIMReadsEnterpriseExtension(t *testing.T) {
	r := require.New(t)
	existing := AppState{Users: []User{{
		ID: "troy", GivenName: "Troy", Username: "troy", Email: "troy@greendale.edu", Active: true,
		RemoteID: "remote-troy", Attributes: map[string]string{"role": "student"},
	}}}
	resources := []SCIMUserResource{
		{
			ID: "remote-troy", ExternalID: "troy", UserName: "troy",
			Emails: []SCIMEmail{{Value: "troy@greendale.edu"}},
			Enterprise: &SCIMEnterpriseUser{
				EmployeeNumber: " GC-1001 ", Department: "Air Conditioning Repair", Division: "Facilities",
				Organization: "Greendale Community College", CostCenter: "3100",
				Manager: &SCIMManager{Value: "remote-dean"},
			},
		},
		{ID: "remote-dean", ExternalID: "dean", UserName: "dean", Emails: []SCIMEmail{{Value: "dean@greendale.edu"}}},
		{
			ID: "remote-chang", UserName: "chang", Emails: []SCIMEmail{{Value: "chang@greendale.edu"}},
			Enterprise: &SCIMEnterpriseUser{Manager: &SCIMManager{Value: "remote-duncan"}},
		},
	}

	imported, _, err := replaceStateFromSCIM(existing, resources, nil)

	r.NoError(err)
	r.Len(imported.Users, 3)
	troy := imported.Users[0]
	r.Equal("GC-1001", troy.EmployeeNumber)
	r.Equal("Air Conditioning Repair", troy.Department)
	r.Equal("Facilities", troy.Division)
	r.Equal("Greendale Community College", troy.Organization)
	r.Equal("3100", troy.CostCenter)
	r.Equal("dean", troy.ManagerID)
	r.Equal(map[string]string{"role": "student"}, troy.Attributes, "custom attributes are local-only")
	r.Empty(imported.Users[1].ManagerID)
	r.Empty(imported.Users[2].ManagerID, "managers outside the import are dropped")
}
