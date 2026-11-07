package core

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func greendaleEnterpriseUsers() []User {
	return []User{
		{
			ID: "dean", GivenName: "Craig", FamilyName: "Pelton", Email: "dean@greendale.edu", Username: "dean", Active: true,
			EmployeeNumber: "GC-0001", Department: "Office of the Dean", Division: "Administration",
			Organization: "Greendale Community College", CostCenter: "1000",
		},
		{
			ID: "troy", GivenName: "Troy", FamilyName: "Barnes", Email: "troy@greendale.edu", Username: "troy", Active: true,
			EmployeeNumber: "GC-1001", Department: "Air Conditioning Repair", Division: "Facilities",
			Organization: "Greendale Community College", CostCenter: "3100", ManagerID: "dean",
			Attributes: map[string]string{"role": "student", "https://greendale.edu/claims/annex": "true"},
		},
	}
}

func TestUserAttributesSurviveSaveAndLoad(t *testing.T) {
	r := require.New(t)
	t.Setenv("SCIMTEST_STATE_FILE", filepath.Join(t.TempDir(), "state.db"))
	users := greendaleEnterpriseUsers()
	r.NoError(SaveState(AppState{
		Users: users,
		Apps:  []App{{ID: "app-1", Name: "Greendale Portal", Slug: "greendale", Protocol: "oidc"}},
	}))

	global, err := LoadState()
	r.NoError(err)
	r.Equal(users, global.Users)

	// SaveState copies the shared directory into each environment.
	environment, err := LoadStateForApp("app-1")
	r.NoError(err)
	r.Equal(users, environment.Users)

	environment.Users[1].Department = "Study Room F"
	environment.Users[1].ManagerID = ""
	environment.Users[1].Attributes = nil
	r.NoError(SaveEnvironmentState(environment))
	reloaded, err := LoadStateForApp("app-1")
	r.NoError(err)
	r.Equal("Study Room F", reloaded.Users[1].Department)
	r.Empty(reloaded.Users[1].ManagerID)
	r.Nil(reloaded.Users[1].Attributes)
}

func TestSchemaMigrationAddsUserAttributeColumns(t *testing.T) {
	r := require.New(t)
	t.Setenv("SCIMTEST_STATE_FILE", filepath.Join(t.TempDir(), "state.db"))
	troy := User{ID: "troy", GivenName: "Troy", FamilyName: "Barnes", Email: "troy@greendale.edu", Username: "troy", Active: true}
	r.NoError(SaveState(AppState{Users: []User{troy}}))

	// Rebuild the version 2 users table, which had no attribute columns.
	db, err := openStateDB()
	r.NoError(err)
	for _, column := range []string{"employee_number", "cost_center", "organization", "division", "department", "manager_id", "attributes"} {
		_, err = db.Exec(`ALTER TABLE users DROP COLUMN ` + column)
		r.NoError(err)
	}
	_, err = db.Exec(`PRAGMA user_version = 2`)
	r.NoError(err)
	r.NoError(resetStateDBCache())

	state, err := LoadState()
	r.NoError(err)
	r.Equal([]User{troy}, state.Users)
	db, err = openStateDB()
	r.NoError(err)
	version, err := schemaVersion(db)
	r.NoError(err)
	r.Equal(currentSchemaVersion, version)

	state.Users[0].Department = "Air Conditioning Repair"
	state.Users[0].Attributes = map[string]string{"role": "student"}
	r.NoError(SaveState(state))
	state, err = LoadState()
	r.NoError(err)
	r.Equal("Air Conditioning Repair", state.Users[0].Department)
	r.Equal(map[string]string{"role": "student"}, state.Users[0].Attributes)
}

func TestStateBackupRestoresUserAttributes(t *testing.T) {
	tests := map[string]struct {
		backup func(r *require.Assertions) []byte
		want   []User
	}{
		"current backup": {
			backup: func(r *require.Assertions) []byte {
				data, err := json.Marshal(NewStateBackup(AppState{Users: greendaleEnterpriseUsers()}))
				r.NoError(err)
				return data
			},
			want: greendaleEnterpriseUsers(),
		},
		"backup from before user attributes": {
			backup: func(*require.Assertions) []byte {
				return []byte(`{"version":1,"exported_at":"2026-09-01T00:00:00Z","state":{"environment":{"id":"","name":"","slug":""},"config":{"base_url":"","bearer_token":"","auto_open_sync_trace":false},"users":[{"id":"troy","given_name":"Troy","family_name":"Barnes","email":"troy@greendale.edu","username":"troy","active":true,"dirty":false,"deleted":false}],"groups":null,"apps":null}}`)
			},
			want: []User{{ID: "troy", GivenName: "Troy", FamilyName: "Barnes", Email: "troy@greendale.edu", Username: "troy", Active: true}},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			var backup StateBackup
			r.NoError(json.Unmarshal(tc.backup(r), &backup))
			restored, err := backup.RestoredState()
			r.NoError(err)
			r.Equal(tc.want, restored.Users)
		})
	}
}

func TestParseCustomAttributes(t *testing.T) {
	tests := map[string]struct {
		text    string
		want    map[string]string
		wantErr string
	}{
		"empty text":             {text: " \n\n", want: nil},
		"trims names and values": {text: " role = student \r\ncampus=Greendale\n", want: map[string]string{"role": "student", "campus": "Greendale"}},
		"keeps equals in values": {text: "token=a=b", want: map[string]string{"token": "a=b"}},
		"allows empty values":    {text: "nickname=", want: map[string]string{"nickname": ""}},
		"missing equals":         {text: "role=student\nannex", wantErr: "custom attribute on line 2 must look like name=value"},
		"duplicate name":         {text: "role=student\nrole=faculty", wantErr: `custom attribute "role" is listed more than once`},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			got, err := ParseCustomAttributes(tc.text)
			if tc.wantErr != "" {
				r.EqualError(err, tc.wantErr)
				return
			}
			r.NoError(err)
			r.Equal(tc.want, got)
			r.Equal(tc.want, mustParseCustomAttributes(t, FormatCustomAttributes(got)))
		})
	}
}

func mustParseCustomAttributes(t *testing.T, text string) map[string]string {
	t.Helper()
	attributes, err := ParseCustomAttributes(text)
	require.NoError(t, err)
	return attributes
}

func TestValidateCustomAttributes(t *testing.T) {
	tooMany := make(map[string]string, maxCustomAttributes+1)
	for i := range maxCustomAttributes + 1 {
		tooMany["attribute_"+strings.Repeat("x", i)] = "value"
	}
	tests := map[string]struct {
		attributes map[string]string
		wantErr    string
	}{
		"none":                {},
		"plain and URI names": {attributes: map[string]string{"role": "student", "http://schemas.microsoft.com/ws/2008/06/identity/claims/role": "student", "_tier": "gold"}},
		"name with a space":   {attributes: map[string]string{"study group": "yes"}, wantErr: `custom attribute name "study group" must start with a letter or underscore and use only letters, digits, and _ . : / # -`},
		"protocol claim":      {attributes: map[string]string{"sub": "abed"}, wantErr: `custom attribute name "sub" is reserved`},
		"enterprise name":     {attributes: map[string]string{"department": "Law"}, wantErr: `custom attribute name "department" is reserved`},
		"multi-line value":    {attributes: map[string]string{"motto": "e pluribus\nanus"}, wantErr: `custom attribute "motto" must be a single line`},
		"long value":          {attributes: map[string]string{"bio": strings.Repeat("x", maxCustomAttributeValueLength+1)}, wantErr: `custom attribute "bio" is longer than 1024 characters`},
		"too many":            {attributes: tooMany, wantErr: "a user can have at most 50 custom attributes"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			err := ValidateCustomAttributes(tc.attributes)
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.EqualError(t, err, tc.wantErr)
		})
	}
}

func TestValidateManager(t *testing.T) {
	users := append(greendaleEnterpriseUsers(), User{ID: "chang", Email: "chang@greendale.edu", Deleted: true})
	tests := map[string]struct {
		userID    string
		managerID string
		wantErr   string
	}{
		"no manager":    {userID: "troy"},
		"existing user": {userID: "troy", managerID: "dean"},
		"new user":      {managerID: "dean"},
		"self":          {userID: "troy", managerID: "troy", wantErr: "a user cannot be their own manager"},
		"unknown user":  {userID: "troy", managerID: "duncan", wantErr: `manager "duncan" is not a user in this environment`},
		"deleted user":  {userID: "troy", managerID: "chang", wantErr: `manager "chang" is not a user in this environment`},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			err := ValidateManager(users, tc.userID, tc.managerID)
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.EqualError(t, err, tc.wantErr)
		})
	}
}
