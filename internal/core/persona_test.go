package core

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSchemaMigrationAddsPersonaColumns(t *testing.T) {
	r := require.New(t)
	t.Setenv("SCIMTEST_STATE_FILE", filepath.Join(t.TempDir(), "state.db"))
	greendale := App{ID: "app-1", Name: "Greendale Portal", Slug: "greendale", Protocol: "none"}
	r.NoError(SaveState(AppState{Apps: []App{greendale}}))

	// Rebuild the version 3 apps table, which had no persona columns.
	db, err := openStateDB()
	r.NoError(err)
	for _, column := range []string{"persona", "groups_overage_threshold"} {
		_, err = db.Exec(`ALTER TABLE apps DROP COLUMN ` + column)
		r.NoError(err)
	}
	_, err = db.Exec(`PRAGMA user_version = 3`)
	r.NoError(err)
	r.NoError(resetStateDBCache())

	state, err := LoadState()
	r.NoError(err)
	r.Len(state.Apps, 1)
	r.Equal(PersonaGeneric, state.Apps[0].Persona)
	r.Zero(state.Apps[0].GroupsOverageThreshold)
	db, err = openStateDB()
	r.NoError(err)
	version, err := schemaVersion(db)
	r.NoError(err)
	r.Equal(currentSchemaVersion, version)

	state.Apps[0].Persona = PersonaEntra
	state.Apps[0].GroupsOverageThreshold = 150
	r.NoError(SaveState(state))
	state, err = LoadState()
	r.NoError(err)
	r.Equal(PersonaEntra, state.Apps[0].Persona)
	r.Equal(150, state.Apps[0].GroupsOverageThreshold)
	r.Equal(150, GroupsOverageThresholdForApp(state.Apps[0]))
	r.Equal(DefaultGroupsOverageThreshold, GroupsOverageThresholdForApp(App{}))
}

func TestValidateAppPersona(t *testing.T) {
	tests := map[string]struct {
		app     App
		wantErr string
	}{
		"generic":            {app: App{Persona: PersonaGeneric}},
		"empty":              {app: App{}},
		"entra":              {app: App{Persona: PersonaEntra, GroupsOverageThreshold: 150}},
		"unknown persona":    {app: App{Persona: "auth0"}, wantErr: "persona must be"},
		"negative threshold": {app: App{GroupsOverageThreshold: -1}, wantErr: "groups overage threshold"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			tc.app.Name, tc.app.Slug, tc.app.Protocol = "Greendale Portal", "greendale", "none"
			err := ValidateApp(tc.app, nil)
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}
