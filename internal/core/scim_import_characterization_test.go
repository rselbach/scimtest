package core

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestImportedUserMatchPrecedenceAndAttributes(t *testing.T) {
	users := []User{
		{ID: "remote-match", RemoteID: "remote-troy", Attributes: map[string]string{"campus": "Greendale"}},
		{ID: "external-match", RemoteID: "other", Attributes: map[string]string{"campus": "City College"}},
	}
	for name, tc := range map[string]struct {
		externalID string
		wantID     string
		wantCampus string
	}{
		"external ID takes precedence":                      {" external-match ", "external-match", "City College"},
		"unmatched external ID preserves remote attributes": {"new-local", "new-local", "Greendale"},
		"remote match recovers local ID":                    {"", "remote-match", "Greendale"},
	} {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			got, err := importedUserFromSCIM(users, SCIMUserResource{ID: " remote-troy ", ExternalID: tc.externalID, UserName: "troy"})
			r.NoError(err)
			r.Equal(tc.wantID, got.ID)
			r.Equal(tc.wantCampus, got.Attributes["campus"])
			r.Equal("remote-troy", got.RemoteID)
		})
	}
}
