package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestApplicationInstanceMutationsRollBackAfterSaveFailure(t *testing.T) {
	actor := enrollmentActor{GitHubUserID: 101, GitHubLogin: "troy-barnes"}
	tests := map[string]func(*Store, string) error{
		"enroll": func(store *Store, profileID string) error {
			return store.EnrollApplicationInstance(profileID, "installation-2", "replacement-key", actor)
		},
		"prune": func(store *Store, profileID string) error {
			_, err := store.PruneIdleApplicationInstances(profileID, time.Now().Add(time.Hour), nil)
			return err
		},
		"revoke for user": func(store *Store, profileID string) error {
			_, err := store.RevokeApplicationInstanceForGitHubUser(profileID, "installation-1", actor.GitHubUserID)
			return err
		},
		"set revoked": func(store *Store, profileID string) error {
			_, err := store.SetApplicationInstanceRevoked(profileID, "installation-1", true)
			return err
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			store, profile := newTestApplicationProfile(t)
			r.NoError(store.EnrollApplicationInstance(profile.ID, "installation-1", profile.PublicKey, actor))
			want, ok := store.ApplicationProfile(profile.ID)
			r.True(ok)
			store.path = t.TempDir()

			r.Error(tc(store, profile.ID))
			got, ok := store.ApplicationProfile(profile.ID)
			r.True(ok)
			r.Equal(want, got)
		})
	}
}
