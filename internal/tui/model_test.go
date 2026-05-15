package tui

import (
	"path/filepath"
	"testing"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/require"
)

func TestToggleAutoOpenSyncTracePersists(t *testing.T) {
	t.Setenv("SCIMTEST_STATE_FILE", filepath.Join(t.TempDir(), "state.db"))
	r := require.New(t)

	r.NoError(saveState(appState{}))

	m, err := newModel()
	r.NoError(err)
	r.False(m.state.Config.AutoOpenSyncTrace)

	r.NoError(m.toggleAutoOpenSyncTrace())
	r.True(m.state.Config.AutoOpenSyncTrace)
	r.Equal("sync trace popup enabled", m.status)

	loaded, err := loadState()
	r.NoError(err)
	r.True(loaded.Config.AutoOpenSyncTrace)
}

func TestOpenSelectedHistoryDetailOnlyForSyncEntries(t *testing.T) {
	r := require.New(t)

	m := model{}
	m.trace.viewport = viewport.New(0, 0)
	m.history.title = "User History: Troy Barnes"
	m.history.returnTo = modeUsersList
	m.history.entries = []operationLog{{
		Kind:      "local",
		Summary:   "Updated email",
		CreatedAt: "2026-05-01T10:00:00Z",
	}}

	err := m.openSelectedHistoryDetail()
	r.EqualError(err, "details only available for sync operations")

	m.history.entries = []operationLog{{
		Kind:               "sync",
		Summary:            "Synced",
		Method:             "PUT",
		Path:               "/Users/remote-1",
		RequestBody:        `{"userName":"troy"}`,
		Status:             "200 OK",
		ResponseRetryAfter: "60",
		ResponseBody:       `{"id":"remote-1"}`,
		CreatedAt:          "2026-05-01T10:01:00Z",
	}}

	r.NoError(m.openSelectedHistoryDetail())
	r.Equal(modeSyncTrace, m.mode)
	r.Equal(modeOperationHistory, m.trace.returnTo)
	r.Equal("User History: Troy Barnes Detail", m.trace.title)
	r.Contains(m.trace.content, "PUT /Users/remote-1")
	r.Contains(m.trace.content, "Retry-After: 60")
}

func TestImportRequiresConfirmation(t *testing.T) {
	r := require.New(t)

	m := model{mode: modeUsersList}
	updated, cmd := m.updateList(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'i'}})
	next := updated.(model)

	r.Equal(modeImportConfirm, next.mode)
	r.Empty(next.status)
	r.Nil(cmd)

	cancelled, cancelCmd := next.updateImportConfirm(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'n'}})
	back := cancelled.(model)
	r.Equal(modeUsersList, back.mode)
	r.Equal("import cancelled", back.status)
	r.Nil(cancelCmd)
}

func TestClearConfigInputs(t *testing.T) {
	r := require.New(t)

	m := model{}
	m.startConfigForm()
	m.form.inputs[0].SetValue("https://example.com/scim/v2")
	m.form.inputs[1].SetValue("chang-secret")
	m.form.focusIndex = 1
	m.form.inputs[0].Blur()
	m.form.inputs[1].Focus()

	r.NoError(m.clearFocusedConfigInput())
	r.Equal("", m.form.inputs[1].Value())
	r.Equal("bearer token cleared", m.status)
	r.Equal("https://example.com/scim/v2", m.form.inputs[0].Value())

	r.NoError(m.clearAllConfigInputs())
	r.Equal("", m.form.inputs[0].Value())
	r.Equal("", m.form.inputs[1].Value())
	r.Equal("config fields cleared", m.status)
	r.Equal(0, m.form.focusIndex)
}

func TestResetAllSyncStatusPersists(t *testing.T) {
	t.Setenv("SCIMTEST_STATE_FILE", filepath.Join(t.TempDir(), "state.db"))
	r := require.New(t)

	initial := appState{
		Users: []user{{
			ID:        "user-1",
			Username:  "troy",
			Email:     "troy@greendale.edu",
			Active:    true,
			RemoteID:  "remote-user-1",
			LastError: "boom",
		}},
		Groups: []group{{
			ID:          "group-1",
			DisplayName: "Study Group",
			RemoteID:    "remote-group-1",
			LastError:   "kapow",
		}},
	}
	r.NoError(saveState(initial))

	m, err := newModel()
	r.NoError(err)

	r.NoError(m.resetAllSyncStatus())
	r.Equal("", m.state.Users[0].RemoteID)
	r.True(m.state.Users[0].Dirty)
	r.Empty(m.state.Users[0].LastError)
	r.Equal("", m.state.Groups[0].RemoteID)
	r.True(m.state.Groups[0].Dirty)
	r.Empty(m.state.Groups[0].LastError)
	r.Equal("reset sync status for 1 users and 1 groups", m.status)

	loaded, err := loadState()
	r.NoError(err)
	r.Equal("", loaded.Users[0].RemoteID)
	r.True(loaded.Users[0].Dirty)
	r.Empty(loaded.Users[0].LastError)
	r.Equal("", loaded.Groups[0].RemoteID)
	r.True(loaded.Groups[0].Dirty)
	r.Empty(loaded.Groups[0].LastError)
}

func TestResetRequiresConfirmation(t *testing.T) {
	t.Setenv("SCIMTEST_STATE_FILE", filepath.Join(t.TempDir(), "state.db"))
	r := require.New(t)

	initial := appState{
		Users: []user{{
			ID:        "user-1",
			Username:  "troy",
			Email:     "troy@greendale.edu",
			Active:    true,
			RemoteID:  "remote-user-1",
			LastError: "boom",
		}},
	}
	r.NoError(saveState(initial))

	m, err := newModel()
	r.NoError(err)

	updated, cmd := m.updateList(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'R'}})
	next := updated.(model)
	r.Equal(modeResetConfirm, next.mode)
	r.Empty(next.status)
	r.Nil(cmd)

	cancelled, cancelCmd := next.updateResetConfirm(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'n'}})
	back := cancelled.(model)
	r.Equal(modeUsersList, back.mode)
	r.Equal("reset cancelled", back.status)
	r.Nil(cancelCmd)

	loaded, err := loadState()
	r.NoError(err)
	r.Equal("remote-user-1", loaded.Users[0].RemoteID)
	r.False(loaded.Users[0].Dirty)
	r.Equal("boom", loaded.Users[0].LastError)
}

func TestResetConfirmationAppliesReset(t *testing.T) {
	t.Setenv("SCIMTEST_STATE_FILE", filepath.Join(t.TempDir(), "state.db"))
	r := require.New(t)

	initial := appState{
		Groups: []group{{
			ID:          "group-1",
			DisplayName: "Study Group",
			RemoteID:    "remote-group-1",
			LastError:   "kapow",
		}},
	}
	r.NoError(saveState(initial))

	m, err := newModel()
	r.NoError(err)
	m.mode = modeGroupsList

	updated, _ := m.updateList(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'R'}})
	confirmed, confirmCmd := updated.(model).updateResetConfirm(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'y'}})
	next := confirmed.(model)

	r.Equal(modeGroupsList, next.mode)
	r.Equal("", next.state.Groups[0].RemoteID)
	r.True(next.state.Groups[0].Dirty)
	r.Empty(next.state.Groups[0].LastError)
	r.Equal("reset sync status for 0 users and 1 groups", next.status)
	r.Nil(confirmCmd)
}

func TestResetAllSyncStatusRequiresResources(t *testing.T) {
	r := require.New(t)

	m := model{}
	err := m.resetAllSyncStatus()
	r.EqualError(err, "no users or groups to reset")
}
