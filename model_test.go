package main

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
		Kind:         "sync",
		Summary:      "Synced",
		Method:       "PUT",
		Path:         "/Users/remote-1",
		RequestBody:  `{"userName":"troy"}`,
		Status:       "200 OK",
		ResponseBody: `{"id":"remote-1"}`,
		CreatedAt:    "2026-05-01T10:01:00Z",
	}}

	r.NoError(m.openSelectedHistoryDetail())
	r.Equal(modeSyncTrace, m.mode)
	r.Equal(modeOperationHistory, m.trace.returnTo)
	r.Equal("User History: Troy Barnes Detail", m.trace.title)
	r.Contains(m.trace.content, "PUT /Users/remote-1")
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
