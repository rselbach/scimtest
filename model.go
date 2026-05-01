package main

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type mode int

const (
	modeUsersList mode = iota
	modeGroupsList
	modeUserForm
	modeGroupForm
	modeGroupMembers
	modeSyncTrace
	modeOperationHistory
	modeConfigForm
	modeImportConfirm
)

type syncFinishedMsg syncResult
type importFinishedMsg importResult

type formState struct {
	kind       mode
	inputs     []textinput.Model
	focusIndex int
	editingID  string
	title      string
	help       string
}

type memberPickerState struct {
	groupID           string
	groupName         string
	memberTable       table.Model
	selectedMemberIDs map[string]struct{}
}

type traceViewState struct {
	viewport viewport.Model
	title    string
	content  string
	returnTo mode
}

type historyViewState struct {
	table    table.Model
	title    string
	returnTo mode
	entries  []operationLog
}

type importConfirmState struct {
	returnTo mode
}

type model struct {
	state       appState
	usersTable  table.Model
	groupsTable table.Model
	mode        mode
	form        formState
	members     memberPickerState
	trace       traceViewState
	history     historyViewState
	importing   importConfirmState
	status      string
	syncing     bool
	width       int
	height      int
}

var (
	titleStyle      = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("12"))
	errorStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
	helpStyle       = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	fieldLabelStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("153"))
	infoBarStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	infoLabelStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("159"))
	urlValueStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("229"))
	viewValueStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("121"))
	toggleOnStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("118"))
	toggleOffStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("216"))
	helpKeyStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("117"))
	helpDescStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("252"))
	helpSepStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	boxStyle        = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(1, 2)
)

func newModel() (model, error) {
	state, err := loadState()
	if err != nil {
		return model{}, err
	}

	usersTable := table.New(
		table.WithColumns([]table.Column{
			{Title: "Name", Width: 22},
			{Title: "Username", Width: 20},
			{Title: "Email", Width: 28},
			{Title: "Active", Width: 10},
			{Title: "Status", Width: 16},
			{Title: "Remote ID", Width: 16},
		}),
		table.WithRows(nil),
		table.WithFocused(true),
		table.WithHeight(12),
	)

	groupsTable := table.New(
		table.WithColumns([]table.Column{
			{Title: "Group", Width: 24},
			{Title: "Members", Width: 34},
			{Title: "Status", Width: 16},
			{Title: "Remote ID", Width: 18},
		}),
		table.WithRows(nil),
		table.WithFocused(true),
		table.WithHeight(12),
	)

	styles := table.DefaultStyles()
	styles.Header = styles.Header.Bold(true).BorderStyle(lipgloss.NormalBorder()).BorderBottom(true)
	styles.Selected = styles.Selected.Foreground(lipgloss.Color("230")).Background(lipgloss.Color("62")).Bold(true)
	usersTable.SetStyles(styles)
	groupsTable.SetStyles(styles)

	memberTable := table.New(
		table.WithColumns([]table.Column{
			{Title: "Pick", Width: 6},
			{Title: "Username", Width: 20},
			{Title: "Name", Width: 24},
			{Title: "Email", Width: 28},
			{Title: "State", Width: 10},
		}),
		table.WithRows(nil),
		table.WithFocused(true),
		table.WithHeight(12),
	)
	memberTable.SetStyles(styles)

	m := model{
		state:       state,
		usersTable:  usersTable,
		groupsTable: groupsTable,
		members: memberPickerState{
			memberTable:       memberTable,
			selectedMemberIDs: map[string]struct{}{},
		},
		mode:   modeUsersList,
		status: userListHelp(),
	}
	m.trace.viewport = viewport.New(0, 0)
	m.trace.title = "Sync Trace"
	m.history.table = table.New(
		table.WithColumns([]table.Column{
			{Title: "When", Width: 22},
			{Title: "Event", Width: 36},
		}),
		table.WithRows(nil),
		table.WithFocused(true),
		table.WithHeight(12),
	)
	m.history.table.SetStyles(styles)
	m.refreshTables()

	return m, nil
}

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.resizeTables()
		return m, nil
	case syncFinishedMsg:
		m.syncing = false

		if msg.fatal != nil {
			m.status = msg.fatal.Error()
			return m, nil
		}

		m.state = msg.state
		appendOperationLogs(&m.state, msg.traces)
		if err := saveState(m.state); err != nil {
			m.status = err.Error()
			return m, nil
		}

		m.status = msg.status
		m.refreshTables()
		m.rememberTraceView(msg.traces)
		if m.state.Config.AutoOpenSyncTrace {
			m.openTraceView()
		}
		return m, nil
	case importFinishedMsg:
		m.syncing = false

		if msg.fatal != nil {
			m.rememberTraceView(msg.traces)
			m.status = msg.fatal.Error()
			return m, nil
		}

		m.state = msg.state
		if err := saveState(m.state); err != nil {
			m.status = err.Error()
			return m, nil
		}

		m.status = msg.status
		m.refreshTables()
		m.rememberTraceView(msg.traces)
		if m.state.Config.AutoOpenSyncTrace {
			m.openTraceView()
		}
		return m, nil
	}

	switch m.mode {
	case modeUsersList, modeGroupsList:
		return m.updateList(msg)
	case modeUserForm, modeGroupForm, modeConfigForm:
		return m.updateForm(msg)
	case modeGroupMembers:
		return m.updateMemberPicker(msg)
	case modeImportConfirm:
		return m.updateImportConfirm(msg)
	case modeSyncTrace:
		return m.updateTraceView(msg)
	case modeOperationHistory:
		return m.updateHistoryView(msg)
	default:
		return m, nil
	}
}

func (m model) View() string {
	if m.mode == modeUsersList || m.mode == modeGroupsList {
		return m.viewList()
	}
	if m.mode == modeGroupMembers {
		return m.viewMemberPicker()
	}
	if m.mode == modeImportConfirm {
		return m.viewImportConfirm()
	}
	if m.mode == modeSyncTrace {
		return m.viewTraceView()
	}
	if m.mode == modeOperationHistory {
		return m.viewHistoryView()
	}

	return m.viewForm()
}

func (m model) updateList(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		case "tab":
			if m.mode == modeUsersList {
				m.mode = modeGroupsList
				m.status = groupListHelp()
			} else {
				m.mode = modeUsersList
				m.status = userListHelp()
			}
			return m, nil
		case "c":
			m.startConfigForm()
			return m, nil
		case "p":
			if err := m.toggleAutoOpenSyncTrace(); err != nil {
				m.status = err.Error()
				return m, nil
			}
			return m, nil
		case "l":
			if strings.TrimSpace(m.trace.content) == "" {
				m.status = "no sync trace yet"
				return m, nil
			}
			m.trace.returnTo = m.mode
			m.openTraceView()
			return m, nil
		case "o":
			if err := m.openSelectedHistory(); err != nil {
				m.status = err.Error()
				return m, nil
			}
			return m, nil
		case "s":
			if m.syncing {
				return m, nil
			}
			m.syncing = true
			m.status = "syncing to SCIM..."
			state := m.state
			return m, func() tea.Msg {
				return syncFinishedMsg(syncDirtyState(state))
			}
		case "i":
			m.startImportConfirm()
			return m, nil
		}

		if m.mode == modeUsersList {
			return m.updateUsersList(msg)
		}

		return m.updateGroupsList(msg)
	}

	if m.mode == modeUsersList {
		var cmd tea.Cmd
		m.usersTable, cmd = m.usersTable.Update(msg)
		return m, cmd
	}

	var cmd tea.Cmd
	m.groupsTable, cmd = m.groupsTable.Update(msg)
	return m, cmd
}

func (m model) updateImportConfirm(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc", "n":
			m.closeImportConfirm("import cancelled")
			return m, nil
		case "y", "enter":
			if m.syncing {
				return m, nil
			}
			m.syncing = true
			m.mode = m.importing.returnTo
			m.status = "importing users and groups from SCIM..."
			state := m.state
			return m, func() tea.Msg {
				return importFinishedMsg(importStateFromSCIM(state))
			}
		}
	}

	return m, nil
}

func (m model) updateHistoryView(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc", "q":
			m.closeHistoryView()
			return m, nil
		case "tab":
			if m.history.returnTo == modeGroupsList {
				m.history.returnTo = modeUsersList
			} else {
				m.history.returnTo = modeGroupsList
			}
			m.mode = m.history.returnTo
			m.status = helpForMode(m.mode)
			return m, nil
		case "enter":
			if err := m.openSelectedHistoryDetail(); err != nil {
				m.status = err.Error()
				return m, nil
			}
			return m, nil
		}
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.resizeTables()
		m.resizeTraceViewport()
		m.resizeHistoryViewport()
		return m, nil
	}

	var cmd tea.Cmd
	m.history.table, cmd = m.history.table.Update(msg)
	return m, cmd
}

func (m model) updateTraceView(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc", "q":
			m.closeTraceView()
			return m, nil
		case "tab":
			if m.trace.returnTo == modeOperationHistory {
				return m, nil
			}
			if m.trace.returnTo == modeGroupsList {
				m.trace.returnTo = modeUsersList
			} else {
				m.trace.returnTo = modeGroupsList
			}
			m.mode = m.trace.returnTo
			m.status = helpForMode(m.mode)
			return m, nil
		}
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.resizeTables()
		m.resizeTraceViewport()
		return m, nil
	}

	var cmd tea.Cmd
	m.trace.viewport, cmd = m.trace.viewport.Update(msg)
	return m, cmd
}

func (m model) updateUsersList(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "a":
		m.startUserForm(nil)
		return m, nil
	case "e", "enter":
		selected, ok := m.selectedUser()
		if !ok {
			m.status = "pick a user first"
			return m, nil
		}
		if selected.Deleted {
			m.status = "restore the user before editing it"
			return m, nil
		}
		m.startUserForm(&selected)
		return m, nil
	case "d":
		if err := m.markSelectedUserDeleted(true); err != nil {
			m.status = err.Error()
			return m, nil
		}
		m.status = "user marked for deletion"
		return m, nil
	case "r":
		if err := m.markSelectedUserDeleted(false); err != nil {
			m.status = err.Error()
			return m, nil
		}
		m.status = "user restored"
		return m, nil
	case "t":
		if err := m.toggleSelectedActive(); err != nil {
			m.status = err.Error()
			return m, nil
		}
		return m, nil
	case "o":
		if err := m.openSelectedHistory(); err != nil {
			m.status = err.Error()
			return m, nil
		}
		return m, nil
	default:
		m.usersTable, _ = m.usersTable.Update(msg)
		return m, nil
	}
}

func (m model) updateGroupsList(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "a":
		m.startGroupForm(nil, false)
		return m, nil
	case "e", "enter":
		selected, ok := m.selectedGroup()
		if !ok {
			m.status = "pick a group first"
			return m, nil
		}
		if selected.Deleted {
			m.status = "restore the group before editing it"
			return m, nil
		}
		m.startGroupForm(&selected, false)
		return m, nil
	case "m":
		selected, ok := m.selectedGroup()
		if !ok {
			m.status = "pick a group first"
			return m, nil
		}
		if selected.Deleted {
			m.status = "restore the group before editing members"
			return m, nil
		}
		m.startGroupMembers(&selected)
		return m, nil
	case "d":
		if err := m.markSelectedGroupDeleted(true); err != nil {
			m.status = err.Error()
			return m, nil
		}
		m.status = "group marked for deletion"
		return m, nil
	case "r":
		if err := m.markSelectedGroupDeleted(false); err != nil {
			m.status = err.Error()
			return m, nil
		}
		m.status = "group restored"
		return m, nil
	case "o":
		if err := m.openSelectedHistory(); err != nil {
			m.status = err.Error()
			return m, nil
		}
		return m, nil
	default:
		m.groupsTable, _ = m.groupsTable.Update(msg)
		return m, nil
	}
}

func (m model) updateMemberPicker(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc":
			m.mode = modeGroupsList
			m.status = "cancelled"
			return m, nil
		case " ":
			if err := m.togglePickedMember(); err != nil {
				m.status = err.Error()
				return m, nil
			}
			return m, nil
		case "enter", "s":
			if err := m.savePickedMembers(); err != nil {
				m.status = err.Error()
				return m, nil
			}
			return m, nil
		}
	}

	var cmd tea.Cmd
	m.members.memberTable, cmd = m.members.memberTable.Update(msg)
	return m, cmd
}

func (m model) updateForm(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc":
			m.returnToList("cancelled")
			return m, nil
		case "tab", "shift+tab", "up", "down":
			m.moveFormFocus(msg.String())
			return m, nil
		case "enter":
			if err := m.submitForm(); err != nil {
				m.status = err.Error()
				return m, nil
			}
			return m, nil
		}
	}

	cmds := make([]tea.Cmd, 0, len(m.form.inputs))
	for i := range m.form.inputs {
		var cmd tea.Cmd
		m.form.inputs[i], cmd = m.form.inputs[i].Update(msg)
		cmds = append(cmds, cmd)
	}

	return m, tea.Batch(cmds...)
}

func (m *model) refreshTables() {
	userRows := make([]table.Row, 0, len(m.state.Users))
	for _, u := range m.state.Users {
		remoteID := u.RemoteID
		if remoteID == "" {
			remoteID = "-"
		}

		userRows = append(userRows, table.Row{fullName(u), u.Username, u.Email, activeStatus(u), syncStatus(u), remoteID})
	}
	m.usersTable.SetRows(userRows)

	groupRows := make([]table.Row, 0, len(m.state.Groups))
	for _, g := range m.state.Groups {
		remoteID := g.RemoteID
		if remoteID == "" {
			remoteID = "-"
		}

		groupRows = append(groupRows, table.Row{g.DisplayName, m.groupMembersSummary(g), groupSyncStatus(g), remoteID})
	}
	m.groupsTable.SetRows(groupRows)
	m.refreshMemberPickerRows()
	m.resizeTables()
}

func (m *model) resizeTables() {
	if m.width > 0 {
		m.usersTable.SetWidth(max(70, m.width-4))
		m.groupsTable.SetWidth(max(70, m.width-4))
		m.members.memberTable.SetWidth(max(70, m.width-4))
	}
	if m.height > 0 {
		height := max(8, m.height-8)
		m.usersTable.SetHeight(height)
		m.groupsTable.SetHeight(height)
		m.members.memberTable.SetHeight(height)
	}
	m.resizeTraceViewport()
	m.resizeHistoryViewport()
}

func (m *model) startUserForm(existing *user) {
	givenName := ""
	familyName := ""
	username := ""
	email := ""
	editingID := ""
	title := "Add User"
	if existing != nil {
		givenName = existing.GivenName
		familyName = existing.FamilyName
		username = existing.Username
		email = existing.Email
		editingID = existing.ID
		title = "Edit User"
	}

	inputs := []textinput.Model{
		newInput("Username", username, false),
		newInput("Given Name", givenName, false),
		newInput("Family Name", familyName, false),
		newInput("Email", email, false),
	}
	inputs[0].Focus()

	m.form = formState{
		kind:       modeUserForm,
		inputs:     inputs,
		focusIndex: 0,
		editingID:  editingID,
		title:      title,
		help:       "tab moves • enter saves • esc cancels",
	}
	m.mode = modeUserForm
	m.status = ""
}

func (m *model) startGroupForm(existing *group, focusMembers bool) {
	if focusMembers && existing != nil {
		m.startGroupMembers(existing)
		return
	}

	name := ""
	editingID := ""
	title := "Add Group"
	if existing != nil {
		name = existing.DisplayName
		editingID = existing.ID
		title = "Edit Group"
	}

	inputs := []textinput.Model{
		newInput("Group Name", name, false),
	}
	inputs[0].Focus()

	m.form = formState{
		kind:       modeGroupForm,
		inputs:     inputs,
		focusIndex: 0,
		editingID:  editingID,
		title:      title,
		help:       "enter saves • esc cancels • m members from groups list",
	}
	m.mode = modeGroupForm
	m.status = ""
}

func (m *model) startGroupMembers(existing *group) {
	selected := make(map[string]struct{}, len(existing.MemberIDs))
	for _, memberID := range existing.MemberIDs {
		selected[memberID] = struct{}{}
	}

	m.members.groupID = existing.ID
	m.members.groupName = existing.DisplayName
	m.members.selectedMemberIDs = selected
	m.refreshMemberPickerRows()
	m.mode = modeGroupMembers
	m.status = "space toggles • enter saves • esc cancels"
}

func (m *model) startConfigForm() {
	inputs := []textinput.Model{
		newInput("SCIM Base URL", m.state.Config.BaseURL, false),
		newInput("Bearer Token", m.state.Config.BearerToken, true),
	}
	inputs[0].Focus()

	m.form = formState{
		kind:       modeConfigForm,
		inputs:     inputs,
		focusIndex: 0,
		title:      "SCIM Config",
		help:       "tab moves • enter saves • esc cancels",
	}
	m.mode = modeConfigForm
	m.status = ""
}

func (m *model) startImportConfirm() {
	m.importing.returnTo = m.mode
	m.mode = modeImportConfirm
	m.status = ""
}

func (m *model) rememberTraceView(traces []syncTraceEntry) {
	m.trace.title = "Sync Trace"
	m.trace.content = formatSyncTraces(traces)
	m.resizeTraceViewport()
	m.trace.viewport.SetContent(m.trace.content)
	m.trace.viewport.GotoTop()
}

func (m *model) openTraceView() {
	m.trace.returnTo = m.mode
	m.resizeTraceViewport()
	m.trace.viewport.SetContent(m.trace.content)
	m.trace.viewport.GotoTop()
	m.mode = modeSyncTrace
	m.status = ""
}

func (m *model) closeTraceView() {
	switch m.trace.returnTo {
	case modeGroupsList, modeUsersList, modeOperationHistory:
	default:
		m.trace.returnTo = modeUsersList
	}
	m.mode = m.trace.returnTo
	if m.mode == modeOperationHistory {
		m.status = ""
		return
	}
	m.status = helpForMode(m.mode)
}

func (m *model) closeHistoryView() {
	if m.history.returnTo != modeGroupsList {
		m.history.returnTo = modeUsersList
	}
	m.mode = m.history.returnTo
	m.status = helpForMode(m.mode)
}

func (m *model) closeImportConfirm(status string) {
	if m.importing.returnTo != modeGroupsList {
		m.importing.returnTo = modeUsersList
	}
	m.mode = m.importing.returnTo
	m.status = status
}

func (m *model) moveFormFocus(direction string) {
	m.form.inputs[m.form.focusIndex].Blur()

	switch direction {
	case "up", "shift+tab":
		m.form.focusIndex--
	default:
		m.form.focusIndex++
	}

	if m.form.focusIndex < 0 {
		m.form.focusIndex = len(m.form.inputs) - 1
	}
	if m.form.focusIndex >= len(m.form.inputs) {
		m.form.focusIndex = 0
	}

	m.form.inputs[m.form.focusIndex].Focus()
}

func (m *model) submitForm() error {
	switch m.form.kind {
	case modeUserForm:
		return m.submitUserForm()
	case modeGroupForm:
		return m.submitGroupForm()
	case modeConfigForm:
		return m.submitConfigForm()
	default:
		return fmt.Errorf("unknown form")
	}
}

func (m *model) submitUserForm() error {
	username := strings.TrimSpace(m.form.inputs[0].Value())
	givenName := strings.TrimSpace(m.form.inputs[1].Value())
	familyName := strings.TrimSpace(m.form.inputs[2].Value())
	email := strings.TrimSpace(m.form.inputs[3].Value())
	if username == "" {
		username = email
	}

	if err := validateUser(givenName, familyName, email, username); err != nil {
		return err
	}

	if m.form.editingID == "" {
		id, err := newUserID()
		if err != nil {
			return err
		}

		m.state.Users = append(m.state.Users, user{
			ID:         id,
			GivenName:  givenName,
			FamilyName: familyName,
			Username:   username,
			Email:      email,
			Active:     true,
			Dirty:      true,
		})
		appendLocalOperationLog(&m.state, "user", id, "Created")
		m.status = "user added"
	} else {
		index, ok := m.userIndexByID(m.form.editingID)
		if !ok {
			return fmt.Errorf("user %s not found", m.form.editingID)
		}

		summary := summarizeUserUpdate(m.state.Users[index], givenName, familyName, email, username)
		m.state.Users[index].GivenName = givenName
		m.state.Users[index].FamilyName = familyName
		m.state.Users[index].Username = username
		m.state.Users[index].Email = email
		m.state.Users[index].Deleted = false
		m.state.Users[index].Dirty = true
		m.state.Users[index].LastError = ""
		appendLocalOperationLog(&m.state, "user", m.state.Users[index].ID, summary)
		m.status = "user updated"
	}

	if err := saveState(m.state); err != nil {
		return err
	}

	m.returnToList(m.status)
	return nil
}

func (m *model) submitGroupForm() error {
	displayName := strings.TrimSpace(m.form.inputs[0].Value())
	if err := validateGroup(displayName); err != nil {
		return err
	}

	if m.form.editingID == "" {
		id, err := newGroupID()
		if err != nil {
			return err
		}

		m.state.Groups = append(m.state.Groups, group{
			ID:          id,
			DisplayName: displayName,
			Dirty:       true,
		})
		appendLocalOperationLog(&m.state, "group", id, "Created")
		m.status = "group added"
	} else {
		index, ok := m.groupIndexByID(m.form.editingID)
		if !ok {
			return fmt.Errorf("group %s not found", m.form.editingID)
		}

		summary := summarizeGroupUpdate(m.state.Groups[index], displayName)
		m.state.Groups[index].DisplayName = displayName
		m.state.Groups[index].Deleted = false
		m.state.Groups[index].Dirty = true
		m.state.Groups[index].LastError = ""
		appendLocalOperationLog(&m.state, "group", m.state.Groups[index].ID, summary)
		m.status = "group updated"
	}

	if err := saveState(m.state); err != nil {
		return err
	}

	m.returnToList(m.status)
	return nil
}

func (m *model) submitConfigForm() error {
	m.state.Config = config{
		BaseURL:           strings.TrimSpace(m.form.inputs[0].Value()),
		BearerToken:       strings.TrimSpace(m.form.inputs[1].Value()),
		AutoOpenSyncTrace: m.state.Config.AutoOpenSyncTrace,
	}

	if err := saveState(m.state); err != nil {
		return err
	}

	m.returnToList("config saved")
	return nil
}

func (m *model) markSelectedUserDeleted(deleted bool) error {
	selected, ok := m.selectedUser()
	if !ok {
		return fmt.Errorf("pick a user first")
	}

	index, ok := m.userIndexByID(selected.ID)
	if !ok {
		return fmt.Errorf("user %s not found", selected.ID)
	}

	m.state.Users[index].Deleted = deleted
	m.state.Users[index].Dirty = true
	m.state.Users[index].LastError = ""
	appendLocalOperationLog(&m.state, "user", m.state.Users[index].ID, localDeleteSummary(deleted))

	if err := saveState(m.state); err != nil {
		return err
	}

	m.refreshTables()
	return nil
}

func (m *model) togglePickedMember() error {
	row := m.members.memberTable.Cursor()
	if row < 0 || row >= len(m.state.Users) {
		return fmt.Errorf("pick a user first")
	}

	user := m.state.Users[row]
	if _, ok := m.members.selectedMemberIDs[user.ID]; ok {
		delete(m.members.selectedMemberIDs, user.ID)
	} else {
		m.members.selectedMemberIDs[user.ID] = struct{}{}
	}

	m.refreshMemberPickerRows()
	return nil
}

func (m *model) savePickedMembers() error {
	index, ok := m.groupIndexByID(m.members.groupID)
	if !ok {
		return fmt.Errorf("group %s not found", m.members.groupID)
	}

	memberIDs := make([]string, 0, len(m.state.Users))
	for _, u := range m.state.Users {
		if _, ok := m.members.selectedMemberIDs[u.ID]; !ok {
			continue
		}

		memberIDs = append(memberIDs, u.ID)
	}

	m.state.Groups[index].MemberIDs = memberIDs
	m.state.Groups[index].Dirty = true
	m.state.Groups[index].LastError = ""
	appendLocalOperationLog(&m.state, "group", m.state.Groups[index].ID, "Updated members")

	if err := saveState(m.state); err != nil {
		return err
	}

	m.mode = modeGroupsList
	m.status = "group members updated"
	m.refreshTables()
	return nil
}

func (m *model) markSelectedGroupDeleted(deleted bool) error {
	selected, ok := m.selectedGroup()
	if !ok {
		return fmt.Errorf("pick a group first")
	}

	index, ok := m.groupIndexByID(selected.ID)
	if !ok {
		return fmt.Errorf("group %s not found", selected.ID)
	}

	m.state.Groups[index].Deleted = deleted
	m.state.Groups[index].Dirty = true
	m.state.Groups[index].LastError = ""
	appendLocalOperationLog(&m.state, "group", m.state.Groups[index].ID, localDeleteSummary(deleted))

	if err := saveState(m.state); err != nil {
		return err
	}

	m.refreshTables()
	return nil
}

func (m *model) toggleSelectedActive() error {
	selected, ok := m.selectedUser()
	if !ok {
		return fmt.Errorf("pick a user first")
	}
	if selected.Deleted {
		return fmt.Errorf("restore the user before changing active state")
	}

	index, ok := m.userIndexByID(selected.ID)
	if !ok {
		return fmt.Errorf("user %s not found", selected.ID)
	}

	m.state.Users[index].Active = !m.state.Users[index].Active
	m.state.Users[index].Dirty = true
	m.state.Users[index].LastError = ""
	appendLocalOperationLog(&m.state, "user", m.state.Users[index].ID, summarizeActiveToggle(m.state.Users[index].Active))

	if err := saveState(m.state); err != nil {
		return err
	}

	if m.state.Users[index].Active {
		m.status = "user activated"
	} else {
		m.status = "user deactivated"
	}

	m.refreshTables()
	return nil
}

func (m *model) returnToList(status string) {
	if m.mode == modeGroupForm && m.form.kind == modeGroupForm {
		m.mode = modeGroupsList
	} else {
		m.mode = modeUsersList
	}
	if m.form.kind == modeConfigForm {
		m.mode = modeUsersList
	}
	if m.form.kind == modeGroupForm {
		m.mode = modeGroupsList
	}
	if m.form.kind == modeUserForm {
		m.mode = modeUsersList
	}
	m.status = status
	m.refreshTables()
}

func (m *model) refreshMemberPickerRows() {
	rows := make([]table.Row, 0, len(m.state.Users))
	for _, u := range m.state.Users {
		picked := "[ ]"
		if _, ok := m.members.selectedMemberIDs[u.ID]; ok {
			picked = "[x]"
		}

		rows = append(rows, table.Row{picked, u.Username, fullName(u), u.Email, activeStatus(u)})
	}

	m.members.memberTable.SetRows(rows)
}

func (m model) selectedUser() (user, bool) {
	row := m.usersTable.Cursor()
	if row < 0 || row >= len(m.state.Users) {
		return user{}, false
	}

	return m.state.Users[row], true
}

func (m model) selectedGroup() (group, bool) {
	row := m.groupsTable.Cursor()
	if row < 0 || row >= len(m.state.Groups) {
		return group{}, false
	}

	return m.state.Groups[row], true
}

func (m model) userIndexByID(id string) (int, bool) {
	for i, u := range m.state.Users {
		if u.ID == id {
			return i, true
		}
	}

	return 0, false
}

func (m model) groupIndexByID(id string) (int, bool) {
	for i, g := range m.state.Groups {
		if g.ID == id {
			return i, true
		}
	}

	return 0, false
}

func (m model) viewList() string {
	resource := "Users"
	help := userListHelp()
	currentTable := m.usersTable.View()
	if m.mode == modeGroupsList {
		resource = "Groups"
		help = groupListHelp()
		currentTable = m.groupsTable.View()
	}

	header := titleStyle.Render("scimtest")
	configLine := lipgloss.JoinHorizontal(
		lipgloss.Left,
		infoLabelStyle.Render("SCIM:"),
		" ",
		urlValueStyle.Render(configuredBaseURL(m.state.Config.BaseURL)),
		infoBarStyle.Render(" • "),
		infoLabelStyle.Render("View:"),
		" ",
		viewValueStyle.Render(resource),
		infoBarStyle.Render(" • "),
		infoLabelStyle.Render("Trace Popup:"),
		" ",
		tracePopupStyle(m.state.Config.AutoOpenSyncTrace).Render(enabledLabel(m.state.Config.AutoOpenSyncTrace)),
	)
	statusLine := m.status
	if statusLine == help {
		statusLine = ""
	}
	if m.syncing {
		statusLine = "syncing to SCIM..."
	}

	var errors []string
	for _, u := range m.state.Users {
		if u.LastError != "" {
			errors = append(errors, fmt.Sprintf("user %s: %s", userLabel(u), u.LastError))
		}
	}
	for _, g := range m.state.Groups {
		if g.LastError != "" {
			errors = append(errors, fmt.Sprintf("group %s: %s", g.DisplayName, g.LastError))
		}
	}

	sections := []string{header, configLine, currentTable, renderHelpLine(help + " • p trace popup • o history • l last sync log")}
	if len(errors) > 0 {
		sections = append(sections, errorStyle.Render(strings.Join(errors, "\n")))
	}
	if statusLine != "" {
		sections = append(sections, statusLine)
	}

	return lipgloss.JoinVertical(lipgloss.Left, sections...)
}

func (m model) viewForm() string {
	fields := make([]string, 0, len(m.form.inputs))
	for _, input := range m.form.inputs {
		fields = append(fields, lipgloss.JoinVertical(
			lipgloss.Left,
			fieldLabelStyle.Render(input.Placeholder),
			input.View(),
		))
	}

	content := lipgloss.JoinVertical(
		lipgloss.Left,
		titleStyle.Render(m.form.title),
		strings.Join(fields, "\n\n"),
		helpStyle.Render(m.form.help),
	)

	if m.status != "" {
		content = lipgloss.JoinVertical(lipgloss.Left, content, errorStyle.Render(m.status))
	}

	return boxStyle.Render(content)
}

func (m model) viewMemberPicker() string {
	title := titleStyle.Render("Edit Group Members")
	subtitle := helpStyle.Render(fmt.Sprintf("Group: %s", m.members.groupName))
	content := lipgloss.JoinVertical(
		lipgloss.Left,
		title,
		subtitle,
		m.members.memberTable.View(),
		helpStyle.Render("space toggle • enter save • esc cancel"),
	)

	if m.status != "" {
		content = lipgloss.JoinVertical(lipgloss.Left, content, m.status)
	}

	return boxStyle.Render(content)
}

func (m model) viewImportConfirm() string {
	content := lipgloss.JoinVertical(
		lipgloss.Left,
		titleStyle.Render("Import From SCIM"),
		errorStyle.Render("This will delete all local users, groups, and operation history."),
		"The SCIM server will become the new source of truth for the local database.",
		helpStyle.Render("enter/y import everything • esc/n cancel"),
	)

	return boxStyle.Render(content)
}

func (m model) viewTraceView() string {
	titleText := m.trace.title
	if strings.TrimSpace(titleText) == "" {
		titleText = "Sync Trace"
	}
	help := "up/down/pgup/pgdn scroll • esc close • tab switch list"
	if m.trace.returnTo == modeOperationHistory {
		help = "up/down/pgup/pgdn scroll • esc back"
	}
	title := titleStyle.Render(titleText)
	content := lipgloss.JoinVertical(
		lipgloss.Left,
		title,
		m.trace.viewport.View(),
		helpStyle.Render(help),
	)

	return boxStyle.Render(content)
}

func (m model) viewHistoryView() string {
	title := titleStyle.Render(m.history.title)
	content := lipgloss.JoinVertical(
		lipgloss.Left,
		title,
		m.history.table.View(),
		helpStyle.Render("up/down scroll • enter detail • esc close • tab switch list"),
	)

	return boxStyle.Render(content)
}

func (m model) groupMembersSummary(g group) string {
	labels := make([]string, 0, len(g.MemberIDs))
	for _, memberID := range g.MemberIDs {
		user, ok := m.userByID(memberID)
		if !ok {
			continue
		}

		labels = append(labels, user.Username)
	}

	if len(labels) == 0 {
		return "-"
	}

	return strings.Join(labels, ", ")
}

func (m model) userByID(id string) (user, bool) {
	for _, u := range m.state.Users {
		if u.ID == id {
			return u, true
		}
	}

	return user{}, false
}

func newInput(placeholder string, value string, password bool) textinput.Model {
	input := textinput.New()
	input.Placeholder = placeholder
	input.SetValue(value)
	input.Width = 48
	input.CharLimit = 512
	if password {
		input.EchoMode = textinput.EchoPassword
		input.EchoCharacter = '•'
	}

	return input
}

func configuredBaseURL(baseURL string) string {
	baseURL = strings.TrimSpace(baseURL)
	if baseURL == "" {
		return "not configured"
	}

	return baseURL
}

func userLabel(u user) string {
	if name := fullName(u); name != "" {
		return name
	}

	return u.Username
}

func userListHelp() string {
	return "tab switch • a add • e edit • t toggle active • d delete • r restore • i import • c config • p trace popup • s sync • q quit"
}

func groupListHelp() string {
	return "tab switch • a add • e edit • m members • d delete • r restore • i import • c config • p trace popup • s sync • q quit"
}

func helpForMode(mode mode) string {
	if mode == modeGroupsList {
		return groupListHelp()
	}

	return userListHelp()
}

func (m *model) resizeTraceViewport() {
	if m.width <= 0 || m.height <= 0 {
		return
	}

	width := max(40, m.width-10)
	height := max(8, m.height-8)
	m.trace.viewport.Width = width
	m.trace.viewport.Height = height
	if m.trace.content != "" {
		m.trace.viewport.SetContent(m.trace.content)
	}
}

func (m *model) resizeHistoryViewport() {
	if m.width <= 0 || m.height <= 0 {
		return
	}

	width := max(40, m.width-10)
	height := max(8, m.height-8)
	m.history.table.SetWidth(width)
	m.history.table.SetHeight(height)
}

func (m *model) openSelectedHistory() error {
	if m.mode == modeUsersList {
		selected, ok := m.selectedUser()
		if !ok {
			return fmt.Errorf("pick a user first")
		}
		entries := m.state.UserOperations[selected.ID]
		m.showHistoryEntries("User History: "+userLabel(selected), entries)
		return nil
	}

	selected, ok := m.selectedGroup()
	if !ok {
		return fmt.Errorf("pick a group first")
	}
	entries := m.state.GroupOperations[selected.ID]
	m.showHistoryEntries("Group History: "+selected.DisplayName, entries)
	return nil
}

func (m *model) showHistoryEntries(title string, entries []operationLog) {
	m.history.title = title
	m.history.returnTo = m.mode
	m.history.entries = entries
	rows := make([]table.Row, 0, len(entries))
	for _, entry := range entries {
		rows = append(rows, table.Row{formatHistoryTimestamp(entry.CreatedAt), entry.Summary})
	}
	if len(rows) == 0 {
		rows = append(rows, table.Row{"-", "No operations recorded yet"})
	}
	m.history.table.SetRows(rows)
	m.history.table.SetCursor(0)
	m.mode = modeOperationHistory
	m.status = ""
}

func (m *model) openSelectedHistoryDetail() error {
	row := m.history.table.Cursor()
	if row < 0 || row >= len(m.history.entries) {
		return fmt.Errorf("no operation details for this entry")
	}

	entry := m.history.entries[row]
	if entry.Kind != "sync" {
		return fmt.Errorf("details only available for sync operations")
	}

	m.trace.title = m.history.title + " Detail"
	m.trace.content = formatOperationDetail(entry)
	m.trace.returnTo = modeOperationHistory
	m.resizeTraceViewport()
	m.trace.viewport.SetContent(m.trace.content)
	m.trace.viewport.GotoTop()
	m.mode = modeSyncTrace
	m.status = ""
	return nil
}

func formatOperationDetail(entry operationLog) string {
	lines := []string{fmt.Sprintf("%s %s", entry.CreatedAt, entry.Summary)}
	if entry.Method != "" || entry.Path != "" {
		lines = append(lines, fmt.Sprintf("%s %s", entry.Method, entry.Path))
	}
	if entry.RequestBody != "" {
		lines = append(lines, "Request:")
		lines = append(lines, indentBlock(prettyJSON(entry.RequestBody), "  "))
	}
	if entry.Status != "" {
		lines = append(lines, "Response Status: "+entry.Status)
	}
	if entry.ResponseBody != "" {
		lines = append(lines, "Response Body:")
		lines = append(lines, indentBlock(prettyJSON(entry.ResponseBody), "  "))
	}
	if entry.Err != "" {
		lines = append(lines, "Error: "+entry.Err)
	}

	return strings.Join(lines, "\n")
}

func formatHistoryTimestamp(raw string) string {
	if raw == "" {
		return "-"
	}
	if len(raw) >= 19 {
		return strings.ReplaceAll(raw[:19], "T", " ")
	}
	return raw
}

func (m *model) toggleAutoOpenSyncTrace() error {
	m.state.Config.AutoOpenSyncTrace = !m.state.Config.AutoOpenSyncTrace
	if err := saveState(m.state); err != nil {
		m.state.Config.AutoOpenSyncTrace = !m.state.Config.AutoOpenSyncTrace
		return err
	}

	if m.state.Config.AutoOpenSyncTrace {
		m.status = "sync trace popup enabled"
		return nil
	}

	m.status = "sync trace popup disabled"
	return nil
}

func enabledLabel(enabled bool) string {
	if enabled {
		return "on"
	}

	return "off"
}

func tracePopupStyle(enabled bool) lipgloss.Style {
	if enabled {
		return toggleOnStyle
	}

	return toggleOffStyle
}

func renderHelpLine(help string) string {
	parts := strings.Split(help, " • ")
	rendered := make([]string, 0, len(parts)*2)
	for i, part := range parts {
		fields := strings.SplitN(part, " ", 2)
		if len(fields) == 2 {
			rendered = append(rendered, helpKeyStyle.Render(fields[0])+" "+helpDescStyle.Render(fields[1]))
		} else {
			rendered = append(rendered, helpDescStyle.Render(part))
		}
		if i < len(parts)-1 {
			rendered = append(rendered, helpSepStyle.Render(" • "))
		}
	}

	return lipgloss.JoinHorizontal(lipgloss.Left, rendered...)
}

func summarizeUserUpdate(existing user, givenName string, familyName string, email string, username string) string {
	switch {
	case existing.GivenName != givenName || existing.FamilyName != familyName:
		return "Updated name"
	case existing.Email != email:
		return "Updated email"
	case existing.Username != username:
		return "Updated username"
	default:
		return "Updated"
	}
}

func summarizeGroupUpdate(existing group, displayName string) string {
	if existing.DisplayName != displayName {
		return "Updated name"
	}

	return "Updated"
}

func localDeleteSummary(deleted bool) string {
	if deleted {
		return "Marked for deletion"
	}

	return "Restored"
}

func summarizeActiveToggle(active bool) string {
	if active {
		return "Activated"
	}

	return "Deactivated"
}

func max(a int, b int) int {
	if a > b {
		return a
	}

	return b
}
