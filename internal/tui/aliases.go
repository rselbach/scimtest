package tui

import "scimtest/internal/core"

type (
	config         = core.Config
	user           = core.User
	appState       = core.AppState
	operationLog   = core.OperationLog
	group          = core.Group
	syncResult     = core.SyncResult
	importResult   = core.ImportResult
	syncTraceEntry = core.SyncTraceEntry
)

var (
	loadState               = core.LoadState
	saveState               = core.SaveState
	appendOperationLogs     = core.AppendOperationLogs
	appendLocalOperationLog = core.AppendLocalOperationLog
	userLabel               = core.UserLabel
	newUserID               = core.NewUserID
	newGroupID              = core.NewGroupID
	validateUser            = core.ValidateUser
	validateGroup           = core.ValidateGroup
	fullName                = core.FullName
	syncStatus              = core.SyncStatus
	groupSyncStatus         = core.GroupSyncStatus
	activeStatus            = core.ActiveStatus
	syncDirtyState          = core.SyncDirtyState
	importStateFromSCIM     = core.ImportStateFromSCIM
	configuredBaseURL       = core.ConfiguredBaseURL
)
