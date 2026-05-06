package web

import "scimtest/internal/core"

type (
	config         = core.Config
	user           = core.User
	appState       = core.AppState
	operationLog   = core.OperationLog
	group          = core.Group
	syncTraceEntry = core.SyncTraceEntry
)

var (
	loadState               = core.LoadState
	saveState               = core.SaveState
	appendOperationLogs     = core.AppendOperationLogs
	appendLocalOperationLog = core.AppendLocalOperationLog
	groupByID               = core.GroupByID
	userByID                = core.UserByID
	userLabel               = core.UserLabel
	newUserID               = core.NewUserID
	newGroupID              = core.NewGroupID
	validateUser            = core.ValidateUser
	validateGroup           = core.ValidateGroup
	syncStatus              = core.SyncStatus
	groupSyncStatus         = core.GroupSyncStatus
	activeStatus            = core.ActiveStatus
	syncDirtyState          = core.SyncDirtyState
	importStateFromSCIM     = core.ImportStateFromSCIM
	configuredBaseURL       = core.ConfiguredBaseURL
)
