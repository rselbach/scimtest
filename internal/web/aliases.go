package web

import "scimtest/internal/core"

type (
	config         = core.Config
	user           = core.User
	app            = core.App
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
	newAppID                = core.NewAppID
	newID                   = core.NewID
	randomSecret            = core.RandomSecret
	slugify                 = core.Slugify
	lines                   = core.Lines
	joinLines               = core.JoinLines
	validateUser            = core.ValidateUser
	validateGroup           = core.ValidateGroup
	validateApp             = core.ValidateApp
	supportsOIDC            = core.SupportsOIDC
	supportsSAML            = core.SupportsSAML
	appBySlug               = core.AppBySlug
	userGroups              = core.UserGroups
	syncStatus              = core.SyncStatus
	groupSyncStatus         = core.GroupSyncStatus
	activeStatus            = core.ActiveStatus
	syncDirtyState          = core.SyncDirtyState
	importStateFromSCIM     = core.ImportStateFromSCIM
	configuredBaseURL       = core.ConfiguredBaseURL
)

const (
	defaultSAMLEmailAttributeName = core.DefaultSAMLEmailAttributeName
	defaultSAMLEmailNameIDFormat  = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
)
