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
	syncProgress   = core.SyncProgress
)

var (
	loadState                  = core.LoadState
	saveState                  = core.SaveState
	appendOperationLogs        = core.AppendOperationLogs
	appendLocalOperationLog    = core.AppendLocalOperationLog
	groupByID                  = core.GroupByID
	userByID                   = core.UserByID
	userLabel                  = core.UserLabel
	newUserID                  = core.NewUserID
	newGroupID                 = core.NewGroupID
	newAppID                   = core.NewAppID
	newID                      = core.NewID
	randomSecret               = core.RandomSecret
	slugify                    = core.Slugify
	lines                      = core.Lines
	joinLines                  = core.JoinLines
	validateUser               = core.ValidateUser
	validateGroup              = core.ValidateGroup
	validateHTTPBaseURL        = core.ValidateHTTPBaseURL
	validateApp                = core.ValidateApp
	supportsOIDC               = core.SupportsOIDC
	supportsSAML               = core.SupportsSAML
	normalizeSAMLNameIDField   = core.NormalizeSAMLNameIDField
	samlNameIDFormatForField   = core.SAMLNameIDFormatForField
	samlNameIDValue            = core.SAMLNameIDValue
	appBySlug                  = core.AppBySlug
	userGroups                 = core.UserGroups
	syncStatus                 = core.SyncStatus
	groupSyncStatus            = core.GroupSyncStatus
	activeStatus               = core.ActiveStatus
	syncDirtyStateWithProgress = core.SyncDirtyStateWithProgress
	importStateFromSCIM        = core.ImportStateFromSCIM
	configuredBaseURL          = core.ConfiguredBaseURL
)

const (
	defaultSAMLEmailAttributeName = core.DefaultSAMLEmailAttributeName
	defaultSAMLNameIDField        = core.DefaultSAMLNameIDField
)
