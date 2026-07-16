package web

import "scimtest/internal/core"

type (
	config                = core.Config
	user                  = core.User
	app                   = core.App
	appState              = core.AppState
	operationLog          = core.OperationLog
	group                 = core.Group
	syncTraceEntry        = core.SyncTraceEntry
	syncProgress          = core.SyncProgress
	resourceSyncState     = core.ResourceSyncState
	stateBackup           = core.StateBackup
	oidcClaimMappings     = core.OIDCClaimMappings
	samlAttributeMappings = core.SAMLAttributeMappings
)

var errAppNotFound = core.ErrAppNotFound

var (
	loadState                    = core.LoadState
	loadStateForAppSlug          = core.LoadStateForAppSlug
	loadAllApps                  = core.LoadAllApps
	stateFilePath                = core.StateFilePath
	ensureRgrokInstanceID        = core.EnsureRgrokInstanceID
	saveState                    = core.SaveState
	appendOperationLogs          = core.AppendOperationLogs
	appendLocalOperationLog      = core.AppendLocalOperationLog
	groupByID                    = core.GroupByID
	userByID                     = core.UserByID
	userLabel                    = core.UserLabel
	newUserID                    = core.NewUserID
	newGroupID                   = core.NewGroupID
	newAppID                     = core.NewAppID
	newID                        = core.NewID
	randomSecret                 = core.RandomSecret
	slugify                      = core.Slugify
	lines                        = core.Lines
	joinLines                    = core.JoinLines
	validateUser                 = core.ValidateUser
	validateUserUnique           = core.ValidateUserUnique
	validateGroup                = core.ValidateGroup
	validateHTTPBaseURL          = core.ValidateHTTPBaseURL
	validateApp                  = core.ValidateApp
	supportsOIDC                 = core.SupportsOIDC
	supportsSAML                 = core.SupportsSAML
	normalizeSAMLNameIDField     = core.NormalizeSAMLNameIDField
	samlNameIDFormatForField     = core.SAMLNameIDFormatForField
	samlNameIDValue              = core.SAMLNameIDValue
	appBySlug                    = core.AppBySlug
	stateForApp                  = core.StateForApp
	markUserDirtyForApps         = core.MarkUserDirtyForApps
	markGroupDirtyForApps        = core.MarkGroupDirtyForApps
	initializeAppSync            = core.InitializeAppSync
	mergeAppSyncState            = core.MergeAppSyncState
	mergeAppImportState          = core.MergeAppImportState
	purgeFullySyncedDeletions    = core.PurgeFullySyncedDeletions
	dropAppOperationLogs         = core.DropAppOperationLogs
	userGroups                   = core.UserGroups
	syncStatus                   = core.SyncStatus
	groupSyncStatus              = core.GroupSyncStatus
	activeStatus                 = core.ActiveStatus
	syncDirtyStateWithContext    = core.SyncDirtyStateWithContext
	reconcileStateWithContext    = core.ReconcileStateWithContext
	importStateFromSCIM          = core.ImportStateFromSCIM
	configuredBaseURL            = core.ConfiguredBaseURL
	discoverSCIMCapabilities     = core.DiscoverSCIMCapabilities
	newStateBackup               = core.NewStateBackup
	writeSafetyBackup            = core.WriteSafetyBackup
	defaultOIDCClaimMappings     = core.DefaultOIDCClaimMappings
	defaultSAMLAttributeMappings = core.DefaultSAMLAttributeMappings
	oidcClaimMappingsForApp      = core.OIDCClaimMappingsForApp
	samlAttributeMappingsForApp  = core.SAMLAttributeMappingsForApp
	normalizeChooserMode         = core.NormalizeChooserMode
)

const (
	defaultSAMLEmailAttributeName = core.DefaultSAMLEmailAttributeName
	defaultSAMLNameIDField        = core.DefaultSAMLNameIDField
	chooserModeList               = core.ChooserModeList
	chooserModeIdentifier         = core.ChooserModeIdentifier
)
