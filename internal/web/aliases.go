package web

import "github.com/rselbach/scimtest/internal/core"

type (
	config                = core.Config
	environment           = core.Environment
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
	loadStateForApp              = core.LoadStateForApp
	loadStateForAppSlug          = core.LoadStateForAppSlug
	stateFilePath                = core.StateFilePath
	ensureTunnelInstanceID       = core.EnsureTunnelInstanceID
	saveState                    = core.SaveState
	saveGlobalConfig             = core.SaveGlobalConfig
	saveEnvironmentState         = core.SaveEnvironmentState
	deleteEnvironment            = core.DeleteEnvironment
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
	oidcSetupStatus              = core.OIDCSetupStatus
	samlSetupStatus              = core.SAMLSetupStatus
	scimSetupStatus              = core.SCIMSetupStatus
	inferAppProtocol             = core.InferAppProtocol
	normalizeSAMLNameIDField     = core.NormalizeSAMLNameIDField
	samlNameIDFormatForField     = core.SAMLNameIDFormatForField
	samlNameIDValue              = core.SAMLNameIDValue
	appBySlug                    = core.AppBySlug
	stateForApp                  = core.StateForApp
	markUserDirtyForApps         = core.MarkUserDirtyForApps
	markGroupDirtyForApps        = core.MarkGroupDirtyForApps
	initializeAppSync            = core.InitializeAppSync
	appHasSyncState              = core.AppHasSyncState
	mergeAppSyncState            = core.MergeAppSyncState
	mergeAppImportState          = core.MergeAppImportState
	purgeFullySyncedDeletions    = core.PurgeFullySyncedDeletions
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
	defaultEnvironmentID          = core.DefaultEnvironmentID
	defaultSAMLEmailAttributeName = core.DefaultSAMLEmailAttributeName
	defaultSAMLNameIDField        = core.DefaultSAMLNameIDField
	chooserModeList               = core.ChooserModeList
	chooserModeIdentifier         = core.ChooserModeIdentifier
	setupStatusNotSetUp           = core.SetupStatusNotSetUp
	setupStatusIncomplete         = core.SetupStatusIncomplete
	setupStatusConfigured         = core.SetupStatusConfigured
)
