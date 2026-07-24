package core

import (
	"fmt"
	"strings"
	"time"
)

// AppByID finds an app by its stable local ID.
func AppByID(apps []App, id string) (App, bool) {
	for _, app := range apps {
		if app.ID == id {
			return app, true
		}
	}
	return App{}, false
}

// StateForApp projects the global directory into the legacy shape consumed by
// the SCIM engine. Remote IDs and sync status belong to the selected app.
func StateForApp(state AppState, appID string) (AppState, error) {
	app, ok := AppByID(state.Apps, appID)
	if !ok {
		return AppState{}, fmt.Errorf("app %q not found", appID)
	}
	projected := state
	projected.Users = append([]User(nil), state.Users...)
	projected.Groups = append([]Group(nil), state.Groups...)
	for i := range projected.Groups {
		projected.Groups[i].MemberIDs = append([]string(nil), state.Groups[i].MemberIDs...)
	}
	projected.Config.BaseURL = app.SCIMBaseURL
	projected.Config.BearerToken = app.SCIMBearerToken
	projected.Config.AutoOpenSyncTrace = app.SCIMAutoOpenTrace
	projected.Config.SCIMDisabled = !app.SCIMEnabled
	projected.Config.FilterSupported = app.SCIMFilterSupported
	projected.Config.PatchSupported = app.SCIMPatchSupported
	projected.UserOperations = operationLogsForApp(state.UserOperations, appID)
	projected.GroupOperations = operationLogsForApp(state.GroupOperations, appID)
	if !app.SCIMEnabled {
		return projected, nil
	}
	deletedUserIDs := make(map[string]bool)
	for i := range projected.Users {
		syncState, exists := state.UserSync[appID][projected.Users[i].ID]
		if !exists {
			syncState.Dirty = true
		}
		projected.Users[i].RemoteID = syncState.RemoteID
		projected.Users[i].Dirty = syncState.Dirty
		projected.Users[i].Deleted = projected.Users[i].Deleted || syncState.Deleted
		projected.Users[i].LastError = syncState.LastError
		if projected.Users[i].Deleted {
			deletedUserIDs[projected.Users[i].ID] = true
		}
	}
	for i := range projected.Groups {
		syncState, exists := state.GroupSync[appID][projected.Groups[i].ID]
		if !exists {
			syncState.Dirty = true
		}
		projected.Groups[i].RemoteID = syncState.RemoteID
		projected.Groups[i].Dirty = syncState.Dirty
		projected.Groups[i].Deleted = projected.Groups[i].Deleted || syncState.Deleted
		projected.Groups[i].LastError = syncState.LastError
		members := make([]string, 0, len(projected.Groups[i].MemberIDs))
		for _, userID := range projected.Groups[i].MemberIDs {
			if !deletedUserIDs[userID] {
				members = append(members, userID)
			}
		}
		projected.Groups[i].MemberIDs = members
	}
	return projected, nil
}

func operationLogsForApp(logs map[string][]OperationLog, appID string) map[string][]OperationLog {
	filtered := make(map[string][]OperationLog, len(logs))
	for resourceID, entries := range logs {
		for _, entry := range entries {
			if entry.Kind != "local" && entry.AppID != appID {
				continue
			}
			filtered[resourceID] = append(filtered[resourceID], entry)
		}
	}
	return filtered
}

// DropAppOperationLogs removes the sync log entries recorded for one app.
// Local entries carry no app ID and are kept.
func DropAppOperationLogs(state *AppState, appID string) {
	if appID == "" {
		return
	}
	dropFrom := func(logs map[string][]OperationLog) {
		for resourceID, entries := range logs {
			kept := entries[:0]
			for _, entry := range entries {
				if entry.AppID != appID {
					kept = append(kept, entry)
				}
			}
			if len(kept) == 0 {
				delete(logs, resourceID)
				continue
			}
			logs[resourceID] = kept
		}
	}
	dropFrom(state.UserOperations)
	dropFrom(state.GroupOperations)
}

// MarkUserDirtyForApps schedules a user change for every sync-enabled app,
// and for SCIM-paused apps that already remember this user so a later
// re-enable still pushes the edit or delete.
func MarkUserDirtyForApps(state *AppState, userID string, deleted bool) {
	if state.UserSync == nil {
		state.UserSync = make(map[string]map[string]ResourceSyncState)
	}
	for _, app := range state.Apps {
		_, hasEntry := state.UserSync[app.ID][userID]
		if !app.SCIMEnabled && !hasEntry {
			continue
		}
		if state.UserSync[app.ID] == nil {
			state.UserSync[app.ID] = make(map[string]ResourceSyncState)
		}
		syncState := state.UserSync[app.ID][userID]
		syncState.Dirty = true
		syncState.Deleted = deleted
		syncState.LastError = ""
		state.UserSync[app.ID][userID] = syncState
	}
}

// MarkGroupDirtyForApps schedules a group change for every sync-enabled app,
// and for SCIM-paused apps that already remember this group.
func MarkGroupDirtyForApps(state *AppState, groupID string, deleted bool) {
	if state.GroupSync == nil {
		state.GroupSync = make(map[string]map[string]ResourceSyncState)
	}
	for _, app := range state.Apps {
		_, hasEntry := state.GroupSync[app.ID][groupID]
		if !app.SCIMEnabled && !hasEntry {
			continue
		}
		if state.GroupSync[app.ID] == nil {
			state.GroupSync[app.ID] = make(map[string]ResourceSyncState)
		}
		syncState := state.GroupSync[app.ID][groupID]
		syncState.Dirty = true
		syncState.Deleted = deleted
		syncState.LastError = ""
		state.GroupSync[app.ID][groupID] = syncState
	}
}

// InitializeAppSync resets one app so every directory resource is recreated.
func InitializeAppSync(state *AppState, appID string) {
	if state.UserSync == nil {
		state.UserSync = make(map[string]map[string]ResourceSyncState)
	}
	if state.GroupSync == nil {
		state.GroupSync = make(map[string]map[string]ResourceSyncState)
	}
	state.UserSync[appID] = make(map[string]ResourceSyncState, len(state.Users))
	for _, user := range state.Users {
		state.UserSync[appID][user.ID] = ResourceSyncState{Dirty: true, Deleted: user.Deleted}
	}
	state.GroupSync[appID] = make(map[string]ResourceSyncState, len(state.Groups))
	for _, group := range state.Groups {
		state.GroupSync[appID][group.ID] = ResourceSyncState{Dirty: true, Deleted: group.Deleted}
	}
}

// AppHasSyncState reports whether an app already has remembered remote IDs or
// pending sync rows. Used so re-enabling SCIM resumes instead of recreating.
func AppHasSyncState(state AppState, appID string) bool {
	return len(state.UserSync[appID]) > 0 || len(state.GroupSync[appID]) > 0
}

// MergeAppSyncState stores one SCIM result without changing other apps.
func MergeAppSyncState(state *AppState, appID string, synced AppState) {
	if state.UserSync == nil {
		state.UserSync = make(map[string]map[string]ResourceSyncState)
	}
	if state.GroupSync == nil {
		state.GroupSync = make(map[string]map[string]ResourceSyncState)
	}
	userSync := make(map[string]ResourceSyncState, len(state.Users))
	for _, user := range synced.Users {
		userSync[user.ID] = ResourceSyncState{RemoteID: user.RemoteID, Dirty: user.Dirty, Deleted: user.Deleted, LastError: user.LastError}
	}
	for _, user := range state.Users {
		if _, ok := userSync[user.ID]; !ok && user.Deleted {
			userSync[user.ID] = ResourceSyncState{Deleted: true}
		}
	}
	state.UserSync[appID] = userSync

	groupSync := make(map[string]ResourceSyncState, len(state.Groups))
	for _, group := range synced.Groups {
		groupSync[group.ID] = ResourceSyncState{RemoteID: group.RemoteID, Dirty: group.Dirty, Deleted: group.Deleted, LastError: group.LastError}
	}
	for _, group := range state.Groups {
		if _, ok := groupSync[group.ID]; !ok && group.Deleted {
			groupSync[group.ID] = ResourceSyncState{Deleted: true}
		}
	}
	state.GroupSync[appID] = groupSync
}

// MergeAppImportState replaces the directory from one app and schedules the
// resulting changes for every other sync-enabled app.
func MergeAppImportState(state *AppState, appID string, imported AppState) {
	MergeAppSyncState(state, appID, imported)
	if state.UserOperations == nil {
		state.UserOperations = make(map[string][]OperationLog)
	}
	if state.GroupOperations == nil {
		state.GroupOperations = make(map[string][]OperationLog)
	}
	previousUsers := make(map[string]User, len(state.Users))
	for _, user := range state.Users {
		previousUsers[user.ID] = user
	}
	previousGroups := make(map[string]Group, len(state.Groups))
	for _, group := range state.Groups {
		previousGroups[group.ID] = group
	}

	state.Users = imported.Users
	importedUserIDs := make(map[string]bool, len(imported.Users))
	for i := range state.Users {
		importedUserIDs[state.Users[i].ID] = true
		mergeImportOperationLog(state.UserOperations, imported.UserOperations, state.Users[i].ID)
		state.Users[i].RemoteID = ""
		state.Users[i].Dirty = false
		state.Users[i].Deleted = false
		state.Users[i].LastError = ""
	}
	for id, user := range previousUsers {
		if importedUserIDs[id] {
			continue
		}
		user.Deleted = true
		user.RemoteID = ""
		user.Dirty = false
		user.LastError = ""
		state.Users = append(state.Users, user)
	}

	state.Groups = imported.Groups
	importedGroupIDs := make(map[string]bool, len(imported.Groups))
	for i := range state.Groups {
		importedGroupIDs[state.Groups[i].ID] = true
		mergeImportOperationLog(state.GroupOperations, imported.GroupOperations, state.Groups[i].ID)
		state.Groups[i].RemoteID = ""
		state.Groups[i].Dirty = false
		state.Groups[i].Deleted = false
		state.Groups[i].LastError = ""
	}
	for id, group := range previousGroups {
		if importedGroupIDs[id] {
			continue
		}
		group.Deleted = true
		group.RemoteID = ""
		group.Dirty = false
		group.LastError = ""
		state.Groups = append(state.Groups, group)
	}

	for _, app := range state.Apps {
		if !app.SCIMEnabled || app.ID == appID {
			continue
		}
		for _, user := range state.Users {
			markResourceDirty(state.UserSync, app.ID, user.ID, user.Deleted)
		}
		for _, group := range state.Groups {
			markResourceDirty(state.GroupSync, app.ID, group.ID, group.Deleted)
		}
	}
}

func mergeImportOperationLog(destination map[string][]OperationLog, imported map[string][]OperationLog, resourceID string) {
	for _, entry := range imported[resourceID] {
		if entry.Kind != "local" || entry.Summary != "Imported from SCIM" {
			continue
		}
		destination[resourceID] = append([]OperationLog{entry}, destination[resourceID]...)
		return
	}
}

func markResourceDirty(syncStates map[string]map[string]ResourceSyncState, appID string, resourceID string, deleted bool) {
	if syncStates[appID] == nil {
		syncStates[appID] = make(map[string]ResourceSyncState)
	}
	syncState := syncStates[appID][resourceID]
	syncState.Dirty = true
	syncState.Deleted = deleted
	syncState.LastError = ""
	syncStates[appID][resourceID] = syncState
}

// PurgeFullySyncedDeletions removes locally soft-deleted resources only after
// every SCIM-linked environment that still remembers them has finished
// deleting. Pausing SCIM (SCIMEnabled=false) does not count as finished: a
// remembered RemoteID or pending dirty delete still blocks purge.
func PurgeFullySyncedDeletions(state *AppState) {
	keptUsers := state.Users[:0]
	for _, user := range state.Users {
		if user.Deleted && resourceDeletedEverywhere(state.Apps, state.UserSync, user.ID) {
			delete(state.UserOperations, user.ID)
			for appID := range state.UserSync {
				delete(state.UserSync[appID], user.ID)
			}
			for i := range state.Groups {
				state.Groups[i].MemberIDs = removeValue(state.Groups[i].MemberIDs, user.ID)
			}
			continue
		}
		keptUsers = append(keptUsers, user)
	}
	state.Users = keptUsers

	keptGroups := state.Groups[:0]
	for _, group := range state.Groups {
		if group.Deleted && resourceDeletedEverywhere(state.Apps, state.GroupSync, group.ID) {
			delete(state.GroupOperations, group.ID)
			for appID := range state.GroupSync {
				delete(state.GroupSync[appID], group.ID)
			}
			continue
		}
		keptGroups = append(keptGroups, group)
	}
	state.Groups = keptGroups
}

// syncDeletionSettled is the terminal sync row after a successful remote
// delete: tombstoned, not dirty, and no RemoteID left to target.
func syncDeletionSettled(syncState ResourceSyncState, ok bool) bool {
	return ok && syncState.Deleted && !syncState.Dirty && syncState.RemoteID == ""
}

func resourceDeletedEverywhere(apps []App, syncByApp map[string]map[string]ResourceSyncState, resourceID string) bool {
	seen := make(map[string]bool, len(apps))
	for _, app := range apps {
		seen[app.ID] = true
		syncState, ok := syncByApp[app.ID][resourceID]
		if app.SCIMEnabled {
			if !syncDeletionSettled(syncState, ok) {
				return false
			}
			continue
		}
		// SCIM paused: no row means this environment never tracked the
		// resource. Any remaining live or pending remote identity blocks GC.
		if !ok {
			continue
		}
		if !syncDeletionSettled(syncState, true) {
			return false
		}
	}
	for appID, syncs := range syncByApp {
		if seen[appID] {
			continue
		}
		syncState, ok := syncs[resourceID]
		if !ok {
			continue
		}
		if !syncDeletionSettled(syncState, true) {
			return false
		}
	}
	return true
}

func removeValue(values []string, value string) []string {
	kept := values[:0]
	for _, candidate := range values {
		if candidate != value {
			kept = append(kept, candidate)
		}
	}
	return kept
}

func AppendOperationLogs(state *AppState, appID string, traces []SyncTraceEntry) {
	if state.UserOperations == nil {
		state.UserOperations = make(map[string][]OperationLog)
	}
	if state.GroupOperations == nil {
		state.GroupOperations = make(map[string][]OperationLog)
	}

	for _, trace := range traces {
		entry := OperationLog{
			AppID:              appID,
			Kind:               "sync",
			Summary:            summarizeSyncTrace(trace),
			Operation:          trace.Operation,
			Method:             trace.Method,
			Path:               trace.Path,
			RequestBody:        trace.RequestBody,
			Status:             trace.Status,
			ResponseRetryAfter: trace.ResponseRetryAfter,
			ResponseBody:       trace.ResponseBody,
			Err:                trace.Err,
			CreatedAt:          trace.CreatedAt,
		}

		switch trace.ResourceType {
		case "user":
			state.UserOperations[trace.ResourceID] = append([]OperationLog{entry}, state.UserOperations[trace.ResourceID]...)
		case "group":
			state.GroupOperations[trace.ResourceID] = append([]OperationLog{entry}, state.GroupOperations[trace.ResourceID]...)
		}
	}
}

func AppendLocalOperationLog(state *AppState, resourceType string, resourceID string, summary string) {
	entry := OperationLog{
		Kind:      "local",
		Summary:   summary,
		CreatedAt: NowTimestamp(),
	}

	if state.UserOperations == nil {
		state.UserOperations = make(map[string][]OperationLog)
	}
	if state.GroupOperations == nil {
		state.GroupOperations = make(map[string][]OperationLog)
	}

	switch resourceType {
	case "user":
		state.UserOperations[resourceID] = append([]OperationLog{entry}, state.UserOperations[resourceID]...)
	case "group":
		state.GroupOperations[resourceID] = append([]OperationLog{entry}, state.GroupOperations[resourceID]...)
	}
}

func summarizeSyncTrace(trace SyncTraceEntry) string {
	if trace.Err != "" {
		operation := strings.TrimSpace(trace.Operation)
		if operation == "" {
			return "Failed"
		}
		return "Failed to " + operation
	}
	if trace.Operation == "create" {
		return "Created"
	}
	if trace.Operation == "delete" {
		return "Deleted"
	}

	return "Synced"
}

func NowTimestamp() string {
	return currentTime().UTC().Format(time.RFC3339)
}
