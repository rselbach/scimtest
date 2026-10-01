package web

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

func (a *webApp) handleAPIEnvironmentsList(w http.ResponseWriter, _ *http.Request) {
	state, err := loadState()
	if err != nil {
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, append([]app{}, state.Apps...))
}

func (a *webApp) handleAPIEnvironmentGet(w http.ResponseWriter, r *http.Request) {
	state, err := loadStateForApp(r.PathValue("environment_id"))
	if err != nil {
		apiError(w, http.StatusNotFound, err.Error())
		return
	}
	found, err := apiAppByID(state, r.PathValue("environment_id"))
	if err != nil {
		apiError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, found)
}

func (a *webApp) handleAPIEnvironmentCreate(w http.ResponseWriter, r *http.Request) {
	var request apiEnvironmentRequest
	if decodeAPIJSON(w, r, &request) != nil {
		return
	}
	requestHTTP := withAPIEnvironmentRequest(apiInternalRequest(r, ""), request)
	a.handleAppSave(w, requestHTTP)
}

func (a *webApp) handleAPIEnvironmentPatch(w http.ResponseWriter, r *http.Request) {
	var request apiEnvironmentRequest
	if decodeAPIJSON(w, r, &request) != nil {
		return
	}
	requestHTTP := apiInternalRequest(r, r.PathValue("environment_id"))
	requestHTTP.SetPathValue("environment_id", r.PathValue("environment_id"))
	requestHTTP = withAPIEnvironmentRequest(requestHTTP, request)
	a.handleAppSave(w, requestHTTP)
}

func (a *webApp) handleAPIEnvironmentDelete(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, err := loadStateForApp(r.PathValue("environment_id")); err != nil {
		apiError(w, http.StatusNotFound, err.Error())
		return
	}
	if err := deleteEnvironment(r.PathValue("environment_id")); err != nil {
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, map[string]string{"message": "environment deleted"})
}

func apiMutationStatus(err error) int {
	if errors.Is(err, errAppNotFound) || strings.Contains(err.Error(), "not found") {
		return http.StatusNotFound
	}
	return http.StatusBadRequest
}

func (a *webApp) loadAPIEnvironment(id string) (appState, error) {
	if strings.TrimSpace(id) == "" {
		return appState{}, errors.New("environment ID is required")
	}
	state, err := loadStateForApp(id)
	if err != nil {
		return appState{}, err
	}
	if _, err := apiAppByID(state, id); err != nil {
		return appState{}, err
	}
	return state, nil
}

func (a *webApp) handleAPIUsersList(w http.ResponseWriter, r *http.Request) {
	state, err := a.loadAPIEnvironment(r.PathValue("environment_id"))
	if err != nil {
		apiError(w, http.StatusNotFound, err.Error())
		return
	}
	state, err = stateForApp(state, r.PathValue("environment_id"))
	if err != nil {
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, append([]user{}, state.Users...))
}

func (a *webApp) handleAPIUserGet(w http.ResponseWriter, r *http.Request) {
	state, err := a.loadAPIEnvironment(r.PathValue("environment_id"))
	if err != nil {
		apiError(w, http.StatusNotFound, err.Error())
		return
	}
	state, err = stateForApp(state, r.PathValue("environment_id"))
	if err != nil {
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}
	found, ok := userByID(state.Users, r.PathValue("user_id"))
	if !ok {
		apiError(w, http.StatusNotFound, "user not found")
		return
	}
	writeJSON(w, found)
}

func (a *webApp) handleAPIUserCreate(w http.ResponseWriter, r *http.Request) {
	var request apiUserRequest
	if decodeAPIJSON(w, r, &request) != nil {
		return
	}
	found, err := a.saveAPIUser(r.PathValue("environment_id"), "", request)
	if err != nil {
		apiError(w, apiMutationStatus(err), err.Error())
		return
	}
	writeJSONStatus(w, http.StatusCreated, found)
}

func (a *webApp) handleAPIUserPatch(w http.ResponseWriter, r *http.Request) {
	var request apiUserRequest
	if decodeAPIJSON(w, r, &request) != nil {
		return
	}
	found, err := a.saveAPIUser(r.PathValue("environment_id"), r.PathValue("user_id"), request)
	if err != nil {
		apiError(w, apiMutationStatus(err), err.Error())
		return
	}
	writeJSON(w, found)
}

func (a *webApp) saveAPIUser(environmentID, id string, request apiUserRequest) (user, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	state, err := a.loadAPIEnvironment(environmentID)
	if err != nil {
		return user{}, err
	}
	found := user{Active: true}
	if id != "" {
		var ok bool
		found, ok = userByID(state.Users, id)
		if !ok {
			return user{}, errors.New("user not found")
		}
		if found.Deleted {
			return user{}, errors.New("deleted users must be restored before editing")
		}
	}
	if request.GivenName != nil {
		found.GivenName = strings.TrimSpace(*request.GivenName)
	}
	if request.FamilyName != nil {
		found.FamilyName = strings.TrimSpace(*request.FamilyName)
	}
	if request.Email != nil {
		found.Email = strings.TrimSpace(*request.Email)
	}
	if request.Username != nil {
		found.Username = strings.TrimSpace(*request.Username)
	}
	if request.Active != nil {
		found.Active = *request.Active
	}
	if found.Username == "" {
		found.Username = found.Email
	}
	if err := validateUser(found.GivenName, found.Email, found.Username); err != nil {
		return user{}, err
	}
	if err := validateUserUnique(state.Users, found.ID, found.Email, found.Username); err != nil {
		return user{}, err
	}
	if id == "" {
		found.ID, err = newUserID()
		if err != nil {
			return user{}, err
		}
		found.Dirty = true
		state.Users = append(state.Users, found)
		appendLocalOperationLog(&state, "user", found.ID, "Created")
	} else {
		index, _ := userIndexByID(state.Users, id)
		old := state.Users[index]
		found.Dirty = true
		found.LastError = ""
		state.Users[index] = found
		summary := summarizeUserUpdate(old, found.GivenName, found.FamilyName, found.Email, found.Username)
		if old.Active != found.Active {
			summary += fmt.Sprintf("; active set to %t", found.Active)
		}
		appendLocalOperationLog(&state, "user", id, summary)
	}
	markUserDirty(&state, found.ID, false)
	if err := saveRequestState(state); err != nil {
		return user{}, err
	}
	return found, nil
}

func (a *webApp) handleAPIUserDelete(w http.ResponseWriter, r *http.Request) {
	a.setAPIUserDeleted(w, r, true)
}
func (a *webApp) handleAPIUserRestore(w http.ResponseWriter, r *http.Request) {
	a.setAPIUserDeleted(w, r, false)
}
func (a *webApp) setAPIUserDeleted(w http.ResponseWriter, r *http.Request, deleted bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	state, err := a.loadAPIEnvironment(r.PathValue("environment_id"))
	if err != nil {
		apiError(w, http.StatusNotFound, err.Error())
		return
	}
	index, ok := userIndexByID(state.Users, r.PathValue("user_id"))
	if !ok {
		apiError(w, http.StatusNotFound, "user not found")
		return
	}
	if scimTracksDirectory(state) {
		state.Users[index].Deleted = deleted
		state.Users[index].Dirty = true
		state.Users[index].LastError = ""
		markUserDirty(&state, state.Users[index].ID, deleted)
		appendLocalOperationLog(&state, "user", state.Users[index].ID, localDeleteSummary(deleted))
	} else if deleted {
		id := state.Users[index].ID
		state.Users = append(state.Users[:index], state.Users[index+1:]...)
		for i := range state.Groups {
			state.Groups[i].MemberIDs = removeString(state.Groups[i].MemberIDs, id)
		}
	} else {
		apiError(w, http.StatusConflict, "SCIM is disabled")
		return
	}
	if err := saveRequestState(state); err != nil {
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if deleted {
		message := "user deleted"
		if scimTracksDirectory(state) {
			message = "user marked for deletion"
		}
		writeJSON(w, map[string]string{"message": message})
	} else {
		writeJSON(w, state.Users[index])
	}
}

type apiIDsRequest struct {
	IDs []string `json:"ids"`
}

func (a *webApp) handleAPIUsersBulkDelete(w http.ResponseWriter, r *http.Request) {
	var request apiIDsRequest
	if decodeAPIJSON(w, r, &request) != nil {
		return
	}
	if len(request.IDs) == 0 {
		apiError(w, http.StatusBadRequest, "ids must not be empty")
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	state, err := a.loadAPIEnvironment(r.PathValue("environment_id"))
	if err != nil {
		apiError(w, http.StatusNotFound, err.Error())
		return
	}
	selected := make(map[string]bool, len(request.IDs))
	for _, id := range request.IDs {
		index, ok := userIndexByID(state.Users, id)
		if !ok || state.Users[index].Deleted {
			apiError(w, http.StatusBadRequest, "user "+id+" is not available for deletion")
			return
		}
		selected[id] = true
	}
	if scimTracksDirectory(state) {
		for i := range state.Users {
			if selected[state.Users[i].ID] {
				state.Users[i].Deleted = true
				state.Users[i].Dirty = true
				state.Users[i].LastError = ""
				markUserDirty(&state, state.Users[i].ID, true)
				appendLocalOperationLog(&state, "user", state.Users[i].ID, "Marked for deletion in bulk")
			}
		}
	} else {
		kept := state.Users[:0]
		for _, found := range state.Users {
			if !selected[found.ID] {
				kept = append(kept, found)
			}
		}
		state.Users = kept
		for i := range state.Groups {
			for id := range selected {
				state.Groups[i].MemberIDs = removeString(state.Groups[i].MemberIDs, id)
			}
		}
	}
	if err := saveRequestState(state); err != nil {
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, map[string]int{"deleted": len(selected)})
}

func (a *webApp) handleAPIUserOperations(w http.ResponseWriter, r *http.Request) {
	state, err := a.loadAPIEnvironment(r.PathValue("environment_id"))
	if err != nil {
		apiError(w, http.StatusNotFound, err.Error())
		return
	}
	if _, ok := userByID(state.Users, r.PathValue("user_id")); !ok {
		apiError(w, http.StatusNotFound, "user not found")
		return
	}
	writeJSON(w, apiOperations(state, "user", r.PathValue("user_id")))
}

func (a *webApp) handleAPIGroupsList(w http.ResponseWriter, r *http.Request) {
	state, err := a.loadAPIEnvironment(r.PathValue("environment_id"))
	if err != nil {
		apiError(w, http.StatusNotFound, err.Error())
		return
	}
	state, err = stateForApp(state, r.PathValue("environment_id"))
	if err != nil {
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, append([]group{}, state.Groups...))
}
func (a *webApp) handleAPIGroupGet(w http.ResponseWriter, r *http.Request) {
	state, err := a.loadAPIEnvironment(r.PathValue("environment_id"))
	if err != nil {
		apiError(w, http.StatusNotFound, err.Error())
		return
	}
	state, err = stateForApp(state, r.PathValue("environment_id"))
	if err != nil {
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}
	found, ok := groupByID(state.Groups, r.PathValue("group_id"))
	if !ok {
		apiError(w, http.StatusNotFound, "group not found")
		return
	}
	writeJSON(w, found)
}
func (a *webApp) handleAPIGroupCreate(w http.ResponseWriter, r *http.Request) {
	var request apiGroupRequest
	if decodeAPIJSON(w, r, &request) != nil {
		return
	}
	found, err := a.saveAPIGroup(r.PathValue("environment_id"), "", request)
	if err != nil {
		apiError(w, apiMutationStatus(err), err.Error())
		return
	}
	writeJSONStatus(w, http.StatusCreated, found)
}
func (a *webApp) handleAPIGroupPatch(w http.ResponseWriter, r *http.Request) {
	var request apiGroupRequest
	if decodeAPIJSON(w, r, &request) != nil {
		return
	}
	found, err := a.saveAPIGroup(r.PathValue("environment_id"), r.PathValue("group_id"), request)
	if err != nil {
		apiError(w, apiMutationStatus(err), err.Error())
		return
	}
	writeJSON(w, found)
}

func (a *webApp) saveAPIGroup(environmentID, id string, request apiGroupRequest) (group, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	state, err := a.loadAPIEnvironment(environmentID)
	if err != nil {
		return group{}, err
	}
	found := group{}
	if id != "" {
		var ok bool
		found, ok = groupByID(state.Groups, id)
		if !ok {
			return group{}, errors.New("group not found")
		}
		if found.Deleted {
			return group{}, errors.New("deleted groups must be restored before editing")
		}
	}
	if request.DisplayName != nil {
		found.DisplayName = strings.TrimSpace(*request.DisplayName)
	}
	if request.MemberIDs != nil {
		valid := make(map[string]bool, len(state.Users))
		for _, member := range state.Users {
			if !member.Deleted {
				valid[member.ID] = true
			}
		}
		for _, memberID := range *request.MemberIDs {
			if !valid[memberID] {
				return group{}, fmt.Errorf("user %q is not available for membership", memberID)
			}
		}
		found.MemberIDs = selectedMemberIDs(state.Users, *request.MemberIDs)
	}
	if err := validateGroup(found.DisplayName); err != nil {
		return group{}, err
	}
	if id == "" {
		found.ID, err = newGroupID()
		if err != nil {
			return group{}, err
		}
		found.Dirty = true
		state.Groups = append(state.Groups, found)
		appendLocalOperationLog(&state, "group", found.ID, "Created")
	} else {
		index, _ := groupIndexByID(state.Groups, id)
		summary := summarizeGroupSave(state.Groups[index], found.DisplayName, found.MemberIDs)
		found.Dirty = true
		found.LastError = ""
		state.Groups[index] = found
		appendLocalOperationLog(&state, "group", id, summary)
	}
	markGroupDirty(&state, found.ID, false)
	if err := saveRequestState(state); err != nil {
		return group{}, err
	}
	return found, nil
}

func (a *webApp) handleAPIGroupDelete(w http.ResponseWriter, r *http.Request) {
	a.setAPIGroupDeleted(w, r, true)
}
func (a *webApp) handleAPIGroupRestore(w http.ResponseWriter, r *http.Request) {
	a.setAPIGroupDeleted(w, r, false)
}
func (a *webApp) setAPIGroupDeleted(w http.ResponseWriter, r *http.Request, deleted bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	state, err := a.loadAPIEnvironment(r.PathValue("environment_id"))
	if err != nil {
		apiError(w, http.StatusNotFound, err.Error())
		return
	}
	index, ok := groupIndexByID(state.Groups, r.PathValue("group_id"))
	if !ok {
		apiError(w, http.StatusNotFound, "group not found")
		return
	}
	if scimTracksDirectory(state) {
		state.Groups[index].Deleted = deleted
		state.Groups[index].Dirty = true
		state.Groups[index].LastError = ""
		markGroupDirty(&state, state.Groups[index].ID, deleted)
		appendLocalOperationLog(&state, "group", state.Groups[index].ID, localDeleteSummary(deleted))
	} else if deleted {
		state.Groups = append(state.Groups[:index], state.Groups[index+1:]...)
	} else {
		apiError(w, http.StatusConflict, "SCIM is disabled")
		return
	}
	if err := saveRequestState(state); err != nil {
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if deleted {
		message := "group deleted"
		if scimTracksDirectory(state) {
			message = "group marked for deletion"
		}
		writeJSON(w, map[string]string{"message": message})
	} else {
		writeJSON(w, state.Groups[index])
	}
}
func (a *webApp) handleAPIGroupsBulkDelete(w http.ResponseWriter, r *http.Request) {
	var request apiIDsRequest
	if decodeAPIJSON(w, r, &request) != nil {
		return
	}
	if len(request.IDs) == 0 {
		apiError(w, http.StatusBadRequest, "ids must not be empty")
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	state, err := a.loadAPIEnvironment(r.PathValue("environment_id"))
	if err != nil {
		apiError(w, http.StatusNotFound, err.Error())
		return
	}
	selected := make(map[string]bool, len(request.IDs))
	for _, id := range request.IDs {
		index, ok := groupIndexByID(state.Groups, id)
		if !ok || state.Groups[index].Deleted {
			apiError(w, http.StatusBadRequest, "group "+id+" is not available for deletion")
			return
		}
		selected[id] = true
	}
	if scimTracksDirectory(state) {
		for i := range state.Groups {
			if selected[state.Groups[i].ID] {
				state.Groups[i].Deleted = true
				state.Groups[i].Dirty = true
				state.Groups[i].LastError = ""
				markGroupDirty(&state, state.Groups[i].ID, true)
				appendLocalOperationLog(&state, "group", state.Groups[i].ID, "Marked for deletion in bulk")
			}
		}
	} else {
		kept := state.Groups[:0]
		for _, found := range state.Groups {
			if !selected[found.ID] {
				kept = append(kept, found)
			}
		}
		state.Groups = kept
	}
	if err := saveRequestState(state); err != nil {
		apiError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, map[string]int{"deleted": len(selected)})
}
func (a *webApp) handleAPIGroupOperations(w http.ResponseWriter, r *http.Request) {
	state, err := a.loadAPIEnvironment(r.PathValue("environment_id"))
	if err != nil {
		apiError(w, http.StatusNotFound, err.Error())
		return
	}
	if _, ok := groupByID(state.Groups, r.PathValue("group_id")); !ok {
		apiError(w, http.StatusNotFound, "group not found")
		return
	}
	writeJSON(w, apiOperations(state, "group", r.PathValue("group_id")))
}
