package web

import (
	"fmt"
	"net/http"
	"strings"
)

func (a *webApp) handleUserSave(w http.ResponseWriter, r *http.Request) {
	tab := normalizedTab(r.FormValue("tab"))
	a.mu.Lock()
	defer a.mu.Unlock()

	state, err := loadRequestState(r)
	if err != nil {
		a.redirectError(w, r, tab, err)
		return
	}

	id := strings.TrimSpace(r.FormValue("id"))
	submitted := user{
		Username:       strings.TrimSpace(r.FormValue("username")),
		GivenName:      strings.TrimSpace(r.FormValue("given_name")),
		FamilyName:     strings.TrimSpace(r.FormValue("family_name")),
		Email:          strings.TrimSpace(r.FormValue("email")),
		EmployeeNumber: strings.TrimSpace(r.FormValue("employee_number")),
		CostCenter:     strings.TrimSpace(r.FormValue("cost_center")),
		Organization:   strings.TrimSpace(r.FormValue("organization")),
		Division:       strings.TrimSpace(r.FormValue("division")),
		Department:     strings.TrimSpace(r.FormValue("department")),
		ManagerID:      strings.TrimSpace(r.FormValue("manager_id")),
	}
	if submitted.Username == "" {
		submitted.Username = submitted.Email
	}

	if err := validateUser(submitted.GivenName, submitted.Email, submitted.Username); err != nil {
		a.redirectFormError(w, r, tab, "user", err)
		return
	}
	if err := validateUserUnique(state.Users, id, submitted.Email, submitted.Username); err != nil {
		a.redirectFormError(w, r, tab, "user", err)
		return
	}
	previous, _ := userByID(state.Users, id)
	if submitted.ManagerID != previous.ManagerID {
		if err := validateManager(state.Users, id, submitted.ManagerID); err != nil {
			a.redirectFormError(w, r, tab, "user", err)
			return
		}
	}
	submitted.Attributes, err = parseCustomAttributes(r.FormValue("attributes"))
	if err == nil {
		err = validateCustomAttributes(submitted.Attributes)
	}
	if err != nil {
		a.redirectFormError(w, r, tab, "user", err)
		return
	}

	status := "user updated"
	switch id {
	case "":
		id, err = newUserID()
		if err != nil {
			a.redirectError(w, r, tab, err)
			return
		}

		created := submitted
		created.ID = id
		created.Active = true
		created.Dirty = true
		state.Users = append(state.Users, created)
		appendLocalOperationLog(&state, "user", id, "Created")
		status = "user added"
	default:
		index, ok := userIndexByID(state.Users, id)
		if !ok {
			a.redirectError(w, r, tab, fmt.Errorf("user %s not found", id))
			return
		}
		existing := state.Users[index]
		updated := existing
		updated.GivenName = submitted.GivenName
		updated.FamilyName = submitted.FamilyName
		updated.Username = submitted.Username
		updated.Email = submitted.Email
		updated.EmployeeNumber = submitted.EmployeeNumber
		updated.CostCenter = submitted.CostCenter
		updated.Organization = submitted.Organization
		updated.Division = submitted.Division
		updated.Department = submitted.Department
		updated.ManagerID = submitted.ManagerID
		updated.Attributes = submitted.Attributes
		updated.Deleted = false
		updated.Dirty = true
		updated.LastError = ""
		state.Users[index] = updated
		appendLocalOperationLog(&state, "user", updated.ID, summarizeUserUpdate(existing, updated))
	}
	markUserDirty(&state, id, false)

	if err := a.saveRequestState(state); err != nil {
		a.redirectError(w, r, tab, err)
		return
	}

	redirectWithFlash(w, r, dashboardURLWithPage("users", formPage(r), formPageSize(r), formSearch(r), nil), flashMessage{Kind: "success", Message: status})
}

func (a *webApp) handleUserToggleActive(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	tab := normalizedTab(r.FormValue("tab"))
	a.mu.Lock()
	defer a.mu.Unlock()

	state, err := loadRequestState(r)
	if err != nil {
		a.redirectError(w, r, tab, err)
		return
	}

	index, ok := userIndexByID(state.Users, id)
	if !ok {
		a.redirectError(w, r, tab, fmt.Errorf("user %s not found", id))
		return
	}
	if state.Users[index].Deleted {
		a.redirectError(w, r, tab, fmt.Errorf("restore the user before changing active state"))
		return
	}

	state.Users[index].Active = !state.Users[index].Active
	state.Users[index].Dirty = true
	state.Users[index].LastError = ""
	markUserDirty(&state, id, false)
	appendLocalOperationLog(&state, "user", state.Users[index].ID, summarizeActiveToggle(state.Users[index].Active))

	if err := a.saveRequestState(state); err != nil {
		a.redirectError(w, r, tab, err)
		return
	}

	status := "user deactivated"
	if state.Users[index].Active {
		status = "user activated"
	}
	redirectWithFlash(w, r, dashboardURLWithPage("users", formPage(r), formPageSize(r), formSearch(r), nil), flashMessage{Kind: "success", Message: status})
}

func (a *webApp) handleUserDelete(w http.ResponseWriter, r *http.Request) {
	a.handleUserDeletedState(w, r, true)
}

func (a *webApp) handleUsersDelete(w http.ResponseWriter, r *http.Request) {
	tab := normalizedTab(r.FormValue("tab"))
	userIDs := r.Form["user_ids"]
	if len(userIDs) == 0 {
		a.redirectError(w, r, tab, fmt.Errorf("select at least one user to delete"))
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	state, err := loadRequestState(r)
	if err != nil {
		a.redirectError(w, r, tab, err)
		return
	}

	for i := range userIDs {
		userIDs[i] = strings.TrimSpace(userIDs[i])
	}
	count, err := deleteUsers(&state, userIDs)
	if err != nil {
		a.redirectError(w, r, tab, err)
		return
	}

	if err := a.saveRequestState(state); err != nil {
		a.redirectError(w, r, tab, err)
		return
	}

	message := fmt.Sprintf("deleted %d users", count)
	if scimTracksDirectory(state) {
		message = fmt.Sprintf("marked %d users for deletion", count)
	}
	redirectWithFlash(w, r, dashboardURLWithPage("users", formPage(r), formPageSize(r), formSearch(r), nil), flashMessage{Kind: "success", Message: message})
}

func (a *webApp) handleUserRestore(w http.ResponseWriter, r *http.Request) {
	a.handleUserDeletedState(w, r, false)
}

func (a *webApp) handleUserDeletedState(w http.ResponseWriter, r *http.Request, deleted bool) {
	id := r.PathValue("id")
	tab := normalizedTab(r.FormValue("tab"))
	a.mu.Lock()
	defer a.mu.Unlock()

	state, err := loadRequestState(r)
	if err != nil {
		a.redirectError(w, r, tab, err)
		return
	}

	index, ok := userIndexByID(state.Users, id)
	if !ok {
		a.redirectError(w, r, tab, fmt.Errorf("user %s not found", id))
		return
	}
	if !scimTracksDirectory(state) && !deleted {
		a.redirectError(w, r, tab, fmt.Errorf("SCIM is disabled"))
		return
	}
	setUserDeleted(&state, index, deleted, localDeleteSummary(deleted))

	if err := a.saveRequestState(state); err != nil {
		a.redirectError(w, r, tab, err)
		return
	}

	status := "user restored"
	if deleted {
		status = "user deleted"
		if scimTracksDirectory(state) {
			status = "user marked for deletion"
		}
	}
	redirectWithFlash(w, r, dashboardURLWithPage("users", formPage(r), formPageSize(r), formSearch(r), nil), flashMessage{Kind: "success", Message: status})
}

func (a *webApp) handleGroupSave(w http.ResponseWriter, r *http.Request) {
	tab := normalizedTab(r.FormValue("tab"))
	a.mu.Lock()
	defer a.mu.Unlock()

	state, err := loadRequestState(r)
	if err != nil {
		a.redirectError(w, r, tab, err)
		return
	}

	id := strings.TrimSpace(r.FormValue("id"))
	displayName := strings.TrimSpace(r.FormValue("display_name"))
	memberIDs := selectedMemberIDs(state.Users, r.Form["member_ids"])

	if err := validateGroup(displayName); err != nil {
		a.redirectFormError(w, r, tab, "group", err)
		return
	}

	status := "group updated"
	switch id {
	case "":
		id, err = newGroupID()
		if err != nil {
			a.redirectError(w, r, tab, err)
			return
		}

		state.Groups = append(state.Groups, group{
			ID:          id,
			DisplayName: displayName,
			MemberIDs:   memberIDs,
			Dirty:       true,
		})
		appendLocalOperationLog(&state, "group", id, "Created")
		status = "group added"
	default:
		index, ok := groupIndexByID(state.Groups, id)
		if !ok {
			a.redirectError(w, r, tab, fmt.Errorf("group %s not found", id))
			return
		}
		summary := summarizeGroupSave(state.Groups[index], displayName, memberIDs)
		state.Groups[index].DisplayName = displayName
		state.Groups[index].MemberIDs = memberIDs
		state.Groups[index].Deleted = false
		state.Groups[index].Dirty = true
		state.Groups[index].LastError = ""
		appendLocalOperationLog(&state, "group", state.Groups[index].ID, summary)
	}
	markGroupDirty(&state, id, false)

	if err := a.saveRequestState(state); err != nil {
		a.redirectError(w, r, tab, err)
		return
	}

	redirectWithFlash(w, r, dashboardURLWithPage("groups", formPage(r), formPageSize(r), formSearch(r), nil), flashMessage{Kind: "success", Message: status})
}

func (a *webApp) handleGroupDelete(w http.ResponseWriter, r *http.Request) {
	a.handleGroupDeletedState(w, r, true)
}

func (a *webApp) handleGroupsDelete(w http.ResponseWriter, r *http.Request) {
	tab := normalizedTab(r.FormValue("tab"))
	groupIDs := r.Form["group_ids"]
	if len(groupIDs) == 0 {
		a.redirectError(w, r, tab, fmt.Errorf("select at least one group to delete"))
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	state, err := loadRequestState(r)
	if err != nil {
		a.redirectError(w, r, tab, err)
		return
	}

	for i := range groupIDs {
		groupIDs[i] = strings.TrimSpace(groupIDs[i])
	}
	count, err := deleteGroups(&state, groupIDs)
	if err != nil {
		a.redirectError(w, r, tab, err)
		return
	}

	if err := a.saveRequestState(state); err != nil {
		a.redirectError(w, r, tab, err)
		return
	}

	message := fmt.Sprintf("deleted %d groups", count)
	if scimTracksDirectory(state) {
		message = fmt.Sprintf("marked %d groups for deletion", count)
	}
	redirectWithFlash(w, r, dashboardURLWithPage("groups", formPage(r), formPageSize(r), formSearch(r), nil), flashMessage{Kind: "success", Message: message})
}

func (a *webApp) handleGroupRestore(w http.ResponseWriter, r *http.Request) {
	a.handleGroupDeletedState(w, r, false)
}

func (a *webApp) handleGroupDeletedState(w http.ResponseWriter, r *http.Request, deleted bool) {
	id := r.PathValue("id")
	tab := normalizedTab(r.FormValue("tab"))
	a.mu.Lock()
	defer a.mu.Unlock()

	state, err := loadRequestState(r)
	if err != nil {
		a.redirectError(w, r, tab, err)
		return
	}

	index, ok := groupIndexByID(state.Groups, id)
	if !ok {
		a.redirectError(w, r, tab, fmt.Errorf("group %s not found", id))
		return
	}
	if !scimTracksDirectory(state) && !deleted {
		a.redirectError(w, r, tab, fmt.Errorf("SCIM is disabled"))
		return
	}
	setGroupDeleted(&state, index, deleted, localDeleteSummary(deleted))

	if err := a.saveRequestState(state); err != nil {
		a.redirectError(w, r, tab, err)
		return
	}

	status := "group restored"
	if deleted {
		status = "group deleted"
		if scimTracksDirectory(state) {
			status = "group marked for deletion"
		}
	}
	redirectWithFlash(w, r, dashboardURLWithPage("groups", formPage(r), formPageSize(r), formSearch(r), nil), flashMessage{Kind: "success", Message: status})
}
