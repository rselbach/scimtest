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
	username := strings.TrimSpace(r.FormValue("username"))
	givenName := strings.TrimSpace(r.FormValue("given_name"))
	familyName := strings.TrimSpace(r.FormValue("family_name"))
	email := strings.TrimSpace(r.FormValue("email"))
	if username == "" {
		username = email
	}

	if err := validateUser(givenName, email, username); err != nil {
		a.redirectFormError(w, r, tab, "user", err)
		return
	}
	if err := validateUserUnique(state.Users, id, email, username); err != nil {
		a.redirectFormError(w, r, tab, "user", err)
		return
	}

	status := "user updated"
	if id == "" {
		id, err = newUserID()
		if err != nil {
			a.redirectError(w, r, tab, err)
			return
		}

		state.Users = append(state.Users, user{
			ID:         id,
			GivenName:  givenName,
			FamilyName: familyName,
			Username:   username,
			Email:      email,
			Active:     true,
			Dirty:      true,
		})
		appendLocalOperationLog(&state, "user", id, "Created")
		status = "user added"
	}
	if id != "" {
		index, ok := userIndexByID(state.Users, id)
		if !ok {
			a.redirectError(w, r, tab, fmt.Errorf("user %s not found", id))
			return
		}
		if status == "user updated" {
			summary := summarizeUserUpdate(state.Users[index], givenName, familyName, email, username)
			state.Users[index].GivenName = givenName
			state.Users[index].FamilyName = familyName
			state.Users[index].Username = username
			state.Users[index].Email = email
			state.Users[index].Deleted = false
			state.Users[index].Dirty = true
			state.Users[index].LastError = ""
			appendLocalOperationLog(&state, "user", state.Users[index].ID, summary)
		}
	}
	markUserDirtyForApps(&state, id, false)

	if err := saveState(state); err != nil {
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
	markUserDirtyForApps(&state, id, false)
	appendLocalOperationLog(&state, "user", state.Users[index].ID, summarizeActiveToggle(state.Users[index].Active))

	if err := saveState(state); err != nil {
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

	selected := make(map[string]bool, len(userIDs))
	for _, id := range userIDs {
		id = strings.TrimSpace(id)
		index, ok := userIndexByID(state.Users, id)
		if !ok || state.Users[index].Deleted {
			a.redirectError(w, r, tab, fmt.Errorf("user %s is not available for deletion", id))
			return
		}
		selected[id] = true
	}

	if scimEnabled(state) {
		for i := range state.Users {
			if !selected[state.Users[i].ID] {
				continue
			}
			state.Users[i].Deleted = true
			state.Users[i].Dirty = true
			state.Users[i].LastError = ""
			markUserDirtyForApps(&state, state.Users[i].ID, true)
			appendLocalOperationLog(&state, "user", state.Users[i].ID, "Marked for deletion in bulk")
		}
	} else {
		keptUsers := make([]user, 0, len(state.Users)-len(selected))
		for _, u := range state.Users {
			if !selected[u.ID] {
				keptUsers = append(keptUsers, u)
			}
		}
		state.Users = keptUsers
		for i := range state.Groups {
			for id := range selected {
				state.Groups[i].MemberIDs = removeString(state.Groups[i].MemberIDs, id)
			}
		}
	}

	if err := saveState(state); err != nil {
		a.redirectError(w, r, tab, err)
		return
	}

	message := fmt.Sprintf("deleted %d users", len(selected))
	if scimEnabled(state) {
		message = fmt.Sprintf("marked %d users for deletion", len(selected))
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
	if !scimEnabled(state) {
		if !deleted {
			a.redirectError(w, r, tab, fmt.Errorf("SCIM is disabled"))
			return
		}
		state.Users = append(state.Users[:index], state.Users[index+1:]...)
		for i := range state.Groups {
			state.Groups[i].MemberIDs = removeString(state.Groups[i].MemberIDs, id)
		}
		if err := saveState(state); err != nil {
			a.redirectError(w, r, tab, err)
			return
		}
		redirectWithFlash(w, r, dashboardURLWithPage("users", formPage(r), formPageSize(r), formSearch(r), nil), flashMessage{Kind: "success", Message: "user deleted"})
		return
	}

	state.Users[index].Deleted = deleted
	state.Users[index].Dirty = true
	state.Users[index].LastError = ""
	markUserDirtyForApps(&state, id, deleted)
	appendLocalOperationLog(&state, "user", state.Users[index].ID, localDeleteSummary(deleted))

	if err := saveState(state); err != nil {
		a.redirectError(w, r, tab, err)
		return
	}

	status := "user restored"
	if deleted {
		status = "user marked for deletion"
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
	if id == "" {
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
	}
	if id != "" {
		index, ok := groupIndexByID(state.Groups, id)
		if !ok {
			a.redirectError(w, r, tab, fmt.Errorf("group %s not found", id))
			return
		}
		if status == "group updated" {
			summary := summarizeGroupSave(state.Groups[index], displayName, memberIDs)
			state.Groups[index].DisplayName = displayName
			state.Groups[index].MemberIDs = memberIDs
			state.Groups[index].Deleted = false
			state.Groups[index].Dirty = true
			state.Groups[index].LastError = ""
			appendLocalOperationLog(&state, "group", state.Groups[index].ID, summary)
		}
	}
	markGroupDirtyForApps(&state, id, false)

	if err := saveState(state); err != nil {
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

	selected := make(map[string]bool, len(groupIDs))
	for _, id := range groupIDs {
		id = strings.TrimSpace(id)
		index, ok := groupIndexByID(state.Groups, id)
		if !ok || state.Groups[index].Deleted {
			a.redirectError(w, r, tab, fmt.Errorf("group %s is not available for deletion", id))
			return
		}
		selected[id] = true
	}

	if scimEnabled(state) {
		for i := range state.Groups {
			if !selected[state.Groups[i].ID] {
				continue
			}
			state.Groups[i].Deleted = true
			state.Groups[i].Dirty = true
			state.Groups[i].LastError = ""
			markGroupDirtyForApps(&state, state.Groups[i].ID, true)
			appendLocalOperationLog(&state, "group", state.Groups[i].ID, "Marked for deletion in bulk")
		}
	} else {
		keptGroups := make([]group, 0, len(state.Groups)-len(selected))
		for _, g := range state.Groups {
			if !selected[g.ID] {
				keptGroups = append(keptGroups, g)
			}
		}
		state.Groups = keptGroups
	}

	if err := saveState(state); err != nil {
		a.redirectError(w, r, tab, err)
		return
	}

	message := fmt.Sprintf("deleted %d groups", len(selected))
	if scimEnabled(state) {
		message = fmt.Sprintf("marked %d groups for deletion", len(selected))
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
	if !scimEnabled(state) {
		if !deleted {
			a.redirectError(w, r, tab, fmt.Errorf("SCIM is disabled"))
			return
		}
		state.Groups = append(state.Groups[:index], state.Groups[index+1:]...)
		if err := saveState(state); err != nil {
			a.redirectError(w, r, tab, err)
			return
		}
		redirectWithFlash(w, r, dashboardURLWithPage("groups", formPage(r), formPageSize(r), formSearch(r), nil), flashMessage{Kind: "success", Message: "group deleted"})
		return
	}

	state.Groups[index].Deleted = deleted
	state.Groups[index].Dirty = true
	state.Groups[index].LastError = ""
	markGroupDirtyForApps(&state, id, deleted)
	appendLocalOperationLog(&state, "group", state.Groups[index].ID, localDeleteSummary(deleted))

	if err := saveState(state); err != nil {
		a.redirectError(w, r, tab, err)
		return
	}

	status := "group restored"
	if deleted {
		status = "group marked for deletion"
	}
	redirectWithFlash(w, r, dashboardURLWithPage("groups", formPage(r), formPageSize(r), formSearch(r), nil), flashMessage{Kind: "success", Message: status})
}
