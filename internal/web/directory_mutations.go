package web

import "fmt"

func setUserDeleted(state *appState, index int, deleted bool, summary string) {
	id := state.Users[index].ID
	if !scimTracksDirectory(*state) {
		state.Users = append(state.Users[:index], state.Users[index+1:]...)
		for i := range state.Groups {
			state.Groups[i].MemberIDs = removeString(state.Groups[i].MemberIDs, id)
		}
		return
	}
	state.Users[index].Deleted = deleted
	state.Users[index].Dirty = true
	state.Users[index].LastError = ""
	markUserDirty(state, id, deleted)
	appendLocalOperationLog(state, "user", id, summary)
}

func setGroupDeleted(state *appState, index int, deleted bool, summary string) {
	id := state.Groups[index].ID
	if !scimTracksDirectory(*state) {
		state.Groups = append(state.Groups[:index], state.Groups[index+1:]...)
		return
	}
	state.Groups[index].Deleted = deleted
	state.Groups[index].Dirty = true
	state.Groups[index].LastError = ""
	markGroupDirty(state, id, deleted)
	appendLocalOperationLog(state, "group", id, summary)
}

func deleteUsers(state *appState, ids []string) (int, error) {
	selected := make(map[string]bool, len(ids))
	for _, id := range ids {
		index, ok := userIndexByID(state.Users, id)
		if !ok || state.Users[index].Deleted {
			return 0, fmt.Errorf("user %s is not available for deletion", id)
		}
		selected[id] = true
	}
	if scimTracksDirectory(*state) {
		for i := range state.Users {
			if selected[state.Users[i].ID] {
				setUserDeleted(state, i, true, "Marked for deletion in bulk")
			}
		}
		return len(selected), nil
	}
	kept := make([]user, 0, len(state.Users)-len(selected))
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
	return len(selected), nil
}

func deleteGroups(state *appState, ids []string) (int, error) {
	selected := make(map[string]bool, len(ids))
	for _, id := range ids {
		index, ok := groupIndexByID(state.Groups, id)
		if !ok || state.Groups[index].Deleted {
			return 0, fmt.Errorf("group %s is not available for deletion", id)
		}
		selected[id] = true
	}
	if scimTracksDirectory(*state) {
		for i := range state.Groups {
			if selected[state.Groups[i].ID] {
				setGroupDeleted(state, i, true, "Marked for deletion in bulk")
			}
		}
		return len(selected), nil
	}
	kept := make([]group, 0, len(state.Groups)-len(selected))
	for _, found := range state.Groups {
		if !selected[found.ID] {
			kept = append(kept, found)
		}
	}
	state.Groups = kept
	return len(selected), nil
}
