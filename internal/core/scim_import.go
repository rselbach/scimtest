package core

import (
	"strings"
)

func replaceStateFromSCIM(state AppState, userResources []SCIMUserResource, groupResources []SCIMGroupResource) (AppState, int, error) {
	importedUsers := make([]User, 0, len(userResources))
	remoteToLocalUserID := make(map[string]string, len(userResources))

	for _, resource := range userResources {
		importedUser, err := importedUserFromSCIM(state.Users, resource)
		if err != nil {
			return AppState{}, 0, err
		}
		importedUsers = append(importedUsers, importedUser)
		if importedUser.RemoteID != "" {
			remoteToLocalUserID[importedUser.RemoteID] = importedUser.ID
		}
	}

	importedGroups := make([]Group, 0, len(groupResources))
	skippedMembers := 0
	for _, resource := range groupResources {
		importedGroup, skipped, err := importedGroupFromSCIM(state.Groups, resource, remoteToLocalUserID)
		if err != nil {
			return AppState{}, 0, err
		}
		importedGroups = append(importedGroups, importedGroup)
		skippedMembers += skipped
	}

	state.Users = importedUsers
	state.Groups = importedGroups

	for _, importedUser := range importedUsers {
		AppendLocalOperationLog(&state, "user", importedUser.ID, "Imported from SCIM")
	}
	for _, importedGroup := range importedGroups {
		AppendLocalOperationLog(&state, "group", importedGroup.ID, "Imported from SCIM")
	}

	return state, skippedMembers, nil
}

func importedUserFromSCIM(existingUsers []User, resource SCIMUserResource) (User, error) {
	localID := strings.TrimSpace(resource.ExternalID)
	if localID == "" {
		if matched, ok := importedUserMatch(existingUsers, resource); ok {
			localID = matched.ID
		} else {
			var err error
			localID, err = NewUserID()
			if err != nil {
				return User{}, err
			}
		}
	}

	username := strings.TrimSpace(resource.UserName)
	if username == "" {
		username = strings.TrimSpace(firstNonEmpty(resource.DisplayName, resource.ID))
	}

	email := firstNonEmpty(firstSCIMEmail(resource.Emails), username)
	active := true
	if resource.Active != nil {
		active = *resource.Active
	}

	givenName := ""
	familyName := ""
	if resource.Name != nil {
		givenName = strings.TrimSpace(resource.Name.GivenName)
		familyName = strings.TrimSpace(resource.Name.FamilyName)
	}
	if givenName == "" || familyName == "" {
		fallbackGiven, fallbackFamily := SplitName(firstNonEmpty(resource.DisplayName, username))
		if givenName == "" {
			givenName = fallbackGiven
		}
		if familyName == "" {
			familyName = fallbackFamily
		}
	}

	return User{
		ID:         localID,
		GivenName:  givenName,
		FamilyName: familyName,
		Email:      email,
		Username:   username,
		Active:     active,
		RemoteID:   strings.TrimSpace(resource.ID),
		Dirty:      false,
		Deleted:    false,
		LastError:  "",
	}, nil
}

func importedGroupFromSCIM(existingGroups []Group, resource SCIMGroupResource, remoteToLocalUserID map[string]string) (Group, int, error) {
	localID := strings.TrimSpace(resource.ExternalID)
	if localID == "" {
		remoteID := strings.TrimSpace(resource.ID)
		for _, existing := range existingGroups {
			if remoteID != "" && existing.RemoteID == remoteID {
				localID = existing.ID
				break
			}
		}
		if localID == "" {
			var err error
			localID, err = NewGroupID()
			if err != nil {
				return Group{}, 0, err
			}
		}
	}

	// Members that do not resolve to an imported user are skipped rather
	// than failing the import: RFC 7643 section 4.2 allows Group-type
	// members (nested groups), which this directory does not model.
	memberIDs := make([]string, 0, len(resource.Members))
	skipped := 0
	for _, member := range resource.Members {
		localUserID, ok := remoteToLocalUserID[strings.TrimSpace(member.Value)]
		if !ok {
			skipped++
			continue
		}
		memberIDs = append(memberIDs, localUserID)
	}

	return Group{
		ID:          localID,
		DisplayName: strings.TrimSpace(resource.DisplayName),
		MemberIDs:   memberIDs,
		RemoteID:    strings.TrimSpace(resource.ID),
		Dirty:       false,
		Deleted:     false,
		LastError:   "",
	}, skipped, nil
}

func importedUserIndex(users []User, resource SCIMUserResource, localID string) (int, bool) {
	if localID != "" {
		for i, existing := range users {
			if existing.ID == localID {
				return i, true
			}
		}
	}

	remoteID := strings.TrimSpace(resource.ID)
	if remoteID != "" {
		for i, existing := range users {
			if existing.RemoteID == remoteID {
				return i, true
			}
		}
	}

	return 0, false
}

func importedUserMatch(users []User, resource SCIMUserResource) (User, bool) {
	if index, ok := importedUserIndex(users, resource, strings.TrimSpace(resource.ExternalID)); ok {
		return users[index], true
	}

	return User{}, false
}

func firstSCIMEmail(emails []SCIMEmail) string {
	for _, email := range emails {
		value := strings.TrimSpace(email.Value)
		if value != "" {
			return value
		}
	}

	return ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}

	return ""
}
