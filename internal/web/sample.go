package web

import (
	"fmt"
	"net/http"
	"strings"
)

// The Greendale sample is a small realistic directory for first runs and
// demos: ten named users and three overlapping groups. One user is inactive
// so deactivation paths get exercised on the first sync. Every user has
// enterprise attributes, a role attribute, and, except the Dean, a manager.
var sampleUsers = []struct {
	given      string
	family     string
	username   string
	email      string
	active     bool
	employee   string
	department string
	division   string
	costCenter string
	manager    string
	role       string
}{
	{given: "Troy", family: "Barnes", username: "tbarnes", email: "troy.barnes@greendale.edu", active: true, employee: "GC-1001", department: "Air Conditioning Repair", division: "Facilities", costCenter: "3100", manager: "dpelton", role: "student"},
	{given: "Abed", family: "Nadir", username: "anadir", email: "abed.nadir@greendale.edu", active: true, employee: "GC-1002", department: "Film Studies", division: "Academics", costCenter: "2100", manager: "jwinger", role: "student"},
	{given: "Annie", family: "Edison", username: "aedison", email: "annie.edison@greendale.edu", active: true, employee: "GC-1003", department: "Criminology", division: "Academics", costCenter: "2200", manager: "jwinger", role: "student"},
	{given: "Britta", family: "Perry", username: "bperry", email: "britta.perry@greendale.edu", active: true, employee: "GC-1004", department: "Psychology", division: "Academics", costCenter: "2300", manager: "jwinger", role: "student"},
	{given: "Shirley", family: "Bennett", username: "sbennett", email: "shirley.bennett@greendale.edu", active: true, employee: "GC-1005", department: "Business", division: "Academics", costCenter: "2400", manager: "jwinger", role: "student"},
	{given: "Jeff", family: "Winger", username: "jwinger", email: "jeff.winger@greendale.edu", active: true, employee: "GC-1006", department: "Law", division: "Academics", costCenter: "2500", manager: "dpelton", role: "faculty"},
	{given: "Dean", family: "Pelton", username: "dpelton", email: "dean.pelton@greendale.edu", active: true, employee: "GC-0001", department: "Office of the Dean", division: "Administration", costCenter: "1000", role: "admin"},
	{given: "Señor", family: "Chang", username: "schang", email: "senor.chang@greendale.edu", active: false, employee: "GC-0666", department: "Spanish", division: "Academics", costCenter: "2600", manager: "dpelton", role: "faculty"},
	{given: "Leonard", family: "Rodriguez", username: "lrodriguez", email: "leonard.rodriguez@greendale.edu", active: true, employee: "GC-1007", department: "Continuing Education", division: "Academics", costCenter: "2700", manager: "dpelton", role: "student"},
	{given: "Magnitude", family: "PopPop", username: "magnitude", email: "magnitude@greendale.edu", active: true, employee: "GC-1008", department: "Air Conditioning Repair", division: "Facilities", costCenter: "3100", manager: "tbarnes", role: "student"},
}

const sampleOrganization = "Greendale Community College"

var sampleGroups = []struct {
	name      string
	usernames []string
}{
	{name: "Study Group", usernames: []string{"tbarnes", "anadir", "aedison", "bperry", "sbennett", "jwinger"}},
	{name: "Faculty", usernames: []string{"dpelton", "schang"}},
	{name: "Air Conditioning Repair Annex", usernames: []string{"tbarnes", "magnitude"}},
}

// appendSampleDirectory adds the sample users and groups that do not exist
// yet, keyed by username, email, and group display name. Existing resources
// are left untouched, so loading the sample twice is a no-op.
func appendSampleDirectory(state *appState) (usersAdded, groupsAdded int, err error) {
	userIDs := make(map[string]string, len(state.Users)+len(sampleUsers))
	usedEmails := make(map[string]struct{}, len(state.Users)+len(sampleUsers))
	for _, u := range state.Users {
		userIDs[strings.ToLower(u.Username)] = u.ID
		usedEmails[strings.ToLower(u.Email)] = struct{}{}
	}

	addedManagers := make(map[int]string, len(sampleUsers))
	for _, sample := range sampleUsers {
		if _, ok := userIDs[sample.username]; ok {
			continue
		}
		if _, ok := usedEmails[strings.ToLower(sample.email)]; ok {
			continue
		}
		if err := validateUser(sample.given, sample.email, sample.username); err != nil {
			return usersAdded, groupsAdded, err
		}
		id, err := newUserID()
		if err != nil {
			return usersAdded, groupsAdded, err
		}
		addedManagers[len(state.Users)] = sample.manager
		state.Users = append(state.Users, user{
			ID:             id,
			GivenName:      sample.given,
			FamilyName:     sample.family,
			Username:       sample.username,
			Email:          sample.email,
			Active:         sample.active,
			EmployeeNumber: sample.employee,
			Department:     sample.department,
			Division:       sample.division,
			Organization:   sampleOrganization,
			CostCenter:     sample.costCenter,
			Attributes:     map[string]string{"role": sample.role},
			Dirty:          true,
		})
		appendLocalOperationLog(state, "user", id, "Created by the Greendale sample")
		userIDs[sample.username] = id
		usedEmails[strings.ToLower(sample.email)] = struct{}{}
		usersAdded++
	}
	// Managers resolve by username once every sample user exists, so a
	// manager listed later in the sample still links.
	for index, managerUsername := range addedManagers {
		state.Users[index].ManagerID = userIDs[managerUsername]
	}

	groupNames := make(map[string]struct{}, len(state.Groups))
	for _, g := range state.Groups {
		groupNames[strings.ToLower(g.DisplayName)] = struct{}{}
	}
	for _, sample := range sampleGroups {
		if _, ok := groupNames[strings.ToLower(sample.name)]; ok {
			continue
		}
		var memberIDs []string
		for _, username := range sample.usernames {
			if id, ok := userIDs[username]; ok {
				memberIDs = append(memberIDs, id)
			}
		}
		id, err := newGroupID()
		if err != nil {
			return usersAdded, groupsAdded, err
		}
		state.Groups = append(state.Groups, group{
			ID:          id,
			DisplayName: sample.name,
			MemberIDs:   memberIDs,
			Dirty:       true,
		})
		appendLocalOperationLog(state, "group", id, "Created by the Greendale sample")
		groupNames[strings.ToLower(sample.name)] = struct{}{}
		groupsAdded++
	}

	return usersAdded, groupsAdded, nil
}

func (a *webApp) handleToolsSeedSample(w http.ResponseWriter, r *http.Request) {
	tab := normalizedTab(r.FormValue("tab"))
	a.mu.Lock()
	defer a.mu.Unlock()

	state, err := loadRequestState(r)
	if err != nil {
		a.redirectError(w, r, tab, err)
		return
	}

	firstNewUser := len(state.Users)
	firstNewGroup := len(state.Groups)
	usersAdded, groupsAdded, err := appendSampleDirectory(&state)
	if err != nil {
		a.redirectToolsError(w, r, tab, err)
		return
	}
	if usersAdded == 0 && groupsAdded == 0 {
		redirectWithFlash(w, r, dashboardURL("users", nil), flashMessage{Kind: "success", Message: "the Greendale sample is already loaded"})
		return
	}
	for _, created := range state.Users[firstNewUser:] {
		markUserDirty(&state, created.ID, false)
	}
	for _, created := range state.Groups[firstNewGroup:] {
		markGroupDirty(&state, created.ID, false)
	}
	if err := saveRequestState(state); err != nil {
		a.redirectError(w, r, tab, err)
		return
	}

	message := fmt.Sprintf("loaded the Greendale sample: %d users and %d groups", usersAdded, groupsAdded)
	redirectWithFlash(w, r, dashboardURL("users", nil), flashMessage{Kind: "success", Message: message})
}
