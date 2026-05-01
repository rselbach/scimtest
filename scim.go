package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode"
)

const scimUserSchema = "urn:ietf:params:scim:schemas:core:2.0:User"
const scimGroupSchema = "urn:ietf:params:scim:schemas:core:2.0:Group"

const ansiReset = "\x1b[0m"
const ansiJSONKey = "\x1b[38;5;12m"
const ansiJSONString = "\x1b[38;5;10m"
const ansiJSONNumber = "\x1b[38;5;14m"
const ansiJSONBool = "\x1b[1;38;5;13m"
const ansiJSONNull = "\x1b[38;5;8m"
const ansiJSONPunct = "\x1b[38;5;241m"

type scimClient struct {
	baseURL string
	token   string
	client  *http.Client
	traces  []syncTraceEntry
}

type traceTarget struct {
	ResourceType string
	ResourceID   string
	Label        string
	Operation    string
}

type scimEmail struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

type scimName struct {
	GivenName  string `json:"givenName,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
	Formatted  string `json:"formatted,omitempty"`
}

type scimUserResource struct {
	Schemas     []string    `json:"schemas"`
	ID          string      `json:"id,omitempty"`
	ExternalID  string      `json:"externalId,omitempty"`
	UserName    string      `json:"userName"`
	DisplayName string      `json:"displayName,omitempty"`
	Active      *bool       `json:"active,omitempty"`
	Name        *scimName   `json:"name,omitempty"`
	Emails      []scimEmail `json:"emails,omitempty"`
}

type scimMember struct {
	Value string `json:"value"`
	Type  string `json:"type,omitempty"`
}

type scimGroupResource struct {
	Schemas     []string     `json:"schemas"`
	ID          string       `json:"id,omitempty"`
	ExternalID  string       `json:"externalId,omitempty"`
	DisplayName string       `json:"displayName"`
	Members     []scimMember `json:"members,omitempty"`
}

type syncResult struct {
	state   appState
	status  string
	fatal   error
	changed bool
	traces  []syncTraceEntry
}

type importResult struct {
	state  appState
	status string
	fatal  error
	traces []syncTraceEntry
}

type syncTraceEntry struct {
	ResourceType string
	ResourceID   string
	Label        string
	Operation    string
	Method       string
	Path         string
	RequestBody  string
	Status       string
	ResponseBody string
	Err          string
	CreatedAt    string
}

type scimListResponse[T any] struct {
	TotalResults int `json:"totalResults"`
	StartIndex   int `json:"startIndex"`
	ItemsPerPage int `json:"itemsPerPage"`
	Resources    []T `json:"Resources"`
}

func newSCIMClient(cfg config) (*scimClient, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	token := strings.TrimSpace(cfg.BearerToken)

	switch {
	case baseURL == "":
		return nil, fmt.Errorf("SCIM base URL is required")
	case token == "":
		return nil, fmt.Errorf("SCIM bearer token is required")
	}

	if _, err := url.Parse(baseURL); err != nil {
		return nil, fmt.Errorf("parse SCIM base URL %q: %w", baseURL, err)
	}

	return &scimClient{
		baseURL: baseURL,
		token:   token,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		traces: make([]syncTraceEntry, 0, 16),
	}, nil
}

func syncDirtyState(state appState) syncResult {
	client, err := newSCIMClient(state.Config)
	if err != nil {
		return syncResult{fatal: err}
	}

	state, userCounts := syncDirtyUsers(client, state)
	state, groupCounts := syncDirtyGroups(client, state)
	status := fmt.Sprintf(
		"sync finished: users %d created, %d updated, %d deleted, %d failed; groups %d created, %d updated, %d deleted, %d failed",
		userCounts.created,
		userCounts.updated,
		userCounts.deleted,
		userCounts.failed,
		groupCounts.created,
		groupCounts.updated,
		groupCounts.deleted,
		groupCounts.failed,
	)

	return syncResult{
		state:   state,
		status:  status,
		changed: userCounts.total()+groupCounts.total() > 0,
		traces:  client.traces,
	}
}

func importStateFromSCIM(state appState) importResult {
	client, err := newSCIMClient(state.Config)
	if err != nil {
		return importResult{fatal: err}
	}

	userResources, err := client.listUsers()
	if err != nil {
		return importResult{fatal: err, traces: client.traces}
	}

	groupResources, err := client.listGroups()
	if err != nil {
		return importResult{fatal: err, traces: client.traces}
	}

	updatedState, err := replaceStateFromSCIM(state, userResources, groupResources)
	if err != nil {
		return importResult{fatal: err, traces: client.traces}
	}

	return importResult{
		state:  updatedState,
		status: fmt.Sprintf("imported %d users and %d groups from SCIM", len(updatedState.Users), len(updatedState.Groups)),
		traces: client.traces,
	}
}

type syncCounts struct {
	created int
	updated int
	deleted int
	failed  int
}

func (c syncCounts) total() int {
	return c.created + c.updated + c.deleted + c.failed
}

func syncDirtyUsers(client *scimClient, state appState) (appState, syncCounts) {

	nextUsers := make([]user, 0, len(state.Users))
	counts := syncCounts{}

	for _, u := range state.Users {
		if !u.Dirty {
			nextUsers = append(nextUsers, u)
			continue
		}

		u.LastError = ""

		switch {
		case u.Deleted && u.RemoteID == "":
			counts.deleted++
			continue
		case u.Deleted:
			if err := client.deleteUser(u, "delete"); err != nil {
				u.LastError = err.Error()
				counts.failed++
				nextUsers = append(nextUsers, u)
				continue
			}

			counts.deleted++
		case u.RemoteID == "":
			remoteID, err := client.createUser(u)
			if err != nil {
				u.LastError = err.Error()
				counts.failed++
				nextUsers = append(nextUsers, u)
				continue
			}

			u.RemoteID = remoteID
			u.Dirty = false
			counts.created++
			nextUsers = append(nextUsers, u)
		default:
			if err := client.replaceUser(u); err != nil {
				u.LastError = err.Error()
				counts.failed++
				nextUsers = append(nextUsers, u)
				continue
			}

			u.Dirty = false
			counts.updated++
			nextUsers = append(nextUsers, u)
		}
	}

	state.Users = nextUsers
	return state, counts
}

func syncDirtyGroups(client *scimClient, state appState) (appState, syncCounts) {
	nextGroups := make([]group, 0, len(state.Groups))
	counts := syncCounts{}

	for _, g := range state.Groups {
		if !g.Dirty {
			nextGroups = append(nextGroups, g)
			continue
		}

		g.LastError = ""

		switch {
		case g.Deleted && g.RemoteID == "":
			counts.deleted++
			continue
		case g.Deleted:
			if err := client.deleteGroup(g, "delete"); err != nil {
				g.LastError = err.Error()
				counts.failed++
				nextGroups = append(nextGroups, g)
				continue
			}

			counts.deleted++
		case g.RemoteID == "":
			remoteID, err := client.createGroup(g, state.Users)
			if err != nil {
				g.LastError = err.Error()
				counts.failed++
				nextGroups = append(nextGroups, g)
				continue
			}

			g.RemoteID = remoteID
			g.Dirty = false
			counts.created++
			nextGroups = append(nextGroups, g)
		default:
			if err := client.replaceGroup(g, state.Users); err != nil {
				g.LastError = err.Error()
				counts.failed++
				nextGroups = append(nextGroups, g)
				continue
			}

			g.Dirty = false
			counts.updated++
			nextGroups = append(nextGroups, g)
		}
	}

	state.Groups = nextGroups
	return state, counts
}

func (c *scimClient) createUser(u user) (string, error) {
	resource := newSCIMUserResource(u)

	var response scimUserResource
	if err := c.doJSON(http.MethodPost, "/Users", resource, &response, traceTargetForUser(u, "create")); err != nil {
		return "", err
	}

	if strings.TrimSpace(response.ID) == "" {
		return "", fmt.Errorf("SCIM create response missing id")
	}

	return response.ID, nil
}

func (c *scimClient) listUsers() ([]scimUserResource, error) {
	resources := make([]scimUserResource, 0, 32)
	startIndex := 1
	count := 100

	for {
		path := fmt.Sprintf("/Users?startIndex=%d&count=%d", startIndex, count)
		var response scimListResponse[scimUserResource]
		if err := c.doJSON(http.MethodGet, path, nil, &response, traceTarget{
			ResourceType: "user",
			Label:        "SCIM /Users",
			Operation:    "import",
		}); err != nil {
			return nil, err
		}

		resources = append(resources, response.Resources...)
		if len(response.Resources) == 0 {
			return resources, nil
		}

		nextIndex := startIndex + len(response.Resources)
		if response.StartIndex > 0 {
			nextIndex = response.StartIndex + len(response.Resources)
		}
		if response.TotalResults > 0 && nextIndex > response.TotalResults {
			return resources, nil
		}
		if response.ItemsPerPage > 0 && len(response.Resources) < response.ItemsPerPage {
			return resources, nil
		}
		if response.TotalResults == 0 && response.ItemsPerPage == 0 && len(response.Resources) < count {
			return resources, nil
		}

		startIndex = nextIndex
	}
}

func (c *scimClient) listGroups() ([]scimGroupResource, error) {
	resources := make([]scimGroupResource, 0, 32)
	startIndex := 1
	count := 100

	for {
		path := fmt.Sprintf("/Groups?startIndex=%d&count=%d", startIndex, count)
		var response scimListResponse[scimGroupResource]
		if err := c.doJSON(http.MethodGet, path, nil, &response, traceTarget{
			ResourceType: "group",
			Label:        "SCIM /Groups",
			Operation:    "import",
		}); err != nil {
			return nil, err
		}

		resources = append(resources, response.Resources...)
		if len(response.Resources) == 0 {
			return resources, nil
		}

		nextIndex := startIndex + len(response.Resources)
		if response.StartIndex > 0 {
			nextIndex = response.StartIndex + len(response.Resources)
		}
		if response.TotalResults > 0 && nextIndex > response.TotalResults {
			return resources, nil
		}
		if response.ItemsPerPage > 0 && len(response.Resources) < response.ItemsPerPage {
			return resources, nil
		}
		if response.TotalResults == 0 && response.ItemsPerPage == 0 && len(response.Resources) < count {
			return resources, nil
		}

		startIndex = nextIndex
	}
}

func (c *scimClient) replaceUser(u user) error {
	resource := newSCIMUserResource(u)
	resource.ID = u.RemoteID

	return c.doJSON(http.MethodPut, "/Users/"+url.PathEscape(u.RemoteID), resource, nil, traceTargetForUser(u, "update"))
}

func newSCIMUserResource(u user) scimUserResource {
	active := u.Active
	formattedName := fullName(u)
	resource := scimUserResource{
		Schemas:     []string{scimUserSchema},
		ExternalID:  u.ID,
		UserName:    strings.TrimSpace(u.Username),
		DisplayName: formattedName,
		Active:      &active,
		Emails: []scimEmail{{
			Value:   strings.TrimSpace(u.Email),
			Type:    "work",
			Primary: true,
		}},
	}

	resource.Name = &scimName{
		GivenName:  strings.TrimSpace(u.GivenName),
		FamilyName: strings.TrimSpace(u.FamilyName),
		Formatted:  formattedName,
	}

	return resource
}

func (c *scimClient) deleteUser(u user, operation string) error {
	return c.doJSON(http.MethodDelete, "/Users/"+url.PathEscape(u.RemoteID), nil, nil, traceTargetForUser(u, operation))
}

func (c *scimClient) createGroup(g group, users []user) (string, error) {
	resource, err := newSCIMGroupResource(g, users)
	if err != nil {
		return "", err
	}

	var response scimGroupResource
	if err := c.doJSON(http.MethodPost, "/Groups", resource, &response, traceTargetForGroup(g, "create")); err != nil {
		return "", err
	}

	if strings.TrimSpace(response.ID) == "" {
		return "", fmt.Errorf("SCIM create group response missing id")
	}

	return response.ID, nil
}

func (c *scimClient) replaceGroup(g group, users []user) error {
	resource, err := newSCIMGroupResource(g, users)
	if err != nil {
		return err
	}
	resource.ID = g.RemoteID

	return c.doJSON(http.MethodPut, "/Groups/"+url.PathEscape(g.RemoteID), resource, nil, traceTargetForGroup(g, "update"))
}

func (c *scimClient) deleteGroup(g group, operation string) error {
	return c.doJSON(http.MethodDelete, "/Groups/"+url.PathEscape(g.RemoteID), nil, nil, traceTargetForGroup(g, operation))
}

func newSCIMGroupResource(g group, users []user) (scimGroupResource, error) {
	members := make([]scimMember, 0, len(g.MemberIDs))
	for _, memberID := range g.MemberIDs {
		user, ok := userByID(users, memberID)
		if !ok {
			return scimGroupResource{}, fmt.Errorf("group %q references unknown user %q", g.DisplayName, memberID)
		}
		if strings.TrimSpace(user.RemoteID) == "" {
			return scimGroupResource{}, fmt.Errorf("group %q member %q has not been synced yet", g.DisplayName, userLabel(user))
		}

		members = append(members, scimMember{Value: user.RemoteID, Type: "User"})
	}

	return scimGroupResource{
		Schemas:     []string{scimGroupSchema},
		ExternalID:  g.ID,
		DisplayName: strings.TrimSpace(g.DisplayName),
		Members:     members,
	}, nil
}

func userByID(users []user, id string) (user, bool) {
	for _, u := range users {
		if u.ID == id {
			return u, true
		}
	}

	return user{}, false
}

func (c *scimClient) doJSON(method string, path string, body any, out any, target traceTarget) error {
	var reader io.Reader
	requestBody := ""
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode SCIM %s %s body: %w", method, path, err)
		}

		requestBody = string(payload)
		reader = bytes.NewReader(payload)
	}

	req, err := http.NewRequest(method, c.baseURL+path, reader)
	if err != nil {
		return fmt.Errorf("build SCIM %s %s request: %w", method, path, err)
	}

	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/scim+json")
	if body != nil {
		req.Header.Set("Content-Type", "application/scim+json")
	}

	trace := syncTraceEntry{
		ResourceType: target.ResourceType,
		ResourceID:   target.ResourceID,
		Label:        target.Label,
		Operation:    target.Operation,
		Method:       method,
		Path:         path,
		RequestBody:  requestBody,
		CreatedAt:    time.Now().UTC().Format(time.RFC3339),
	}

	resp, err := c.client.Do(req)
	if err != nil {
		trace.Err = err.Error()
		c.traces = append(c.traces, trace)
		return fmt.Errorf("run SCIM %s %s request: %w", method, path, err)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		trace.Status = resp.Status
		if closeErr := resp.Body.Close(); closeErr != nil {
			trace.Err = fmt.Sprintf("%v (close body: %v)", err, closeErr)
			c.traces = append(c.traces, trace)
			return fmt.Errorf("read SCIM %s %s response: %w (close body: %v)", method, path, err, closeErr)
		}

		trace.Err = err.Error()
		c.traces = append(c.traces, trace)
		return fmt.Errorf("read SCIM %s %s response: %w", method, path, err)
	}
	trace.Status = resp.Status
	trace.ResponseBody = strings.TrimSpace(string(data))

	if err := resp.Body.Close(); err != nil {
		trace.Err = err.Error()
		c.traces = append(c.traces, trace)
		return fmt.Errorf("close SCIM %s %s response body: %w", method, path, err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		c.traces = append(c.traces, trace)
		if requestBody == "" {
			return fmt.Errorf("SCIM %s %s returned %s: %s", method, path, resp.Status, strings.TrimSpace(string(data)))
		}

		return fmt.Errorf("SCIM %s %s returned %s: %s | request body: %s", method, path, resp.Status, strings.TrimSpace(string(data)), requestBody)
	}

	c.traces = append(c.traces, trace)

	if out == nil || len(data) == 0 {
		return nil
	}

	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decode SCIM %s %s response: %w", method, path, err)
	}

	return nil
}

func traceTargetForUser(u user, operation string) traceTarget {
	return traceTarget{
		ResourceType: "user",
		ResourceID:   u.ID,
		Label:        userLabel(u),
		Operation:    operation,
	}
}

func traceTargetForGroup(g group, operation string) traceTarget {
	return traceTarget{
		ResourceType: "group",
		ResourceID:   g.ID,
		Label:        g.DisplayName,
		Operation:    operation,
	}
}

func replaceStateFromSCIM(state appState, userResources []scimUserResource, groupResources []scimGroupResource) (appState, error) {
	importedUsers := make([]user, 0, len(userResources))
	remoteToLocalUserID := make(map[string]string, len(userResources))

	for _, resource := range userResources {
		importedUser, err := importedUserFromSCIM(nil, resource)
		if err != nil {
			return appState{}, err
		}
		importedUsers = append(importedUsers, importedUser)
		if importedUser.RemoteID != "" {
			remoteToLocalUserID[importedUser.RemoteID] = importedUser.ID
		}
	}

	importedGroups := make([]group, 0, len(groupResources))
	for _, resource := range groupResources {
		importedGroup, err := importedGroupFromSCIM(resource, remoteToLocalUserID)
		if err != nil {
			return appState{}, err
		}
		importedGroups = append(importedGroups, importedGroup)
	}

	state.Users = importedUsers
	state.Groups = importedGroups
	state.UserOperations = make(map[string][]operationLog, len(importedUsers))
	state.GroupOperations = make(map[string][]operationLog, len(importedGroups))

	for _, importedUser := range importedUsers {
		appendLocalOperationLog(&state, "user", importedUser.ID, "Imported from SCIM")
	}
	for _, importedGroup := range importedGroups {
		appendLocalOperationLog(&state, "group", importedGroup.ID, "Imported from SCIM")
	}

	return state, nil
}

func importedUserFromSCIM(existingUsers []user, resource scimUserResource) (user, error) {
	localID := strings.TrimSpace(resource.ExternalID)
	if localID == "" {
		if matched, ok := importedUserMatch(existingUsers, resource); ok {
			localID = matched.ID
		} else {
			var err error
			localID, err = newUserID()
			if err != nil {
				return user{}, err
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
		fallbackGiven, fallbackFamily := splitName(firstNonEmpty(resource.DisplayName, username))
		if givenName == "" {
			givenName = fallbackGiven
		}
		if familyName == "" {
			familyName = fallbackFamily
		}
	}

	return user{
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

func importedGroupFromSCIM(resource scimGroupResource, remoteToLocalUserID map[string]string) (group, error) {
	localID := strings.TrimSpace(resource.ExternalID)
	if localID == "" {
		var err error
		localID, err = newGroupID()
		if err != nil {
			return group{}, err
		}
	}

	memberIDs := make([]string, 0, len(resource.Members))
	for _, member := range resource.Members {
		localUserID, ok := remoteToLocalUserID[strings.TrimSpace(member.Value)]
		if !ok {
			return group{}, fmt.Errorf("group %q references unknown imported user %q", strings.TrimSpace(resource.DisplayName), strings.TrimSpace(member.Value))
		}
		memberIDs = append(memberIDs, localUserID)
	}

	return group{
		ID:          localID,
		DisplayName: strings.TrimSpace(resource.DisplayName),
		MemberIDs:   memberIDs,
		RemoteID:    strings.TrimSpace(resource.ID),
		Dirty:       false,
		Deleted:     false,
		LastError:   "",
	}, nil
}

func importedUserIndex(users []user, resource scimUserResource, localID string) (int, bool) {
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

func importedUserMatch(users []user, resource scimUserResource) (user, bool) {
	if index, ok := importedUserIndex(users, resource, strings.TrimSpace(resource.ExternalID)); ok {
		return users[index], true
	}

	return user{}, false
}

func firstSCIMEmail(emails []scimEmail) string {
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

func formatSyncTraces(traces []syncTraceEntry) string {
	if len(traces) == 0 {
		return "No sync requests were made."
	}

	lines := make([]string, 0, len(traces)*8)
	for i, trace := range traces {
		lines = append(lines, fmt.Sprintf("[%d] %s %s %s", i+1, trace.CreatedAt, trace.Method, trace.Path))
		if trace.Operation != "" || trace.Label != "" {
			lines = append(lines, fmt.Sprintf("Target: %s %s (%s)", trace.ResourceType, trace.Label, trace.Operation))
		}
		if trace.RequestBody != "" {
			lines = append(lines, "Request:")
			lines = append(lines, indentBlock(prettyJSON(trace.RequestBody), "  "))
		}
		if trace.Status != "" {
			lines = append(lines, "Response Status: "+trace.Status)
		}
		if trace.ResponseBody != "" {
			lines = append(lines, "Response Body:")
			lines = append(lines, indentBlock(prettyJSON(trace.ResponseBody), "  "))
		}
		if trace.Err != "" {
			lines = append(lines, "Error: "+trace.Err)
		}
		if i < len(traces)-1 {
			lines = append(lines, strings.Repeat("-", 48))
		}
	}

	return strings.Join(lines, "\n")
}

func prettyJSON(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return raw
	}

	var decoded any
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		return raw
	}

	canonical := normalizeJSON(decoded)
	formatted, err := json.MarshalIndent(canonical, "", "  ")
	if err != nil {
		return raw
	}

	return highlightJSON(string(formatted))
}

func highlightJSON(formatted string) string {
	var out strings.Builder
	for i := 0; i < len(formatted); {
		switch ch := formatted[i]; {
		case ch == '"':
			end := scanJSONString(formatted, i)
			token := formatted[i:end]
			next := nextNonSpaceByte(formatted, end)
			if next == ':' {
				out.WriteString(colorizeANSI(token, ansiJSONKey))
			} else {
				out.WriteString(colorizeANSI(token, ansiJSONString))
			}
			i = end
		case isJSONPunctuation(ch):
			out.WriteString(colorizeANSI(string(ch), ansiJSONPunct))
			i++
		case isJSONNumberStart(ch):
			end := scanJSONLiteral(formatted, i)
			out.WriteString(colorizeANSI(formatted[i:end], ansiJSONNumber))
			i = end
		case strings.HasPrefix(formatted[i:], "true") || strings.HasPrefix(formatted[i:], "false"):
			end := scanJSONLiteral(formatted, i)
			out.WriteString(colorizeANSI(formatted[i:end], ansiJSONBool))
			i = end
		case strings.HasPrefix(formatted[i:], "null"):
			end := scanJSONLiteral(formatted, i)
			out.WriteString(colorizeANSI(formatted[i:end], ansiJSONNull))
			i = end
		default:
			out.WriteByte(ch)
			i++
		}
	}

	return out.String()
}

func scanJSONString(s string, start int) int {
	escaped := false
	for i := start + 1; i < len(s); i++ {
		switch {
		case escaped:
			escaped = false
		case s[i] == '\\':
			escaped = true
		case s[i] == '"':
			return i + 1
		}
	}

	return len(s)
}

func scanJSONLiteral(s string, start int) int {
	for i := start; i < len(s); i++ {
		if unicode.IsSpace(rune(s[i])) || isJSONPunctuation(s[i]) {
			return i
		}
	}

	return len(s)
}

func nextNonSpaceByte(s string, start int) byte {
	for i := start; i < len(s); i++ {
		if !unicode.IsSpace(rune(s[i])) {
			return s[i]
		}
	}

	return 0
}

func isJSONNumberStart(ch byte) bool {
	return ch == '-' || (ch >= '0' && ch <= '9')
}

func isJSONPunctuation(ch byte) bool {
	switch ch {
	case '{', '}', '[', ']', ':', ',':
		return true
	default:
		return false
	}
}

func colorizeANSI(text string, code string) string {
	return code + text + ansiReset
}

func normalizeJSON(v any) any {
	switch value := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Strings(keys)

		normalized := make(map[string]any, len(value))
		for _, key := range keys {
			normalized[key] = normalizeJSON(value[key])
		}

		return normalized
	case []any:
		normalized := make([]any, 0, len(value))
		for _, item := range value {
			normalized = append(normalized, normalizeJSON(item))
		}

		return normalized
	default:
		return value
	}
}

func indentBlock(text string, prefix string) string {
	if text == "" {
		return prefix
	}

	parts := strings.Split(text, "\n")
	for i, part := range parts {
		parts[i] = prefix + part
	}

	return strings.Join(parts, "\n")
}
