package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const scimUserSchema = "urn:ietf:params:scim:schemas:core:2.0:User"
const scimGroupSchema = "urn:ietf:params:scim:schemas:core:2.0:Group"

type SCIMClient struct {
	baseURL string
	token   string
	client  *http.Client
	traces  []SyncTraceEntry
}

type TraceTarget struct {
	ResourceType string
	ResourceID   string
	Label        string
	Operation    string
}

type SCIMEmail struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

type SCIMName struct {
	GivenName  string `json:"givenName,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
	Formatted  string `json:"formatted,omitempty"`
}

type SCIMUserResource struct {
	Schemas     []string    `json:"schemas"`
	ID          string      `json:"id,omitempty"`
	ExternalID  string      `json:"externalId,omitempty"`
	UserName    string      `json:"userName"`
	DisplayName string      `json:"displayName,omitempty"`
	Active      *bool       `json:"active,omitempty"`
	Name        *SCIMName   `json:"name,omitempty"`
	Emails      []SCIMEmail `json:"emails,omitempty"`
}

type SCIMMember struct {
	Value string `json:"value"`
	Type  string `json:"type,omitempty"`
}

type SCIMGroupResource struct {
	Schemas     []string     `json:"schemas"`
	ID          string       `json:"id,omitempty"`
	ExternalID  string       `json:"externalId,omitempty"`
	DisplayName string       `json:"displayName"`
	Members     []SCIMMember `json:"members,omitempty"`
}

type SyncResult struct {
	State   AppState
	Status  string
	Fatal   error
	Stopped error
	Changed bool
	Traces  []SyncTraceEntry
}

// RateLimitError describes a SCIM 429 response.
type RateLimitError struct {
	Method       string
	Path         string
	Status       string
	RetryAfter   string
	ResponseBody string
}

func (e *RateLimitError) Error() string {
	message := fmt.Sprintf("SCIM server rate limit hit (%s)", e.Status)
	if e.RetryAfter != "" {
		message += ". Try again " + e.RetryAfter + "."
		return message
	}

	return message + ". Try again later."
}

type ImportResult struct {
	State  AppState
	Status string
	Fatal  error
	Traces []SyncTraceEntry
}

type SyncTraceEntry struct {
	ResourceType       string
	ResourceID         string
	Label              string
	Operation          string
	Method             string
	Path               string
	RequestBody        string
	Status             string
	ResponseRetryAfter string
	ResponseBody       string
	Err                string
	CreatedAt          string
}

type SCIMListResponse[T any] struct {
	TotalResults int `json:"totalResults"`
	StartIndex   int `json:"startIndex"`
	ItemsPerPage int `json:"itemsPerPage"`
	Resources    []T `json:"Resources"`
}

func NewSCIMClient(cfg Config) (*SCIMClient, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	token := strings.TrimSpace(cfg.BearerToken)

	switch {
	case cfg.SCIMDisabled:
		return nil, fmt.Errorf("SCIM is disabled")
	case baseURL == "":
		return nil, fmt.Errorf("SCIM base URL is required")
	case token == "":
		return nil, fmt.Errorf("SCIM bearer token is required")
	}

	if _, err := url.Parse(baseURL); err != nil {
		return nil, fmt.Errorf("parse SCIM base URL %q: %w", baseURL, err)
	}

	return &SCIMClient{
		baseURL: baseURL,
		token:   token,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		traces: make([]SyncTraceEntry, 0, 16),
	}, nil
}

func SyncDirtyState(state AppState) SyncResult {
	client, err := NewSCIMClient(state.Config)
	if err != nil {
		return SyncResult{Fatal: err}
	}

	state, userCounts, stopped := syncDirtyUsers(client, state)
	groupCounts := syncCounts{}
	if stopped == nil {
		state, groupCounts, stopped = syncDirtyGroups(client, state)
	}

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
	if stopped != nil {
		status = fmt.Sprintf("sync stopped: %v; %s", stopped, status)
	}

	return SyncResult{
		State:   state,
		Status:  status,
		Stopped: stopped,
		Changed: userCounts.total()+groupCounts.total() > 0,
		Traces:  client.traces,
	}
}

func ImportStateFromSCIM(state AppState) ImportResult {
	client, err := NewSCIMClient(state.Config)
	if err != nil {
		return ImportResult{Fatal: err}
	}

	userResources, err := client.listUsers()
	if err != nil {
		return ImportResult{Fatal: err, Traces: client.traces}
	}

	groupResources, err := client.listGroups()
	if err != nil {
		return ImportResult{Fatal: err, Traces: client.traces}
	}

	updatedState, err := replaceStateFromSCIM(state, userResources, groupResources)
	if err != nil {
		return ImportResult{Fatal: err, Traces: client.traces}
	}

	return ImportResult{
		State:  updatedState,
		Status: fmt.Sprintf("imported %d users and %d groups from SCIM", len(updatedState.Users), len(updatedState.Groups)),
		Traces: client.traces,
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

func syncDirtyUsers(client *SCIMClient, state AppState) (AppState, syncCounts, error) {
	nextUsers := make([]User, 0, len(state.Users))
	counts := syncCounts{}

	for i, u := range state.Users {
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
				if isRateLimitError(err) {
					nextUsers = append(nextUsers, state.Users[i+1:]...)
					state.Users = nextUsers
					return state, counts, err
				}
				continue
			}

			counts.deleted++
		case u.RemoteID == "":
			remoteID, err := client.createUser(u)
			if err != nil {
				u.LastError = err.Error()
				counts.failed++
				nextUsers = append(nextUsers, u)
				if isRateLimitError(err) {
					nextUsers = append(nextUsers, state.Users[i+1:]...)
					state.Users = nextUsers
					return state, counts, err
				}
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
				if isRateLimitError(err) {
					nextUsers = append(nextUsers, state.Users[i+1:]...)
					state.Users = nextUsers
					return state, counts, err
				}
				continue
			}

			u.Dirty = false
			counts.updated++
			nextUsers = append(nextUsers, u)
		}
	}

	state.Users = nextUsers
	return state, counts, nil
}

func syncDirtyGroups(client *SCIMClient, state AppState) (AppState, syncCounts, error) {
	nextGroups := make([]Group, 0, len(state.Groups))
	counts := syncCounts{}

	for i, g := range state.Groups {
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
				if isRateLimitError(err) {
					nextGroups = append(nextGroups, state.Groups[i+1:]...)
					state.Groups = nextGroups
					return state, counts, err
				}
				continue
			}

			counts.deleted++
		case g.RemoteID == "":
			remoteID, err := client.createGroup(g, state.Users)
			if err != nil {
				g.LastError = err.Error()
				counts.failed++
				nextGroups = append(nextGroups, g)
				if isRateLimitError(err) {
					nextGroups = append(nextGroups, state.Groups[i+1:]...)
					state.Groups = nextGroups
					return state, counts, err
				}
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
				if isRateLimitError(err) {
					nextGroups = append(nextGroups, state.Groups[i+1:]...)
					state.Groups = nextGroups
					return state, counts, err
				}
				continue
			}

			g.Dirty = false
			counts.updated++
			nextGroups = append(nextGroups, g)
		}
	}

	state.Groups = nextGroups
	return state, counts, nil
}

func isRateLimitError(err error) bool {
	var rateLimitErr *RateLimitError
	return errors.As(err, &rateLimitErr)
}

func (c *SCIMClient) createUser(u User) (string, error) {
	resource := newSCIMUserResource(u)

	var response SCIMUserResource
	if err := c.doJSON(http.MethodPost, "/Users", resource, &response, traceTargetForUser(u, "create")); err != nil {
		return "", err
	}

	if strings.TrimSpace(response.ID) == "" {
		return "", fmt.Errorf("SCIM create response missing id")
	}

	return response.ID, nil
}

func (c *SCIMClient) listUsers() ([]SCIMUserResource, error) {
	resources := make([]SCIMUserResource, 0, 32)
	startIndex := 1
	count := 100

	for {
		path := fmt.Sprintf("/Users?startIndex=%d&count=%d", startIndex, count)
		var response SCIMListResponse[SCIMUserResource]
		if err := c.doJSON(http.MethodGet, path, nil, &response, TraceTarget{
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

func (c *SCIMClient) listGroups() ([]SCIMGroupResource, error) {
	resources := make([]SCIMGroupResource, 0, 32)
	startIndex := 1
	count := 100

	for {
		path := fmt.Sprintf("/Groups?startIndex=%d&count=%d", startIndex, count)
		var response SCIMListResponse[SCIMGroupResource]
		if err := c.doJSON(http.MethodGet, path, nil, &response, TraceTarget{
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

func (c *SCIMClient) replaceUser(u User) error {
	resource := newSCIMUserResource(u)
	resource.ID = u.RemoteID

	return c.doJSON(http.MethodPut, "/Users/"+url.PathEscape(u.RemoteID), resource, nil, traceTargetForUser(u, "update"))
}

func newSCIMUserResource(u User) SCIMUserResource {
	active := u.Active
	formattedName := FullName(u)
	resource := SCIMUserResource{
		Schemas:     []string{scimUserSchema},
		ExternalID:  u.ID,
		UserName:    strings.TrimSpace(u.Username),
		DisplayName: formattedName,
		Active:      &active,
		Emails: []SCIMEmail{{
			Value:   strings.TrimSpace(u.Email),
			Type:    "work",
			Primary: true,
		}},
	}

	resource.Name = &SCIMName{
		GivenName:  strings.TrimSpace(u.GivenName),
		FamilyName: strings.TrimSpace(u.FamilyName),
		Formatted:  formattedName,
	}

	return resource
}

func (c *SCIMClient) deleteUser(u User, operation string) error {
	return c.doJSON(http.MethodDelete, "/Users/"+url.PathEscape(u.RemoteID), nil, nil, traceTargetForUser(u, operation))
}

func (c *SCIMClient) createGroup(g Group, users []User) (string, error) {
	resource, err := newSCIMGroupResource(g, users)
	if err != nil {
		return "", err
	}

	var response SCIMGroupResource
	if err := c.doJSON(http.MethodPost, "/Groups", resource, &response, traceTargetForGroup(g, "create")); err != nil {
		return "", err
	}

	if strings.TrimSpace(response.ID) == "" {
		return "", fmt.Errorf("SCIM create group response missing id")
	}

	return response.ID, nil
}

func (c *SCIMClient) replaceGroup(g Group, users []User) error {
	resource, err := newSCIMGroupResource(g, users)
	if err != nil {
		return err
	}
	resource.ID = g.RemoteID

	return c.doJSON(http.MethodPut, "/Groups/"+url.PathEscape(g.RemoteID), resource, nil, traceTargetForGroup(g, "update"))
}

func (c *SCIMClient) deleteGroup(g Group, operation string) error {
	return c.doJSON(http.MethodDelete, "/Groups/"+url.PathEscape(g.RemoteID), nil, nil, traceTargetForGroup(g, operation))
}

func newSCIMGroupResource(g Group, users []User) (SCIMGroupResource, error) {
	members := make([]SCIMMember, 0, len(g.MemberIDs))
	for _, memberID := range g.MemberIDs {
		u, ok := UserByID(users, memberID)
		if !ok {
			return SCIMGroupResource{}, fmt.Errorf("group %q references unknown user %q", g.DisplayName, memberID)
		}
		if strings.TrimSpace(u.RemoteID) == "" {
			return SCIMGroupResource{}, fmt.Errorf("group %q member %q has not been synced yet", g.DisplayName, UserLabel(u))
		}

		members = append(members, SCIMMember{Value: u.RemoteID, Type: "User"})
	}

	return SCIMGroupResource{
		Schemas:     []string{scimGroupSchema},
		ExternalID:  g.ID,
		DisplayName: strings.TrimSpace(g.DisplayName),
		Members:     members,
	}, nil
}

func (c *SCIMClient) doJSON(method string, path string, body any, out any, target TraceTarget) error {
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

	trace := SyncTraceEntry{
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
	trace.ResponseRetryAfter = strings.TrimSpace(resp.Header.Get("Retry-After"))

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
		if resp.StatusCode == http.StatusTooManyRequests {
			err := &RateLimitError{
				Method:       method,
				Path:         path,
				Status:       resp.Status,
				RetryAfter:   parseRetryAfter(resp.Header.Get("Retry-After"), currentTime()),
				ResponseBody: strings.TrimSpace(string(data)),
			}
			trace.Err = err.Error()
			c.traces = append(c.traces, trace)
			return err
		}

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

func parseRetryAfter(value string, now time.Time) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	seconds, err := strconv.Atoi(value)
	if err == nil {
		if seconds <= 0 {
			return "now"
		}

		return "in " + humanRetryAfter(time.Duration(seconds)*time.Second)
	}

	retryAt, err := http.ParseTime(value)
	if err != nil {
		return "after " + value
	}

	delay := retryAt.Sub(now)
	if delay <= 0 {
		return "now"
	}

	return "in " + humanRetryAfter(delay)
}

func humanRetryAfter(delay time.Duration) string {
	seconds := int64((delay + time.Second - 1) / time.Second)
	switch {
	case seconds <= 1:
		return "1 second"
	case seconds < 60:
		return fmt.Sprintf("%d seconds", seconds)
	case seconds < 3600:
		minutes := (seconds + 59) / 60
		if minutes == 1 {
			return "1 minute"
		}

		return fmt.Sprintf("%d minutes", minutes)
	case seconds < 86400:
		hours := (seconds + 3599) / 3600
		if hours == 1 {
			return "1 hour"
		}

		return fmt.Sprintf("%d hours", hours)
	default:
		days := (seconds + 86399) / 86400
		if days == 1 {
			return "1 day"
		}

		return fmt.Sprintf("%d days", days)
	}
}

func traceTargetForUser(u User, operation string) TraceTarget {
	return TraceTarget{
		ResourceType: "user",
		ResourceID:   u.ID,
		Label:        UserLabel(u),
		Operation:    operation,
	}
}

func traceTargetForGroup(g Group, operation string) TraceTarget {
	return TraceTarget{
		ResourceType: "group",
		ResourceID:   g.ID,
		Label:        g.DisplayName,
		Operation:    operation,
	}
}

func replaceStateFromSCIM(state AppState, userResources []SCIMUserResource, groupResources []SCIMGroupResource) (AppState, error) {
	importedUsers := make([]User, 0, len(userResources))
	remoteToLocalUserID := make(map[string]string, len(userResources))

	for _, resource := range userResources {
		importedUser, err := importedUserFromSCIM(nil, resource)
		if err != nil {
			return AppState{}, err
		}
		importedUsers = append(importedUsers, importedUser)
		if importedUser.RemoteID != "" {
			remoteToLocalUserID[importedUser.RemoteID] = importedUser.ID
		}
	}

	importedGroups := make([]Group, 0, len(groupResources))
	for _, resource := range groupResources {
		importedGroup, err := importedGroupFromSCIM(resource, remoteToLocalUserID)
		if err != nil {
			return AppState{}, err
		}
		importedGroups = append(importedGroups, importedGroup)
	}

	state.Users = importedUsers
	state.Groups = importedGroups
	state.UserOperations = make(map[string][]OperationLog, len(importedUsers))
	state.GroupOperations = make(map[string][]OperationLog, len(importedGroups))

	for _, importedUser := range importedUsers {
		AppendLocalOperationLog(&state, "user", importedUser.ID, "Imported from SCIM")
	}
	for _, importedGroup := range importedGroups {
		AppendLocalOperationLog(&state, "group", importedGroup.ID, "Imported from SCIM")
	}

	return state, nil
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

func importedGroupFromSCIM(resource SCIMGroupResource, remoteToLocalUserID map[string]string) (Group, error) {
	localID := strings.TrimSpace(resource.ExternalID)
	if localID == "" {
		var err error
		localID, err = NewGroupID()
		if err != nil {
			return Group{}, err
		}
	}

	memberIDs := make([]string, 0, len(resource.Members))
	for _, member := range resource.Members {
		localUserID, ok := remoteToLocalUserID[strings.TrimSpace(member.Value)]
		if !ok {
			return Group{}, fmt.Errorf("group %q references unknown imported user %q", strings.TrimSpace(resource.DisplayName), strings.TrimSpace(member.Value))
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
	}, nil
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
