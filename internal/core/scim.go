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
	baseURL     string
	token       string
	client      *http.Client
	onRateLimit func(TraceTarget, time.Duration, string, int)
	traces      []SyncTraceEntry
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
	Method           string
	Path             string
	Status           string
	RetryAfter       string
	RetryAfterHeader string
	ResponseBody     string
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

// SyncProgress reports foreground progress during a dirty-state sync.
type SyncProgress struct {
	Total        int
	Processed    int
	ResourceType string
	ResourceID   string
	Label        string
	Operation    string
	Status       string
	RateLimited  bool
	RetryAfter   string
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

const maxSCIMRateLimitRetries = 3

var rateLimitSleep = time.Sleep

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
	return SyncDirtyStateWithProgress(state, nil)
}

// SyncDirtyStateWithProgress syncs dirty resources and reports per-resource progress.
func SyncDirtyStateWithProgress(state AppState, onProgress func(SyncProgress)) SyncResult {
	client, err := NewSCIMClient(state.Config)
	if err != nil {
		return SyncResult{Fatal: err}
	}

	progress := newSyncProgressReporter(countDirtyResources(state), onProgress)
	client.onRateLimit = progress.reportRateLimit
	progress.report(SyncProgress{Status: "Starting sync"})
	state, userCounts, stopped := syncDirtyUsers(client, state, progress)
	groupCounts := syncCounts{}
	if stopped == nil {
		state, groupCounts, stopped = syncDirtyGroups(client, state, progress)
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

type syncProgressReporter struct {
	total      int
	processed  int
	onProgress func(SyncProgress)
}

func newSyncProgressReporter(total int, onProgress func(SyncProgress)) *syncProgressReporter {
	return &syncProgressReporter{total: total, onProgress: onProgress}
}

func (r *syncProgressReporter) report(progress SyncProgress) {
	if r == nil || r.onProgress == nil {
		return
	}

	progress.Total = r.total
	progress.Processed = r.processed
	r.onProgress(progress)
}

func (r *syncProgressReporter) addTotal(delta int) {
	if r == nil || delta <= 0 {
		return
	}
	r.total += delta
}

func (r *syncProgressReporter) reportUser(u User, operation string, status string) {
	if r == nil {
		return
	}

	r.processed++
	r.report(SyncProgress{
		ResourceType: "user",
		ResourceID:   u.ID,
		Label:        progressUserLabel(u),
		Operation:    operation,
		Status:       status,
	})
}

func (r *syncProgressReporter) reportRateLimit(target TraceTarget, delay time.Duration, retryAfterHeader string, _ int) {
	if r == nil {
		return
	}

	wait := "now"
	if delay > 0 {
		wait = humanRetryAfter(delay)
	}
	status := "Rate limited; retrying " + wait
	if retryAfterHeader != "" {
		status = "Rate limited; waiting " + wait
	}

	r.report(SyncProgress{
		ResourceType: target.ResourceType,
		ResourceID:   target.ResourceID,
		Label:        target.Label,
		Operation:    target.Operation,
		Status:       status,
		RateLimited:  true,
		RetryAfter:   retryAfterHeader,
	})
}

func progressUserLabel(u User) string {
	label := UserLabel(u)
	username := strings.TrimSpace(u.Username)
	if username == "" || username == label {
		return label
	}

	return fmt.Sprintf("%s (%s)", label, username)
}

func (r *syncProgressReporter) reportGroup(g Group, operation string, status string) {
	if r == nil {
		return
	}

	r.processed++
	r.report(SyncProgress{
		ResourceType: "group",
		ResourceID:   g.ID,
		Label:        g.DisplayName,
		Operation:    operation,
		Status:       status,
	})
}

func countDirtyResources(state AppState) int {
	total := 0
	for _, u := range state.Users {
		if u.Dirty {
			total++
		}
	}
	for _, g := range state.Groups {
		if g.Dirty {
			total++
		}
	}

	return total
}

func syncDirtyUsers(client *SCIMClient, state AppState, progress *syncProgressReporter) (AppState, syncCounts, error) {
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
			progress.addTotal(pruneUserFromGroups(&state, u.ID))
			counts.deleted++
			progress.reportUser(u, "delete", "Deleted locally")
			continue
		case u.Deleted:
			if err := client.deleteUser(u, "delete"); err != nil {
				u.LastError = err.Error()
				counts.failed++
				nextUsers = append(nextUsers, u)
				progress.reportUser(u, "delete", "Failed")
				if isRateLimitError(err) {
					nextUsers = append(nextUsers, state.Users[i+1:]...)
					state.Users = nextUsers
					return state, counts, err
				}
				continue
			}

			progress.addTotal(pruneUserFromGroups(&state, u.ID))
			counts.deleted++
			progress.reportUser(u, "delete", "Deleted")
		case u.RemoteID == "":
			remoteID, err := client.createUser(u)
			if err != nil {
				u.LastError = err.Error()
				counts.failed++
				nextUsers = append(nextUsers, u)
				progress.reportUser(u, "create", "Failed")
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
			progress.reportUser(u, "create", "Created")
		default:
			if err := client.replaceUser(u); err != nil {
				u.LastError = err.Error()
				counts.failed++
				nextUsers = append(nextUsers, u)
				progress.reportUser(u, "update", "Failed")
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
			progress.reportUser(u, "update", "Updated")
		}
	}

	state.Users = nextUsers
	return state, counts, nil
}

func pruneUserFromGroups(state *AppState, userID string) int {
	newlyDirty := 0
	for i := range state.Groups {
		memberIDs := make([]string, 0, len(state.Groups[i].MemberIDs))
		removed := false
		for _, memberID := range state.Groups[i].MemberIDs {
			if memberID == userID {
				removed = true
				continue
			}
			memberIDs = append(memberIDs, memberID)
		}
		if !removed {
			continue
		}
		state.Groups[i].MemberIDs = memberIDs
		state.Groups[i].LastError = ""
		if !state.Groups[i].Dirty {
			state.Groups[i].Dirty = true
			newlyDirty++
		}
	}
	return newlyDirty
}

func syncDirtyGroups(client *SCIMClient, state AppState, progress *syncProgressReporter) (AppState, syncCounts, error) {
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
			progress.reportGroup(g, "delete", "Deleted locally")
			continue
		case g.Deleted:
			if err := client.deleteGroup(g, "delete"); err != nil {
				g.LastError = err.Error()
				counts.failed++
				nextGroups = append(nextGroups, g)
				progress.reportGroup(g, "delete", "Failed")
				if isRateLimitError(err) {
					nextGroups = append(nextGroups, state.Groups[i+1:]...)
					state.Groups = nextGroups
					return state, counts, err
				}
				continue
			}

			counts.deleted++
			progress.reportGroup(g, "delete", "Deleted")
		case g.RemoteID == "":
			remoteID, err := client.createGroup(g, state.Users)
			if err != nil {
				g.LastError = err.Error()
				counts.failed++
				nextGroups = append(nextGroups, g)
				progress.reportGroup(g, "create", "Failed")
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
			progress.reportGroup(g, "create", "Created")
		default:
			if err := client.replaceGroup(g, state.Users); err != nil {
				g.LastError = err.Error()
				counts.failed++
				nextGroups = append(nextGroups, g)
				progress.reportGroup(g, "update", "Failed")
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
			progress.reportGroup(g, "update", "Updated")
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
		err := fmt.Errorf("SCIM create response missing id")
		c.setLastTraceError(err)
		return "", err
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
		err := fmt.Errorf("SCIM create group response missing id")
		c.setLastTraceError(err)
		return "", err
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
	var payload []byte
	requestBody := ""
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode SCIM %s %s body: %w", method, path, err)
		}

		payload = encoded
		requestBody = string(encoded)
	}

	for attempt := 0; ; attempt++ {
		err := c.doJSONOnce(method, path, payload, requestBody, out, target)
		if err == nil {
			return nil
		}

		var rateLimitErr *RateLimitError
		if !errors.As(err, &rateLimitErr) {
			return err
		}
		if attempt >= maxSCIMRateLimitRetries {
			return err
		}

		delay := rateLimitRetryDelay(rateLimitErr.RetryAfterHeader, attempt, currentTime())
		if c.onRateLimit != nil {
			c.onRateLimit(target, delay, rateLimitErr.RetryAfterHeader, attempt+1)
		}
		rateLimitSleep(delay)
	}
}

func (c *SCIMClient) doJSONOnce(method string, path string, payload []byte, requestBody string, out any, target TraceTarget) error {
	var reader io.Reader
	if payload != nil {
		reader = bytes.NewReader(payload)
	}

	req, err := http.NewRequest(method, c.baseURL+path, reader)
	if err != nil {
		return fmt.Errorf("build SCIM %s %s request: %w", method, path, err)
	}

	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/scim+json")
	if payload != nil {
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
		if method == http.MethodDelete && (resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone) {
			c.traces = append(c.traces, trace)
			return nil
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			err := &RateLimitError{
				Method:           method,
				Path:             path,
				Status:           resp.Status,
				RetryAfter:       parseRetryAfter(trace.ResponseRetryAfter, currentTime()),
				RetryAfterHeader: trace.ResponseRetryAfter,
				ResponseBody:     strings.TrimSpace(string(data)),
			}
			trace.Err = err.Error()
			c.traces = append(c.traces, trace)
			return err
		}

		var responseErr error
		if requestBody == "" {
			responseErr = fmt.Errorf("SCIM %s %s returned %s: %s", method, path, resp.Status, strings.TrimSpace(string(data)))
		} else {
			responseErr = fmt.Errorf("SCIM %s %s returned %s: %s | request body: %s", method, path, resp.Status, strings.TrimSpace(string(data)), requestBody)
		}
		trace.Err = responseErr.Error()
		c.traces = append(c.traces, trace)
		return responseErr
	}

	if out == nil || len(data) == 0 {
		c.traces = append(c.traces, trace)
		return nil
	}

	if err := json.Unmarshal(data, out); err != nil {
		responseErr := fmt.Errorf("decode SCIM %s %s response: %w", method, path, err)
		trace.Err = responseErr.Error()
		c.traces = append(c.traces, trace)
		return responseErr
	}

	c.traces = append(c.traces, trace)
	return nil
}

func (c *SCIMClient) setLastTraceError(err error) {
	if err == nil || len(c.traces) == 0 {
		return
	}
	c.traces[len(c.traces)-1].Err = err.Error()
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

func rateLimitRetryDelay(value string, attempt int, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallbackRateLimitDelay(attempt)
	}

	seconds, err := strconv.Atoi(value)
	if err == nil {
		if seconds <= 0 {
			return 0
		}

		return time.Duration(seconds) * time.Second
	}

	retryAt, err := http.ParseTime(value)
	if err != nil {
		return fallbackRateLimitDelay(attempt)
	}

	delay := retryAt.Sub(now)
	if delay <= 0 {
		return 0
	}

	return delay
}

func fallbackRateLimitDelay(attempt int) time.Duration {
	if attempt < 0 {
		return time.Second
	}
	if attempt > maxSCIMRateLimitRetries {
		attempt = maxSCIMRateLimitRetries
	}

	return time.Duration(1<<attempt) * time.Second
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
		Label:        progressUserLabel(u),
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
		importedUser, err := importedUserFromSCIM(state.Users, resource)
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
