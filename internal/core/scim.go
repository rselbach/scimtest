package core

import (
	"errors"
	"fmt"
	"net/http"
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
	Phase        string
	Status       string
	Detail       string
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

const (
	maxSCIMRateLimitRetries    = 3
	maxAutomaticRateLimitDelay = 30 * time.Second
	maxSCIMResponseBodyBytes   = 10 << 20
)

var rateLimitSleep = time.Sleep

// errSCIMNotFound marks a 404/410 SCIM response so reconcile can recreate the resource.
var errSCIMNotFound = errors.New("resource not found")

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

	if err := ValidateHTTPBaseURL("SCIM base URL", baseURL, true); err != nil {
		return nil, err
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

// ReconcileState checks every user and group against the SCIM server and
// repairs drift regardless of local dirty flags: resources missing remotely
// are created, mismatched ones replaced, and deletions carried out.
func ReconcileState(state AppState) SyncResult {
	return ReconcileStateWithProgress(state, nil)
}

// ReconcileStateWithProgress reconciles all resources and reports per-resource progress.
func ReconcileStateWithProgress(state AppState, onProgress func(SyncProgress)) SyncResult {
	client, err := NewSCIMClient(state.Config)
	if err != nil {
		return SyncResult{Fatal: err}
	}

	progress := newSyncProgressReporter(len(state.Users)+len(state.Groups), onProgress)
	client.onRateLimit = progress.reportRateLimit
	progress.report(SyncProgress{Status: "Starting reconcile"})
	state, userCounts, stopped := reconcileUsers(client, state, progress)
	groupCounts := syncCounts{}
	if stopped == nil {
		state, groupCounts, stopped = reconcileGroups(client, state, progress)
	}

	status := fmt.Sprintf(
		"reconcile finished: users %d created, %d updated, %d deleted, %d in sync, %d failed; groups %d created, %d updated, %d deleted, %d in sync, %d failed",
		userCounts.created,
		userCounts.updated,
		userCounts.deleted,
		userCounts.inSync,
		userCounts.failed,
		groupCounts.created,
		groupCounts.updated,
		groupCounts.deleted,
		groupCounts.inSync,
		groupCounts.failed,
	)
	if stopped != nil {
		status = fmt.Sprintf("reconcile stopped: %v; %s", stopped, status)
	}

	return SyncResult{
		State:   state,
		Status:  status,
		Stopped: stopped,
		Changed: userCounts.total()+groupCounts.total() > 0,
		Traces:  client.traces,
	}
}

type syncCounts struct {
	created int
	updated int
	deleted int
	inSync  int
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
	phase := "done"
	detail := ""
	if status == "Failed" {
		phase = "failed"
		detail = u.LastError
	}
	r.report(SyncProgress{
		ResourceType: "user",
		ResourceID:   u.ID,
		Label:        progressUserLabel(u),
		Operation:    operation,
		Phase:        phase,
		Status:       status,
		Detail:       detail,
	})
}

func (r *syncProgressReporter) startUser(u User, operation string) {
	if r == nil {
		return
	}

	r.report(SyncProgress{
		ResourceType: "user",
		ResourceID:   u.ID,
		Label:        progressUserLabel(u),
		Operation:    operation,
		Phase:        "running",
		Status:       "In progress",
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
		Phase:        "waiting",
		Status:       status,
		Detail:       status,
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
	phase := "done"
	detail := ""
	if status == "Failed" {
		phase = "failed"
		detail = g.LastError
	}
	r.report(SyncProgress{
		ResourceType: "group",
		ResourceID:   g.ID,
		Label:        g.DisplayName,
		Operation:    operation,
		Phase:        phase,
		Status:       status,
		Detail:       detail,
	})
}

func (r *syncProgressReporter) startGroup(g Group, operation string) {
	if r == nil {
		return
	}

	r.report(SyncProgress{
		ResourceType: "group",
		ResourceID:   g.ID,
		Label:        g.DisplayName,
		Operation:    operation,
		Phase:        "running",
		Status:       "In progress",
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
		operation := "update"
		switch {
		case u.Deleted:
			operation = "delete"
		case u.RemoteID == "":
			operation = "create"
		}
		progress.startUser(u, operation)

		switch {
		case u.Deleted && u.RemoteID == "":
			progress.addTotal(pruneUserFromGroups(&state, u.ID))
			counts.deleted++
			progress.reportUser(u, operation, "Deleted locally")
			continue
		case u.Deleted:
			if err := client.deleteUser(u, "delete"); err != nil {
				u.LastError = err.Error()
				counts.failed++
				nextUsers = append(nextUsers, u)
				progress.reportUser(u, operation, "Failed")
				if isRateLimitError(err) {
					nextUsers = append(nextUsers, state.Users[i+1:]...)
					state.Users = nextUsers
					return state, counts, err
				}
				continue
			}

			progress.addTotal(pruneUserFromGroups(&state, u.ID))
			counts.deleted++
			progress.reportUser(u, operation, "Deleted")
		case u.RemoteID == "":
			remoteID, err := client.createUser(u)
			if err != nil {
				u.LastError = err.Error()
				counts.failed++
				nextUsers = append(nextUsers, u)
				progress.reportUser(u, operation, "Failed")
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
			progress.reportUser(u, operation, "Created")
		default:
			if err := client.replaceUser(u); err != nil {
				u.LastError = err.Error()
				counts.failed++
				nextUsers = append(nextUsers, u)
				progress.reportUser(u, operation, "Failed")
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
			progress.reportUser(u, operation, "Updated")
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
		operation := "update"
		switch {
		case g.Deleted:
			operation = "delete"
		case g.RemoteID == "":
			operation = "create"
		}
		progress.startGroup(g, operation)

		switch {
		case g.Deleted && g.RemoteID == "":
			counts.deleted++
			progress.reportGroup(g, operation, "Deleted locally")
			continue
		case g.Deleted:
			if err := client.deleteGroup(g, "delete"); err != nil {
				g.LastError = err.Error()
				counts.failed++
				nextGroups = append(nextGroups, g)
				progress.reportGroup(g, operation, "Failed")
				if isRateLimitError(err) {
					nextGroups = append(nextGroups, state.Groups[i+1:]...)
					state.Groups = nextGroups
					return state, counts, err
				}
				continue
			}

			counts.deleted++
			progress.reportGroup(g, operation, "Deleted")
		case g.RemoteID == "":
			remoteID, err := client.createGroup(g, state.Users)
			if err != nil {
				g.LastError = err.Error()
				counts.failed++
				nextGroups = append(nextGroups, g)
				progress.reportGroup(g, operation, "Failed")
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
			progress.reportGroup(g, operation, "Created")
		default:
			if err := client.replaceGroup(g, state.Users); err != nil {
				g.LastError = err.Error()
				counts.failed++
				nextGroups = append(nextGroups, g)
				progress.reportGroup(g, operation, "Failed")
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
			progress.reportGroup(g, operation, "Updated")
		}
	}

	state.Groups = nextGroups
	return state, counts, nil
}

func reconcileUsers(client *SCIMClient, state AppState, progress *syncProgressReporter) (AppState, syncCounts, error) {
	nextUsers := make([]User, 0, len(state.Users))
	counts := syncCounts{}

	for i, u := range state.Users {
		u.LastError = ""
		operation := "check"
		switch {
		case u.Deleted:
			operation = "delete"
		case u.RemoteID == "":
			operation = "create"
		}
		progress.startUser(u, operation)

		fail := func(err error) error {
			u.LastError = err.Error()
			u.Dirty = true
			counts.failed++
			nextUsers = append(nextUsers, u)
			progress.reportUser(u, operation, "Failed")
			if isRateLimitError(err) {
				nextUsers = append(nextUsers, state.Users[i+1:]...)
				state.Users = nextUsers
				return err
			}
			return nil
		}

		switch {
		case u.Deleted && u.RemoteID == "":
			pruneUserFromGroups(&state, u.ID)
			counts.deleted++
			progress.reportUser(u, operation, "Deleted locally")
		case u.Deleted:
			if err := client.deleteUser(u, "delete"); err != nil {
				if stopped := fail(err); stopped != nil {
					return state, counts, stopped
				}
				continue
			}

			pruneUserFromGroups(&state, u.ID)
			counts.deleted++
			progress.reportUser(u, operation, "Deleted")
		case u.RemoteID == "":
			remoteID, err := client.createUser(u)
			if err != nil {
				if stopped := fail(err); stopped != nil {
					return state, counts, stopped
				}
				continue
			}

			u.RemoteID = remoteID
			u.Dirty = false
			counts.created++
			nextUsers = append(nextUsers, u)
			progress.reportUser(u, operation, "Created")
		default:
			remote, err := client.getUser(u)
			switch {
			case errors.Is(err, errSCIMNotFound):
				remoteID, createErr := client.createUser(u)
				if createErr != nil {
					if stopped := fail(createErr); stopped != nil {
						return state, counts, stopped
					}
					continue
				}

				u.RemoteID = remoteID
				u.Dirty = false
				counts.created++
				nextUsers = append(nextUsers, u)
				progress.reportUser(u, "create", "Created")
			case err != nil:
				if stopped := fail(err); stopped != nil {
					return state, counts, stopped
				}
			case userMatchesRemote(newSCIMUserResource(u), remote):
				u.Dirty = false
				counts.inSync++
				nextUsers = append(nextUsers, u)
				progress.reportUser(u, operation, "In sync")
			default:
				if err := client.replaceUser(u); err != nil {
					if stopped := fail(err); stopped != nil {
						return state, counts, stopped
					}
					continue
				}

				u.Dirty = false
				counts.updated++
				nextUsers = append(nextUsers, u)
				progress.reportUser(u, "update", "Updated")
			}
		}
	}

	state.Users = nextUsers
	return state, counts, nil
}

func reconcileGroups(client *SCIMClient, state AppState, progress *syncProgressReporter) (AppState, syncCounts, error) {
	nextGroups := make([]Group, 0, len(state.Groups))
	counts := syncCounts{}

	for i, g := range state.Groups {
		g.LastError = ""
		operation := "check"
		switch {
		case g.Deleted:
			operation = "delete"
		case g.RemoteID == "":
			operation = "create"
		}
		progress.startGroup(g, operation)

		fail := func(err error) error {
			g.LastError = err.Error()
			g.Dirty = true
			counts.failed++
			nextGroups = append(nextGroups, g)
			progress.reportGroup(g, operation, "Failed")
			if isRateLimitError(err) {
				nextGroups = append(nextGroups, state.Groups[i+1:]...)
				state.Groups = nextGroups
				return err
			}
			return nil
		}

		switch {
		case g.Deleted && g.RemoteID == "":
			counts.deleted++
			progress.reportGroup(g, operation, "Deleted locally")
		case g.Deleted:
			if err := client.deleteGroup(g, "delete"); err != nil {
				if stopped := fail(err); stopped != nil {
					return state, counts, stopped
				}
				continue
			}

			counts.deleted++
			progress.reportGroup(g, operation, "Deleted")
		case g.RemoteID == "":
			remoteID, err := client.createGroup(g, state.Users)
			if err != nil {
				if stopped := fail(err); stopped != nil {
					return state, counts, stopped
				}
				continue
			}

			g.RemoteID = remoteID
			g.Dirty = false
			counts.created++
			nextGroups = append(nextGroups, g)
			progress.reportGroup(g, operation, "Created")
		default:
			remote, err := client.getGroup(g)
			var desired SCIMGroupResource
			if err == nil {
				desired, err = newSCIMGroupResource(g, state.Users)
			}
			switch {
			case errors.Is(err, errSCIMNotFound):
				remoteID, createErr := client.createGroup(g, state.Users)
				if createErr != nil {
					if stopped := fail(createErr); stopped != nil {
						return state, counts, stopped
					}
					continue
				}

				g.RemoteID = remoteID
				g.Dirty = false
				counts.created++
				nextGroups = append(nextGroups, g)
				progress.reportGroup(g, "create", "Created")
			case err != nil:
				if stopped := fail(err); stopped != nil {
					return state, counts, stopped
				}
			case groupMatchesRemote(desired, remote):
				g.Dirty = false
				counts.inSync++
				nextGroups = append(nextGroups, g)
				progress.reportGroup(g, operation, "In sync")
			default:
				if err := client.replaceGroup(g, state.Users); err != nil {
					if stopped := fail(err); stopped != nil {
						return state, counts, stopped
					}
					continue
				}

				g.Dirty = false
				counts.updated++
				nextGroups = append(nextGroups, g)
				progress.reportGroup(g, "update", "Updated")
			}
		}
	}

	state.Groups = nextGroups
	return state, counts, nil
}

func userMatchesRemote(desired SCIMUserResource, remote SCIMUserResource) bool {
	remoteActive := remote.Active == nil || *remote.Active
	desiredGiven, desiredFamily := scimNameParts(desired.Name)
	remoteGiven, remoteFamily := scimNameParts(remote.Name)

	return desired.UserName == strings.TrimSpace(remote.UserName) &&
		desired.DisplayName == strings.TrimSpace(remote.DisplayName) &&
		desired.ExternalID == strings.TrimSpace(remote.ExternalID) &&
		*desired.Active == remoteActive &&
		desiredGiven == remoteGiven &&
		desiredFamily == remoteFamily &&
		firstSCIMEmail(desired.Emails) == firstSCIMEmail(remote.Emails)
}

func scimNameParts(name *SCIMName) (string, string) {
	if name == nil {
		return "", ""
	}

	return strings.TrimSpace(name.GivenName), strings.TrimSpace(name.FamilyName)
}

func groupMatchesRemote(desired SCIMGroupResource, remote SCIMGroupResource) bool {
	if desired.DisplayName != strings.TrimSpace(remote.DisplayName) ||
		desired.ExternalID != strings.TrimSpace(remote.ExternalID) ||
		len(desired.Members) != len(remote.Members) {
		return false
	}

	remoteMembers := make(map[string]bool, len(remote.Members))
	for _, member := range remote.Members {
		remoteMembers[strings.TrimSpace(member.Value)] = true
	}
	for _, member := range desired.Members {
		if !remoteMembers[member.Value] {
			return false
		}
	}

	return true
}
