package web

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/beevik/etree"
)

// Lifecycle scenarios run a joiner, mover, or leaver through every protocol an
// environment speaks: the directory change, SCIM provisioning, IdP sessions
// and logout, and tokens. Each run keeps a checklist of what scimtest sent,
// where, and how the app answered. Runs live in memory, like sessions, so
// restarting scimtest forgets them.

const (
	lifecycleJoiner = "joiner"
	lifecycleMover  = "mover"
	lifecycleLeaver = "leaver"
)

// Checklist step statuses. running means scimtest is still working on the
// step, waiting means it waits for the app or for a sign-in, and
// needs_browser means the tester must carry a message to the app from the
// checklist.
const (
	lifecycleRunning      = "running"
	lifecycleWaiting      = "waiting"
	lifecycleNeedsBrowser = "needs_browser"
	lifecycleOK           = "ok"
	lifecycleFailed       = "failed"
	lifecycleSkipped      = "skipped"
)

// maxLifecycleRuns bounds the runs kept per environment.
const maxLifecycleRuns = 10

// lifecyclePollInterval is how often a run checks on the SCIM push it started.
const lifecyclePollInterval = 25 * time.Millisecond

// lifecycleRun is one joiner, mover, or leaver scenario and its checklist.
type lifecycleRun struct {
	ID        string          `json:"id"`
	Kind      string          `json:"kind"`
	UserID    string          `json:"user_id"`
	User      string          `json:"user"`
	Status    string          `json:"status"`
	StartedAt string          `json:"started_at"`
	Steps     []lifecycleStep `json:"steps"`

	appSlug string
	// expectedGroups is the user's groups after a mover's change, which the
	// next token and assertion should carry.
	expectedGroups []string
}

// lifecycleStep is one checklist item: a change scimtest made, or messages it
// sent the app.
type lifecycleStep struct {
	ID         string             `json:"id"`
	Protocol   string             `json:"protocol"` // directory, idp, oidc, saml, or scim
	Title      string             `json:"title"`
	Status     string             `json:"status"`
	Detail     string             `json:"detail,omitempty"`
	Messages   []lifecycleMessage `json:"messages,omitempty"`
	BrowserURL string             `json:"browser_url,omitempty"`

	session   idpSession // the ended session a logout step is about
	requestID string     // the latest LogoutRequest a SAML logout step sent
}

// lifecycleMessage is one message a step sent, and the app's answer.
type lifecycleMessage struct {
	At       string `json:"at"`
	Sent     string `json:"sent"`
	To       string `json:"to,omitempty"`
	Body     string `json:"body,omitempty"`
	Response string `json:"response,omitempty"`
	Outcome  string `json:"outcome"` // ok, failed, skipped, or pending
}

// lifecyclePush is a SCIM push that a run's step makes. A push whose
// DependsOn step failed is skipped.
type lifecyclePush struct {
	StepID       string
	ResourceType string // user or group
	ResourceID   string
	DependsOn    string
}

// groupChange is a change to one user's group memberships.
type groupChange struct {
	App     app
	User    user
	Added   []group
	Removed []group
	Groups  []string // the user's group names after the change
}

func (c groupChange) describe() string {
	var parts []string
	if len(c.Added) > 0 {
		parts = append(parts, "added to "+groupNames(c.Added))
	}
	if len(c.Removed) > 0 {
		parts = append(parts, "removed from "+groupNames(c.Removed))
	}
	summary := strings.Join(parts, "; ")
	return strings.ToUpper(summary[:1]) + summary[1:]
}

func groupNames(groups []group) string {
	names := make([]string, len(groups))
	for i, found := range groups {
		names[i] = found.DisplayName
	}
	return strings.Join(names, ", ")
}

// startJoiner creates a user, adds them to groupIDs, and pushes the user and
// the groups through SCIM.
func (a *webApp) startJoiner(environmentID string, request apiUserRequest, groupIDs []string) (lifecycleRun, error) {
	found, err := a.checkJoinerGroups(environmentID, groupIDs)
	if err != nil {
		return lifecycleRun{}, err
	}
	active := true
	request.Active = &active
	joiner, err := a.saveAPIUser(environmentID, "", request)
	if err != nil {
		return lifecycleRun{}, err
	}
	label := userLabel(joiner)
	run, err := newLifecycleRun(lifecycleJoiner, found, joiner)
	if err != nil {
		return lifecycleRun{}, err
	}
	run.Steps = append(run.Steps, lifecycleStep{ID: "create", Protocol: "directory", Title: "Create " + label, Status: lifecycleOK, Detail: "Created " + label + " <" + joiner.Email + "> in scimtest"})
	var change groupChange
	if len(groupIDs) > 0 {
		step := lifecycleStep{ID: "groups", Protocol: "directory", Title: "Add " + label + " to groups", Status: lifecycleOK}
		change, err = a.changeUserGroups(environmentID, joiner.ID, groupIDs, nil, false)
		if err != nil {
			step.Status, step.Detail = lifecycleFailed, err.Error()
		} else {
			step.Detail = change.describe()
		}
		run.Steps = append(run.Steps, step)
	}

	var pushes []lifecyclePush
	if reason := scimSkipReason(found); reason != "" {
		run.Steps = append(run.Steps, lifecycleStep{ID: "scim", Protocol: "scim", Title: "Provision " + label + " through SCIM", Status: lifecycleSkipped, Detail: reason})
		return a.startLifecycleRun(run, found, nil), nil
	}
	run.Steps = append(run.Steps, lifecycleStep{ID: "scim-user", Protocol: "scim", Title: "Provision " + label + " through SCIM", Status: lifecycleRunning, Detail: "Waiting to push"})
	pushes = append(pushes, lifecyclePush{StepID: "scim-user", ResourceType: "user", ResourceID: joiner.ID})
	for _, added := range change.Added {
		run.Steps = append(run.Steps, groupPushStep(added))
		pushes = append(pushes, lifecyclePush{StepID: "scim-group-" + added.ID, ResourceType: "group", ResourceID: added.ID, DependsOn: "scim-user"})
	}
	return a.startLifecycleRun(run, found, pushes), nil
}

// checkJoinerGroups checks that groupIDs name groups a new user can join
// before the joiner creates anything, and returns the environment.
func (a *webApp) checkJoinerGroups(environmentID string, groupIDs []string) (app, error) {
	state, err := a.loadAPIEnvironment(environmentID)
	if err != nil {
		return app{}, err
	}
	found, _ := appByID(state.Apps, environmentID)
	for _, id := range groupIDs {
		if existing, ok := groupByID(state.Groups, id); !ok || existing.Deleted {
			return app{}, fmt.Errorf("group %q not found", id)
		}
	}
	return found, nil
}

// startMover changes userID's groups, pushes each changed group through SCIM,
// and waits for the next ID token, userinfo response, and SAML assertion
// issued to the user to check that they carry the new groups.
func (a *webApp) startMover(environmentID, userID string, addGroupIDs, removeGroupIDs []string) (lifecycleRun, error) {
	change, err := a.changeUserGroups(environmentID, userID, addGroupIDs, removeGroupIDs, true)
	if err != nil {
		return lifecycleRun{}, err
	}
	found := change.App
	label := userLabel(change.User)
	run, err := newLifecycleRun(lifecycleMover, found, change.User)
	if err != nil {
		return lifecycleRun{}, err
	}
	run.expectedGroups = change.Groups
	run.Steps = append(run.Steps, lifecycleStep{ID: "groups", Protocol: "directory", Title: "Change " + label + "'s groups", Status: lifecycleOK, Detail: change.describe()})

	var pushes []lifecyclePush
	if reason := scimSkipReason(found); reason != "" {
		run.Steps = append(run.Steps, lifecycleStep{ID: "scim", Protocol: "scim", Title: "Push the changed groups through SCIM", Status: lifecycleSkipped, Detail: reason})
	} else {
		for _, changed := range slices.Concat(change.Added, change.Removed) {
			run.Steps = append(run.Steps, groupPushStep(changed))
			pushes = append(pushes, lifecyclePush{StepID: "scim-group-" + changed.ID, ResourceType: "group", ResourceID: changed.ID})
		}
	}
	run.Steps = append(run.Steps, issuedGroupsStep(found, "oidc", label, change.Groups), issuedGroupsStep(found, "saml", label, change.Groups))
	return a.startLifecycleRun(run, found, pushes), nil
}

// startLeaver deactivates userID, which ends the user's IdP sessions and sends
// back-channel logout tokens for them. It then revokes the user's tokens,
// offers SAML Single Logout for each ended SAML session, and pushes
// active=false through SCIM.
func (a *webApp) startLeaver(environmentID, userID string) (lifecycleRun, error) {
	a.mu.Lock()
	state, err := a.loadAPIEnvironment(environmentID)
	if err != nil {
		a.mu.Unlock()
		return lifecycleRun{}, err
	}
	found, _ := appByID(state.Apps, environmentID)
	index, ok := userIndexByID(state.Users, userID)
	if !ok || state.Users[index].Deleted {
		a.mu.Unlock()
		return lifecycleRun{}, fmt.Errorf("user %q not found", userID)
	}
	leaver := state.Users[index]
	label := userLabel(leaver)
	deactivate := lifecycleStep{ID: "deactivate", Protocol: "directory", Title: "Deactivate " + label, Status: lifecycleOK, Detail: "Set active to false in scimtest"}
	var ended []idpSession
	if leaver.Active {
		state.Users[index].Active = false
		state.Users[index].Dirty = true
		state.Users[index].LastError = ""
		markUserDirty(&state, userID, false)
		appendLocalOperationLog(&state, "user", userID, summarizeActiveToggle(false))
		ended, err = a.saveRequestStateEndingSessions(state)
	} else {
		deactivate.Status, deactivate.Detail = lifecycleSkipped, label+" was already inactive"
		ended = a.endInactiveUserSessions(state)
	}
	a.mu.Unlock()
	if err != nil {
		return lifecycleRun{}, err
	}
	ended = slices.DeleteFunc(ended, func(session idpSession) bool { return session.SignIn.UserID != userID })

	run, err := newLifecycleRun(lifecycleLeaver, found, leaver)
	if err != nil {
		return lifecycleRun{}, err
	}
	run.Steps = append(run.Steps, deactivate, endedSessionsStep(found, label, ended))
	run.Steps = append(run.Steps, backchannelLogoutSteps(found, ended)...)
	run.Steps = append(run.Steps, samlLogoutSteps(found, ended)...)
	run.Steps = append(run.Steps, a.revokeTokensStep(found, leaver))

	var pushes []lifecyclePush
	if reason := scimSkipReason(found); reason != "" {
		run.Steps = append(run.Steps, lifecycleStep{ID: "scim", Protocol: "scim", Title: "Push active=false through SCIM", Status: lifecycleSkipped, Detail: reason})
	} else {
		run.Steps = append(run.Steps, lifecycleStep{ID: "scim-user", Protocol: "scim", Title: "Push active=false through SCIM", Status: lifecycleRunning, Detail: "Waiting to push"})
		pushes = append(pushes, lifecyclePush{StepID: "scim-user", ResourceType: "user", ResourceID: userID})
	}
	return a.startLifecycleRun(run, found, pushes), nil
}

// changeUserGroups adds userID to addGroupIDs and removes them from
// removeGroupIDs in one save. A mover needs an active user.
func (a *webApp) changeUserGroups(environmentID, userID string, addGroupIDs, removeGroupIDs []string, requireActive bool) (groupChange, error) {
	if len(addGroupIDs)+len(removeGroupIDs) == 0 {
		return groupChange{}, errors.New("choose at least one group to add or remove")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	state, err := a.loadAPIEnvironment(environmentID)
	if err != nil {
		return groupChange{}, err
	}
	found, _ := appByID(state.Apps, environmentID)
	target, ok := userByID(state.Users, userID)
	switch {
	case !ok || target.Deleted:
		return groupChange{}, fmt.Errorf("user %q not found", userID)
	case requireActive && !target.Active:
		return groupChange{}, fmt.Errorf("%s is inactive; activate the user before moving them", userLabel(target))
	}
	label := userLabel(target)
	change := groupChange{App: found, User: target}
	seen := make(map[string]bool)
	for _, adding := range []bool{true, false} {
		ids := removeGroupIDs
		if adding {
			ids = addGroupIDs
		}
		for _, id := range ids {
			index, ok := groupIndexByID(state.Groups, id)
			switch {
			case !ok || state.Groups[index].Deleted:
				return groupChange{}, fmt.Errorf("group %q not found", id)
			case seen[id]:
				return groupChange{}, fmt.Errorf("group %s is listed more than once", state.Groups[index].DisplayName)
			case adding && slices.Contains(state.Groups[index].MemberIDs, userID):
				return groupChange{}, fmt.Errorf("%s is already in %s", label, state.Groups[index].DisplayName)
			case !adding && !slices.Contains(state.Groups[index].MemberIDs, userID):
				return groupChange{}, fmt.Errorf("%s is not in %s", label, state.Groups[index].DisplayName)
			}
			seen[id] = true
			existing := state.Groups[index]
			members := removeString(existing.MemberIDs, userID)
			if adding {
				members = append(slices.Clone(existing.MemberIDs), userID)
			}
			state.Groups[index].MemberIDs = members
			state.Groups[index].Dirty = true
			state.Groups[index].LastError = ""
			markGroupDirty(&state, id, false)
			appendLocalOperationLog(&state, "group", id, summarizeGroupSave(existing, existing.DisplayName, members))
			if adding {
				change.Added = append(change.Added, state.Groups[index])
			} else {
				change.Removed = append(change.Removed, state.Groups[index])
			}
		}
	}
	if err := a.saveRequestState(state); err != nil {
		return groupChange{}, err
	}
	change.Groups = userGroups(state, userID)
	return change, nil
}

func newLifecycleRun(kind string, found app, subject user) (lifecycleRun, error) {
	id, err := newID("lifecycle")
	if err != nil {
		return lifecycleRun{}, err
	}
	return lifecycleRun{
		ID:        id,
		Kind:      kind,
		UserID:    subject.ID,
		User:      userLabel(subject),
		StartedAt: time.Now().UTC().Format(time.RFC3339),
		appSlug:   found.Slug,
	}, nil
}

// endedSessionsStep reports the IdP sessions a leaver's deactivation ended.
func endedSessionsStep(found app, label string, ended []idpSession) lifecycleStep {
	step := lifecycleStep{ID: "sessions", Protocol: "idp", Title: "End " + label + "'s IdP sessions", Status: lifecycleOK}
	switch {
	case !supportsAnyIDP(found):
		step.Status, step.Detail = lifecycleSkipped, "The environment has no OIDC or SAML configuration"
	case len(ended) == 0:
		step.Status, step.Detail = lifecycleSkipped, label+" had no live IdP sessions"
	default:
		descriptions := make([]string, len(ended))
		for i, session := range ended {
			descriptions[i] = "session " + session.ID + " (" + strings.Join(session.Protocols, ", ") + ")"
		}
		step.Detail = "Ended " + strings.Join(descriptions, ", ")
	}
	return step
}

// backchannelLogoutSteps follows the logout token that ending each session
// sent. Ending the sessions already sent them, so the steps only wait for
// the app's answers.
func backchannelLogoutSteps(found app, ended []idpSession) []lifecycleStep {
	skipped := func(detail string) []lifecycleStep {
		return []lifecycleStep{{ID: "backchannel", Protocol: "oidc", Title: "Send back-channel logout tokens", Status: lifecycleSkipped, Detail: detail}}
	}
	switch {
	case !supportsOIDC(found):
		return skipped("OIDC is not enabled for this environment")
	case strings.TrimSpace(found.OIDCBackchannelLogoutURI) == "":
		return skipped("Set the environment's back-channel logout URI to send logout tokens")
	}
	var steps []lifecycleStep
	for _, session := range ended {
		if session.OIDCIssuer == "" {
			continue
		}
		steps = append(steps, lifecycleStep{
			ID:       "backchannel-" + session.ID,
			Protocol: "oidc",
			Title:    "Back-channel logout for session " + session.ID,
			Status:   lifecycleRunning,
			Detail:   "Sending a logout token",
			session:  session,
		})
	}
	if len(steps) == 0 {
		return skipped("No ended session had issued ID tokens")
	}
	return steps
}

// samlLogoutSteps offers IdP-initiated Single Logout for each ended session
// with a SAML sign-in. Both bindings travel through a browser, so each step
// waits for the tester to send its LogoutRequest from the checklist.
func samlLogoutSteps(found app, ended []idpSession) []lifecycleStep {
	skipped := func(detail string) []lifecycleStep {
		return []lifecycleStep{{ID: "saml-logout", Protocol: "saml", Title: "Send SAML LogoutRequests", Status: lifecycleSkipped, Detail: detail}}
	}
	switch {
	case !supportsSAML(found):
		return skipped("SAML is not enabled for this environment")
	case strings.TrimSpace(found.SAMLSLOURL) == "":
		return skipped("Set the SP's Single Logout URL on the environment to send LogoutRequests")
	}
	var steps []lifecycleStep
	for _, session := range ended {
		if session.SAMLSessionIndex == "" {
			continue
		}
		steps = append(steps, lifecycleStep{
			ID:       "saml-logout-" + session.ID,
			Protocol: "saml",
			Title:    "SAML Single Logout for session " + session.ID,
			Status:   lifecycleNeedsBrowser,
			Detail:   "A LogoutRequest travels through a browser. Send it from the Lifecycle checklist.",
			session:  session,
		})
	}
	if len(steps) == 0 {
		return skipped("No ended session had signed in over SAML")
	}
	return steps
}

// revokeTokensStep revokes the leaver's access and refresh tokens.
func (a *webApp) revokeTokensStep(found app, leaver user) lifecycleStep {
	step := lifecycleStep{ID: "revoke", Protocol: "oidc", Title: "Revoke " + userLabel(leaver) + "'s tokens", Status: lifecycleOK}
	if !supportsOIDC(found) {
		step.Status, step.Detail = lifecycleSkipped, "OIDC is not enabled for this environment"
		return step
	}
	revoked := a.revokeOIDCTokens(found.Slug, leaver.ID)
	step.Detail = fmt.Sprintf("Revoked %d tokens", revoked)
	a.recordFlowEvent(found.Slug, "oidc", "revoke", "ok", userLabel(leaver), step.Detail)
	return step
}

func groupPushStep(changed group) lifecycleStep {
	return lifecycleStep{ID: "scim-group-" + changed.ID, Protocol: "scim", Title: "Push group " + changed.DisplayName + " through SCIM", Status: lifecycleRunning, Detail: "Waiting to push"}
}

// issuedGroupsStep waits for the next ID token or userinfo response (oidc),
// or the next assertion (saml), issued to a mover.
func issuedGroupsStep(found app, protocol, label string, expected []string) lifecycleStep {
	step := lifecycleStep{ID: protocol + "-groups", Protocol: protocol, Title: "Next SAML assertion carries the new groups"}
	enabled, name := supportsSAML(found), "SAML"
	waitingFor := "the next SAML assertion for " + label
	if protocol == "oidc" {
		step.Title = "Next ID token or userinfo response carries the new groups"
		enabled, name = supportsOIDC(found), "OIDC"
		waitingFor = "the next ID token or userinfo response for " + label + ". The app must request the groups scope"
	}
	switch {
	case !enabled:
		step.Status, step.Detail = lifecycleSkipped, name+" is not enabled for this environment"
	case !found.IncludeGroupsClaim:
		step.Status, step.Detail = lifecycleSkipped, "The environment does not send groups; turn on the groups claim to check them"
	default:
		step.Status, step.Detail = lifecycleWaiting, "Waiting for "+waitingFor+". Expected groups: "+describeGroups(expected)
	}
	return step
}

func describeGroups(groups []string) string {
	if len(groups) == 0 {
		return "none"
	}
	return strings.Join(groups, ", ")
}

// scimSkipReason explains why a run cannot push through SCIM, or returns
// empty when it can.
func scimSkipReason(found app) string {
	switch {
	case !found.SCIMEnabled:
		return "SCIM is not enabled for this environment"
	case strings.TrimSpace(found.SCIMBaseURL) == "" || strings.TrimSpace(found.SCIMBearerToken) == "":
		return "Set the environment's SCIM base URL and bearer token to provision"
	}
	return ""
}

// startLifecycleRun stores run, starts its SCIM pushes in the background, and
// returns the run as it stands.
func (a *webApp) startLifecycleRun(run lifecycleRun, found app, pushes []lifecyclePush) lifecycleRun {
	a.lifecycleMu.Lock()
	if a.lifecycleRuns == nil {
		a.lifecycleRuns = make(map[string][]lifecycleRun)
	}
	runs := append([]lifecycleRun{run}, a.lifecycleRuns[found.Slug]...)
	if len(runs) > maxLifecycleRuns {
		runs = runs[:maxLifecycleRuns]
	}
	a.lifecycleRuns[found.Slug] = runs
	a.lifecycleMu.Unlock()

	a.recordFlowEvent(found.Slug, "lifecycle", run.Kind, "ok", run.User, strings.ToUpper(run.Kind[:1])+run.Kind[1:]+" scenario started; see its Lifecycle checklist")
	if len(pushes) > 0 {
		a.lifecycleWork.Add(1)
		go func() {
			defer a.lifecycleWork.Done()
			a.runLifecyclePushes(found, run.ID, pushes)
		}()
	}
	current, _ := a.lifecycleRun(found.Slug, run.ID)
	return current
}

// runLifecyclePushes pushes each resource in turn, since scimtest runs one
// sync at a time.
func (a *webApp) runLifecyclePushes(found app, runID string, pushes []lifecyclePush) {
	failed := make(map[string]bool)
	for _, push := range pushes {
		if push.DependsOn != "" && failed[push.DependsOn] {
			a.updateLifecycleStep(found.Slug, runID, push.StepID, func(step *lifecycleStep) {
				step.Status, step.Detail = lifecycleSkipped, "Skipped because the user was not provisioned"
			})
			continue
		}
		if !a.runLifecyclePush(found, runID, push) {
			failed[push.StepID] = true
		}
	}
}

// runLifecyclePush pushes one resource and records each SCIM request it made
// and the app's answers. It reports whether the push succeeded.
func (a *webApp) runLifecyclePush(found app, runID string, push lifecyclePush) bool {
	a.updateLifecycleStep(found.Slug, runID, push.StepID, func(step *lifecycleStep) { step.Detail = "Pushing" })
	job, err := a.startSyncJob(found.ID, found.Name, "push", push.ResourceType, push.ResourceID)
	if err != nil {
		a.updateLifecycleStep(found.Slug, runID, push.StepID, func(step *lifecycleStep) {
			step.Status, step.Detail = lifecycleFailed, "The push did not start: "+err.Error()
		})
		return false
	}
	done := a.awaitSyncJob(found.ID, job.ID)
	messages := a.lifecycleSCIMMessages(found, push)
	a.updateLifecycleStep(found.Slug, runID, push.StepID, func(step *lifecycleStep) {
		step.Messages = messages
		switch {
		case done == nil:
			step.Status, step.Detail = lifecycleFailed, "A later sync replaced this push's result; see the sync trace"
		case done.Success:
			step.Status, step.Detail = lifecycleOK, done.Message
		default:
			step.Status, step.Detail = lifecycleFailed, done.Message
		}
	})
	return done != nil && done.Success
}

// awaitSyncJob waits for appID's sync job jobID to finish and returns it, or
// nil when another job has replaced it.
func (a *webApp) awaitSyncJob(appID, jobID string) *syncJobSnapshot {
	ticker := time.NewTicker(lifecyclePollInterval)
	defer ticker.Stop()
	for {
		job := a.currentSyncJob(appID)
		switch {
		case job == nil || job.ID != jobID:
			return nil
		case job.Done:
			return job
		}
		<-ticker.C
	}
}

// lifecycleSCIMMessages turns the sync trace's requests for push's resource
// into checklist messages.
func (a *webApp) lifecycleSCIMMessages(found app, push lifecyclePush) []lifecycleMessage {
	a.traceMu.Lock()
	traces := slices.Clone(a.lastTraces[found.ID])
	a.traceMu.Unlock()
	baseURL := strings.TrimRight(strings.TrimSpace(found.SCIMBaseURL), "/")
	var messages []lifecycleMessage
	for _, trace := range traces {
		if trace.ResourceType != push.ResourceType || trace.ResourceID != push.ResourceID {
			continue
		}
		message := lifecycleMessage{
			At:       trace.CreatedAt,
			Sent:     trace.Method + " " + trace.Path,
			To:       baseURL + trace.Path,
			Body:     trace.RequestBody,
			Response: trace.Status,
			Outcome:  lifecycleOK,
		}
		if trace.Err != "" {
			message.Response, message.Outcome = trace.Err, lifecycleFailed
		}
		messages = append(messages, message)
	}
	return messages
}

// updateLifecycleStep applies update to one step of a stored run.
func (a *webApp) updateLifecycleStep(slug, runID, stepID string, update func(*lifecycleStep)) {
	a.lifecycleMu.Lock()
	defer a.lifecycleMu.Unlock()
	for i := range a.lifecycleRuns[slug] {
		run := &a.lifecycleRuns[slug][i]
		if run.ID != runID {
			continue
		}
		if step := run.step(stepID); step != nil {
			update(step)
		}
		return
	}
}

func (r *lifecycleRun) step(id string) *lifecycleStep {
	for i := range r.Steps {
		if r.Steps[i].ID == id {
			return &r.Steps[i]
		}
	}
	return nil
}

// lifecycleRunsFor returns slug's runs, newest first, with the results that
// arrived through the back-channel and Single Logout logs folded in.
func (a *webApp) lifecycleRunsFor(slug string) []lifecycleRun {
	a.lifecycleMu.Lock()
	defer a.lifecycleMu.Unlock()
	runs := make([]lifecycleRun, len(a.lifecycleRuns[slug]))
	for i := range a.lifecycleRuns[slug] {
		run := &a.lifecycleRuns[slug][i]
		a.settleLifecycleRun(run)
		runs[i] = run.clone()
	}
	return runs
}

// lifecycleRun returns slug's run id, settled like lifecycleRunsFor.
func (a *webApp) lifecycleRun(slug, id string) (lifecycleRun, bool) {
	a.lifecycleMu.Lock()
	defer a.lifecycleMu.Unlock()
	for i := range a.lifecycleRuns[slug] {
		run := &a.lifecycleRuns[slug][i]
		if run.ID == id {
			a.settleLifecycleRun(run)
			return run.clone(), true
		}
	}
	return lifecycleRun{}, false
}

// settleLifecycleRun copies results that other logs hold into run's logout
// steps, then sets the run's status. The caller holds lifecycleMu.
func (a *webApp) settleLifecycleRun(run *lifecycleRun) {
	for i := range run.Steps {
		step := &run.Steps[i]
		switch {
		case strings.HasPrefix(step.ID, "backchannel-"):
			settleBackchannelStep(step, a.logoutResultsFor(step.session.ID))
		case step.requestID != "":
			if logout, ok := a.samlLogoutResult(run.appSlug, step.requestID); ok {
				settleSAMLLogoutStep(step, logout)
			}
		}
	}
	run.Status = run.status()
}

// settleBackchannelStep shows each logout token that ending the step's
// session sent, and the app's answers.
func settleBackchannelStep(step *lifecycleStep, results []backchannelLogoutResult) {
	if len(results) == 0 {
		return
	}
	step.Messages = make([]lifecycleMessage, len(results))
	step.Status = lifecycleSkipped
	for i, result := range results {
		step.Messages[i] = lifecycleMessage{
			At:       result.At.UTC().Format(time.RFC3339),
			Sent:     result.Token,
			To:       result.URI,
			Response: result.Response,
			Outcome:  result.Outcome,
		}
		switch {
		case result.Outcome == lifecycleFailed:
			step.Status = lifecycleFailed
		case result.Outcome == lifecycleOK && step.Status == lifecycleSkipped:
			step.Status = lifecycleOK
		}
	}
	step.Detail = results[len(results)-1].Response
}

// settleSAMLLogoutStep shows the SP's answer to the step's latest
// LogoutRequest.
func settleSAMLLogoutStep(step *lifecycleStep, logout samlLogout) {
	if len(step.Messages) == 0 {
		return
	}
	latest := &step.Messages[len(step.Messages)-1]
	switch logout.Outcome {
	case samlLogoutPending:
		step.Status, step.Detail = lifecycleWaiting, "Waiting for the SP's LogoutResponse"
		return
	case "ok":
		step.Status = lifecycleOK
	default:
		step.Status = lifecycleFailed
	}
	step.Detail = "The SP's LogoutResponse: " + logout.Detail
	latest.Response, latest.Outcome = "LogoutResponse: "+logout.Detail, step.Status
}

// status sums up the run: running while scimtest works on a step, failed
// once any step failed, waiting while a step waits for the app or the
// tester, and ok otherwise.
func (r lifecycleRun) status() string {
	status := lifecycleOK
	for _, step := range r.Steps {
		switch step.Status {
		case lifecycleRunning:
			return lifecycleRunning
		case lifecycleFailed:
			status = lifecycleFailed
		case lifecycleWaiting, lifecycleNeedsBrowser:
			if status == lifecycleOK {
				status = lifecycleWaiting
			}
		}
	}
	return status
}

func (r lifecycleRun) clone() lifecycleRun {
	r.Steps = slices.Clone(r.Steps)
	for i := range r.Steps {
		r.Steps[i].Messages = slices.Clone(r.Steps[i].Messages)
	}
	r.expectedGroups = slices.Clone(r.expectedGroups)
	return r
}

// lifecycleGroupClaims describes the group claim or attribute actually issued.
type lifecycleGroupClaims struct {
	Groups  []string
	Carried bool
	Overage bool
}

// noteIssuedGroups checks the next groups issued to a mover's user. An Entra
// overage response leaves the check waiting until its source serves the groups.
func (a *webApp) noteIssuedGroups(app app, userID, protocol, issued, to string, claims lifecycleGroupClaims) {
	stepID := protocol + "-groups"
	now := time.Now().UTC().Format(time.RFC3339)
	a.lifecycleMu.Lock()
	defer a.lifecycleMu.Unlock()
	for i := range a.lifecycleRuns[app.Slug] {
		run := &a.lifecycleRuns[app.Slug][i]
		if run.Kind != lifecycleMover || run.UserID != userID {
			continue
		}
		step := run.step(stepID)
		if step == nil || step.Status != lifecycleWaiting {
			continue
		}
		want := run.expectedGroups
		if protocol == "oidc" && normalizePersona(app.Persona) == personaOkta && !slices.Contains(want, oktaEveryoneGroup) {
			want = append(slices.Clone(want), oktaEveryoneGroup)
		}
		message := lifecycleMessage{At: now, Sent: issued, To: to, Body: "groups: " + describeGroups(claims.Groups)}
		switch {
		case claims.Overage && protocol == "oidc" && supportsEntraPersona(app):
			message.Body = "groups overage"
			step.Detail = "The " + issued + " carried groups overage; waiting for the group source response"
		case !claims.Carried:
			message.Body = "no groups"
			step.Status, step.Detail = lifecycleFailed, "The "+issued+" carried no groups"
		case sameGroups(claims.Groups, want):
			step.Status, step.Detail = lifecycleOK, "The "+issued+" carried the new groups: "+describeGroups(claims.Groups)
		default:
			step.Status, step.Detail = lifecycleFailed, "The "+issued+" carried "+describeGroups(claims.Groups)+"; expected "+describeGroups(want)
		}
		message.Outcome = step.Status
		step.Messages = append(step.Messages, message)
	}
}

func sameGroups(got, want []string) bool {
	got, want = slices.Clone(got), slices.Clone(want)
	slices.Sort(got)
	slices.Sort(want)
	return slices.Equal(got, want)
}

// claimGroups reads the mapped groups claim, including a distributed source.
func claimGroups(claims map[string]any, name string) lifecycleGroupClaims {
	value, ok := claims[name]
	if !ok || name == "" {
		names, _ := claims["_claim_names"].(map[string]string)
		sources, _ := claims["_claim_sources"].(map[string]any)
		source, _ := sources[names[name]].(map[string]string)
		return lifecycleGroupClaims{Overage: name != "" && source["endpoint"] != ""}
	}
	result := lifecycleGroupClaims{Carried: true}
	switch typed := value.(type) {
	case []string:
		result.Groups = typed
	case []any:
		for _, item := range typed {
			result.Groups = append(result.Groups, fmt.Sprint(item))
		}
	case nil:
	default:
		result.Groups = []string{fmt.Sprint(value)}
	}
	return result
}

// samlAssertionGroups reads the values of the attribute name from the
// assertion that posted carries. issued is false when posted carries no
// assertion, as an error status response does not.
func samlAssertionGroups(posted samlPostedResponse, name string) (groups []string, carried, issued bool) {
	source := posted.PlaintextAssertion
	if source == "" {
		source = posted.XML
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromString(source); err != nil {
		return nil, false, false
	}
	assertion := findElementByLocalName(doc.Root(), "Assertion")
	if assertion == nil {
		return nil, false, false
	}
	statement := childElementByLocalName(assertion, "AttributeStatement")
	if statement == nil {
		return nil, false, true
	}
	for _, attribute := range statement.ChildElements() {
		if elementLocalName(attribute) != "Attribute" || attribute.SelectAttrValue("Name", "") != name {
			continue
		}
		for _, value := range attribute.ChildElements() {
			if elementLocalName(value) == "AttributeValue" {
				groups = append(groups, value.Text())
			}
		}
		return groups, true, true
	}
	return nil, false, true
}

// lifecycleLogoutSession returns the ended session that a leaver's SAML
// logout step is about.
func (a *webApp) lifecycleLogoutSession(slug, runID, stepID string) (idpSession, error) {
	a.lifecycleMu.Lock()
	defer a.lifecycleMu.Unlock()
	for i := range a.lifecycleRuns[slug] {
		run := &a.lifecycleRuns[slug][i]
		if run.ID != runID {
			continue
		}
		step := run.step(stepID)
		if step == nil || !step.CanSendLogout() {
			return idpSession{}, fmt.Errorf("step %q has no SAML LogoutRequest to send", stepID)
		}
		return step.session, nil
	}
	return idpSession{}, fmt.Errorf("lifecycle run %q not found", runID)
}

// CanSendLogout reports whether the tester can still send the step's SAML
// LogoutRequest from the checklist.
func (s lifecycleStep) CanSendLogout() bool {
	return strings.HasPrefix(s.ID, "saml-logout-") && s.Status != lifecycleOK
}

// StatusClass picks the status pill style for the step.
func (s lifecycleStep) StatusClass() string { return lifecycleStatusClass(s.Status) }

// StatusLabel names the step's status for people.
func (s lifecycleStep) StatusLabel() string { return lifecycleStatusLabel(s.Status) }

// StatusClass picks the status pill style for the run.
func (r lifecycleRun) StatusClass() string { return lifecycleStatusClass(r.Status) }

// StatusLabel names the run's status for people.
func (r lifecycleRun) StatusLabel() string { return lifecycleStatusLabel(r.Status) }

// KindLabel names the run's scenario for people.
func (r lifecycleRun) KindLabel() string { return strings.ToUpper(r.Kind[:1]) + r.Kind[1:] }

func lifecycleStatusClass(status string) string {
	switch status {
	case lifecycleOK:
		return "synced"
	case lifecycleFailed:
		return "error"
	case lifecycleSkipped:
		return ""
	}
	return "pending"
}

func lifecycleStatusLabel(status string) string {
	switch status {
	case lifecycleRunning:
		return "Running"
	case lifecycleWaiting:
		return "Waiting"
	case lifecycleNeedsBrowser:
		return "Needs browser"
	case lifecycleOK:
		return "OK"
	case lifecycleFailed:
		return "Failed"
	}
	return "Skipped"
}

// lifecyclePageData is the Lifecycle tab.
type lifecyclePageData struct {
	App     app
	Error   string
	Users   []user // users a mover or leaver can pick, active first
	Groups  []group
	Runs    []lifecycleRun
	Running bool // a step is still running, so the page refreshes itself
}

func (a *webApp) buildLifecyclePageData(found app, state appState, pageError string) *lifecyclePageData {
	data := &lifecyclePageData{App: found, Error: strings.TrimSpace(pageError), Runs: a.lifecycleRunsFor(found.Slug)}
	for _, candidate := range state.Users {
		if !candidate.Deleted {
			data.Users = append(data.Users, candidate)
		}
	}
	slices.SortStableFunc(data.Users, func(x, y user) int {
		switch {
		case x.Active == y.Active:
			return strings.Compare(userLabel(x), userLabel(y))
		case x.Active:
			return -1
		}
		return 1
	})
	for _, candidate := range state.Groups {
		if !candidate.Deleted {
			data.Groups = append(data.Groups, candidate)
		}
	}
	for _, run := range data.Runs {
		data.Running = data.Running || run.Status == lifecycleRunning
	}
	return data
}

// handleLifecycle opens the Lifecycle tab for an environment.
func (a *webApp) handleLifecycle(w http.ResponseWriter, r *http.Request) {
	_, found, ok := appForProtocol(w, r, anyEnvironment)
	if !ok {
		return
	}
	http.Redirect(w, r, lifecycleDashboardURL(found, "", ""), http.StatusSeeOther)
}

// handleLifecycleRun runs the scenario that the Lifecycle tab's form names.
func (a *webApp) handleLifecycleRun(w http.ResponseWriter, r *http.Request) {
	_, found, ok := appForProtocol(w, r, anyEnvironment)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, lifecycleDashboardURL(found, "", err.Error()), http.StatusSeeOther)
		return
	}
	var run lifecycleRun
	var err error
	switch r.FormValue("kind") {
	case lifecycleJoiner:
		run, err = a.startJoiner(found.ID, apiUserRequest{
			GivenName:  formStringPointer(r, "given_name"),
			FamilyName: formStringPointer(r, "family_name"),
			Email:      formStringPointer(r, "email"),
			Username:   formStringPointer(r, "username"),
		}, r.Form["group_ids"])
	case lifecycleMover:
		run, err = a.startMover(found.ID, r.FormValue("user_id"), r.Form["add_group_ids"], r.Form["remove_group_ids"])
	case lifecycleLeaver:
		run, err = a.startLeaver(found.ID, r.FormValue("user_id"))
	default:
		err = fmt.Errorf("unknown scenario %q", r.FormValue("kind"))
	}
	if err != nil {
		http.Redirect(w, r, lifecycleDashboardURL(found, "", err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, lifecycleDashboardURL(found, run.ID, ""), http.StatusSeeOther)
}

// handleLifecycleSAMLLogout sends the SP a LogoutRequest for a leaver's ended
// SAML session through the tester's browser. The SP's LogoutResponse comes
// back to the SingleLogoutService and settles the step.
func (a *webApp) handleLifecycleSAMLLogout(w http.ResponseWriter, r *http.Request) {
	state, found, ok := appForProtocol(w, r, supportsSAML)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, lifecycleDashboardURL(found, "", err.Error()), http.StatusSeeOther)
		return
	}
	runID, stepID := r.FormValue("run_id"), r.FormValue("step_id")
	binding, err := parseSAMLBinding(r.FormValue("binding"))
	var session idpSession
	if err == nil {
		session, err = a.lifecycleLogoutSession(found.Slug, runID, stepID)
	}
	var message samlOutboundMessage
	if err == nil {
		message, err = a.startSAMLLogout(found, a.effectiveIDPBaseURL(r, state), session, binding)
	}
	if err != nil {
		http.Redirect(w, r, lifecycleDashboardURL(found, runID, err.Error()), http.StatusSeeOther)
		return
	}
	a.updateLifecycleStep(found.Slug, runID, stepID, func(step *lifecycleStep) {
		step.requestID = message.ID
		step.Status, step.Detail = lifecycleWaiting, "Waiting for the SP's LogoutResponse"
		step.Messages = append(step.Messages, lifecycleMessage{
			At:      time.Now().UTC().Format(time.RFC3339),
			Sent:    "LogoutRequest " + message.ID + " (" + samlBindingName(binding) + ")",
			To:      found.SAMLSLOURL,
			Outcome: samlLogoutPending,
		})
	})
	message.deliver(w, r)
}

func anyEnvironment(app) bool { return true }

func formStringPointer(r *http.Request, name string) *string {
	value := r.FormValue(name)
	return &value
}

// lifecycleDashboardURL opens the Lifecycle tab, scrolled to runID when it is
// set, with pageError shown.
func lifecycleDashboardURL(found app, runID, pageError string) string {
	target := dashboardURL("lifecycle", map[string]string{"environment": found.ID, "error": pageError})
	if runID != "" {
		target += "#lifecycle-run-" + runID
	}
	return target
}
