package web

import (
	"crypto/rsa"
	"embed"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

//go:embed templates/*.html
var templateFS embed.FS

var pageTemplate = template.Must(template.New("index.html").Funcs(template.FuncMap{
	"join": strings.Join,
}).ParseFS(templateFS, "templates/index.html"))

type webApp struct {
	mu               sync.Mutex
	signingKey       *rsa.PrivateKey
	certDER          []byte
	authCodes        map[string]authCode
	accessTokens     map[string]accessToken
	lastTrace        []syncTraceEntry
	lastTraceContent string
}

type flashMessage struct {
	Kind    string
	Message string
}

type statsView struct {
	Users       int
	DirtyUsers  int
	Groups      int
	DirtyGroups int
	Apps        int
}

type userRowView struct {
	ID         string
	Name       string
	Username   string
	Email      string
	Active     string
	Status     string
	RemoteID   string
	Deleted    bool
	EditURL    string
	HistoryURL string
}

type groupRowView struct {
	ID             string
	Name           string
	MembersSummary string
	MemberCount    int
	Status         string
	RemoteID       string
	Deleted        bool
	EditURL        string
	HistoryURL     string
}

type appRowView struct {
	ID                     string
	Name                   string
	Slug                   string
	Protocol               string
	OIDCClientID           string
	OIDCDiscovery          string
	OIDCAuthorize          string
	OIDCJWKS               string
	SAMLMetadata           string
	SAMLSSO                string
	SAMLIDPEntityID        string
	SAMLCertificatePEM     string
	SAMLEmailAttributeName string
	SAMLSPACSURL           string
	SAMLSPAudience         string
	SupportsOIDC           bool
	SupportsSAML           bool
	EditURL                string
	HasRedirectURI         bool
}

type historyEntryView struct {
	Timestamp string
	Summary   string
	Kind      string
	Detail    string
	HasDetail bool
}

type historyView struct {
	Title string
	Close string
	Items []historyEntryView
}

type userFormView struct {
	Title string
	ID    string
	User  user
	Close string
}

type memberOptionView struct {
	ID      string
	Label   string
	Meta    string
	Checked bool
}

type groupFormView struct {
	Title   string
	ID      string
	Group   group
	Members []memberOptionView
	Close   string
}

type appFormView struct {
	Title              string
	App                app
	OIDCRedirectURIs   string
	SAMLCertificatePEM string
	SAMLIDPEntityID    string
	SAMLIDPSSO         string
	Close              string
}

type configFormView struct {
	Config config
	Close  string
}

type pageData struct {
	Tab               string
	Flash             flashMessage
	Stats             statsView
	Users             []userRowView
	Groups            []groupRowView
	Apps              []appRowView
	Errors            []string
	BaseURL           string
	IDPBaseURL        string
	SCIMEnabled       bool
	TracePopupEnabled bool
	UsersURL          string
	GroupsURL         string
	AppsURL           string
	NewUserURL        string
	NewGroupURL       string
	NewAppURL         string
	ConfigURL         string
	TraceURL          string
	TraceCloseURL     string
	ShowTrace         bool
	HasTrace          bool
	TraceContent      string
	History           *historyView
	UserForm          *userFormView
	GroupForm         *groupFormView
	AppForm           *appFormView
	ConfigForm        *configFormView
}

func Run() error {
	port := strings.TrimSpace(os.Getenv("PORT"))
	if port == "" {
		port = "8080"
	}

	key, certDER, err := loadOrCreateSigningMaterial()
	if err != nil {
		return err
	}

	app := &webApp{
		signingKey:   key,
		certDER:      certDER,
		authCodes:    make(map[string]authCode),
		accessTokens: make(map[string]accessToken),
	}
	addr := ":" + port
	log.Printf("merged auth test service listening on http://localhost%s", addr)
	return http.ListenAndServe(addr, app.routes())
}

func (a *webApp) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", a.handleIndex)
	mux.HandleFunc("POST /users/save", a.handleUserSave)
	mux.HandleFunc("POST /users/{id}/toggle-active", a.handleUserToggleActive)
	mux.HandleFunc("POST /users/{id}/delete", a.handleUserDelete)
	mux.HandleFunc("POST /users/{id}/restore", a.handleUserRestore)
	mux.HandleFunc("POST /groups/save", a.handleGroupSave)
	mux.HandleFunc("POST /groups/{id}/delete", a.handleGroupDelete)
	mux.HandleFunc("POST /groups/{id}/restore", a.handleGroupRestore)
	mux.HandleFunc("POST /apps/save", a.handleAppSave)
	mux.HandleFunc("POST /apps/{id}/delete", a.handleAppDelete)
	mux.HandleFunc("POST /config/save", a.handleConfigSave)
	mux.HandleFunc("POST /config/clear", a.handleConfigClear)
	mux.HandleFunc("POST /sync", a.handleSync)
	mux.HandleFunc("POST /import", a.handleImport)
	mux.HandleFunc("POST /reset", a.handleReset)
	mux.HandleFunc("GET /oidc/{slug}/.well-known/openid-configuration", a.handleOIDCDiscovery)
	mux.HandleFunc("GET /oidc/{slug}/jwks", a.handleOIDCJWKS)
	mux.HandleFunc("GET /oidc/{slug}/authorize", a.handleOIDCAuthorize)
	mux.HandleFunc("POST /oidc/{slug}/authorize", a.handleOIDCAuthorizePost)
	mux.HandleFunc("POST /oidc/{slug}/token", a.handleOIDCToken)
	mux.HandleFunc("GET /oidc/{slug}/userinfo", a.handleOIDCUserinfo)
	mux.HandleFunc("POST /oidc/{slug}/userinfo", a.handleOIDCUserinfo)
	mux.HandleFunc("GET /saml/{slug}/metadata", a.handleSAMLMetadata)
	mux.HandleFunc("GET /saml/{slug}/sso", a.handleSAMLSSO)
	mux.HandleFunc("POST /saml/{slug}/sso", a.handleSAMLSSOPost)
	return mux
}

func (a *webApp) handleIndex(w http.ResponseWriter, r *http.Request) {
	state, err := loadState()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	tab := normalizedTab(r.URL.Query().Get("tab"))
	flash := consumeFlash(w, r)
	showTrace := r.URL.Query().Get("showTrace") == "1"
	if consumeShowTrace(w, r) {
		showTrace = true
	}

	data := pageData{
		Tab:               tab,
		Flash:             flash,
		Stats:             buildStats(state),
		Users:             buildUserRows(state, tab),
		Groups:            buildGroupRows(state, tab),
		Apps:              buildAppRows(state, effectiveIDPBaseURL(r, state), certificatePEM(a.certDER)),
		Errors:            buildErrorList(state),
		BaseURL:           configuredBaseURL(state.Config.BaseURL),
		IDPBaseURL:        effectiveIDPBaseURL(r, state),
		SCIMEnabled:       scimEnabled(state),
		TracePopupEnabled: state.Config.AutoOpenSyncTrace,
		UsersURL:          dashboardURL("users", nil),
		GroupsURL:         dashboardURL("groups", nil),
		AppsURL:           dashboardURL("apps", nil),
		NewUserURL:        dashboardURL("users", map[string]string{"modal": "user"}),
		NewGroupURL:       dashboardURL("groups", map[string]string{"modal": "group"}),
		NewAppURL:         dashboardURL("apps", map[string]string{"modal": "app"}),
		ConfigURL:         dashboardURL(tab, map[string]string{"modal": "config"}),
		TraceURL:          dashboardURL(tab, map[string]string{"showTrace": "1"}),
		TraceCloseURL:     dashboardURL(tab, nil),
		ShowTrace:         showTrace && a.hasTrace(),
		HasTrace:          a.hasTrace(),
		TraceContent:      a.traceContent(),
	}
	if !data.SCIMEnabled {
		data.Errors = nil
		data.ShowTrace = false
		data.HasTrace = false
	}

	if history := buildHistoryView(state, tab, r.URL.Query()); history != nil {
		data.History = history
	}

	switch r.URL.Query().Get("modal") {
	case "user":
		if form, formErr := buildUserFormView(state, tab, r.URL.Query().Get("id")); formErr == nil {
			data.UserForm = form
		}
	case "group":
		if form, formErr := buildGroupFormView(state, tab, r.URL.Query().Get("id")); formErr == nil {
			data.GroupForm = form
		}
	case "app":
		if form, formErr := buildAppFormView(state, tab, r.URL.Query().Get("id"), data.IDPBaseURL, certificatePEM(a.certDER)); formErr == nil {
			data.AppForm = form
		}
	case "config":
		data.ConfigForm = &configFormView{
			Config: state.Config,
			Close:  dashboardURL(tab, nil),
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := pageTemplate.ExecuteTemplate(w, "index.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (a *webApp) handleUserSave(w http.ResponseWriter, r *http.Request) {
	tab := normalizedTab(r.FormValue("tab"))
	a.mu.Lock()
	defer a.mu.Unlock()

	state, err := loadState()
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

	if err := validateUser(givenName, familyName, email, username); err != nil {
		a.redirectError(w, r, tab, err)
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

	if err := saveState(state); err != nil {
		a.redirectError(w, r, tab, err)
		return
	}

	redirectWithFlash(w, r, dashboardURL("users", nil), flashMessage{Kind: "success", Message: status})
	return
}

func (a *webApp) handleUserToggleActive(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	tab := normalizedTab(r.FormValue("tab"))
	a.mu.Lock()
	defer a.mu.Unlock()

	state, err := loadState()
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
	appendLocalOperationLog(&state, "user", state.Users[index].ID, summarizeActiveToggle(state.Users[index].Active))

	if err := saveState(state); err != nil {
		a.redirectError(w, r, tab, err)
		return
	}

	status := "user deactivated"
	if state.Users[index].Active {
		status = "user activated"
	}
	redirectWithFlash(w, r, dashboardURL("users", nil), flashMessage{Kind: "success", Message: status})
}

func (a *webApp) handleUserDelete(w http.ResponseWriter, r *http.Request) {
	a.handleUserDeletedState(w, r, true)
}

func (a *webApp) handleUserRestore(w http.ResponseWriter, r *http.Request) {
	a.handleUserDeletedState(w, r, false)
}

func (a *webApp) handleUserDeletedState(w http.ResponseWriter, r *http.Request, deleted bool) {
	id := r.PathValue("id")
	tab := normalizedTab(r.FormValue("tab"))
	a.mu.Lock()
	defer a.mu.Unlock()

	state, err := loadState()
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
		redirectWithFlash(w, r, dashboardURL("users", nil), flashMessage{Kind: "success", Message: "user deleted"})
		return
	}

	state.Users[index].Deleted = deleted
	state.Users[index].Dirty = true
	state.Users[index].LastError = ""
	appendLocalOperationLog(&state, "user", state.Users[index].ID, localDeleteSummary(deleted))

	if err := saveState(state); err != nil {
		a.redirectError(w, r, tab, err)
		return
	}

	status := "user restored"
	if deleted {
		status = "user marked for deletion"
	}
	redirectWithFlash(w, r, dashboardURL("users", nil), flashMessage{Kind: "success", Message: status})
}

func (a *webApp) handleGroupSave(w http.ResponseWriter, r *http.Request) {
	tab := normalizedTab(r.FormValue("tab"))
	a.mu.Lock()
	defer a.mu.Unlock()

	state, err := loadState()
	if err != nil {
		a.redirectError(w, r, tab, err)
		return
	}

	id := strings.TrimSpace(r.FormValue("id"))
	displayName := strings.TrimSpace(r.FormValue("display_name"))
	memberIDs := selectedMemberIDs(state.Users, r.Form["member_ids"])

	if err := validateGroup(displayName); err != nil {
		a.redirectError(w, r, tab, err)
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

	if err := saveState(state); err != nil {
		a.redirectError(w, r, tab, err)
		return
	}

	redirectWithFlash(w, r, dashboardURL("groups", nil), flashMessage{Kind: "success", Message: status})
}

func (a *webApp) handleGroupDelete(w http.ResponseWriter, r *http.Request) {
	a.handleGroupDeletedState(w, r, true)
}

func (a *webApp) handleGroupRestore(w http.ResponseWriter, r *http.Request) {
	a.handleGroupDeletedState(w, r, false)
}

func (a *webApp) handleGroupDeletedState(w http.ResponseWriter, r *http.Request, deleted bool) {
	id := r.PathValue("id")
	tab := normalizedTab(r.FormValue("tab"))
	a.mu.Lock()
	defer a.mu.Unlock()

	state, err := loadState()
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
		redirectWithFlash(w, r, dashboardURL("groups", nil), flashMessage{Kind: "success", Message: "group deleted"})
		return
	}

	state.Groups[index].Deleted = deleted
	state.Groups[index].Dirty = true
	state.Groups[index].LastError = ""
	appendLocalOperationLog(&state, "group", state.Groups[index].ID, localDeleteSummary(deleted))

	if err := saveState(state); err != nil {
		a.redirectError(w, r, tab, err)
		return
	}

	status := "group restored"
	if deleted {
		status = "group marked for deletion"
	}
	redirectWithFlash(w, r, dashboardURL("groups", nil), flashMessage{Kind: "success", Message: status})
}

func (a *webApp) handleConfigSave(w http.ResponseWriter, r *http.Request) {
	tab := normalizedTab(r.FormValue("tab"))
	a.mu.Lock()
	defer a.mu.Unlock()

	state, err := loadState()
	if err != nil {
		a.redirectError(w, r, tab, err)
		return
	}

	state.Config = config{
		BaseURL:               strings.TrimSpace(r.FormValue("base_url")),
		BearerToken:           strings.TrimSpace(r.FormValue("bearer_token")),
		AutoOpenSyncTrace:     r.FormValue("auto_open_sync_trace") == "on",
		SCIMDisabled:          r.FormValue("scim_enabled") != "on",
		IDPBaseURL:            strings.TrimSpace(r.FormValue("idp_base_url")),
		SigningPrivateKeyPEM:  state.Config.SigningPrivateKeyPEM,
		SigningCertificatePEM: state.Config.SigningCertificatePEM,
	}

	if err := saveState(state); err != nil {
		a.redirectError(w, r, tab, err)
		return
	}

	redirectWithFlash(w, r, dashboardURL(tab, nil), flashMessage{Kind: "success", Message: "config saved"})
}

func (a *webApp) handleConfigClear(w http.ResponseWriter, r *http.Request) {
	tab := normalizedTab(r.FormValue("tab"))
	a.mu.Lock()
	defer a.mu.Unlock()

	state, err := loadState()
	if err != nil {
		a.redirectError(w, r, tab, err)
		return
	}

	state.Config = config{
		SigningPrivateKeyPEM:  state.Config.SigningPrivateKeyPEM,
		SigningCertificatePEM: state.Config.SigningCertificatePEM,
	}
	if err := saveState(state); err != nil {
		a.redirectError(w, r, tab, err)
		return
	}

	redirectWithFlash(w, r, dashboardURL(tab, nil), flashMessage{Kind: "success", Message: "config cleared"})
}

func (a *webApp) handleSync(w http.ResponseWriter, r *http.Request) {
	tab := normalizedTab(r.FormValue("tab"))
	a.mu.Lock()
	defer a.mu.Unlock()

	state, err := loadState()
	if err != nil {
		a.redirectError(w, r, tab, err)
		return
	}
	if !scimEnabled(state) {
		a.redirectError(w, r, tab, fmt.Errorf("SCIM is disabled"))
		return
	}

	result := syncDirtyState(state)
	a.rememberTrace(result.Traces)
	if result.Fatal != nil {
		if len(result.Traces) > 0 && state.Config.AutoOpenSyncTrace {
			setShowTraceCookie(w)
		}
		redirectWithFlash(w, r, dashboardURL(tab, nil), flashMessage{Kind: "error", Message: result.Fatal.Error()})
		return
	}

	state = result.State
	appendOperationLogs(&state, result.Traces)
	if err := saveState(state); err != nil {
		a.redirectError(w, r, tab, err)
		return
	}

	if state.Config.AutoOpenSyncTrace {
		setShowTraceCookie(w)
	}
	redirectWithFlash(w, r, dashboardURL(tab, nil), flashMessage{Kind: "success", Message: result.Status})
}

func (a *webApp) handleImport(w http.ResponseWriter, r *http.Request) {
	tab := normalizedTab(r.FormValue("tab"))
	a.mu.Lock()
	defer a.mu.Unlock()

	state, err := loadState()
	if err != nil {
		a.redirectError(w, r, tab, err)
		return
	}
	if !scimEnabled(state) {
		a.redirectError(w, r, tab, fmt.Errorf("SCIM is disabled"))
		return
	}

	result := importStateFromSCIM(state)
	a.rememberTrace(result.Traces)
	if result.Fatal != nil {
		if len(result.Traces) > 0 && state.Config.AutoOpenSyncTrace {
			setShowTraceCookie(w)
		}
		redirectWithFlash(w, r, dashboardURL(tab, nil), flashMessage{Kind: "error", Message: result.Fatal.Error()})
		return
	}

	if err := saveState(result.State); err != nil {
		a.redirectError(w, r, tab, err)
		return
	}

	if result.State.Config.AutoOpenSyncTrace {
		setShowTraceCookie(w)
	}
	redirectWithFlash(w, r, dashboardURL(tab, nil), flashMessage{Kind: "success", Message: result.Status})
}

func (a *webApp) handleReset(w http.ResponseWriter, r *http.Request) {
	tab := normalizedTab(r.FormValue("tab"))
	a.mu.Lock()
	defer a.mu.Unlock()

	state, err := loadState()
	if err != nil {
		a.redirectError(w, r, tab, err)
		return
	}
	if !scimEnabled(state) {
		a.redirectError(w, r, tab, fmt.Errorf("SCIM is disabled"))
		return
	}

	if len(state.Users) == 0 && len(state.Groups) == 0 {
		a.redirectError(w, r, tab, fmt.Errorf("no users or groups to reset"))
		return
	}

	resetUsers := 0
	for i := range state.Users {
		state.Users[i].RemoteID = ""
		state.Users[i].Dirty = true
		state.Users[i].LastError = ""
		resetUsers++
	}

	resetGroups := 0
	for i := range state.Groups {
		state.Groups[i].RemoteID = ""
		state.Groups[i].Dirty = true
		state.Groups[i].LastError = ""
		resetGroups++
	}

	if err := saveState(state); err != nil {
		a.redirectError(w, r, tab, err)
		return
	}

	message := fmt.Sprintf("reset sync status for %d users and %d groups", resetUsers, resetGroups)
	redirectWithFlash(w, r, dashboardURL(tab, nil), flashMessage{Kind: "success", Message: message})
}

func (a *webApp) redirectError(w http.ResponseWriter, r *http.Request, tab string, err error) {
	redirectWithFlash(w, r, dashboardURL(tab, nil), flashMessage{Kind: "error", Message: err.Error()})
}

func (a *webApp) rememberTrace(traces []syncTraceEntry) {
	a.lastTrace = append([]syncTraceEntry(nil), traces...)
	a.lastTraceContent = formatSyncTraces(traces)
}

func (a *webApp) hasTrace() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.lastTrace) > 0
}

func (a *webApp) traceContent() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lastTraceContent
}

func buildStats(state appState) statsView {
	stats := statsView{Apps: len(state.Apps)}
	for _, u := range state.Users {
		if !scimEnabled(state) && u.Deleted {
			continue
		}
		stats.Users++
		if scimEnabled(state) && u.Dirty {
			stats.DirtyUsers++
		}
	}
	for _, g := range state.Groups {
		if !scimEnabled(state) && g.Deleted {
			continue
		}
		stats.Groups++
		if scimEnabled(state) && g.Dirty {
			stats.DirtyGroups++
		}
	}
	return stats
}

func scimEnabled(state appState) bool {
	return !state.Config.SCIMDisabled
}

func buildUserRows(state appState, tab string) []userRowView {
	rows := make([]userRowView, 0, len(state.Users))
	for _, u := range state.Users {
		if !scimEnabled(state) && u.Deleted {
			continue
		}
		remoteID := u.RemoteID
		if remoteID == "" {
			remoteID = "-"
		}
		rows = append(rows, userRowView{
			ID:         u.ID,
			Name:       userLabel(u),
			Username:   u.Username,
			Email:      u.Email,
			Active:     activeStatus(u),
			Status:     syncStatus(u),
			RemoteID:   remoteID,
			Deleted:    u.Deleted,
			EditURL:    dashboardURL("users", map[string]string{"modal": "user", "id": u.ID}),
			HistoryURL: dashboardURL(tab, map[string]string{"historyType": "user", "historyID": u.ID}),
		})
	}
	return rows
}

func buildGroupRows(state appState, tab string) []groupRowView {
	rows := make([]groupRowView, 0, len(state.Groups))
	for _, g := range state.Groups {
		if !scimEnabled(state) && g.Deleted {
			continue
		}
		remoteID := g.RemoteID
		if remoteID == "" {
			remoteID = "-"
		}
		rows = append(rows, groupRowView{
			ID:             g.ID,
			Name:           g.DisplayName,
			MembersSummary: groupMembersSummary(state.Users, g),
			MemberCount:    groupMemberCount(state.Users, g),
			Status:         groupSyncStatus(g),
			RemoteID:       remoteID,
			Deleted:        g.Deleted,
			EditURL:        dashboardURL("groups", map[string]string{"modal": "group", "id": g.ID}),
			HistoryURL:     dashboardURL(tab, map[string]string{"historyType": "group", "historyID": g.ID}),
		})
	}
	return rows
}

func buildAppRows(state appState, base string, certPEM string) []appRowView {
	rows := make([]appRowView, 0, len(state.Apps))
	for _, app := range state.Apps {
		samlIDPEntityID := base + "/saml/" + app.Slug + "/metadata"
		samlAudience := app.SAMLAudience
		if samlAudience == "" {
			samlAudience = app.SAMLEntityID
		}
		row := appRowView{
			ID:                     app.ID,
			Name:                   app.Name,
			Slug:                   app.Slug,
			Protocol:               strings.ToUpper(app.Protocol),
			OIDCClientID:           app.OIDCClientID,
			SupportsOIDC:           supportsOIDC(app),
			SupportsSAML:           supportsSAML(app),
			EditURL:                dashboardURL("apps", map[string]string{"modal": "app", "id": app.ID}),
			HasRedirectURI:         len(app.OIDCRedirectURIs) > 0,
			SAMLIDPEntityID:        samlIDPEntityID,
			SAMLCertificatePEM:     certPEM,
			SAMLEmailAttributeName: app.SAMLEmailAttributeName,
			SAMLSPACSURL:           app.SAMLACSURL,
			SAMLSPAudience:         samlAudience,
		}
		if row.SupportsOIDC {
			row.OIDCDiscovery = base + "/oidc/" + app.Slug + "/.well-known/openid-configuration"
			row.OIDCAuthorize = base + "/oidc/" + app.Slug + "/authorize"
			row.OIDCJWKS = base + "/oidc/" + app.Slug + "/jwks"
		}
		if row.SupportsSAML {
			row.SAMLMetadata = base + "/saml/" + app.Slug + "/metadata"
			row.SAMLSSO = base + "/saml/" + app.Slug + "/sso"
		}
		rows = append(rows, row)
	}
	return rows
}

func buildErrorList(state appState) []string {
	var errors []string
	for _, u := range state.Users {
		if u.LastError != "" {
			errors = append(errors, fmt.Sprintf("user %s: %s", userLabel(u), u.LastError))
		}
	}
	for _, g := range state.Groups {
		if g.LastError != "" {
			errors = append(errors, fmt.Sprintf("group %s: %s", g.DisplayName, g.LastError))
		}
	}
	return errors
}

func buildHistoryView(state appState, tab string, values url.Values) *historyView {
	resourceType := strings.TrimSpace(values.Get("historyType"))
	resourceID := strings.TrimSpace(values.Get("historyID"))
	if resourceType == "" || resourceID == "" {
		return nil
	}

	view := &historyView{Close: dashboardURL(tab, nil)}
	var entries []operationLog
	if resourceType == "user" {
		u, ok := userByID(state.Users, resourceID)
		if !ok {
			return nil
		}
		view.Title = "User History: " + userLabel(u)
		entries = state.UserOperations[resourceID]
	}
	if resourceType == "group" {
		g, ok := groupByID(state.Groups, resourceID)
		if !ok {
			return nil
		}
		view.Title = "Group History: " + g.DisplayName
		entries = state.GroupOperations[resourceID]
	}
	if view.Title == "" {
		return nil
	}

	if len(entries) == 0 {
		view.Items = []historyEntryView{{Timestamp: "-", Summary: "No operations recorded yet"}}
		return view
	}

	view.Items = make([]historyEntryView, 0, len(entries))
	for _, entry := range entries {
		item := historyEntryView{
			Timestamp: formatHistoryTimestamp(entry.CreatedAt),
			Summary:   entry.Summary,
			Kind:      entry.Kind,
		}
		if entry.Kind == "sync" {
			item.Detail = formatOperationDetail(entry)
			item.HasDetail = true
		}
		view.Items = append(view.Items, item)
	}

	return view
}

func buildUserFormView(state appState, tab string, id string) (*userFormView, error) {
	if strings.TrimSpace(id) == "" {
		return &userFormView{Title: "Add User", Close: dashboardURL(tab, nil)}, nil
	}

	u, ok := userByID(state.Users, id)
	if !ok {
		return nil, fmt.Errorf("user %s not found", id)
	}

	return &userFormView{Title: "Edit User", ID: id, User: u, Close: dashboardURL(tab, nil)}, nil
}

func buildGroupFormView(state appState, tab string, id string) (*groupFormView, error) {
	form := &groupFormView{Title: "Add Group", Close: dashboardURL(tab, nil)}
	selected := map[string]struct{}{}
	if strings.TrimSpace(id) != "" {
		g, ok := groupByID(state.Groups, id)
		if !ok {
			return nil, fmt.Errorf("group %s not found", id)
		}
		form.Title = "Edit Group"
		form.ID = id
		form.Group = g
		for _, memberID := range g.MemberIDs {
			selected[memberID] = struct{}{}
		}
	}

	for _, u := range state.Users {
		_, checked := selected[u.ID]
		metaParts := []string{u.Email, activeStatus(u)}
		if scimEnabled(state) {
			metaParts = append(metaParts, syncStatus(u))
		}
		meta := strings.TrimSpace(strings.Join(metaParts, " • "))
		form.Members = append(form.Members, memberOptionView{
			ID:      u.ID,
			Label:   userLabel(u),
			Meta:    meta,
			Checked: checked,
		})
	}

	return form, nil
}

func buildAppFormView(state appState, tab string, id string, baseURL string, certPEM string) (*appFormView, error) {
	form := &appFormView{
		Title: "Add App",
		App: app{
			Protocol:               "oidc",
			SAMLNameIDFormat:       defaultSAMLEmailNameIDFormat,
			SAMLEmailAttributeName: defaultSAMLEmailAttributeName,
			IncludeGroupsClaim:     true,
		},
		SAMLCertificatePEM: certPEM,
		Close:              dashboardURL(tab, nil),
	}
	if strings.TrimSpace(id) == "" {
		return form, nil
	}
	existing, ok := appByID(state.Apps, id)
	if !ok {
		return nil, fmt.Errorf("app %s not found", id)
	}
	form.Title = "Edit App"
	form.App = existing
	form.OIDCRedirectURIs = joinLines(form.App.OIDCRedirectURIs)
	if form.App.Slug != "" {
		form.SAMLIDPEntityID = baseURL + "/saml/" + form.App.Slug + "/metadata"
		form.SAMLIDPSSO = baseURL + "/saml/" + form.App.Slug + "/sso"
	}
	return form, nil
}

func groupMembersSummary(users []user, g group) string {
	labels := make([]string, 0, len(g.MemberIDs))
	for _, memberID := range g.MemberIDs {
		u, ok := userByID(users, memberID)
		if !ok {
			continue
		}
		labels = append(labels, u.Username)
	}
	if len(labels) == 0 {
		return "-"
	}

	return strings.Join(labels, ", ")
}

func groupMemberCount(users []user, g group) int {
	count := 0
	for _, memberID := range g.MemberIDs {
		if _, ok := userByID(users, memberID); ok {
			count++
		}
	}

	return count
}

func userIndexByID(users []user, id string) (int, bool) {
	for i, u := range users {
		if u.ID == id {
			return i, true
		}
	}

	return 0, false
}

func groupIndexByID(groups []group, id string) (int, bool) {
	for i, g := range groups {
		if g.ID == id {
			return i, true
		}
	}

	return 0, false
}

func appIndexByID(apps []app, id string) (int, bool) {
	for i, app := range apps {
		if app.ID == id {
			return i, true
		}
	}

	return 0, false
}

func appByID(apps []app, id string) (app, bool) {
	for _, app := range apps {
		if app.ID == id {
			return app, true
		}
	}

	return app{}, false
}

func selectedMemberIDs(users []user, ids []string) []string {
	allowed := make(map[string]struct{}, len(users))
	for _, u := range users {
		allowed[u.ID] = struct{}{}
	}

	selected := make([]string, 0, len(ids))
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, ok := allowed[id]; !ok {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		selected = append(selected, id)
	}

	return selected
}

func removeString(values []string, target string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value != target {
			out = append(out, value)
		}
	}
	return out
}

func summarizeGroupSave(existing group, displayName string, memberIDs []string) string {
	if existing.DisplayName != displayName {
		return "Updated name"
	}
	if !stringSlicesEqual(existing.MemberIDs, memberIDs) {
		return "Updated members"
	}

	return "Updated"
}

func normalizedTab(tab string) string {
	switch strings.TrimSpace(tab) {
	case "groups":
		return "groups"
	case "apps":
		return "apps"
	}

	return "users"
}

func dashboardURL(tab string, extra map[string]string) string {
	values := url.Values{}
	values.Set("tab", normalizedTab(tab))
	for key, value := range extra {
		if strings.TrimSpace(value) == "" {
			continue
		}
		values.Set(key, value)
	}
	return "/?" + values.Encode()
}

func redirectWithFlash(w http.ResponseWriter, r *http.Request, location string, flash flashMessage) {
	setFlashCookie(w, flash)
	http.Redirect(w, r, location, http.StatusSeeOther)
}

func setFlashCookie(w http.ResponseWriter, flash flashMessage) {
	value := flash.Kind + "|" + url.QueryEscape(flash.Message)
	http.SetCookie(w, &http.Cookie{
		Name:     "scimtest_flash",
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func consumeFlash(w http.ResponseWriter, r *http.Request) flashMessage {
	cookie, err := r.Cookie("scimtest_flash")
	if err != nil {
		return flashMessage{}
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "scimtest_flash",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})

	parts := strings.SplitN(cookie.Value, "|", 2)
	if len(parts) != 2 {
		return flashMessage{}
	}
	message, err := url.QueryUnescape(parts[1])
	if err != nil {
		message = parts[1]
	}
	return flashMessage{Kind: parts[0], Message: message}
}

func setShowTraceCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "scimtest_trace",
		Value:    strconvFormatInt(time.Now().UnixNano()),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func consumeShowTrace(w http.ResponseWriter, r *http.Request) bool {
	_, err := r.Cookie("scimtest_trace")
	if err != nil {
		return false
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "scimtest_trace",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
	return true
}

func strconvFormatInt(v int64) string {
	return fmt.Sprintf("%d", v)
}
