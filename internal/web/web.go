package web

import (
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"embed"
	"encoding/base64"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	rgrokclient "github.com/rselbach/rgrok/client"
)

//go:embed templates/*.html
var templateFS embed.FS

var pageTemplate = template.Must(template.New("index.html").Funcs(template.FuncMap{
	"join": strings.Join,
}).ParseFS(templateFS, "templates/*.html"))

type webApp struct {
	mu               sync.Mutex
	signingKey       *rsa.PrivateKey
	certDER          []byte
	debugRP          bool
	debugSecrets     bool
	localPort        int
	rgrokStart       rgrokStarter
	rgrokLifecycleMu sync.Mutex
	rgrokMu          sync.Mutex
	rgrokTunnel      *activeRgrokTunnel
	rgrokLastError   string
	syncJobMu        sync.Mutex
	syncJobs         map[string]*syncJobSnapshot
	// oidcMu guards authCodes and accessTokens so sign-in flows never
	// wait on mu, which is held for the full duration of a SCIM sync.
	oidcMu           sync.Mutex
	authCodes        map[string]authCode
	accessTokens     map[string]accessToken
	lastTraces       map[string][]syncTraceEntry
	lastTraceContent map[string]string
	formDraftMu      sync.Mutex
	formDrafts       map[string]formDraft
}

type rgrokStarter func(context.Context, rgrokclient.Config) (*startedRgrokTunnel, error)

type startedRgrokTunnel struct {
	PublicURL string
	Tunnel    tunnelCloser
}

type tunnelCloser interface {
	Close() error
}

type cancelingTunnelCloser struct {
	tunnel tunnelCloser
	cancel context.CancelFunc
}

func (c cancelingTunnelCloser) Close() error {
	c.cancel()
	if c.tunnel == nil {
		return nil
	}

	return c.tunnel.Close()
}

type activeRgrokTunnel struct {
	Name      string
	PublicURL string
	Tunnel    tunnelCloser
}

type rgrokTunnelView struct {
	Name      string
	PublicURL string
}

type rgrokApplicationIdentity struct {
	profileID  string
	privateKey ed25519.PrivateKey
}

var (
	rgrokApplicationProfileID    string
	rgrokApplicationPrivateSeed  string
	rgrokReleaseIdentityRequired string
)

type flashMessage struct {
	Kind    string
	Message string
}

type formDraft struct {
	Modal     string
	Values    url.Values
	Error     string
	CreatedAt time.Time
}

type syncJobSnapshot struct {
	ID              string         `json:"id"`
	EnvironmentName string         `json:"environmentName"`
	Running         bool           `json:"running"`
	Done            bool           `json:"done"`
	Success         bool           `json:"success"`
	TraceAvailable  bool           `json:"traceAvailable"`
	Total           int            `json:"total"`
	Processed       int            `json:"processed"`
	Percent         int            `json:"percent"`
	Message         string         `json:"message"`
	Error           string         `json:"error"`
	Current         string         `json:"current"`
	RateLimited     bool           `json:"rateLimited"`
	StartedAt       string         `json:"startedAt"`
	FinishedAt      string         `json:"finishedAt,omitempty"`
	LatestSequence  int            `json:"latestSequence"`
	Events          []syncJobEvent `json:"events,omitempty"`
}

// Remaining reports how many operations have not finished yet.
func (j *syncJobSnapshot) Remaining() int {
	remaining := j.Total - j.Processed
	if remaining < 0 {
		return 0
	}
	return remaining
}

type syncJobEvent struct {
	Sequence     int    `json:"sequence"`
	ID           string `json:"id"`
	ResourceType string `json:"resourceType"`
	ResourceID   string `json:"resourceID"`
	Label        string `json:"label"`
	Operation    string `json:"operation"`
	Phase        string `json:"phase"`
	Detail       string `json:"detail,omitempty"`
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
	OIDCTestURL            string
	SAMLTestURL            string
	SCIMEnabled            bool
	Active                 bool
	OpenURL                string
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

type paginationView struct {
	Page            int
	PageSize        int
	SearchQuery     string
	TotalPages      int
	Summary         string
	PreviousURL     string
	NextURL         string
	HasPrevious     bool
	HasNext         bool
	PageSizeOptions []pageSizeOptionView
}

type pageSizeOptionView struct {
	Size     int
	Label    string
	Selected bool
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
	Config             config
	Close              string
	IDPBaseURLValue    string
	IDPBaseURLDisabled bool
	Tunnel             *rgrokTunnelView
	TunnelError        string
}

type toolsFormView struct {
	Close       string
	Count       string
	EmailDomain string
}

type pageData struct {
	Tab                    string
	Flash                  flashMessage
	Stats                  statsView
	Users                  []userRowView
	Groups                 []groupRowView
	Apps                   []appRowView
	Pagination             *paginationView
	Errors                 []string
	BaseURL                string
	IDPBaseURL             string
	SCIMEnabled            bool
	UsersURL               string
	GroupsURL              string
	AppsURL                string
	EnvironmentSettingsURL string
	NewUserURL             string
	NewGroupURL            string
	NewAppURL              string
	ConfigURL              string
	ToolsURL               string
	TraceURL               string
	TraceCloseURL          string
	ShowTrace              bool
	HasTrace               bool
	TraceContent           string
	History                *historyView
	UserForm               *userFormView
	GroupForm              *groupFormView
	AppForm                *appFormView
	ConfigForm             *configFormView
	ToolsForm              *toolsFormView
	SyncJob                *syncJobSnapshot
	ShowSetupGuide         bool
	HasLocalUsers          bool
	HasApps                bool
	HasSCIMEnvironments    bool
	HasPublicIDP           bool
	FormError              string
	Environments           []app
	ActiveEnvironment      app
}

type RunOptions struct {
	Debug        bool
	DebugSecrets bool
	Port         string
	browserOpen  browserOpener
}

type serverError struct {
	name string
	err  error
}

const defaultListPageSize = 15
const maxToolCreateUsers = 10000

var listPageSizeOptions = []int{15, 25, 50, 100}

var toolUserNames = []struct {
	given  string
	family string
}{
	{given: "Troy", family: "Barnes"},
	{given: "Abed", family: "Nadir"},
	{given: "Annie", family: "Edison"},
	{given: "Britta", family: "Perry"},
	{given: "Shirley", family: "Bennett"},
	{given: "Jeff", family: "Winger"},
	{given: "Dean", family: "Pelton"},
	{given: "Señor", family: "Chang"},
	{given: "Leonard", family: "Rodriguez"},
	{given: "Magnitude", family: "PopPop"},
}

func Run(options ...RunOptions) error {
	var opts RunOptions
	if len(options) > 0 {
		opts = options[0]
	}
	identity, err := loadRgrokApplicationIdentity()
	if err != nil {
		return err
	}

	port := strings.TrimSpace(opts.Port)
	if port == "" {
		port = strings.TrimSpace(os.Getenv("PORT"))
	}
	portSpecified := port != ""
	if !portSpecified {
		port = strconv.Itoa(defaultPort)
	}

	key, certDER, err := loadOrCreateSigningMaterial()
	if err != nil {
		return err
	}

	idpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen for tunneled IDP traffic: %w", err)
	}
	idpAddress, ok := idpListener.Addr().(*net.TCPAddr)
	if !ok {
		if closeErr := idpListener.Close(); closeErr != nil {
			return fmt.Errorf("get tunneled IDP listener address; close listener: %v", closeErr)
		}
		return fmt.Errorf("get tunneled IDP listener address")
	}

	app := &webApp{
		signingKey:   key,
		certDER:      certDER,
		debugRP:      opts.Debug,
		debugSecrets: opts.DebugSecrets,
		localPort:    idpAddress.Port,
		rgrokStart:   startRgrokTunnel,
		authCodes:    make(map[string]authCode),
		accessTokens: make(map[string]accessToken),
	}
	listener, err := listenForAdmin(defaultHost, port, !portSpecified)
	if err != nil {
		if closeErr := idpListener.Close(); closeErr != nil {
			return fmt.Errorf("%w; close tunneled IDP listener: %v", err, closeErr)
		}
		return err
	}
	localURL, err := listenerURL(listener)
	if err != nil {
		adminCloseErr := listener.Close()
		idpCloseErr := idpListener.Close()
		return fmt.Errorf("%w; close admin listener: %v; close tunneled IDP listener: %v", err, adminCloseErr, idpCloseErr)
	}
	log.Printf("merged auth test service listening on %s", localURL)
	if opts.Debug {
		if _, err := fmt.Fprintln(os.Stdout, "RP debug logging enabled"); err != nil {
			adminCloseErr := listener.Close()
			idpCloseErr := idpListener.Close()
			switch {
			case adminCloseErr != nil && idpCloseErr != nil:
				return fmt.Errorf("write debug status: %w; close admin listener: %v; close tunneled IDP listener: %v", err, adminCloseErr, idpCloseErr)
			case adminCloseErr != nil:
				return fmt.Errorf("write debug status: %w; close admin listener: %v", err, adminCloseErr)
			case idpCloseErr != nil:
				return fmt.Errorf("write debug status: %w; close tunneled IDP listener: %v", err, idpCloseErr)
			}
			return fmt.Errorf("write debug status: %w", err)
		}
	}

	serveErrors := make(chan serverError, 2)
	go func() {
		serveErrors <- serverError{name: "admin", err: http.Serve(listener, app.routes())}
	}()
	go func() {
		serveErrors <- serverError{name: "tunneled IDP", err: http.Serve(idpListener, app.idpRoutes())}
	}()
	if identity != nil {
		go app.startAutomaticRgrokTunnel(*identity)
	}
	opener := opts.browserOpen
	if opener == nil {
		opener = openBrowser
	}
	if err := opener(localURL); err != nil {
		log.Printf("warning: open browser at %s: %v", localURL, err)
	}

	result := <-serveErrors
	other := idpListener
	if result.name == "tunneled IDP" {
		other = listener
	}
	listenerCloseErr := other.Close()
	tunnelCloseErr := app.closeAutomaticRgrokTunnel()
	switch {
	case listenerCloseErr != nil && tunnelCloseErr != nil:
		return fmt.Errorf("serve %s: %w; close other listener: %v; close rgrok tunnel: %v", result.name, result.err, listenerCloseErr, tunnelCloseErr)
	case listenerCloseErr != nil:
		return fmt.Errorf("serve %s: %w; close other listener: %v", result.name, result.err, listenerCloseErr)
	case tunnelCloseErr != nil:
		return fmt.Errorf("serve %s: %w; close rgrok tunnel: %v", result.name, result.err, tunnelCloseErr)
	}
	return fmt.Errorf("serve %s: %w", result.name, result.err)
}

func (a *webApp) routes() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/", a.adminRoutes())
	a.registerIDPRoutes(mux)
	return mux
}

const environmentCookieName = "scimtest_environment"
const legacySyncAppCookieName = "scimtest_sync_app"

func requestEnvironmentID(r *http.Request, state appState) string {
	requested := strings.TrimSpace(r.FormValue("environment"))
	if requested == "" {
		requested = strings.TrimSpace(r.FormValue("app"))
	}
	if requested != "" {
		if selected, ok := appByID(state.Apps, requested); ok {
			return selected.ID
		}
		return ""
	}

	for _, cookieName := range []string{environmentCookieName, legacySyncAppCookieName} {
		cookie, err := r.Cookie(cookieName)
		if err != nil {
			continue
		}
		if selected, ok := appByID(state.Apps, strings.TrimSpace(cookie.Value)); ok {
			return selected.ID
		}
	}

	if len(state.Apps) > 0 {
		return state.Apps[0].ID
	}
	return ""
}

func requestSyncAppID(r *http.Request, state appState) string {
	environmentID := requestEnvironmentID(r, state)
	selected, ok := appByID(state.Apps, environmentID)
	if ok && selected.SCIMEnabled {
		return selected.ID
	}
	return ""
}

func loadRequestState(r *http.Request) (appState, error) {
	return loadState()
}

func rememberEnvironment(w http.ResponseWriter, environmentID string) {
	if environmentID == "" {
		return
	}
	http.SetCookie(w, &http.Cookie{Name: environmentCookieName, Value: environmentID, Path: "/", MaxAge: 365 * 24 * 60 * 60, HttpOnly: true, SameSite: http.SameSiteStrictMode})
}

func (a *webApp) adminRoutes() http.Handler {
	mux := http.NewServeMux()
	a.registerAdminRoutes(mux)
	return http.NewCrossOriginProtection().Handler(mux)
}

func (a *webApp) idpRoutes() http.Handler {
	mux := http.NewServeMux()
	a.registerIDPRoutes(mux)
	return mux
}

func (a *webApp) registerAdminRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /", a.handleIndex)
	mux.HandleFunc("POST /users/save", a.rejectWhileSyncing(a.handleUserSave))
	mux.HandleFunc("POST /users/{id}/toggle-active", a.rejectWhileSyncing(a.handleUserToggleActive))
	mux.HandleFunc("POST /users/delete", a.rejectWhileSyncing(a.handleUsersDelete))
	mux.HandleFunc("POST /users/{id}/delete", a.rejectWhileSyncing(a.handleUserDelete))
	mux.HandleFunc("POST /users/{id}/restore", a.rejectWhileSyncing(a.handleUserRestore))
	mux.HandleFunc("POST /groups/save", a.rejectWhileSyncing(a.handleGroupSave))
	mux.HandleFunc("POST /groups/{id}/delete", a.rejectWhileSyncing(a.handleGroupDelete))
	mux.HandleFunc("POST /groups/{id}/restore", a.rejectWhileSyncing(a.handleGroupRestore))
	mux.HandleFunc("POST /apps/save", a.rejectWhileSyncing(a.handleAppSave))
	mux.HandleFunc("POST /apps/{id}/delete", a.rejectWhileSyncing(a.handleAppDelete))
	mux.HandleFunc("POST /config/save", a.rejectWhileSyncing(a.handleConfigSave))
	mux.HandleFunc("POST /tools/delete-all", a.rejectWhileSyncing(a.handleToolsDeleteAll))
	mux.HandleFunc("POST /tools/clear-users-local", a.rejectWhileSyncing(a.handleToolsClearUsersLocal))
	mux.HandleFunc("POST /tools/deactivate-all", a.rejectWhileSyncing(a.handleToolsDeactivateAll))
	mux.HandleFunc("POST /tools/activate-all", a.rejectWhileSyncing(a.handleToolsActivateAll))
	mux.HandleFunc("POST /tools/create-users", a.rejectWhileSyncing(a.handleToolsCreateUsers))
	mux.HandleFunc("GET /sync/status", a.handleSyncStatus)
	mux.HandleFunc("POST /sync", a.handleSync)
	mux.HandleFunc("POST /import", a.rejectWhileSyncing(a.handleImport))
	mux.HandleFunc("POST /reset", a.rejectWhileSyncing(a.handleReset))
}

func (a *webApp) rejectWhileSyncing(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if a.anySyncRunning() {
			if wantsJSON(r) {
				w.WriteHeader(http.StatusConflict)
				writeJSON(w, map[string]string{"error": "sync is running; wait for it to finish"})
				return
			}
			a.redirectError(w, r, normalizedTab(r.FormValue("tab")), fmt.Errorf("sync is running; wait for it to finish"))
			return
		}
		next(w, r)
	}
}

func (a *webApp) anySyncRunning() bool {
	a.syncJobMu.Lock()
	defer a.syncJobMu.Unlock()
	for _, job := range a.syncJobs {
		if job != nil && job.Running {
			return true
		}
	}
	return false
}

func (a *webApp) registerIDPRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /oidc/{slug}/.well-known/openid-configuration", a.debugRPHandler(a.handleOIDCDiscovery))
	mux.HandleFunc("GET /oidc/{slug}/jwks", a.debugRPHandler(a.handleOIDCJWKS))
	mux.HandleFunc("GET /oidc/{slug}/authorize", a.debugRPHandler(a.handleOIDCAuthorize))
	mux.HandleFunc("POST /oidc/{slug}/authorize", a.debugRPHandler(a.handleOIDCAuthorizePost))
	mux.HandleFunc("POST /oidc/{slug}/token", a.debugRPHandler(a.handleOIDCToken))
	mux.HandleFunc("GET /oidc/{slug}/userinfo", a.debugRPHandler(a.handleOIDCUserinfo))
	mux.HandleFunc("POST /oidc/{slug}/userinfo", a.debugRPHandler(a.handleOIDCUserinfo))
	mux.HandleFunc("GET /saml/{slug}/metadata", a.debugRPHandler(a.handleSAMLMetadata))
	mux.HandleFunc("GET /saml/{slug}/sso", a.debugRPHandler(a.handleSAMLSSO))
	mux.HandleFunc("POST /saml/{slug}/sso", a.debugRPHandler(a.handleSAMLSSOPost))
}

func (a *webApp) handleIndex(w http.ResponseWriter, r *http.Request) {
	state, err := loadRequestState(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	globalState := state
	environmentID := requestEnvironmentID(r, globalState)
	var activeEnvironment app
	if environmentID != "" {
		activeEnvironment, _ = appByID(globalState.Apps, environmentID)
		state, err = stateForApp(globalState, environmentID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		rememberEnvironment(w, environmentID)
	} else {
		state.Config.SCIMDisabled = true
	}

	tab := normalizedTab(r.URL.Query().Get("tab"))
	page := requestPage(r.URL.Query().Get("page"))
	pageSize := requestPageSize(r.URL.Query().Get("pageSize"))
	search := searchQuery(r.URL.Query().Get("q"))
	flash := consumeFlash(w, r)
	showTrace := r.URL.Query().Get("showTrace") == "1"
	if consumeShowTrace(w, r) {
		showTrace = true
	}

	users := filterUserRows(buildUserRows(state, tab, page, pageSize, search), search)
	groups := filterGroupRows(buildGroupRows(state, tab, page, pageSize, search), search)
	var pagination *paginationView
	switch tab {
	case "groups":
		total := len(groups)
		page = currentListPage(total, page, pageSize)
		groups = filterGroupRows(buildGroupRows(state, tab, page, pageSize, search), search)
		groups = slicePage(groups, page, pageSize)
		pagination = buildPagination(total, tab, page, pageSize, search)
	case "users":
		total := len(users)
		page = currentListPage(total, page, pageSize)
		users = filterUserRows(buildUserRows(state, tab, page, pageSize, search), search)
		users = slicePage(users, page, pageSize)
		pagination = buildPagination(total, tab, page, pageSize, search)
	default:
		page = 1
	}

	data := pageData{
		Tab:                    tab,
		Flash:                  flash,
		Stats:                  buildStats(state),
		Users:                  users,
		Groups:                 groups,
		Apps:                   buildAppRows(state, environmentID, a.effectiveIDPBaseURL(r, state), certificatePEM(a.certDER)),
		Pagination:             pagination,
		Errors:                 buildErrorList(state),
		BaseURL:                configuredBaseURL(state.Config.BaseURL),
		IDPBaseURL:             a.effectiveIDPBaseURL(r, state),
		SCIMEnabled:            activeEnvironment.SCIMEnabled,
		UsersURL:               dashboardURL("users", nil),
		GroupsURL:              dashboardURL("groups", nil),
		AppsURL:                dashboardURL("apps", nil),
		EnvironmentSettingsURL: dashboardURL("apps", map[string]string{"modal": "app", "id": environmentID}),
		NewUserURL:             dashboardURLWithPage("users", page, pageSize, search, map[string]string{"modal": "user"}),
		NewGroupURL:            dashboardURLWithPage("groups", page, pageSize, search, map[string]string{"modal": "group"}),
		NewAppURL:              dashboardURL("apps", map[string]string{"modal": "app"}),
		ConfigURL:              dashboardURLWithPage(tab, page, pageSize, search, map[string]string{"modal": "config"}),
		ToolsURL:               dashboardURLWithPage(tab, page, pageSize, search, map[string]string{"modal": "tools"}),
		TraceURL:               dashboardURLWithPage(tab, page, pageSize, search, map[string]string{"showTrace": "1"}),
		TraceCloseURL:          dashboardURLWithPage(tab, page, pageSize, search, nil),
		ShowTrace:              showTrace && a.hasTrace(environmentID),
		HasTrace:               a.hasTrace(environmentID),
		TraceContent:           a.traceContent(environmentID),
		SyncJob:                a.currentSyncJob(environmentID),
		ShowSetupGuide:         len(state.Users) == 0 || len(state.Apps) == 0,
		HasLocalUsers:          len(state.Users) > 0,
		HasApps:                len(state.Apps) > 0,
		HasSCIMEnvironments:    scimEnabled(globalState),
		HasPublicIDP:           a.rgrokPublicURL() != "" || strings.TrimSpace(state.Config.IDPBaseURL) != "",
		Environments:           globalState.Apps,
		ActiveEnvironment:      activeEnvironment,
	}
	if !data.SCIMEnabled {
		data.Errors = nil
		data.ShowTrace = false
		data.HasTrace = false
	}

	if r.URL.Query().Get("partial") == "list" {
		scopePageDataURLs(&data, environmentID)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := pageTemplate.ExecuteTemplate(w, "list-card.html", data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	if history := buildHistoryView(state, tab, page, pageSize, search, r.URL.Query()); history != nil {
		data.History = history
	}

	switch r.URL.Query().Get("modal") {
	case "user":
		if form, formErr := buildUserFormView(state, tab, page, pageSize, search, r.URL.Query().Get("id")); formErr == nil {
			data.UserForm = form
		}
	case "group":
		if form, formErr := buildGroupFormView(state, tab, page, pageSize, search, r.URL.Query().Get("id")); formErr == nil {
			data.GroupForm = form
		}
	case "app":
		if form, formErr := buildAppFormView(state, tab, r.URL.Query().Get("id"), data.IDPBaseURL, certificatePEM(a.certDER)); formErr == nil {
			data.AppForm = form
		}
	case "config":
		data.ConfigForm = a.buildConfigFormView(globalState.Config, tab, page, pageSize, search)
	case "tools":
		data.ToolsForm = &toolsFormView{Close: dashboardURLWithPage(tab, page, pageSize, search, nil), Count: "10"}
	}
	if draft := a.consumeFormDraft(w, r); draft != nil {
		applyFormDraft(&data, *draft)
		data.FormError = draft.Error
	}
	scopePageDataURLs(&data, environmentID)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := pageTemplate.ExecuteTemplate(w, "index.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

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

	if err := validateUser(givenName, familyName, email, username); err != nil {
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

func (a *webApp) handleConfigSave(w http.ResponseWriter, r *http.Request) {
	tab := normalizedTab(r.FormValue("tab"))
	idpBaseURL := strings.TrimSpace(r.FormValue("idp_base_url"))
	if err := validateHTTPBaseURL("IDP base URL", idpBaseURL, false); err != nil {
		a.redirectFormError(w, r, tab, "config", err)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	state, err := loadRequestState(r)
	if err != nil {
		a.redirectError(w, r, tab, err)
		return
	}
	state.Config = config{
		IDPBaseURL:            idpBaseURL,
		TrustForwardedHeaders: r.FormValue("trust_forwarded_headers") == "on",
		RgrokInstanceID:       state.Config.RgrokInstanceID,
		SigningPrivateKeyPEM:  state.Config.SigningPrivateKeyPEM,
		SigningCertificatePEM: state.Config.SigningCertificatePEM,
	}
	if publicURL := a.rgrokPublicURL(); publicURL != "" {
		state.Config.IDPBaseURL = publicURL
	}

	if err := saveState(state); err != nil {
		a.redirectError(w, r, tab, err)
		return
	}

	redirectWithFlash(w, r, dashboardURLWithPage(tab, formPage(r), formPageSize(r), formSearch(r), nil), flashMessage{Kind: "success", Message: "config saved"})
}

func (a *webApp) startAutomaticRgrokTunnel(identity rgrokApplicationIdentity) {
	a.rgrokLifecycleMu.Lock()
	defer a.rgrokLifecycleMu.Unlock()

	instanceID, err := ensureRgrokInstanceID()
	if err != nil {
		a.setRgrokError(fmt.Sprintf("load rgrok instance identity: %v", err))
		log.Printf("start rgrok tunnel: load instance identity: %v", err)
		return
	}
	starter := a.rgrokStart
	if starter == nil {
		starter = startRgrokTunnel
	}
	started, err := startRgrokWithTimeout(starter, rgrokclient.Config{
		ServerBaseURL:         "https://rgrok.rselbach.com",
		ApplicationProfileID:  identity.profileID,
		InstanceID:            instanceID,
		ApplicationPrivateKey: identity.privateKey,
		LocalPort:             a.localPort,
	}, 20*time.Second)
	if err != nil {
		a.setRgrokError(fmt.Sprintf("start automatic tunnel: %v", err))
		log.Printf("start rgrok tunnel: %v", err)
		return
	}
	if started == nil || started.Tunnel == nil || strings.TrimSpace(started.PublicURL) == "" {
		err := fmt.Errorf("rgrok did not return a public URL")
		if started != nil && started.Tunnel != nil {
			if closeErr := started.Tunnel.Close(); closeErr != nil {
				err = fmt.Errorf("%w; close tunnel: %v", err, closeErr)
			}
		}
		a.setRgrokError(err.Error())
		log.Printf("start rgrok tunnel: %v", err)
		return
	}

	publicURL := strings.TrimRight(strings.TrimSpace(started.PublicURL), "/")
	a.rgrokMu.Lock()
	a.rgrokTunnel = &activeRgrokTunnel{
		PublicURL: publicURL,
		Tunnel:    started.Tunnel,
	}
	a.rgrokLastError = ""
	a.rgrokMu.Unlock()
	log.Printf("rgrok tunnel established at %s", publicURL)
}

func (a *webApp) closeAutomaticRgrokTunnel() error {
	a.rgrokLifecycleMu.Lock()
	defer a.rgrokLifecycleMu.Unlock()

	a.rgrokMu.Lock()
	tunnel := a.rgrokTunnel
	a.rgrokTunnel = nil
	a.rgrokMu.Unlock()
	if tunnel == nil || tunnel.Tunnel == nil {
		return nil
	}
	return tunnel.Tunnel.Close()
}

func startRgrokTunnel(ctx context.Context, cfg rgrokclient.Config) (*startedRgrokTunnel, error) {
	tunnel, err := rgrokclient.Start(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return &startedRgrokTunnel{
		PublicURL: tunnel.PublicURL,
		Tunnel:    tunnel,
	}, nil
}

func startRgrokWithTimeout(starter rgrokStarter, cfg rgrokclient.Config, timeout time.Duration) (*startedRgrokTunnel, error) {
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan struct {
		tunnel *startedRgrokTunnel
		err    error
	}, 1)

	go func() {
		tunnel, err := starter(ctx, cfg)
		result <- struct {
			tunnel *startedRgrokTunnel
			err    error
		}{tunnel: tunnel, err: err}
	}()

	select {
	case outcome := <-result:
		if outcome.err != nil {
			cancel()
			return nil, outcome.err
		}
		return startedRgrokTunnelWithCancel(outcome.tunnel, cancel), nil
	case <-time.After(timeout):
		cancel()
		return nil, fmt.Errorf("timed out waiting for rgrok tunnel registration")
	}
}

func startedRgrokTunnelWithCancel(started *startedRgrokTunnel, cancel context.CancelFunc) *startedRgrokTunnel {
	if started == nil || started.Tunnel == nil {
		cancel()
		return started
	}

	started.Tunnel = cancelingTunnelCloser{tunnel: started.Tunnel, cancel: cancel}
	return started
}

var rgrokApplicationProfilePattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

func loadRgrokApplicationIdentity() (*rgrokApplicationIdentity, error) {
	profileID := strings.TrimSpace(rgrokApplicationProfileID)
	encodedSeed := strings.TrimSpace(rgrokApplicationPrivateSeed)
	required := strings.EqualFold(strings.TrimSpace(rgrokReleaseIdentityRequired), "true")
	if profileID == "" && encodedSeed == "" && !required {
		return nil, nil
	}
	if !rgrokApplicationProfilePattern.MatchString(profileID) {
		return nil, fmt.Errorf("rgrok application profile id must be 32 lowercase hexadecimal characters")
	}
	if encodedSeed == "" {
		return nil, fmt.Errorf("rgrok application private seed is required")
	}
	seed, err := base64.StdEncoding.DecodeString(encodedSeed)
	if err != nil {
		return nil, fmt.Errorf("decode rgrok application private seed: invalid base64")
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("rgrok application private seed must decode to %d bytes", ed25519.SeedSize)
	}
	return &rgrokApplicationIdentity{
		profileID:  profileID,
		privateKey: ed25519.NewKeyFromSeed(seed),
	}, nil
}

func (a *webApp) buildConfigFormView(cfg config, tab string, page int, pageSize int, search string) *configFormView {
	closeURL := dashboardURLWithPage(tab, page, pageSize, search, nil)
	form := &configFormView{
		Config:          cfg,
		Close:           closeURL,
		IDPBaseURLValue: cfg.IDPBaseURL,
		TunnelError:     a.rgrokError(),
	}
	if tunnel := a.rgrokTunnelView(); tunnel != nil {
		form.Tunnel = tunnel
		form.IDPBaseURLValue = tunnel.PublicURL
		form.IDPBaseURLDisabled = true
	}
	return form
}

func (a *webApp) effectiveIDPBaseURL(r *http.Request, state appState) string {
	if publicURL := a.rgrokPublicURL(); publicURL != "" {
		return publicURL
	}
	return effectiveIDPBaseURL(r, state)
}

func (a *webApp) rgrokPublicURL() string {
	a.rgrokMu.Lock()
	defer a.rgrokMu.Unlock()
	if a.rgrokTunnel == nil {
		return ""
	}
	return a.rgrokTunnel.PublicURL
}

func (a *webApp) rgrokTunnelView() *rgrokTunnelView {
	a.rgrokMu.Lock()
	defer a.rgrokMu.Unlock()
	if a.rgrokTunnel == nil {
		return nil
	}
	return &rgrokTunnelView{
		Name:      a.rgrokTunnel.Name,
		PublicURL: a.rgrokTunnel.PublicURL,
	}
}

func (a *webApp) setRgrokError(message string) {
	a.rgrokMu.Lock()
	defer a.rgrokMu.Unlock()
	a.rgrokLastError = message
}

func (a *webApp) rgrokError() string {
	a.rgrokMu.Lock()
	defer a.rgrokMu.Unlock()
	return a.rgrokLastError
}

func (a *webApp) handleSync(w http.ResponseWriter, r *http.Request) {
	tab := normalizedTab(r.FormValue("tab"))
	a.mu.Lock()
	state, err := loadRequestState(r)
	a.mu.Unlock()
	if err != nil {
		a.respondSyncStartError(w, r, tab, err)
		return
	}
	appID := requestSyncAppID(r, state)
	if appID == "" {
		a.respondSyncStartError(w, r, tab, fmt.Errorf("SCIM is not enabled for the active environment"))
		return
	}
	activeEnvironment, _ := appByID(state.Apps, appID)
	if job := a.currentSyncJob(appID); job != nil && job.Running {
		a.respondSyncStartError(w, r, tab, fmt.Errorf("sync already running"))
		return
	}
	job, err := a.startSyncJob(appID, activeEnvironment.Name)
	if err != nil {
		a.respondSyncStartError(w, r, tab, err)
		return
	}

	if wantsJSON(r) {
		writeJSON(w, job)
		return
	}

	redirectWithFlash(w, r, dashboardURLWithPage(tab, formPage(r), formPageSize(r), formSearch(r), nil), flashMessage{Kind: "success", Message: "sync started"})
}

func (a *webApp) handleSyncStatus(w http.ResponseWriter, r *http.Request) {
	state, err := loadRequestState(r)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		writeJSON(w, map[string]string{"error": err.Error()})
		return
	}
	after, err := syncEventSequence(r.URL.Query().Get("after"))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, a.currentSyncJobAfter(requestSyncAppID(r, state), after))
}

func syncEventSequence(value string) (int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, nil
	}
	sequence, err := strconv.Atoi(value)
	if err != nil || sequence < 0 {
		return 0, fmt.Errorf("sync event sequence must be a non-negative integer")
	}
	return sequence, nil
}

func (a *webApp) respondSyncStartError(w http.ResponseWriter, r *http.Request, tab string, err error) {
	if wantsJSON(r) {
		w.WriteHeader(http.StatusConflict)
		writeJSON(w, syncJobSnapshot{Done: true, Error: err.Error(), Message: err.Error()})
		return
	}

	a.redirectError(w, r, tab, err)
}

func (a *webApp) startSyncJob(appID string, environmentName string) (*syncJobSnapshot, error) {
	a.syncJobMu.Lock()
	defer a.syncJobMu.Unlock()

	if a.syncJobs == nil {
		a.syncJobs = make(map[string]*syncJobSnapshot)
	}
	for jobAppID, job := range a.syncJobs {
		if job == nil || !job.Running {
			continue
		}
		if jobAppID == appID {
			return nil, fmt.Errorf("sync already running")
		}
		return nil, fmt.Errorf("a sync is already running for %s; wait for it to finish", job.EnvironmentName)
	}

	job := &syncJobSnapshot{
		ID:              strconvFormatInt(time.Now().UnixNano()),
		EnvironmentName: environmentName,
		Running:         true,
		Message:         "Starting sync for " + environmentName,
		StartedAt:       time.Now().UTC().Format(time.RFC3339),
	}
	a.syncJobs[appID] = job
	go a.runSyncJob(job.ID, appID)

	return cloneSyncJob(job), nil
}

func (a *webApp) runSyncJob(id string, appID string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	state, err := loadState()
	if err != nil {
		a.finishSyncJob(appID, id, false, err.Error(), false)
		return
	}
	projected, err := stateForApp(state, appID)
	if err != nil {
		a.finishSyncJob(appID, id, false, err.Error(), false)
		return
	}

	result := syncDirtyStateWithProgress(projected, func(progress syncProgress) {
		a.updateSyncJobProgress(appID, id, progress)
	})
	a.rememberTrace(appID, result.Traces)
	if result.Fatal != nil {
		a.finishSyncJob(appID, id, false, result.Fatal.Error(), len(result.Traces) > 0)
		return
	}

	mergeAppSyncState(&state, appID, result.State)
	appendOperationLogs(&state, appID, result.Traces)
	purgeFullySyncedDeletions(&state)
	if err := saveState(state); err != nil {
		a.finishSyncJob(appID, id, false, err.Error(), len(result.Traces) > 0)
		return
	}

	success := result.Stopped == nil
	a.finishSyncJob(appID, id, success, result.Status, len(result.Traces) > 0)
}

func (a *webApp) updateSyncJobProgress(appID string, id string, progress syncProgress) {
	a.syncJobMu.Lock()
	defer a.syncJobMu.Unlock()

	job := a.syncJobs[appID]
	if job == nil || job.ID != id {
		return
	}
	job.Total = progress.Total
	job.Processed = progress.Processed
	job.Percent = syncProgressPercent(progress.Processed, progress.Total, false)
	if progress.Label != "" {
		job.Current = strings.TrimSpace(strings.Join([]string{progress.Operation, progress.ResourceType, progress.Label}, " "))
		if progress.Phase != "" {
			job.LatestSequence++
			job.Events = append(job.Events, syncJobEvent{
				Sequence:     job.LatestSequence,
				ID:           progress.ResourceType + ":" + progress.ResourceID,
				ResourceType: progress.ResourceType,
				ResourceID:   progress.ResourceID,
				Label:        progress.Label,
				Operation:    progress.Operation,
				Phase:        progress.Phase,
				Detail:       progress.Detail,
			})
		}
	}
	job.RateLimited = progress.RateLimited
	if progress.Status != "" {
		job.Message = progress.Status
	}
}

func (a *webApp) finishSyncJob(appID string, id string, success bool, message string, traceAvailable bool) {
	a.syncJobMu.Lock()
	defer a.syncJobMu.Unlock()

	job := a.syncJobs[appID]
	if job == nil || job.ID != id {
		return
	}
	job.Running = false
	job.Done = true
	job.Success = success
	job.TraceAvailable = traceAvailable
	job.RateLimited = false
	job.Message = message
	job.Percent = syncProgressPercent(job.Processed, job.Total, true)
	job.FinishedAt = time.Now().UTC().Format(time.RFC3339)
	if !success {
		job.Error = message
	}
}

func (a *webApp) currentSyncJob(appID string) *syncJobSnapshot {
	a.syncJobMu.Lock()
	defer a.syncJobMu.Unlock()

	return cloneSyncJob(a.syncJobs[appID])
}

func (a *webApp) currentSyncJobAfter(appID string, sequence int) *syncJobSnapshot {
	a.syncJobMu.Lock()
	defer a.syncJobMu.Unlock()

	job := cloneSyncJob(a.syncJobs[appID])
	if job == nil || sequence == 0 {
		return job
	}
	events := make([]syncJobEvent, 0, len(job.Events))
	for _, event := range job.Events {
		if event.Sequence > sequence {
			events = append(events, event)
		}
	}
	job.Events = events
	return job
}

func cloneSyncJob(job *syncJobSnapshot) *syncJobSnapshot {
	if job == nil {
		return nil
	}

	cloned := *job
	cloned.Events = append([]syncJobEvent(nil), job.Events...)
	return &cloned
}

func syncProgressPercent(processed int, total int, done bool) int {
	if total <= 0 {
		if done {
			return 100
		}
		return 0
	}

	percent := processed * 100 / total
	if done {
		return 100
	}
	if percent > 99 {
		return 99
	}

	return percent
}

func wantsJSON(r *http.Request) bool {
	return r.Header.Get("X-Requested-With") == "fetch" || strings.Contains(r.Header.Get("Accept"), "application/json")
}

func (a *webApp) handleImport(w http.ResponseWriter, r *http.Request) {
	tab := normalizedTab(r.FormValue("tab"))
	a.mu.Lock()
	defer a.mu.Unlock()

	state, err := loadRequestState(r)
	if err != nil {
		a.redirectError(w, r, tab, err)
		return
	}
	appID := requestSyncAppID(r, state)
	if appID == "" {
		a.redirectError(w, r, tab, fmt.Errorf("SCIM is not enabled for the active environment"))
		return
	}
	projected, err := stateForApp(state, appID)
	if err != nil {
		a.redirectError(w, r, tab, err)
		return
	}

	result := importStateFromSCIM(projected)
	a.rememberTrace(appID, result.Traces)
	if result.Fatal != nil {
		if len(result.Traces) > 0 && projected.Config.AutoOpenSyncTrace {
			setShowTraceCookie(w)
		}
		redirectWithFlash(w, r, dashboardURLWithPage(tab, formPage(r), formPageSize(r), formSearch(r), nil), flashMessage{Kind: "error", Message: result.Fatal.Error()})
		return
	}

	mergeAppImportState(&state, appID, result.State)
	appendOperationLogs(&state, appID, result.Traces)
	purgeFullySyncedDeletions(&state)
	if err := saveState(state); err != nil {
		a.redirectError(w, r, tab, err)
		return
	}

	if result.State.Config.AutoOpenSyncTrace {
		setShowTraceCookie(w)
	}
	redirectWithFlash(w, r, dashboardURLWithPage(tab, formPage(r), formPageSize(r), formSearch(r), nil), flashMessage{Kind: "success", Message: result.Status})
}

func (a *webApp) handleReset(w http.ResponseWriter, r *http.Request) {
	tab := normalizedTab(r.FormValue("tab"))
	a.mu.Lock()
	defer a.mu.Unlock()

	state, err := loadRequestState(r)
	if err != nil {
		a.redirectError(w, r, tab, err)
		return
	}
	appID := requestSyncAppID(r, state)
	if appID == "" {
		a.redirectError(w, r, tab, fmt.Errorf("SCIM is not enabled for the active environment"))
		return
	}
	if _, err := stateForApp(state, appID); err != nil {
		a.redirectError(w, r, tab, err)
		return
	}

	if len(state.Users) == 0 && len(state.Groups) == 0 {
		a.redirectError(w, r, tab, fmt.Errorf("no users or groups to reset"))
		return
	}

	resetUsers := len(state.Users)
	resetGroups := len(state.Groups)
	initializeAppSync(&state, appID)

	if err := saveState(state); err != nil {
		a.redirectError(w, r, tab, err)
		return
	}

	message := fmt.Sprintf("reset sync status for %d users and %d groups", resetUsers, resetGroups)
	redirectWithFlash(w, r, dashboardURLWithPage(tab, formPage(r), formPageSize(r), formSearch(r), nil), flashMessage{Kind: "success", Message: message})
}

func (a *webApp) handleToolsDeleteAll(w http.ResponseWriter, r *http.Request) {
	tab := normalizedTab(r.FormValue("tab"))
	a.mu.Lock()
	defer a.mu.Unlock()

	state, err := loadRequestState(r)
	if err != nil {
		a.redirectError(w, r, tab, err)
		return
	}

	changed := 0
	message := "no users changed"
	if scimEnabled(state) {
		for i := range state.Users {
			if state.Users[i].Deleted {
				continue
			}
			state.Users[i].Deleted = true
			state.Users[i].Dirty = true
			state.Users[i].LastError = ""
			markUserDirtyForApps(&state, state.Users[i].ID, true)
			appendLocalOperationLog(&state, "user", state.Users[i].ID, "Marked for deletion by tools")
			changed++
		}
		if changed > 0 {
			message = fmt.Sprintf("marked %d users for deletion", changed)
		}
	} else {
		changed = len(state.Users)
		state.Users = nil
		for i := range state.Groups {
			state.Groups[i].MemberIDs = nil
		}
		if changed > 0 {
			message = fmt.Sprintf("deleted %d users", changed)
		}
	}

	if changed > 0 {
		if err := saveState(state); err != nil {
			a.redirectError(w, r, tab, err)
			return
		}
	}

	redirectWithFlash(w, r, dashboardURL("users", nil), flashMessage{Kind: "success", Message: message})
}

func (a *webApp) handleToolsClearUsersLocal(w http.ResponseWriter, r *http.Request) {
	tab := normalizedTab(r.FormValue("tab"))
	a.mu.Lock()
	defer a.mu.Unlock()

	state, err := loadRequestState(r)
	if err != nil {
		a.redirectError(w, r, tab, err)
		return
	}
	clearedUsers := len(state.Users)
	affectedGroups := 0
	state.Users = nil
	state.UserOperations = make(map[string][]operationLog)
	state.UserSync = nil
	for i := range state.Groups {
		if len(state.Groups[i].MemberIDs) == 0 {
			continue
		}
		state.Groups[i].MemberIDs = nil
		state.Groups[i].Dirty = true
		state.Groups[i].LastError = ""
		markGroupDirtyForApps(&state, state.Groups[i].ID, false)
		affectedGroups++
	}
	if err := saveState(state); err != nil {
		a.redirectError(w, r, tab, err)
		return
	}

	message := fmt.Sprintf("cleared %d local users without syncing; updated %d groups", clearedUsers, affectedGroups)
	redirectWithFlash(w, r, dashboardURL("users", nil), flashMessage{Kind: "success", Message: message})
}

func (a *webApp) handleToolsDeactivateAll(w http.ResponseWriter, r *http.Request) {
	a.handleToolsSetAllActive(w, r, false)
}

func (a *webApp) handleToolsActivateAll(w http.ResponseWriter, r *http.Request) {
	a.handleToolsSetAllActive(w, r, true)
}

func (a *webApp) handleToolsSetAllActive(w http.ResponseWriter, r *http.Request, active bool) {
	tab := normalizedTab(r.FormValue("tab"))
	a.mu.Lock()
	defer a.mu.Unlock()

	state, err := loadRequestState(r)
	if err != nil {
		a.redirectError(w, r, tab, err)
		return
	}

	changed := 0
	for i := range state.Users {
		if state.Users[i].Deleted || state.Users[i].Active == active {
			continue
		}
		state.Users[i].Active = active
		state.Users[i].Dirty = true
		state.Users[i].LastError = ""
		markUserDirtyForApps(&state, state.Users[i].ID, false)
		appendLocalOperationLog(&state, "user", state.Users[i].ID, summarizeActiveToggle(active))
		changed++
	}

	if changed > 0 {
		if err := saveState(state); err != nil {
			a.redirectError(w, r, tab, err)
			return
		}
	}

	verb := "activated"
	if !active {
		verb = "deactivated"
	}
	message := "no users changed"
	if changed > 0 {
		message = fmt.Sprintf("%s %d users", verb, changed)
	}
	redirectWithFlash(w, r, dashboardURL("users", nil), flashMessage{Kind: "success", Message: message})
}

func (a *webApp) handleToolsCreateUsers(w http.ResponseWriter, r *http.Request) {
	tab := normalizedTab(r.FormValue("tab"))
	count, err := toolUserCount(r.FormValue("count"))
	if err != nil {
		a.redirectToolsError(w, r, tab, err)
		return
	}
	domain, err := toolEmailDomain(r.FormValue("email_domain"))
	if err != nil {
		a.redirectToolsError(w, r, tab, err)
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	state, err := loadRequestState(r)
	if err != nil {
		a.redirectError(w, r, tab, err)
		return
	}

	firstNewUser := len(state.Users)
	created, err := appendToolUsers(&state, count, domain)
	if err != nil {
		a.redirectToolsError(w, r, tab, err)
		return
	}
	for _, createdUser := range state.Users[firstNewUser:] {
		markUserDirtyForApps(&state, createdUser.ID, false)
	}
	if err := saveState(state); err != nil {
		a.redirectError(w, r, tab, err)
		return
	}

	message := fmt.Sprintf("created %d users for %s", created, domain)
	redirectWithFlash(w, r, dashboardURL("users", nil), flashMessage{Kind: "success", Message: message})
}

func (a *webApp) redirectToolsError(w http.ResponseWriter, r *http.Request, tab string, err error) {
	a.redirectFormError(w, r, tab, "tools", err)
}

const formDraftCookieName = "scimtest_form_draft"

func (a *webApp) redirectFormError(w http.ResponseWriter, r *http.Request, tab string, modal string, err error) {
	values := make(url.Values, len(r.Form))
	for key, entries := range r.Form {
		if key == "bearer_token" || key == "scim_bearer_token" || key == "oidc_client_secret" {
			continue
		}
		values[key] = append([]string(nil), entries...)
	}
	token, tokenErr := randomSecret(18)
	if tokenErr != nil {
		a.redirectError(w, r, tab, fmt.Errorf("%v; preserve form: %w", err, tokenErr))
		return
	}
	a.formDraftMu.Lock()
	if a.formDrafts == nil {
		a.formDrafts = make(map[string]formDraft)
	}
	cutoff := time.Now().Add(-5 * time.Minute)
	for existingToken, draft := range a.formDrafts {
		if draft.CreatedAt.Before(cutoff) {
			delete(a.formDrafts, existingToken)
		}
	}
	a.formDrafts[token] = formDraft{Modal: modal, Values: values, Error: err.Error(), CreatedAt: time.Now()}
	a.formDraftMu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: formDraftCookieName, Value: token, Path: "/", MaxAge: 300, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	extra := map[string]string{"modal": modal}
	if id := values.Get("id"); id != "" {
		extra["id"] = id
	}
	redirectWithFlash(w, r, dashboardURLWithPage(tab, formPage(r), formPageSize(r), formSearch(r), extra), flashMessage{})
}

func (a *webApp) consumeFormDraft(w http.ResponseWriter, r *http.Request) *formDraft {
	cookie, err := r.Cookie(formDraftCookieName)
	if err != nil {
		return nil
	}
	http.SetCookie(w, &http.Cookie{Name: formDraftCookieName, Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	a.formDraftMu.Lock()
	defer a.formDraftMu.Unlock()
	draft, ok := a.formDrafts[cookie.Value]
	delete(a.formDrafts, cookie.Value)
	if !ok {
		return nil
	}
	return &draft
}

func applyFormDraft(data *pageData, draft formDraft) {
	values := draft.Values
	switch draft.Modal {
	case "user":
		if data.UserForm == nil {
			return
		}
		data.UserForm.ID = values.Get("id")
		data.UserForm.User.Username = values.Get("username")
		data.UserForm.User.Email = values.Get("email")
		data.UserForm.User.GivenName = values.Get("given_name")
		data.UserForm.User.FamilyName = values.Get("family_name")
	case "group":
		if data.GroupForm == nil {
			return
		}
		data.GroupForm.ID = values.Get("id")
		data.GroupForm.Group.DisplayName = values.Get("display_name")
		selected := values["member_ids"]
		for i := range data.GroupForm.Members {
			data.GroupForm.Members[i].Checked = stringIn(selected, data.GroupForm.Members[i].ID)
		}
	case "app":
		if data.AppForm == nil {
			return
		}
		data.AppForm.App.ID = values.Get("id")
		data.AppForm.App.Name = values.Get("name")
		data.AppForm.App.Slug = values.Get("slug")
		data.AppForm.App.Protocol = values.Get("protocol")
		data.AppForm.App.OIDCClientID = values.Get("oidc_client_id")
		data.AppForm.OIDCRedirectURIs = values.Get("oidc_redirect_uris")
		data.AppForm.App.OIDCPublicClient = values.Get("oidc_public_client") == "on"
		data.AppForm.App.AllowAnyOIDCRedirect = values.Get("allow_any_oidc_redirect") == "on"
		data.AppForm.App.SAMLEntityID = values.Get("saml_entity_id")
		data.AppForm.App.SAMLACSURL = values.Get("saml_acs_url")
		data.AppForm.App.SAMLAudience = values.Get("saml_audience")
		data.AppForm.App.SAMLNameIDField = values.Get("saml_name_id_field")
		data.AppForm.App.SAMLEmailAttributeName = values.Get("saml_email_attribute_name")
		data.AppForm.App.IncludeGroupsClaim = values.Get("include_groups_claim") == "on"
		data.AppForm.App.SCIMEnabled = values.Get("scim_enabled") == "on"
		data.AppForm.App.SCIMBaseURL = values.Get("scim_base_url")
		data.AppForm.App.SCIMAutoOpenTrace = values.Get("scim_auto_open_trace") == "on"
	case "config":
		if data.ConfigForm == nil {
			return
		}
		data.ConfigForm.Config.IDPBaseURL = values.Get("idp_base_url")
		data.ConfigForm.Config.TrustForwardedHeaders = values.Get("trust_forwarded_headers") == "on"
		data.ConfigForm.IDPBaseURLValue = values.Get("idp_base_url")
	case "tools":
		if data.ToolsForm == nil {
			return
		}
		data.ToolsForm.Count = values.Get("count")
		data.ToolsForm.EmailDomain = values.Get("email_domain")
	}
}

func (a *webApp) redirectError(w http.ResponseWriter, r *http.Request, tab string, err error) {
	redirectWithFlash(w, r, dashboardURLWithPage(tab, formPage(r), formPageSize(r), formSearch(r), nil), flashMessage{Kind: "error", Message: err.Error()})
}

func (a *webApp) rememberTrace(appID string, traces []syncTraceEntry) {
	if a.lastTraces == nil {
		a.lastTraces = make(map[string][]syncTraceEntry)
		a.lastTraceContent = make(map[string]string)
	}
	a.lastTraces[appID] = append([]syncTraceEntry(nil), traces...)
	a.lastTraceContent[appID] = formatSyncTraces(traces)
}

func (a *webApp) hasTrace(appID string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.lastTraces[appID]) > 0
}

func (a *webApp) traceContent(appID string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lastTraceContent[appID]
}

func buildStats(state appState) statsView {
	stats := statsView{Apps: len(state.Apps)}
	for _, u := range state.Users {
		if state.Config.SCIMDisabled && u.Deleted {
			continue
		}
		stats.Users++
		if !state.Config.SCIMDisabled && u.Dirty {
			stats.DirtyUsers++
		}
	}
	for _, g := range state.Groups {
		if state.Config.SCIMDisabled && g.Deleted {
			continue
		}
		stats.Groups++
		if !state.Config.SCIMDisabled && g.Dirty {
			stats.DirtyGroups++
		}
	}
	return stats
}

func scimEnabled(state appState) bool {
	for _, candidate := range state.Apps {
		if candidate.SCIMEnabled {
			return true
		}
	}
	return false
}

func buildUserRows(state appState, tab string, page int, pageSize int, search string) []userRowView {
	rows := make([]userRowView, 0, len(state.Users))
	for _, u := range state.Users {
		if state.Config.SCIMDisabled && u.Deleted {
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
			EditURL:    dashboardURLWithPage("users", page, pageSize, search, map[string]string{"modal": "user", "id": u.ID}),
			HistoryURL: dashboardURLWithPage(tab, page, pageSize, search, map[string]string{"historyType": "user", "historyID": u.ID}),
		})
	}
	return rows
}

func buildGroupRows(state appState, tab string, page int, pageSize int, search string) []groupRowView {
	rows := make([]groupRowView, 0, len(state.Groups))
	for _, g := range state.Groups {
		if state.Config.SCIMDisabled && g.Deleted {
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
			EditURL:        dashboardURLWithPage("groups", page, pageSize, search, map[string]string{"modal": "group", "id": g.ID}),
			HistoryURL:     dashboardURLWithPage(tab, page, pageSize, search, map[string]string{"historyType": "group", "historyID": g.ID}),
		})
	}
	return rows
}

func filterUserRows(rows []userRowView, query string) []userRowView {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return rows
	}

	filtered := make([]userRowView, 0, len(rows))
	for _, row := range rows {
		if strings.Contains(strings.ToLower(row.Name), query) ||
			strings.Contains(strings.ToLower(row.Username), query) ||
			strings.Contains(strings.ToLower(row.Email), query) {
			filtered = append(filtered, row)
		}
	}

	return filtered
}

func filterGroupRows(rows []groupRowView, query string) []groupRowView {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return rows
	}

	filtered := make([]groupRowView, 0, len(rows))
	for _, row := range rows {
		if strings.Contains(strings.ToLower(row.Name), query) {
			filtered = append(filtered, row)
		}
	}

	return filtered
}

func buildAppRows(state appState, environmentID string, base string, certPEM string) []appRowView {
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
			SCIMEnabled:            app.SCIMEnabled,
			Active:                 app.ID == environmentID,
			OpenURL:                addEnvironmentToURL(dashboardURL("users", nil), app.ID),
		}
		if row.SupportsOIDC {
			row.OIDCDiscovery = base + "/oidc/" + app.Slug + "/.well-known/openid-configuration"
			row.OIDCAuthorize = base + "/oidc/" + app.Slug + "/authorize"
			row.OIDCJWKS = base + "/oidc/" + app.Slug + "/jwks"
			if len(app.OIDCRedirectURIs) > 0 && !app.OIDCPublicClient {
				query := url.Values{
					"response_type": {"code"},
					"client_id":     {app.OIDCClientID},
					"redirect_uri":  {app.OIDCRedirectURIs[0]},
					"scope":         {"openid profile email groups"},
				}
				row.OIDCTestURL = row.OIDCAuthorize + "?" + query.Encode()
			}
		}
		if row.SupportsSAML {
			row.SAMLMetadata = base + "/saml/" + app.Slug + "/metadata"
			row.SAMLSSO = base + "/saml/" + app.Slug + "/sso"
			row.SAMLTestURL = row.SAMLSSO
		}
		rows = append(rows, row)
	}
	return rows
}

func buildErrorList(state appState) []string {
	var errors []string
	for _, u := range state.Users {
		if u.LastError != "" {
			errors = append(errors, fmt.Sprintf("user %s: %s", userLabel(u), readableLastError(u.LastError)))
		}
	}
	for _, g := range state.Groups {
		if g.LastError != "" {
			errors = append(errors, fmt.Sprintf("group %s: %s", g.DisplayName, readableLastError(g.LastError)))
		}
	}
	return errors
}

func readableLastError(message string) string {
	message = strings.TrimSpace(message)
	if message == "" {
		return ""
	}
	if strings.HasPrefix(message, "SCIM server rate limit hit") {
		return message
	}
	if !strings.Contains(message, "429 Too Many Requests") {
		return message
	}

	retryAfter := legacyRetryAfter(message)
	if retryAfter == "" {
		return "SCIM server rate limit hit (429 Too Many Requests). Try again later."
	}

	return "SCIM server rate limit hit (429 Too Many Requests). Try again " + retryAfter + "."
}

func legacyRetryAfter(message string) string {
	const marker = "retry after "
	index := strings.Index(message, marker)
	if index < 0 {
		return ""
	}

	value := strings.TrimSpace(message[index+len(marker):])
	if colon := strings.Index(value, ":"); colon >= 0 {
		value = value[:colon]
	}
	value = strings.Trim(strings.TrimSpace(value), ".")
	if value == "" {
		return ""
	}

	return readableRetryAfter(value)
}

func readableRetryAfter(value string) string {
	if strings.HasPrefix(value, "in ") || strings.HasPrefix(value, "after ") || value == "now" {
		return value
	}

	delay, err := time.ParseDuration(value)
	if err == nil {
		return readableRetryDelay(delay)
	}

	seconds, err := strconv.Atoi(value)
	if err == nil {
		return readableRetryDelay(time.Duration(seconds) * time.Second)
	}

	return "after " + value
}

func readableRetryDelay(delay time.Duration) string {
	if delay <= 0 {
		return "now"
	}

	seconds := int64((delay + time.Second - 1) / time.Second)
	switch {
	case seconds <= 1:
		return "in 1 second"
	case seconds < 60:
		return fmt.Sprintf("in %d seconds", seconds)
	case seconds < 3600:
		minutes := (seconds + 59) / 60
		if minutes == 1 {
			return "in 1 minute"
		}

		return fmt.Sprintf("in %d minutes", minutes)
	case seconds < 86400:
		hours := (seconds + 3599) / 3600
		if hours == 1 {
			return "in 1 hour"
		}

		return fmt.Sprintf("in %d hours", hours)
	default:
		days := (seconds + 86399) / 86400
		if days == 1 {
			return "in 1 day"
		}

		return fmt.Sprintf("in %d days", days)
	}
}

func buildHistoryView(state appState, tab string, page int, pageSize int, search string, values url.Values) *historyView {
	resourceType := strings.TrimSpace(values.Get("historyType"))
	resourceID := strings.TrimSpace(values.Get("historyID"))
	if resourceType == "" || resourceID == "" {
		return nil
	}

	view := &historyView{Close: dashboardURLWithPage(tab, page, pageSize, search, nil)}
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

func buildUserFormView(state appState, tab string, page int, pageSize int, search string, id string) (*userFormView, error) {
	if strings.TrimSpace(id) == "" {
		return &userFormView{Title: "Add User", Close: dashboardURLWithPage(tab, page, pageSize, search, nil)}, nil
	}

	u, ok := userByID(state.Users, id)
	if !ok {
		return nil, fmt.Errorf("user %s not found", id)
	}

	return &userFormView{Title: "Edit User", ID: id, User: u, Close: dashboardURLWithPage(tab, page, pageSize, search, nil)}, nil
}

func buildGroupFormView(state appState, tab string, page int, pageSize int, search string, id string) (*groupFormView, error) {
	form := &groupFormView{Title: "Add Group", Close: dashboardURLWithPage(tab, page, pageSize, search, nil)}
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
		if !state.Config.SCIMDisabled {
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
		Title: "Add Environment",
		App: app{
			Protocol:               "oidc",
			SAMLNameIDField:        defaultSAMLNameIDField,
			SAMLNameIDFormat:       samlNameIDFormatForField(defaultSAMLNameIDField),
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
	form.Title = "Edit Environment"
	form.App = existing
	form.App.SAMLNameIDField = normalizeSAMLNameIDField(form.App.SAMLNameIDField)
	form.App.SAMLNameIDFormat = samlNameIDFormatForField(form.App.SAMLNameIDField)
	form.OIDCRedirectURIs = joinLines(form.App.OIDCRedirectURIs)
	if form.App.Slug != "" {
		form.SAMLIDPEntityID = baseURL + "/saml/" + form.App.Slug + "/metadata"
		form.SAMLIDPSSO = baseURL + "/saml/" + form.App.Slug + "/sso"
	}
	return form, nil
}

func toolUserCount(value string) (int, error) {
	count, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return 0, fmt.Errorf("number of users must be between 1 and %d", maxToolCreateUsers)
	}
	if count < 1 || count > maxToolCreateUsers {
		return 0, fmt.Errorf("number of users must be between 1 and %d", maxToolCreateUsers)
	}

	return count, nil
}

func toolEmailDomain(value string) (string, error) {
	domain := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(value)), "@")
	switch {
	case domain == "":
		return "", fmt.Errorf("email domain is required")
	case strings.Contains(domain, "@"):
		return "", fmt.Errorf("email domain must not include @")
	case strings.ContainsAny(domain, " \t\r\n/\\"):
		return "", fmt.Errorf("email domain contains invalid characters")
	case strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, "."):
		return "", fmt.Errorf("email domain must not start or end with a dot")
	}

	return domain, nil
}

func appendToolUsers(state *appState, count int, domain string) (int, error) {
	usedEmails := make(map[string]struct{}, len(state.Users)+count)
	usedUsernames := make(map[string]struct{}, len(state.Users)+count)
	for _, u := range state.Users {
		usedEmails[strings.ToLower(u.Email)] = struct{}{}
		usedUsernames[strings.ToLower(u.Username)] = struct{}{}
	}

	created := 0
	candidate := 1
	for created < count {
		username := fmt.Sprintf("user%03d", candidate)
		email := username + "@" + domain
		candidate++
		if _, ok := usedEmails[strings.ToLower(email)]; ok {
			continue
		}
		if _, ok := usedUsernames[strings.ToLower(username)]; ok {
			continue
		}

		name := toolUserNames[created%len(toolUserNames)]
		if err := validateUser(name.given, name.family, email, username); err != nil {
			return created, err
		}
		id, err := newUserID()
		if err != nil {
			return created, err
		}

		state.Users = append(state.Users, user{
			ID:         id,
			GivenName:  name.given,
			FamilyName: name.family,
			Username:   username,
			Email:      email,
			Active:     true,
			Dirty:      true,
		})
		appendLocalOperationLog(state, "user", id, "Created by tools")
		usedEmails[strings.ToLower(email)] = struct{}{}
		usedUsernames[strings.ToLower(username)] = struct{}{}
		created++
	}

	return created, nil
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

func requestPage(value string) int {
	page, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || page < 1 {
		return 1
	}

	return page
}

func formPage(r *http.Request) int {
	return requestPage(r.FormValue("page"))
}

func searchQuery(value string) string {
	return strings.TrimSpace(value)
}

func formSearch(r *http.Request) string {
	return searchQuery(r.FormValue("q"))
}

func requestPageSize(value string) int {
	pageSize, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return defaultListPageSize
	}
	for _, option := range listPageSizeOptions {
		if pageSize == option {
			return pageSize
		}
	}

	return defaultListPageSize
}

func formPageSize(r *http.Request) int {
	return requestPageSize(r.FormValue("pageSize"))
}

func currentListPage(total int, page int, pageSize int) int {
	if total <= pageSize {
		return 1
	}

	totalPages := (total + pageSize - 1) / pageSize
	if page > totalPages {
		return totalPages
	}
	if page < 1 {
		return 1
	}

	return page
}

func slicePage[T any](rows []T, page int, pageSize int) []T {
	start := (page - 1) * pageSize
	if start >= len(rows) {
		return nil
	}

	end := start + pageSize
	if end > len(rows) {
		end = len(rows)
	}

	return rows[start:end]
}

func buildPagination(total int, tab string, page int, pageSize int, search string) *paginationView {
	if total == 0 && search == "" {
		return nil
	}

	totalPages := (total + pageSize - 1) / pageSize
	if totalPages < 1 {
		totalPages = 1
	}
	summary := "No results"
	if total > 0 {
		start := (page-1)*pageSize + 1
		end := page * pageSize
		if end > total {
			end = total
		}
		summary = fmt.Sprintf("Showing %d–%d of %d", start, end, total)
	}

	view := &paginationView{
		Page:            page,
		PageSize:        pageSize,
		SearchQuery:     search,
		TotalPages:      totalPages,
		Summary:         summary,
		PageSizeOptions: buildPageSizeOptions(pageSize),
	}
	if page > 1 {
		view.HasPrevious = true
		view.PreviousURL = dashboardURLWithPage(tab, page-1, pageSize, search, nil)
	}
	if page < totalPages {
		view.HasNext = true
		view.NextURL = dashboardURLWithPage(tab, page+1, pageSize, search, nil)
	}

	return view
}

func buildPageSizeOptions(pageSize int) []pageSizeOptionView {
	options := make([]pageSizeOptionView, 0, len(listPageSizeOptions))
	for _, option := range listPageSizeOptions {
		options = append(options, pageSizeOptionView{
			Size:     option,
			Label:    strconv.Itoa(option),
			Selected: option == pageSize,
		})
	}

	return options
}

func dashboardURLWithPage(tab string, page int, pageSize int, search string, extra map[string]string) string {
	values := make(map[string]string, len(extra)+3)
	for key, value := range extra {
		values[key] = value
	}
	if page > 1 {
		values["page"] = strconv.Itoa(page)
	}
	if pageSize != defaultListPageSize {
		values["pageSize"] = strconv.Itoa(pageSize)
	}
	if strings.TrimSpace(search) != "" {
		values["q"] = search
	}

	return dashboardURL(tab, values)
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

func scopePageDataURLs(data *pageData, environmentID string) {
	if environmentID == "" {
		return
	}
	urls := []*string{
		&data.UsersURL,
		&data.GroupsURL,
		&data.AppsURL,
		&data.EnvironmentSettingsURL,
		&data.NewUserURL,
		&data.NewGroupURL,
		&data.NewAppURL,
		&data.ConfigURL,
		&data.ToolsURL,
		&data.TraceURL,
		&data.TraceCloseURL,
	}
	for _, target := range urls {
		*target = addEnvironmentToURL(*target, environmentID)
	}
	for i := range data.Users {
		data.Users[i].EditURL = addEnvironmentToURL(data.Users[i].EditURL, environmentID)
		data.Users[i].HistoryURL = addEnvironmentToURL(data.Users[i].HistoryURL, environmentID)
	}
	for i := range data.Groups {
		data.Groups[i].EditURL = addEnvironmentToURL(data.Groups[i].EditURL, environmentID)
		data.Groups[i].HistoryURL = addEnvironmentToURL(data.Groups[i].HistoryURL, environmentID)
	}
	for i := range data.Apps {
		data.Apps[i].EditURL = addEnvironmentToURL(data.Apps[i].EditURL, environmentID)
	}
	if data.Pagination != nil {
		data.Pagination.PreviousURL = addEnvironmentToURL(data.Pagination.PreviousURL, environmentID)
		data.Pagination.NextURL = addEnvironmentToURL(data.Pagination.NextURL, environmentID)
	}
	if data.History != nil {
		data.History.Close = addEnvironmentToURL(data.History.Close, environmentID)
	}
	if data.UserForm != nil {
		data.UserForm.Close = addEnvironmentToURL(data.UserForm.Close, environmentID)
	}
	if data.GroupForm != nil {
		data.GroupForm.Close = addEnvironmentToURL(data.GroupForm.Close, environmentID)
	}
	if data.AppForm != nil {
		data.AppForm.Close = addEnvironmentToURL(data.AppForm.Close, environmentID)
	}
	if data.ConfigForm != nil {
		data.ConfigForm.Close = addEnvironmentToURL(data.ConfigForm.Close, environmentID)
	}
	if data.ToolsForm != nil {
		data.ToolsForm.Close = addEnvironmentToURL(data.ToolsForm.Close, environmentID)
	}
}

func addEnvironmentToURL(rawURL string, environmentID string) string {
	if rawURL == "" || environmentID == "" {
		return rawURL
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.IsAbs() || parsed.Path != "/" {
		return rawURL
	}
	values := parsed.Query()
	values.Set("environment", environmentID)
	parsed.RawQuery = values.Encode()
	return parsed.String()
}

func redirectWithFlash(w http.ResponseWriter, r *http.Request, location string, flash flashMessage) {
	setFlashCookie(w, flash)
	parsed, err := url.Parse(location)
	if err == nil && parsed.Query().Get("environment") == "" {
		location = addEnvironmentToURL(location, strings.TrimSpace(r.FormValue("environment")))
	}
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
