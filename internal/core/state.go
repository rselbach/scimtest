package core

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

var currentTime = time.Now

const DefaultSAMLEmailAttributeName = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
const DefaultSAMLNameIDField = "email"
const SAMLNameIDFormatEmail = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
const SAMLNameIDFormatUnspecified = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"

type Config struct {
	BaseURL               string `json:"base_url"`
	BearerToken           string `json:"bearer_token"`
	AutoOpenSyncTrace     bool   `json:"auto_open_sync_trace"`
	SCIMDisabled          bool   `json:"scim_disabled,omitempty"`
	IDPBaseURL            string `json:"idp_base_url,omitempty"`
	TrustForwardedHeaders bool   `json:"trust_forwarded_headers,omitempty"`
	RgrokName             string `json:"rgrok_name,omitempty"`
	RgrokToken            string `json:"rgrok_token,omitempty"`
	SigningPrivateKeyPEM  string `json:"signing_private_key_pem,omitempty"`
	SigningCertificatePEM string `json:"signing_certificate_pem,omitempty"`
}

type User struct {
	ID         string `json:"id"`
	GivenName  string `json:"given_name,omitempty"`
	FamilyName string `json:"family_name,omitempty"`
	Email      string `json:"email"`
	Username   string `json:"username"`
	Active     bool   `json:"active"`
	RemoteID   string `json:"remote_id,omitempty"`
	Dirty      bool   `json:"dirty"`
	Deleted    bool   `json:"deleted"`
	LastError  string `json:"last_error,omitempty"`
}

func (u *User) UnmarshalJSON(data []byte) error {
	type alias User
	aux := struct {
		alias
		LegacyName string `json:"name,omitempty"`
		Active     *bool  `json:"active"`
	}{}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	*u = User(aux.alias)
	if aux.Active != nil {
		u.Active = *aux.Active
	}

	if strings.TrimSpace(aux.LegacyName) == "" {
		if aux.Active == nil {
			u.Active = true
		}

		return nil
	}

	givenName, familyName := SplitName(aux.LegacyName)
	if strings.TrimSpace(u.GivenName) == "" {
		u.GivenName = givenName
	}
	if strings.TrimSpace(u.FamilyName) == "" {
		u.FamilyName = familyName
	}
	if aux.Active == nil {
		u.Active = true
	}

	return nil
}

type AppState struct {
	Config          Config                    `json:"config"`
	Users           []User                    `json:"users"`
	Groups          []Group                   `json:"groups"`
	Apps            []App                     `json:"apps"`
	UserOperations  map[string][]OperationLog `json:"-"`
	GroupOperations map[string][]OperationLog `json:"-"`
}

type OperationLog struct {
	Kind               string
	Summary            string
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

type Group struct {
	ID          string   `json:"id"`
	DisplayName string   `json:"display_name"`
	MemberIDs   []string `json:"member_ids,omitempty"`
	RemoteID    string   `json:"remote_id,omitempty"`
	Dirty       bool     `json:"dirty"`
	Deleted     bool     `json:"deleted"`
	LastError   string   `json:"last_error,omitempty"`
}

type App struct {
	ID                     string   `json:"id"`
	Name                   string   `json:"name"`
	Slug                   string   `json:"slug"`
	Protocol               string   `json:"protocol"`
	OIDCClientID           string   `json:"oidc_client_id,omitempty"`
	OIDCClientSecret       string   `json:"oidc_client_secret,omitempty"`
	OIDCPublicClient       bool     `json:"oidc_public_client,omitempty"`
	OIDCRedirectURIs       []string `json:"oidc_redirect_uris,omitempty"`
	AllowAnyOIDCRedirect   bool     `json:"allow_any_oidc_redirect,omitempty"`
	SAMLEntityID           string   `json:"saml_entity_id,omitempty"`
	SAMLACSURL             string   `json:"saml_acs_url,omitempty"`
	SAMLAudience           string   `json:"saml_audience,omitempty"`
	SAMLNameIDField        string   `json:"saml_name_id_field,omitempty"`
	SAMLNameIDFormat       string   `json:"saml_name_id_format,omitempty"`
	SAMLEmailAttributeName string   `json:"saml_email_attribute_name,omitempty"`
	IncludeGroupsClaim     bool     `json:"include_groups_claim"`
}

func LoadState() (AppState, error) {
	db, err := openStateDB()
	if err != nil {
		return AppState{}, err
	}
	defer closeDB(db)

	state, err := loadStateFromDB(db)
	if err != nil {
		return AppState{}, err
	}
	NormalizeState(&state)
	if !StateEmpty(state) {
		return state, nil
	}

	legacyPath, err := legacyStateFilePath()
	if err != nil {
		return AppState{}, err
	}

	legacyState, ok, err := loadLegacyJSONState(legacyPath)
	if err != nil {
		return AppState{}, err
	}
	if !ok {
		return state, nil
	}
	NormalizeState(&legacyState)

	if err := saveStateToDB(db, legacyState); err != nil {
		return AppState{}, err
	}

	return loadStateFromDB(db)
}

func SaveState(state AppState) error {
	NormalizeState(&state)

	db, err := openStateDB()
	if err != nil {
		return err
	}
	defer closeDB(db)

	return saveStateToDB(db, state)
}

func openStateDB() (*sql.DB, error) {
	path, err := stateFilePath()
	if err != nil {
		return nil, err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create state directory: %w", err)
	}
	if strings.TrimSpace(os.Getenv("SCIMTEST_STATE_FILE")) == "" {
		if err := os.Chmod(dir, 0o700); err != nil {
			return nil, fmt.Errorf("secure state directory: %w", err)
		}
	}

	stateFile, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create sqlite state db %s: %w", path, err)
	}
	if err := stateFile.Close(); err != nil {
		return nil, fmt.Errorf("close sqlite state db %s after creation: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, fmt.Errorf("secure sqlite state db %s: %w", path, err)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite state db %s: %w", path, err)
	}

	if err := initStateDB(db); err != nil {
		if closeErr := db.Close(); closeErr != nil {
			return nil, fmt.Errorf("%w; close sqlite state db: %v", err, closeErr)
		}
		return nil, err
	}

	return db, nil
}

func initStateDB(db *sql.DB) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS config (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			given_name TEXT NOT NULL,
			family_name TEXT NOT NULL,
			email TEXT NOT NULL,
			username TEXT NOT NULL,
			active INTEGER NOT NULL,
			remote_id TEXT NOT NULL DEFAULT '',
			dirty INTEGER NOT NULL,
			deleted INTEGER NOT NULL,
			last_error TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS groups (
			id TEXT PRIMARY KEY,
			display_name TEXT NOT NULL,
			remote_id TEXT NOT NULL DEFAULT '',
			dirty INTEGER NOT NULL,
			deleted INTEGER NOT NULL,
			last_error TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS apps (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			slug TEXT NOT NULL,
			protocol TEXT NOT NULL,
			oidc_client_id TEXT NOT NULL DEFAULT '',
			oidc_client_secret TEXT NOT NULL DEFAULT '',
			oidc_public_client INTEGER NOT NULL DEFAULT 0,
			oidc_redirect_uris TEXT NOT NULL DEFAULT '',
			saml_entity_id TEXT NOT NULL DEFAULT '',
			saml_acs_url TEXT NOT NULL DEFAULT '',
			saml_audience TEXT NOT NULL DEFAULT '',
			saml_name_id_field TEXT NOT NULL DEFAULT 'email',
			saml_name_id_format TEXT NOT NULL DEFAULT '',
			saml_email_attribute_name TEXT NOT NULL DEFAULT '',
			include_groups_claim INTEGER NOT NULL DEFAULT 0,
			allow_any_oidc_redirect INTEGER NOT NULL DEFAULT 1
		)`,
		`CREATE TABLE IF NOT EXISTS group_members (
			group_id TEXT NOT NULL,
			user_id TEXT NOT NULL,
			position INTEGER NOT NULL,
			PRIMARY KEY (group_id, user_id)
		)`,
		`CREATE TABLE IF NOT EXISTS operation_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			resource_type TEXT NOT NULL,
			resource_id TEXT NOT NULL,
			label TEXT NOT NULL,
			kind TEXT NOT NULL DEFAULT 'sync',
			summary TEXT NOT NULL DEFAULT '',
			operation TEXT NOT NULL,
			method TEXT NOT NULL,
			path TEXT NOT NULL,
			request_body TEXT NOT NULL,
			status TEXT NOT NULL,
			response_retry_after TEXT NOT NULL DEFAULT '',
			response_body TEXT NOT NULL,
			error_text TEXT NOT NULL,
			created_at TEXT NOT NULL
		)`,
	}

	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			return fmt.Errorf("initialize sqlite schema: %w", err)
		}
	}

	migrations := []string{
		`ALTER TABLE operation_logs ADD COLUMN kind TEXT NOT NULL DEFAULT 'sync'`,
		`ALTER TABLE operation_logs ADD COLUMN summary TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE operation_logs ADD COLUMN response_retry_after TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE apps ADD COLUMN saml_name_id_field TEXT NOT NULL DEFAULT 'email'`,
		`ALTER TABLE apps ADD COLUMN allow_any_oidc_redirect INTEGER NOT NULL DEFAULT 1`,
		`ALTER TABLE apps ADD COLUMN oidc_public_client INTEGER NOT NULL DEFAULT 0`,
	}
	for _, migration := range migrations {
		if _, err := db.Exec(migration); err != nil && !strings.Contains(err.Error(), "duplicate column name") {
			return fmt.Errorf("migrate sqlite schema: %w", err)
		}
	}

	return nil
}

func loadStateFromDB(db *sql.DB) (AppState, error) {
	state := AppState{}
	state.UserOperations = make(map[string][]OperationLog)
	state.GroupOperations = make(map[string][]OperationLog)

	configRows, err := db.Query(`SELECT key, value FROM config`)
	if err != nil {
		return AppState{}, fmt.Errorf("load config from sqlite: %w", err)
	}
	defer closeRows(configRows)

	for configRows.Next() {
		var key string
		var value string
		if err := configRows.Scan(&key, &value); err != nil {
			return AppState{}, fmt.Errorf("scan sqlite config row: %w", err)
		}

		switch key {
		case "base_url":
			state.Config.BaseURL = value
		case "bearer_token":
			state.Config.BearerToken = value
		case "auto_open_sync_trace":
			state.Config.AutoOpenSyncTrace = value == "1"
		case "scim_disabled":
			state.Config.SCIMDisabled = value == "1"
		case "idp_base_url":
			state.Config.IDPBaseURL = value
		case "trust_forwarded_headers":
			state.Config.TrustForwardedHeaders = value == "1"
		case "rgrok_name":
			state.Config.RgrokName = value
		case "rgrok_token":
			state.Config.RgrokToken = value
		case "signing_private_key_pem":
			state.Config.SigningPrivateKeyPEM = value
		case "signing_certificate_pem":
			state.Config.SigningCertificatePEM = value
		}
	}
	if err := configRows.Err(); err != nil {
		return AppState{}, fmt.Errorf("iterate sqlite config rows: %w", err)
	}

	userRows, err := db.Query(`SELECT id, given_name, family_name, email, username, active, remote_id, dirty, deleted, last_error FROM users ORDER BY rowid`)
	if err != nil {
		return AppState{}, fmt.Errorf("load users from sqlite: %w", err)
	}
	defer closeRows(userRows)

	for userRows.Next() {
		var u User
		var active int
		var dirty int
		var deleted int
		if err := userRows.Scan(&u.ID, &u.GivenName, &u.FamilyName, &u.Email, &u.Username, &active, &u.RemoteID, &dirty, &deleted, &u.LastError); err != nil {
			return AppState{}, fmt.Errorf("scan sqlite user row: %w", err)
		}
		u.Active = active != 0
		u.Dirty = dirty != 0
		u.Deleted = deleted != 0
		state.Users = append(state.Users, u)
	}
	if err := userRows.Err(); err != nil {
		return AppState{}, fmt.Errorf("iterate sqlite user rows: %w", err)
	}

	groupRows, err := db.Query(`SELECT id, display_name, remote_id, dirty, deleted, last_error FROM groups ORDER BY rowid`)
	if err != nil {
		return AppState{}, fmt.Errorf("load groups from sqlite: %w", err)
	}
	defer closeRows(groupRows)

	groupIndex := make(map[string]int)
	for groupRows.Next() {
		var g Group
		var dirty int
		var deleted int
		if err := groupRows.Scan(&g.ID, &g.DisplayName, &g.RemoteID, &dirty, &deleted, &g.LastError); err != nil {
			return AppState{}, fmt.Errorf("scan sqlite group row: %w", err)
		}
		g.Dirty = dirty != 0
		g.Deleted = deleted != 0
		groupIndex[g.ID] = len(state.Groups)
		state.Groups = append(state.Groups, g)
	}
	if err := groupRows.Err(); err != nil {
		return AppState{}, fmt.Errorf("iterate sqlite group rows: %w", err)
	}

	memberRows, err := db.Query(`SELECT group_id, user_id FROM group_members ORDER BY group_id, position`)
	if err != nil {
		return AppState{}, fmt.Errorf("load group members from sqlite: %w", err)
	}
	defer closeRows(memberRows)

	for memberRows.Next() {
		var groupID string
		var userID string
		if err := memberRows.Scan(&groupID, &userID); err != nil {
			return AppState{}, fmt.Errorf("scan sqlite group member row: %w", err)
		}

		index, ok := groupIndex[groupID]
		if !ok {
			continue
		}
		state.Groups[index].MemberIDs = append(state.Groups[index].MemberIDs, userID)
	}
	if err := memberRows.Err(); err != nil {
		return AppState{}, fmt.Errorf("iterate sqlite group member rows: %w", err)
	}

	appRows, err := db.Query(`SELECT id, name, slug, protocol, oidc_client_id, oidc_client_secret, oidc_public_client, oidc_redirect_uris, saml_entity_id, saml_acs_url, saml_audience, saml_name_id_field, saml_name_id_format, saml_email_attribute_name, include_groups_claim, allow_any_oidc_redirect FROM apps ORDER BY rowid`)
	if err != nil {
		return AppState{}, fmt.Errorf("load apps from sqlite: %w", err)
	}
	defer closeRows(appRows)

	for appRows.Next() {
		var app App
		var redirectURIs string
		var includeGroups int
		var allowAnyRedirect int
		var publicClient int
		if err := appRows.Scan(&app.ID, &app.Name, &app.Slug, &app.Protocol, &app.OIDCClientID, &app.OIDCClientSecret, &publicClient, &redirectURIs, &app.SAMLEntityID, &app.SAMLACSURL, &app.SAMLAudience, &app.SAMLNameIDField, &app.SAMLNameIDFormat, &app.SAMLEmailAttributeName, &includeGroups, &allowAnyRedirect); err != nil {
			return AppState{}, fmt.Errorf("scan sqlite app row: %w", err)
		}
		app.OIDCRedirectURIs = Lines(redirectURIs)
		app.IncludeGroupsClaim = includeGroups != 0
		app.AllowAnyOIDCRedirect = allowAnyRedirect != 0
		app.OIDCPublicClient = publicClient != 0
		state.Apps = append(state.Apps, app)
	}
	if err := appRows.Err(); err != nil {
		return AppState{}, fmt.Errorf("iterate sqlite app rows: %w", err)
	}

	logRows, err := db.Query(`SELECT resource_type, resource_id, kind, summary, operation, method, path, request_body, status, response_retry_after, response_body, error_text, created_at FROM operation_logs ORDER BY resource_type, resource_id, created_at DESC, id ASC`)
	if err != nil {
		return AppState{}, fmt.Errorf("load operation logs from sqlite: %w", err)
	}
	defer closeRows(logRows)

	for logRows.Next() {
		var resourceType string
		var resourceID string
		var entry OperationLog
		if err := logRows.Scan(&resourceType, &resourceID, &entry.Kind, &entry.Summary, &entry.Operation, &entry.Method, &entry.Path, &entry.RequestBody, &entry.Status, &entry.ResponseRetryAfter, &entry.ResponseBody, &entry.Err, &entry.CreatedAt); err != nil {
			return AppState{}, fmt.Errorf("scan sqlite operation log row: %w", err)
		}

		switch resourceType {
		case "user":
			state.UserOperations[resourceID] = append(state.UserOperations[resourceID], entry)
		case "group":
			state.GroupOperations[resourceID] = append(state.GroupOperations[resourceID], entry)
		}
	}
	if err := logRows.Err(); err != nil {
		return AppState{}, fmt.Errorf("iterate sqlite operation log rows: %w", err)
	}

	return state, nil
}

func saveStateToDB(db *sql.DB, state AppState) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin sqlite state transaction: %w", err)
	}
	committed := false
	defer rollbackTx(tx, &committed)

	if _, err := tx.Exec(`DELETE FROM config`); err != nil {
		return fmt.Errorf("clear sqlite config: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM users`); err != nil {
		return fmt.Errorf("clear sqlite users: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM groups`); err != nil {
		return fmt.Errorf("clear sqlite groups: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM apps`); err != nil {
		return fmt.Errorf("clear sqlite apps: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM group_members`); err != nil {
		return fmt.Errorf("clear sqlite group members: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM operation_logs`); err != nil {
		return fmt.Errorf("clear sqlite operation logs: %w", err)
	}

	configStmt, err := tx.Prepare(`INSERT INTO config(key, value) VALUES(?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare sqlite config insert: %w", err)
	}
	defer closeStmt(configStmt)

	configEntries := map[string]string{
		"base_url":                state.Config.BaseURL,
		"bearer_token":            state.Config.BearerToken,
		"auto_open_sync_trace":    BoolString(state.Config.AutoOpenSyncTrace),
		"scim_disabled":           BoolString(state.Config.SCIMDisabled),
		"idp_base_url":            state.Config.IDPBaseURL,
		"trust_forwarded_headers": BoolString(state.Config.TrustForwardedHeaders),
		"rgrok_name":              state.Config.RgrokName,
		"rgrok_token":             state.Config.RgrokToken,
		"signing_private_key_pem": state.Config.SigningPrivateKeyPEM,
		"signing_certificate_pem": state.Config.SigningCertificatePEM,
	}
	for key, value := range configEntries {
		if _, err := configStmt.Exec(key, value); err != nil {
			return fmt.Errorf("insert sqlite config %s: %w", key, err)
		}
	}

	userStmt, err := tx.Prepare(`INSERT INTO users(id, given_name, family_name, email, username, active, remote_id, dirty, deleted, last_error) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare sqlite user insert: %w", err)
	}
	defer closeStmt(userStmt)

	for _, u := range state.Users {
		if _, err := userStmt.Exec(u.ID, u.GivenName, u.FamilyName, u.Email, u.Username, boolToInt(u.Active), u.RemoteID, boolToInt(u.Dirty), boolToInt(u.Deleted), u.LastError); err != nil {
			return fmt.Errorf("insert sqlite user %s: %w", u.ID, err)
		}
	}

	groupStmt, err := tx.Prepare(`INSERT INTO groups(id, display_name, remote_id, dirty, deleted, last_error) VALUES(?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare sqlite group insert: %w", err)
	}
	defer closeStmt(groupStmt)

	memberStmt, err := tx.Prepare(`INSERT INTO group_members(group_id, user_id, position) VALUES(?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare sqlite group member insert: %w", err)
	}
	defer closeStmt(memberStmt)

	logStmt, err := tx.Prepare(`INSERT INTO operation_logs(resource_type, resource_id, label, kind, summary, operation, method, path, request_body, status, response_retry_after, response_body, error_text, created_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare sqlite operation log insert: %w", err)
	}
	defer closeStmt(logStmt)

	for _, g := range state.Groups {
		if _, err := groupStmt.Exec(g.ID, g.DisplayName, g.RemoteID, boolToInt(g.Dirty), boolToInt(g.Deleted), g.LastError); err != nil {
			return fmt.Errorf("insert sqlite group %s: %w", g.ID, err)
		}

		for position, userID := range g.MemberIDs {
			if _, err := memberStmt.Exec(g.ID, userID, position); err != nil {
				return fmt.Errorf("insert sqlite group member %s/%s: %w", g.ID, userID, err)
			}
		}
	}

	appStmt, err := tx.Prepare(`INSERT INTO apps(id, name, slug, protocol, oidc_client_id, oidc_client_secret, oidc_public_client, oidc_redirect_uris, saml_entity_id, saml_acs_url, saml_audience, saml_name_id_field, saml_name_id_format, saml_email_attribute_name, include_groups_claim, allow_any_oidc_redirect) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare sqlite app insert: %w", err)
	}
	defer closeStmt(appStmt)

	for _, app := range state.Apps {
		if _, err := appStmt.Exec(app.ID, app.Name, app.Slug, app.Protocol, app.OIDCClientID, app.OIDCClientSecret, boolToInt(app.OIDCPublicClient), JoinLines(app.OIDCRedirectURIs), app.SAMLEntityID, app.SAMLACSURL, app.SAMLAudience, app.SAMLNameIDField, app.SAMLNameIDFormat, app.SAMLEmailAttributeName, boolToInt(app.IncludeGroupsClaim), boolToInt(app.AllowAnyOIDCRedirect)); err != nil {
			return fmt.Errorf("insert sqlite app %s: %w", app.ID, err)
		}
	}

	for resourceID, entries := range state.UserOperations {
		label := resourceID
		if User, ok := UserByID(state.Users, resourceID); ok {
			label = UserLabel(User)
		}
		for _, entry := range entries {
			if _, err := logStmt.Exec("user", resourceID, label, entry.Kind, entry.Summary, entry.Operation, entry.Method, entry.Path, entry.RequestBody, entry.Status, entry.ResponseRetryAfter, entry.ResponseBody, entry.Err, entry.CreatedAt); err != nil {
				return fmt.Errorf("insert sqlite user operation log %s: %w", resourceID, err)
			}
		}
	}

	for resourceID, entries := range state.GroupOperations {
		label := resourceID
		if Group, ok := GroupByID(state.Groups, resourceID); ok {
			label = Group.DisplayName
		}
		for _, entry := range entries {
			if _, err := logStmt.Exec("group", resourceID, label, entry.Kind, entry.Summary, entry.Operation, entry.Method, entry.Path, entry.RequestBody, entry.Status, entry.ResponseRetryAfter, entry.ResponseBody, entry.Err, entry.CreatedAt); err != nil {
				return fmt.Errorf("insert sqlite group operation log %s: %w", resourceID, err)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit sqlite state transaction: %w", err)
	}
	committed = true

	return nil
}

func closeDB(db *sql.DB) {
	if err := db.Close(); err != nil {
		panic(fmt.Sprintf("close sqlite db: %v", err))
	}
}

func closeRows(rows *sql.Rows) {
	if err := rows.Close(); err != nil {
		panic(fmt.Sprintf("close sqlite rows: %v", err))
	}
}

func closeStmt(stmt *sql.Stmt) {
	if err := stmt.Close(); err != nil {
		panic(fmt.Sprintf("close sqlite statement: %v", err))
	}
}

func rollbackTx(tx *sql.Tx, committed *bool) {
	if *committed {
		return
	}
	if err := tx.Rollback(); err != nil && err != sql.ErrTxDone {
		panic(fmt.Sprintf("rollback sqlite transaction: %v", err))
	}
}

func stateFilePath() (string, error) {
	if path := strings.TrimSpace(os.Getenv("SCIMTEST_STATE_FILE")); path != "" {
		return path, nil
	}

	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("get user config dir: %w", err)
	}

	return filepath.Join(configDir, "scimtest", "state.db"), nil
}

func legacyStateFilePath() (string, error) {
	path, err := stateFilePath()
	if err != nil {
		return "", err
	}

	if strings.HasSuffix(path, ".db") {
		return strings.TrimSuffix(path, ".db") + ".json", nil
	}

	return path + ".json", nil
}

func loadLegacyJSONState(path string) (AppState, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return AppState{}, false, nil
		}

		return AppState{}, false, fmt.Errorf("read legacy state %s: %w", path, err)
	}

	var state AppState
	if err := json.Unmarshal(data, &state); err != nil {
		return AppState{}, false, fmt.Errorf("decode legacy state %s: %w", path, err)
	}

	for i := range state.Users {
		migrateLegacyName(&state.Users[i])
	}

	return state, true, nil
}

func StateEmpty(state AppState) bool {
	return state.Config == (Config{}) && len(state.Users) == 0 && len(state.Groups) == 0 && len(state.Apps) == 0
}

func NormalizeState(state *AppState) {
	state.Config.BaseURL = strings.TrimRight(strings.TrimSpace(state.Config.BaseURL), "/")
	state.Config.IDPBaseURL = strings.TrimRight(strings.TrimSpace(state.Config.IDPBaseURL), "/")
	state.Config.RgrokName = strings.TrimSpace(state.Config.RgrokName)
	state.Config.RgrokToken = strings.TrimSpace(state.Config.RgrokToken)

	for i := range state.Users {
		if strings.TrimSpace(state.Users[i].Username) == "" {
			state.Users[i].Username = state.Users[i].Email
		}
	}
	for i := range state.Groups {
		state.Groups[i].MemberIDs = uniqueStrings(state.Groups[i].MemberIDs)
	}
	for i := range state.Apps {
		if state.Apps[i].Protocol == "" {
			state.Apps[i].Protocol = "oidc"
		}
		if state.Apps[i].Slug == "" {
			state.Apps[i].Slug = Slugify(state.Apps[i].Name)
		}
		if state.Apps[i].OIDCClientID == "" && SupportsOIDC(state.Apps[i]) {
			state.Apps[i].OIDCClientID = state.Apps[i].Slug
		}
		if SupportsSAML(state.Apps[i]) {
			state.Apps[i].SAMLNameIDField = NormalizeSAMLNameIDField(state.Apps[i].SAMLNameIDField)
			state.Apps[i].SAMLNameIDFormat = SAMLNameIDFormatForField(state.Apps[i].SAMLNameIDField)
		}
		if SupportsSAML(state.Apps[i]) && state.Apps[i].SAMLEmailAttributeName == "" {
			state.Apps[i].SAMLEmailAttributeName = DefaultSAMLEmailAttributeName
		}
		state.Apps[i].OIDCRedirectURIs = cleanLines(state.Apps[i].OIDCRedirectURIs)
	}
}

func AppendOperationLogs(state *AppState, traces []SyncTraceEntry) {
	if state.UserOperations == nil {
		state.UserOperations = make(map[string][]OperationLog)
	}
	if state.GroupOperations == nil {
		state.GroupOperations = make(map[string][]OperationLog)
	}

	for _, trace := range traces {
		entry := OperationLog{
			Kind:               "sync",
			Summary:            summarizeSyncTrace(trace),
			Operation:          trace.Operation,
			Method:             trace.Method,
			Path:               trace.Path,
			RequestBody:        trace.RequestBody,
			Status:             trace.Status,
			ResponseRetryAfter: trace.ResponseRetryAfter,
			ResponseBody:       trace.ResponseBody,
			Err:                trace.Err,
			CreatedAt:          trace.CreatedAt,
		}

		switch trace.ResourceType {
		case "user":
			state.UserOperations[trace.ResourceID] = append([]OperationLog{entry}, state.UserOperations[trace.ResourceID]...)
		case "group":
			state.GroupOperations[trace.ResourceID] = append([]OperationLog{entry}, state.GroupOperations[trace.ResourceID]...)
		}
	}
}

func AppendLocalOperationLog(state *AppState, resourceType string, resourceID string, summary string) {
	entry := OperationLog{
		Kind:      "local",
		Summary:   summary,
		CreatedAt: NowTimestamp(),
	}

	if state.UserOperations == nil {
		state.UserOperations = make(map[string][]OperationLog)
	}
	if state.GroupOperations == nil {
		state.GroupOperations = make(map[string][]OperationLog)
	}

	switch resourceType {
	case "user":
		state.UserOperations[resourceID] = append([]OperationLog{entry}, state.UserOperations[resourceID]...)
	case "group":
		state.GroupOperations[resourceID] = append([]OperationLog{entry}, state.GroupOperations[resourceID]...)
	}
}

func summarizeSyncTrace(trace SyncTraceEntry) string {
	if trace.Err != "" {
		operation := strings.TrimSpace(trace.Operation)
		if operation == "" {
			return "Failed"
		}
		return "Failed to " + operation
	}
	if trace.Operation == "create" {
		return "Created"
	}
	if trace.Operation == "delete" {
		return "Deleted"
	}

	return "Synced"
}

func NowTimestamp() string {
	return currentTime().UTC().Format(time.RFC3339)
}

func GroupByID(groups []Group, id string) (Group, bool) {
	for _, g := range groups {
		if g.ID == id {
			return g, true
		}
	}

	return Group{}, false
}

func UserByID(users []User, id string) (User, bool) {
	for _, u := range users {
		if u.ID == id {
			return u, true
		}
	}

	return User{}, false
}

func UserLabel(u User) string {
	if name := FullName(u); name != "" {
		return name
	}

	return u.Username
}

func ConfiguredBaseURL(baseURL string) string {
	baseURL = strings.TrimSpace(baseURL)
	if baseURL == "" {
		return "not configured"
	}

	return baseURL
}

func boolToInt(v bool) int {
	if v {
		return 1
	}

	return 0
}

func BoolString(v bool) string {
	if v {
		return "1"
	}

	return "0"
}

func newLocalID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate id: %w", err)
	}

	return hex.EncodeToString(buf), nil
}

func NewUserID() (string, error) {
	return newLocalID()
}

func NewGroupID() (string, error) {
	return newLocalID()
}

func NewID(prefix string) (string, error) {
	id, err := newLocalID()
	if err != nil {
		return "", err
	}
	return prefix + "_" + id[:16], nil
}

func NewAppID() (string, error) {
	return NewID("app")
}

func RandomSecret(byteCount int) (string, error) {
	b := make([]byte, byteCount)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate secret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func ValidateUser(givenName string, familyName string, email string, username string) error {
	givenName = strings.TrimSpace(givenName)
	familyName = strings.TrimSpace(familyName)
	email = strings.TrimSpace(email)

	switch {
	case givenName == "":
		return fmt.Errorf("given name is required")
	case familyName == "":
		return fmt.Errorf("family name is required")
	case email == "":
		return fmt.Errorf("email is required")
	case !strings.Contains(email, "@"):
		return fmt.Errorf("email must look like an email address")
	default:
		return nil
	}
}

func ValidateGroup(displayName string) error {
	if strings.TrimSpace(displayName) == "" {
		return fmt.Errorf("group name is required")
	}

	return nil
}

// ValidateHTTPBaseURL validates a service base URL without restricting its path.
func ValidateHTTPBaseURL(label string, rawURL string, required bool) error {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		if required {
			return fmt.Errorf("%s is required", label)
		}
		return nil
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("%s is invalid: %w", label, err)
	}
	switch {
	case parsed.Scheme == "":
		return fmt.Errorf("%s must be an absolute URL", label)
	case parsed.Scheme != "http" && parsed.Scheme != "https":
		return fmt.Errorf("%s must use HTTP or HTTPS", label)
	case !parsed.IsAbs() || parsed.Host == "":
		return fmt.Errorf("%s must be an absolute URL", label)
	case parsed.User != nil:
		return fmt.Errorf("%s must not contain credentials", label)
	case parsed.RawQuery != "":
		return fmt.Errorf("%s must not contain a query string", label)
	case parsed.Fragment != "":
		return fmt.Errorf("%s must not contain a fragment", label)
	default:
		return nil
	}
}

func ValidateApp(app App, apps []App) error {
	if strings.TrimSpace(app.Name) == "" {
		return fmt.Errorf("app name is required")
	}
	if strings.TrimSpace(app.Slug) == "" {
		return fmt.Errorf("app slug is required")
	}
	if app.Protocol != "oidc" && app.Protocol != "saml" && app.Protocol != "both" {
		return fmt.Errorf("protocol must be oidc, saml, or both")
	}
	for _, existing := range apps {
		if existing.ID != app.ID && strings.EqualFold(existing.Slug, app.Slug) {
			return fmt.Errorf("app slug %q is already in use", app.Slug)
		}
		if SupportsOIDC(app) && SupportsOIDC(existing) && existing.ID != app.ID && app.OIDCClientID != "" && app.OIDCClientID == existing.OIDCClientID {
			return fmt.Errorf("OIDC client ID %q is already in use", app.OIDCClientID)
		}
	}
	if SupportsOIDC(app) {
		if strings.TrimSpace(app.OIDCClientID) == "" {
			return fmt.Errorf("OIDC client ID is required")
		}
		if len(app.OIDCRedirectURIs) == 0 && !app.AllowAnyOIDCRedirect {
			return fmt.Errorf("at least one OIDC redirect URI is required unless arbitrary redirects are explicitly allowed")
		}
		for _, rawURI := range app.OIDCRedirectURIs {
			redirectURI, err := url.Parse(rawURI)
			if err != nil {
				return fmt.Errorf("OIDC redirect URI %q is invalid: %w", rawURI, err)
			}
			if !redirectURI.IsAbs() || redirectURI.Host == "" || (redirectURI.Scheme != "http" && redirectURI.Scheme != "https") || redirectURI.Fragment != "" {
				return fmt.Errorf("OIDC redirect URI %q must be an absolute HTTP(S) URL without a fragment", rawURI)
			}
		}
	}
	if SupportsSAML(app) {
		rawACSURL := strings.TrimSpace(app.SAMLACSURL)
		if rawACSURL == "" {
			return fmt.Errorf("SAML ACS URL is required")
		}
		acsURL, err := url.Parse(rawACSURL)
		if err != nil {
			return fmt.Errorf("SAML ACS URL %q is invalid: %w", app.SAMLACSURL, err)
		}
		if !acsURL.IsAbs() || acsURL.Host == "" || (acsURL.Scheme != "http" && acsURL.Scheme != "https") || acsURL.Fragment != "" {
			return fmt.Errorf("SAML ACS URL must be an absolute HTTP(S) URL without a fragment")
		}
	}
	if SupportsSAML(app) && strings.TrimSpace(app.SAMLNameIDField) != "" && NormalizeSAMLNameIDField(app.SAMLNameIDField) != app.SAMLNameIDField {
		return fmt.Errorf("SAML NameID field must be email, username, firstName, or lastName")
	}
	return nil
}

func NormalizeSAMLNameIDField(field string) string {
	switch strings.TrimSpace(field) {
	case "email":
		return "email"
	case "username":
		return "username"
	case "firstName":
		return "firstName"
	case "lastName":
		return "lastName"
	default:
		return DefaultSAMLNameIDField
	}
}

func SAMLNameIDFormatForField(field string) string {
	if NormalizeSAMLNameIDField(field) == "email" {
		return SAMLNameIDFormatEmail
	}
	return SAMLNameIDFormatUnspecified
}

func SAMLNameIDValue(app App, user User) string {
	switch NormalizeSAMLNameIDField(app.SAMLNameIDField) {
	case "username":
		return user.Username
	case "firstName":
		return user.GivenName
	case "lastName":
		return user.FamilyName
	default:
		return user.Email
	}
}

func SupportsOIDC(app App) bool {
	return app.Protocol == "oidc" || app.Protocol == "both"
}

func SupportsSAML(app App) bool {
	return app.Protocol == "saml" || app.Protocol == "both"
}

func AppBySlug(apps []App, slug string) (App, bool) {
	for _, app := range apps {
		if app.Slug == slug {
			return app, true
		}
	}
	return App{}, false
}

func UserGroups(state AppState, userID string) []string {
	var names []string
	for _, group := range state.Groups {
		if group.Deleted {
			continue
		}
		for _, memberID := range group.MemberIDs {
			if memberID == userID {
				names = append(names, group.DisplayName)
				break
			}
		}
	}
	sort.Strings(names)
	return names
}

func UserDisplayName(u User) string {
	return UserLabel(u)
}

func Slugify(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	lastDash := false
	for _, r := range s {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if ok {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash && b.Len() > 0 {
			b.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

func Lines(s string) []string {
	return cleanLines(strings.Split(s, "\n"))
}

func JoinLines(lines []string) string {
	return strings.Join(cleanLines(lines), "\n")
}

func migrateLegacyName(u *User) {
	if strings.TrimSpace(u.GivenName) != "" && strings.TrimSpace(u.FamilyName) != "" {
		return
	}

	legacyName := strings.TrimSpace(FullName(*u))
	if legacyName == "" {
		legacyName = strings.TrimSpace(u.Username)
	}

	givenName, familyName := SplitName(legacyName)
	if strings.TrimSpace(u.GivenName) == "" {
		u.GivenName = givenName
	}
	if strings.TrimSpace(u.FamilyName) == "" {
		u.FamilyName = familyName
	}
}

func SplitName(FullName string) (string, string) {
	parts := strings.Fields(strings.TrimSpace(FullName))
	switch len(parts) {
	case 0:
		return "", ""
	case 1:
		return parts[0], parts[0]
	default:
		return parts[0], strings.Join(parts[1:], " ")
	}
}

func FullName(u User) string {
	return strings.TrimSpace(strings.TrimSpace(u.GivenName) + " " + strings.TrimSpace(u.FamilyName))
}

func SyncStatus(u User) string {
	return ResourceSyncStatus(u.Deleted, u.Dirty, u.LastError, u.RemoteID)
}

func GroupSyncStatus(g Group) string {
	return ResourceSyncStatus(g.Deleted, g.Dirty, g.LastError, g.RemoteID)
}

func ResourceSyncStatus(deleted bool, dirty bool, lastError string, remoteID string) string {
	switch {
	case deleted && dirty:
		return "pending delete"
	case deleted:
		return "deleted"
	case lastError != "":
		return "sync error"
	case dirty && remoteID == "":
		return "pending create"
	case dirty:
		return "pending update"
	default:
		return "synced"
	}
}

func ActiveStatus(u User) string {
	if !u.Active {
		return "inactive"
	}

	return "active"
}

func uniqueStrings(in []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, value := range in {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func cleanLines(in []string) []string {
	var out []string
	for _, line := range in {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}
