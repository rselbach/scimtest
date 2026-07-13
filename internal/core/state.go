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
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

var currentTime = time.Now

const DefaultSAMLEmailAttributeName = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
const DefaultSAMLNameIDField = "email"
const SAMLNameIDFormatEmail = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
const SAMLNameIDFormatUnspecified = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
const DefaultEnvironmentID = "env_default"

type Environment struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Slug string `json:"slug"`
}

type Config struct {
	BaseURL               string `json:"base_url"`
	BearerToken           string `json:"bearer_token"`
	AutoOpenSyncTrace     bool   `json:"auto_open_sync_trace"`
	SCIMDisabled          bool   `json:"scim_disabled,omitempty"`
	IDPBaseURL            string `json:"idp_base_url,omitempty"`
	TrustForwardedHeaders bool   `json:"trust_forwarded_headers,omitempty"`
	RgrokInstanceID       string `json:"rgrok_instance_id,omitempty"`
	SigningPrivateKeyPEM  string `json:"signing_private_key_pem,omitempty"`
	SigningCertificatePEM string `json:"signing_certificate_pem,omitempty"`
}

// EnsureRgrokInstanceID returns the stable identity used for rgrok tunnel
// reservations, generating and persisting it when necessary.
func EnsureRgrokInstanceID() (string, error) {
	db, err := openStateDB()
	if err != nil {
		return "", err
	}
	instanceID, err := newUUID()
	if err != nil {
		return "", err
	}
	if _, err := db.Exec(`INSERT OR IGNORE INTO config(key, value) VALUES('rgrok_instance_id', ?)`, instanceID); err != nil {
		return "", fmt.Errorf("persist rgrok instance id: %w", err)
	}

	var saved string
	if err := db.QueryRow(`SELECT value FROM config WHERE key = 'rgrok_instance_id'`).Scan(&saved); err != nil {
		return "", fmt.Errorf("load rgrok instance id: %w", err)
	}
	if validUUID(saved) {
		return saved, nil
	}

	result, err := db.Exec(`UPDATE config SET value = ? WHERE key = 'rgrok_instance_id' AND value = ?`, instanceID, saved)
	if err != nil {
		return "", fmt.Errorf("repair rgrok instance id: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return "", fmt.Errorf("check repaired rgrok instance id: %w", err)
	}
	if changed == 0 {
		if err := db.QueryRow(`SELECT value FROM config WHERE key = 'rgrok_instance_id'`).Scan(&saved); err != nil {
			return "", fmt.Errorf("reload rgrok instance id: %w", err)
		}
		if !validUUID(saved) {
			return "", fmt.Errorf("reload rgrok instance id: invalid concurrent value %q", saved)
		}
		return saved, nil
	}
	return instanceID, nil
}

func newUUID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate rgrok instance id: %w", err)
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]), nil
}

func validUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	decoded, err := hex.DecodeString(strings.ReplaceAll(value, "-", ""))
	return err == nil && len(decoded) == 16
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
	Environment     Environment                             `json:"environment"`
	Environments    []Environment                           `json:"environments,omitempty"`
	Config          Config                                  `json:"config"`
	Users           []User                                  `json:"users"`
	Groups          []Group                                 `json:"groups"`
	Apps            []App                                   `json:"apps"`
	UserOperations  map[string][]OperationLog               `json:"-"`
	GroupOperations map[string][]OperationLog               `json:"-"`
	UserSync        map[string]map[string]ResourceSyncState `json:"-"`
	GroupSync       map[string]map[string]ResourceSyncState `json:"-"`
}

// ResourceSyncState is one app's remote state for a directory resource.
type ResourceSyncState struct {
	RemoteID  string
	Dirty     bool
	Deleted   bool
	LastError string
}

type OperationLog struct {
	AppID              string
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
	EnvironmentName        string   `json:"-"`
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
	SCIMEnabled            bool     `json:"scim_enabled,omitempty"`
	SCIMBaseURL            string   `json:"scim_base_url,omitempty"`
	SCIMBearerToken        string   `json:"scim_bearer_token,omitempty"`
	SCIMAutoOpenTrace      bool     `json:"scim_auto_open_trace,omitempty"`
}

func LoadState() (AppState, error) {
	db, err := openStateDB()
	if err != nil {
		return AppState{}, err
	}
	state, err := loadGlobalStateFromDB(db)
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
	if err := saveStateToDB(db, legacyState, true); err != nil {
		return AppState{}, err
	}
	return loadGlobalStateFromDB(db)
}

func LoadStateForAppSlug(slug string) (AppState, error) {
	state, err := LoadState()
	if err != nil {
		return AppState{}, err
	}
	for _, app := range state.Apps {
		if app.Slug == slug {
			return state, nil
		}
	}
	return AppState{}, fmt.Errorf("app slug %q not found", slug)
}

func LoadAllApps() ([]App, error) {
	state, err := LoadState()
	if err != nil {
		return nil, err
	}
	return state.Apps, nil
}

func SaveState(state AppState) error {
	NormalizeState(&state)

	db, err := openStateDB()
	if err != nil {
		return err
	}
	return saveStateToDB(db, state, true)
}

var stateDBMu sync.Mutex
var cachedStateDB *sql.DB
var cachedStateDBPath string

// openStateDB returns a process-wide cached handle so the schema setup runs
// once per state file instead of on every request. The cache is keyed by the
// resolved path because tests point SCIMTEST_STATE_FILE at fresh files.
func openStateDB() (*sql.DB, error) {
	path, err := stateFilePath()
	if err != nil {
		return nil, err
	}

	stateDBMu.Lock()
	defer stateDBMu.Unlock()
	if cachedStateDB != nil && cachedStateDBPath == path {
		return cachedStateDB, nil
	}
	if cachedStateDB != nil {
		previous := cachedStateDB
		cachedStateDB = nil
		cachedStateDBPath = ""
		if err := previous.Close(); err != nil {
			return nil, fmt.Errorf("close previous sqlite state db: %w", err)
		}
	}

	db, err := openStateDBAt(path)
	if err != nil {
		return nil, err
	}
	cachedStateDB = db
	cachedStateDBPath = path
	return db, nil
}

// resetStateDBCache closes and forgets the cached handle so the next open
// re-runs the schema setup. Used by tests that mutate the database file
// behind the cache.
func resetStateDBCache() error {
	stateDBMu.Lock()
	defer stateDBMu.Unlock()
	if cachedStateDB == nil {
		return nil
	}
	db := cachedStateDB
	cachedStateDB = nil
	cachedStateDBPath = ""
	return db.Close()
}

func openStateDBAt(path string) (*sql.DB, error) {
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
		`CREATE TABLE IF NOT EXISTS environments (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			slug TEXT NOT NULL UNIQUE
		)`,
		`CREATE TABLE IF NOT EXISTS environment_config (
			environment_id TEXT NOT NULL,
			key TEXT NOT NULL,
			value TEXT NOT NULL,
			PRIMARY KEY (environment_id, key)
		)`,
		`CREATE TABLE IF NOT EXISTS config (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			environment_id TEXT NOT NULL DEFAULT 'env_default',
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
			environment_id TEXT NOT NULL DEFAULT 'env_default',
			display_name TEXT NOT NULL,
			remote_id TEXT NOT NULL DEFAULT '',
			dirty INTEGER NOT NULL,
			deleted INTEGER NOT NULL,
			last_error TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS apps (
			id TEXT PRIMARY KEY,
			environment_id TEXT NOT NULL DEFAULT 'env_default',
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
			allow_any_oidc_redirect INTEGER NOT NULL DEFAULT 1,
			scim_enabled INTEGER NOT NULL DEFAULT 0,
			scim_base_url TEXT NOT NULL DEFAULT '',
			scim_bearer_token TEXT NOT NULL DEFAULT '',
			scim_auto_open_trace INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS app_user_sync (
			app_id TEXT NOT NULL,
			user_id TEXT NOT NULL,
			remote_id TEXT NOT NULL DEFAULT '',
			dirty INTEGER NOT NULL DEFAULT 1,
			deleted INTEGER NOT NULL DEFAULT 0,
			last_error TEXT NOT NULL DEFAULT '',
			PRIMARY KEY (app_id, user_id)
		)`,
		`CREATE TABLE IF NOT EXISTS app_group_sync (
			app_id TEXT NOT NULL,
			group_id TEXT NOT NULL,
			remote_id TEXT NOT NULL DEFAULT '',
			dirty INTEGER NOT NULL DEFAULT 1,
			deleted INTEGER NOT NULL DEFAULT 0,
			last_error TEXT NOT NULL DEFAULT '',
			PRIMARY KEY (app_id, group_id)
		)`,
		`CREATE TABLE IF NOT EXISTS group_members (
			group_id TEXT NOT NULL,
			environment_id TEXT NOT NULL DEFAULT 'env_default',
			user_id TEXT NOT NULL,
			position INTEGER NOT NULL,
			PRIMARY KEY (group_id, user_id)
		)`,
		`CREATE TABLE IF NOT EXISTS operation_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			environment_id TEXT NOT NULL DEFAULT 'env_default',
			app_id TEXT NOT NULL DEFAULT '',
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
		`ALTER TABLE operation_logs ADD COLUMN app_id TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE apps ADD COLUMN saml_name_id_field TEXT NOT NULL DEFAULT 'email'`,
		`ALTER TABLE apps ADD COLUMN allow_any_oidc_redirect INTEGER NOT NULL DEFAULT 1`,
		`ALTER TABLE apps ADD COLUMN oidc_public_client INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE users ADD COLUMN environment_id TEXT NOT NULL DEFAULT 'env_default'`,
		`ALTER TABLE groups ADD COLUMN environment_id TEXT NOT NULL DEFAULT 'env_default'`,
		`ALTER TABLE apps ADD COLUMN environment_id TEXT NOT NULL DEFAULT 'env_default'`,
		`ALTER TABLE operation_logs ADD COLUMN environment_id TEXT NOT NULL DEFAULT 'env_default'`,
		`ALTER TABLE group_members ADD COLUMN environment_id TEXT NOT NULL DEFAULT 'env_default'`,
		`ALTER TABLE apps ADD COLUMN scim_enabled INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE apps ADD COLUMN scim_base_url TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE apps ADD COLUMN scim_bearer_token TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE apps ADD COLUMN scim_auto_open_trace INTEGER NOT NULL DEFAULT 0`,
	}
	for _, migration := range migrations {
		if _, err := db.Exec(migration); err != nil && !strings.Contains(err.Error(), "duplicate column name") {
			return fmt.Errorf("migrate sqlite schema: %w", err)
		}
	}
	indexes := []string{
		`CREATE INDEX IF NOT EXISTS users_environment_id ON users(environment_id)`,
		`CREATE INDEX IF NOT EXISTS groups_environment_id ON groups(environment_id)`,
		`CREATE INDEX IF NOT EXISTS apps_environment_id ON apps(environment_id)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS apps_slug ON apps(slug)`,
		`CREATE INDEX IF NOT EXISTS operation_logs_environment_id ON operation_logs(environment_id)`,
	}
	for _, statement := range indexes {
		if _, err := db.Exec(statement); err != nil {
			return fmt.Errorf("initialize environment index: %w", err)
		}
	}

	if err := migrateDefaultEnvironment(db); err != nil {
		return err
	}
	if err := migrateEnvironmentSCIMToApps(db); err != nil {
		return err
	}

	return nil
}

func migrateDefaultEnvironment(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin default environment migration: %w", err)
	}
	committed := false
	defer rollbackTx(tx, &committed)

	if _, err := tx.Exec(`INSERT OR IGNORE INTO environments(id, name, slug) VALUES(?, 'Default', 'default')`, DefaultEnvironmentID); err != nil {
		return fmt.Errorf("create default environment: %w", err)
	}
	keys := []string{"base_url", "bearer_token", "auto_open_sync_trace", "scim_disabled"}
	for _, key := range keys {
		if _, err := tx.Exec(`INSERT OR IGNORE INTO environment_config(environment_id, key, value) SELECT ?, key, value FROM config WHERE key = ?`, DefaultEnvironmentID, key); err != nil {
			return fmt.Errorf("migrate default environment config %s: %w", key, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit default environment migration: %w", err)
	}
	committed = true
	return nil
}

func migrateEnvironmentSCIMToApps(db *sql.DB) error {
	var migrated string
	err := db.QueryRow(`SELECT value FROM config WHERE key = 'app_scim_migrated'`).Scan(&migrated)
	if err == nil && migrated == "1" {
		return nil
	}
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("check app SCIM migration: %w", err)
	}

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin app SCIM migration: %w", err)
	}
	committed := false
	defer rollbackTx(tx, &committed)

	_, err = tx.Exec(`INSERT OR IGNORE INTO apps(id, environment_id, name, slug, protocol, scim_enabled, scim_base_url, scim_bearer_token, scim_auto_open_trace)
		SELECT 'migrated_scim_' || environments.id,
			environments.id,
			environments.name || ' SCIM',
			environments.slug || '-scim-' || substr(environments.id, -6),
			'scim', 1,
			base.value,
			COALESCE(token.value, ''),
			COALESCE(trace.value = '1', 0)
		FROM environments
		JOIN environment_config base ON base.environment_id = environments.id AND base.key = 'base_url' AND base.value != ''
		LEFT JOIN environment_config token ON token.environment_id = environments.id AND token.key = 'bearer_token'
		LEFT JOIN environment_config trace ON trace.environment_id = environments.id AND trace.key = 'auto_open_sync_trace'
		LEFT JOIN environment_config disabled ON disabled.environment_id = environments.id AND disabled.key = 'scim_disabled'
		WHERE COALESCE(disabled.value, '0') != '1'
		AND NOT EXISTS (SELECT 1 FROM apps WHERE apps.environment_id = environments.id)`)
	if err != nil {
		return fmt.Errorf("create apps for orphaned environment SCIM config: %w", err)
	}

	_, err = tx.Exec(`UPDATE apps SET
		scim_base_url = COALESCE((SELECT value FROM environment_config WHERE environment_id = apps.environment_id AND key = 'base_url'), ''),
		scim_bearer_token = COALESCE((SELECT value FROM environment_config WHERE environment_id = apps.environment_id AND key = 'bearer_token'), ''),
		scim_auto_open_trace = COALESCE((SELECT value = '1' FROM environment_config WHERE environment_id = apps.environment_id AND key = 'auto_open_sync_trace'), 0),
		scim_enabled = CASE
			WHEN COALESCE((SELECT value FROM environment_config WHERE environment_id = apps.environment_id AND key = 'base_url'), '') != ''
			 AND COALESCE((SELECT value FROM environment_config WHERE environment_id = apps.environment_id AND key = 'scim_disabled'), '0') != '1'
			THEN 1 ELSE 0 END`)
	if err != nil {
		return fmt.Errorf("move environment SCIM config to apps: %w", err)
	}

	_, err = tx.Exec(`INSERT OR IGNORE INTO app_user_sync(app_id, user_id, remote_id, dirty, deleted, last_error)
		SELECT apps.id, users.id,
			CASE WHEN apps.environment_id = users.environment_id THEN users.remote_id ELSE '' END,
			CASE WHEN apps.environment_id = users.environment_id THEN users.dirty ELSE 1 END,
			users.deleted,
			CASE WHEN apps.environment_id = users.environment_id THEN users.last_error ELSE '' END
		FROM apps CROSS JOIN users WHERE apps.scim_enabled = 1`)
	if err != nil {
		return fmt.Errorf("migrate app user sync state: %w", err)
	}
	_, err = tx.Exec(`INSERT OR IGNORE INTO app_group_sync(app_id, group_id, remote_id, dirty, deleted, last_error)
		SELECT apps.id, groups.id,
			CASE WHEN apps.environment_id = groups.environment_id THEN groups.remote_id ELSE '' END,
			CASE WHEN apps.environment_id = groups.environment_id THEN groups.dirty ELSE 1 END,
			groups.deleted,
			CASE WHEN apps.environment_id = groups.environment_id THEN groups.last_error ELSE '' END
		FROM apps CROSS JOIN groups WHERE apps.scim_enabled = 1`)
	if err != nil {
		return fmt.Errorf("migrate app group sync state: %w", err)
	}
	if _, err := tx.Exec(`INSERT OR REPLACE INTO config(key, value) VALUES('app_scim_migrated', '1')`); err != nil {
		return fmt.Errorf("mark app SCIM migration complete: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit app SCIM migration: %w", err)
	}
	committed = true
	return nil
}

func loadStateFromDB(db *sql.DB, environmentID string) (AppState, error) {
	state := AppState{}
	state.UserOperations = make(map[string][]OperationLog)
	state.GroupOperations = make(map[string][]OperationLog)
	var err error
	state.Environments, err = loadEnvironmentsFromDB(db)
	if err != nil {
		return AppState{}, err
	}
	for _, environment := range state.Environments {
		if environment.ID == environmentID {
			state.Environment = environment
			break
		}
	}
	if state.Environment.ID == "" {
		return AppState{}, fmt.Errorf("environment %q not found", environmentID)
	}

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
		case "rgrok_instance_id":
			state.Config.RgrokInstanceID = value
		case "signing_private_key_pem":
			state.Config.SigningPrivateKeyPEM = value
		case "signing_certificate_pem":
			state.Config.SigningCertificatePEM = value
		}
	}
	if err := configRows.Err(); err != nil {
		return AppState{}, fmt.Errorf("iterate sqlite config rows: %w", err)
	}
	environmentConfigRows, err := db.Query(`SELECT key, value FROM environment_config WHERE environment_id = ?`, environmentID)
	if err != nil {
		return AppState{}, fmt.Errorf("load environment config from sqlite: %w", err)
	}
	defer closeRows(environmentConfigRows)
	for environmentConfigRows.Next() {
		var key string
		var value string
		if err := environmentConfigRows.Scan(&key, &value); err != nil {
			return AppState{}, fmt.Errorf("scan environment config row: %w", err)
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
		}
	}
	if err := environmentConfigRows.Err(); err != nil {
		return AppState{}, fmt.Errorf("iterate environment config rows: %w", err)
	}

	userRows, err := db.Query(`SELECT id, given_name, family_name, email, username, active, remote_id, dirty, deleted, last_error FROM users WHERE environment_id = ? ORDER BY rowid`, environmentID)
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

	groupRows, err := db.Query(`SELECT id, display_name, remote_id, dirty, deleted, last_error FROM groups WHERE environment_id = ? ORDER BY rowid`, environmentID)
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

	memberRows, err := db.Query(`SELECT group_id, user_id FROM group_members WHERE environment_id = ? ORDER BY group_id, position`, environmentID)
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

	appRows, err := db.Query(`SELECT id, name, slug, protocol, oidc_client_id, oidc_client_secret, oidc_public_client, oidc_redirect_uris, saml_entity_id, saml_acs_url, saml_audience, saml_name_id_field, saml_name_id_format, saml_email_attribute_name, include_groups_claim, allow_any_oidc_redirect, scim_enabled, scim_base_url, scim_bearer_token, scim_auto_open_trace FROM apps WHERE environment_id = ? ORDER BY rowid`, environmentID)
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
		var scimEnabled int
		var scimAutoOpenTrace int
		if err := appRows.Scan(&app.ID, &app.Name, &app.Slug, &app.Protocol, &app.OIDCClientID, &app.OIDCClientSecret, &publicClient, &redirectURIs, &app.SAMLEntityID, &app.SAMLACSURL, &app.SAMLAudience, &app.SAMLNameIDField, &app.SAMLNameIDFormat, &app.SAMLEmailAttributeName, &includeGroups, &allowAnyRedirect, &scimEnabled, &app.SCIMBaseURL, &app.SCIMBearerToken, &scimAutoOpenTrace); err != nil {
			return AppState{}, fmt.Errorf("scan sqlite app row: %w", err)
		}
		app.OIDCRedirectURIs = Lines(redirectURIs)
		app.IncludeGroupsClaim = includeGroups != 0
		app.AllowAnyOIDCRedirect = allowAnyRedirect != 0
		app.OIDCPublicClient = publicClient != 0
		app.SCIMEnabled = scimEnabled != 0
		app.SCIMAutoOpenTrace = scimAutoOpenTrace != 0
		state.Apps = append(state.Apps, app)
	}
	if err := appRows.Err(); err != nil {
		return AppState{}, fmt.Errorf("iterate sqlite app rows: %w", err)
	}
	userSyncRows, err := db.Query(`SELECT sync.app_id, sync.user_id, sync.remote_id, sync.dirty, sync.deleted, sync.last_error FROM app_user_sync sync JOIN apps ON apps.id = sync.app_id WHERE apps.environment_id = ?`, environmentID)
	if err != nil {
		return AppState{}, fmt.Errorf("load app user sync state: %w", err)
	}
	defer closeRows(userSyncRows)
	for userSyncRows.Next() {
		var appID string
		var userID string
		var syncState ResourceSyncState
		var dirty int
		var deleted int
		if err := userSyncRows.Scan(&appID, &userID, &syncState.RemoteID, &dirty, &deleted, &syncState.LastError); err != nil {
			return AppState{}, fmt.Errorf("scan app user sync state: %w", err)
		}
		syncState.Dirty = dirty != 0
		syncState.Deleted = deleted != 0
		if state.UserSync == nil {
			state.UserSync = make(map[string]map[string]ResourceSyncState)
		}
		if state.UserSync[appID] == nil {
			state.UserSync[appID] = make(map[string]ResourceSyncState)
		}
		state.UserSync[appID][userID] = syncState
	}
	if err := userSyncRows.Err(); err != nil {
		return AppState{}, fmt.Errorf("iterate app user sync state: %w", err)
	}
	groupSyncRows, err := db.Query(`SELECT sync.app_id, sync.group_id, sync.remote_id, sync.dirty, sync.deleted, sync.last_error FROM app_group_sync sync JOIN apps ON apps.id = sync.app_id WHERE apps.environment_id = ?`, environmentID)
	if err != nil {
		return AppState{}, fmt.Errorf("load app group sync state: %w", err)
	}
	defer closeRows(groupSyncRows)
	for groupSyncRows.Next() {
		var appID string
		var groupID string
		var syncState ResourceSyncState
		var dirty int
		var deleted int
		if err := groupSyncRows.Scan(&appID, &groupID, &syncState.RemoteID, &dirty, &deleted, &syncState.LastError); err != nil {
			return AppState{}, fmt.Errorf("scan app group sync state: %w", err)
		}
		syncState.Dirty = dirty != 0
		syncState.Deleted = deleted != 0
		if state.GroupSync == nil {
			state.GroupSync = make(map[string]map[string]ResourceSyncState)
		}
		if state.GroupSync[appID] == nil {
			state.GroupSync[appID] = make(map[string]ResourceSyncState)
		}
		state.GroupSync[appID][groupID] = syncState
	}
	if err := groupSyncRows.Err(); err != nil {
		return AppState{}, fmt.Errorf("iterate app group sync state: %w", err)
	}

	logRows, err := db.Query(`SELECT resource_type, resource_id, app_id, kind, summary, operation, method, path, request_body, status, response_retry_after, response_body, error_text, created_at FROM operation_logs WHERE environment_id = ? ORDER BY resource_type, resource_id, created_at DESC, id ASC`, environmentID)
	if err != nil {
		return AppState{}, fmt.Errorf("load operation logs from sqlite: %w", err)
	}
	defer closeRows(logRows)

	for logRows.Next() {
		var resourceType string
		var resourceID string
		var entry OperationLog
		if err := logRows.Scan(&resourceType, &resourceID, &entry.AppID, &entry.Kind, &entry.Summary, &entry.Operation, &entry.Method, &entry.Path, &entry.RequestBody, &entry.Status, &entry.ResponseRetryAfter, &entry.ResponseBody, &entry.Err, &entry.CreatedAt); err != nil {
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

func loadEnvironmentsFromDB(db *sql.DB) ([]Environment, error) {
	rows, err := db.Query(`SELECT id, name, slug FROM environments ORDER BY rowid`)
	if err != nil {
		return nil, fmt.Errorf("load environments from sqlite: %w", err)
	}
	defer closeRows(rows)
	var environments []Environment
	for rows.Next() {
		var environment Environment
		if err := rows.Scan(&environment.ID, &environment.Name, &environment.Slug); err != nil {
			return nil, fmt.Errorf("scan environment row: %w", err)
		}
		environments = append(environments, environment)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate environment rows: %w", err)
	}
	return environments, nil
}

func loadGlobalStateFromDB(db *sql.DB) (AppState, error) {
	environments, err := loadEnvironmentsFromDB(db)
	if err != nil {
		return AppState{}, err
	}
	state := AppState{
		Environment:     Environment{ID: DefaultEnvironmentID, Name: "Directory", Slug: "directory"},
		UserOperations:  make(map[string][]OperationLog),
		GroupOperations: make(map[string][]OperationLog),
		UserSync:        make(map[string]map[string]ResourceSyncState),
		GroupSync:       make(map[string]map[string]ResourceSyncState),
	}
	for _, environment := range environments {
		environmentState, err := loadStateFromDB(db, environment.ID)
		if err != nil {
			return AppState{}, err
		}
		state.Config = environmentState.Config
		state.Users = append(state.Users, environmentState.Users...)
		state.Groups = append(state.Groups, environmentState.Groups...)
		state.Apps = append(state.Apps, environmentState.Apps...)
		for resourceID, entries := range environmentState.UserOperations {
			state.UserOperations[resourceID] = append(state.UserOperations[resourceID], entries...)
		}
		for resourceID, entries := range environmentState.GroupOperations {
			state.GroupOperations[resourceID] = append(state.GroupOperations[resourceID], entries...)
		}
		for appID, syncStates := range environmentState.UserSync {
			state.UserSync[appID] = syncStates
		}
		for appID, syncStates := range environmentState.GroupSync {
			state.GroupSync[appID] = syncStates
		}
	}
	state.Config.BaseURL = ""
	state.Config.BearerToken = ""
	state.Config.AutoOpenSyncTrace = false
	state.Config.SCIMDisabled = false
	for i := range state.Users {
		state.Users[i].RemoteID = ""
		state.Users[i].Dirty = false
		state.Users[i].LastError = ""
	}
	for i := range state.Groups {
		state.Groups[i].RemoteID = ""
		state.Groups[i].Dirty = false
		state.Groups[i].LastError = ""
	}
	if len(state.UserSync) == 0 {
		state.UserSync = nil
	}
	if len(state.GroupSync) == 0 {
		state.GroupSync = nil
	}
	return state, nil
}

func saveStateToDB(db *sql.DB, state AppState, global bool) error {
	environmentID := state.Environment.ID
	if environmentID == "" || global {
		environmentID = DefaultEnvironmentID
	}
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin sqlite state transaction: %w", err)
	}
	committed := false
	defer rollbackTx(tx, &committed)

	if _, err := tx.Exec(`DELETE FROM config`); err != nil {
		return fmt.Errorf("clear sqlite config: %w", err)
	}
	if global {
		for _, table := range []string{"environment_config", "app_user_sync", "app_group_sync", "group_members", "operation_logs", "apps", "groups", "users"} {
			if _, err := tx.Exec(`DELETE FROM ` + table); err != nil {
				return fmt.Errorf("clear sqlite %s: %w", table, err)
			}
		}
		if _, err := tx.Exec(`DELETE FROM environments WHERE id != ?`, DefaultEnvironmentID); err != nil {
			return fmt.Errorf("remove migrated environments: %w", err)
		}
	} else {
		if _, err := tx.Exec(`DELETE FROM environment_config WHERE environment_id = ?`, environmentID); err != nil {
			return fmt.Errorf("clear sqlite environment config: %w", err)
		}
		if _, err := tx.Exec(`DELETE FROM users WHERE environment_id = ?`, environmentID); err != nil {
			return fmt.Errorf("clear sqlite users: %w", err)
		}
		if _, err := tx.Exec(`DELETE FROM groups WHERE environment_id = ?`, environmentID); err != nil {
			return fmt.Errorf("clear sqlite groups: %w", err)
		}
		if _, err := tx.Exec(`DELETE FROM app_user_sync WHERE app_id IN (SELECT id FROM apps WHERE environment_id = ?)`, environmentID); err != nil {
			return fmt.Errorf("clear sqlite app user sync: %w", err)
		}
		if _, err := tx.Exec(`DELETE FROM app_group_sync WHERE app_id IN (SELECT id FROM apps WHERE environment_id = ?)`, environmentID); err != nil {
			return fmt.Errorf("clear sqlite app group sync: %w", err)
		}
		if _, err := tx.Exec(`DELETE FROM apps WHERE environment_id = ?`, environmentID); err != nil {
			return fmt.Errorf("clear sqlite apps: %w", err)
		}
		if _, err := tx.Exec(`DELETE FROM group_members WHERE environment_id = ?`, environmentID); err != nil {
			return fmt.Errorf("clear sqlite group members: %w", err)
		}
		if _, err := tx.Exec(`DELETE FROM operation_logs WHERE environment_id = ?`, environmentID); err != nil {
			return fmt.Errorf("clear sqlite operation logs: %w", err)
		}
	}

	configStmt, err := tx.Prepare(`INSERT INTO config(key, value) VALUES(?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare sqlite config insert: %w", err)
	}
	defer closeStmt(configStmt)

	configEntries := map[string]string{
		"app_scim_migrated":       "1",
		"idp_base_url":            state.Config.IDPBaseURL,
		"trust_forwarded_headers": BoolString(state.Config.TrustForwardedHeaders),
		"rgrok_instance_id":       state.Config.RgrokInstanceID,
		"signing_private_key_pem": state.Config.SigningPrivateKeyPEM,
		"signing_certificate_pem": state.Config.SigningCertificatePEM,
	}
	for key, value := range configEntries {
		if _, err := configStmt.Exec(key, value); err != nil {
			return fmt.Errorf("insert sqlite config %s: %w", key, err)
		}
	}
	if !global {
		environmentConfigEntries := map[string]string{
			"base_url":             state.Config.BaseURL,
			"bearer_token":         state.Config.BearerToken,
			"auto_open_sync_trace": BoolString(state.Config.AutoOpenSyncTrace),
			"scim_disabled":        BoolString(state.Config.SCIMDisabled),
		}
		for key, value := range environmentConfigEntries {
			if _, err := tx.Exec(`INSERT INTO environment_config(environment_id, key, value) VALUES(?, ?, ?)`, environmentID, key, value); err != nil {
				return fmt.Errorf("insert environment config %s: %w", key, err)
			}
		}
	}

	userStmt, err := tx.Prepare(`INSERT INTO users(id, environment_id, given_name, family_name, email, username, active, remote_id, dirty, deleted, last_error) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare sqlite user insert: %w", err)
	}
	defer closeStmt(userStmt)

	for _, u := range state.Users {
		if global {
			u.RemoteID = ""
			u.Dirty = false
			u.LastError = ""
		}
		if _, err := userStmt.Exec(u.ID, environmentID, u.GivenName, u.FamilyName, u.Email, u.Username, boolToInt(u.Active), u.RemoteID, boolToInt(u.Dirty), boolToInt(u.Deleted), u.LastError); err != nil {
			return fmt.Errorf("insert sqlite user %s: %w", u.ID, err)
		}
	}

	groupStmt, err := tx.Prepare(`INSERT INTO groups(id, environment_id, display_name, remote_id, dirty, deleted, last_error) VALUES(?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare sqlite group insert: %w", err)
	}
	defer closeStmt(groupStmt)

	memberStmt, err := tx.Prepare(`INSERT INTO group_members(group_id, environment_id, user_id, position) VALUES(?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare sqlite group member insert: %w", err)
	}
	defer closeStmt(memberStmt)

	logStmt, err := tx.Prepare(`INSERT INTO operation_logs(environment_id, resource_type, resource_id, label, app_id, kind, summary, operation, method, path, request_body, status, response_retry_after, response_body, error_text, created_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare sqlite operation log insert: %w", err)
	}
	defer closeStmt(logStmt)

	for _, g := range state.Groups {
		if global {
			g.RemoteID = ""
			g.Dirty = false
			g.LastError = ""
		}
		if _, err := groupStmt.Exec(g.ID, environmentID, g.DisplayName, g.RemoteID, boolToInt(g.Dirty), boolToInt(g.Deleted), g.LastError); err != nil {
			return fmt.Errorf("insert sqlite group %s: %w", g.ID, err)
		}

		for position, userID := range g.MemberIDs {
			if _, err := memberStmt.Exec(g.ID, environmentID, userID, position); err != nil {
				return fmt.Errorf("insert sqlite group member %s/%s: %w", g.ID, userID, err)
			}
		}
	}

	appStmt, err := tx.Prepare(`INSERT INTO apps(id, environment_id, name, slug, protocol, oidc_client_id, oidc_client_secret, oidc_public_client, oidc_redirect_uris, saml_entity_id, saml_acs_url, saml_audience, saml_name_id_field, saml_name_id_format, saml_email_attribute_name, include_groups_claim, allow_any_oidc_redirect, scim_enabled, scim_base_url, scim_bearer_token, scim_auto_open_trace) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare sqlite app insert: %w", err)
	}
	defer closeStmt(appStmt)

	for _, app := range state.Apps {
		if _, err := appStmt.Exec(app.ID, environmentID, app.Name, app.Slug, app.Protocol, app.OIDCClientID, app.OIDCClientSecret, boolToInt(app.OIDCPublicClient), JoinLines(app.OIDCRedirectURIs), app.SAMLEntityID, app.SAMLACSURL, app.SAMLAudience, app.SAMLNameIDField, app.SAMLNameIDFormat, app.SAMLEmailAttributeName, boolToInt(app.IncludeGroupsClaim), boolToInt(app.AllowAnyOIDCRedirect), boolToInt(app.SCIMEnabled), app.SCIMBaseURL, app.SCIMBearerToken, boolToInt(app.SCIMAutoOpenTrace)); err != nil {
			return fmt.Errorf("insert sqlite app %s: %w", app.ID, err)
		}
	}
	userSyncStmt, err := tx.Prepare(`INSERT INTO app_user_sync(app_id, user_id, remote_id, dirty, deleted, last_error) VALUES(?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare app user sync insert: %w", err)
	}
	defer closeStmt(userSyncStmt)
	for appID, syncStates := range state.UserSync {
		for userID, syncState := range syncStates {
			if _, err := userSyncStmt.Exec(appID, userID, syncState.RemoteID, boolToInt(syncState.Dirty), boolToInt(syncState.Deleted), syncState.LastError); err != nil {
				return fmt.Errorf("insert app user sync %s/%s: %w", appID, userID, err)
			}
		}
	}
	groupSyncStmt, err := tx.Prepare(`INSERT INTO app_group_sync(app_id, group_id, remote_id, dirty, deleted, last_error) VALUES(?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare app group sync insert: %w", err)
	}
	defer closeStmt(groupSyncStmt)
	for appID, syncStates := range state.GroupSync {
		for groupID, syncState := range syncStates {
			if _, err := groupSyncStmt.Exec(appID, groupID, syncState.RemoteID, boolToInt(syncState.Dirty), boolToInt(syncState.Deleted), syncState.LastError); err != nil {
				return fmt.Errorf("insert app group sync %s/%s: %w", appID, groupID, err)
			}
		}
	}

	for resourceID, entries := range state.UserOperations {
		label := resourceID
		if User, ok := UserByID(state.Users, resourceID); ok {
			label = UserLabel(User)
		}
		for _, entry := range entries {
			if _, err := logStmt.Exec(environmentID, "user", resourceID, label, entry.AppID, entry.Kind, entry.Summary, entry.Operation, entry.Method, entry.Path, entry.RequestBody, entry.Status, entry.ResponseRetryAfter, entry.ResponseBody, entry.Err, entry.CreatedAt); err != nil {
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
			if _, err := logStmt.Exec(environmentID, "group", resourceID, label, entry.AppID, entry.Kind, entry.Summary, entry.Operation, entry.Method, entry.Path, entry.RequestBody, entry.Status, entry.ResponseRetryAfter, entry.ResponseBody, entry.Err, entry.CreatedAt); err != nil {
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

// maxOperationLogsPerResource bounds per-resource history; logs are ordered
// newest first and rewritten on every save, so unbounded growth slows every
// state write.
const maxOperationLogsPerResource = 100

func NormalizeState(state *AppState) {
	migrateLegacySCIMConfig(state)
	capOperationLogs(state.UserOperations)
	capOperationLogs(state.GroupOperations)
	state.Config.BaseURL = strings.TrimRight(strings.TrimSpace(state.Config.BaseURL), "/")
	state.Config.IDPBaseURL = strings.TrimRight(strings.TrimSpace(state.Config.IDPBaseURL), "/")
	state.Config.RgrokInstanceID = strings.TrimSpace(state.Config.RgrokInstanceID)

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
		state.Apps[i].SCIMBaseURL = strings.TrimRight(strings.TrimSpace(state.Apps[i].SCIMBaseURL), "/")
	}
}

func capOperationLogs(logs map[string][]OperationLog) {
	for resourceID, entries := range logs {
		if len(entries) > maxOperationLogsPerResource {
			logs[resourceID] = entries[:maxOperationLogsPerResource]
		}
	}
}

func migrateLegacySCIMConfig(state *AppState) {
	baseURL := strings.TrimRight(strings.TrimSpace(state.Config.BaseURL), "/")
	token := strings.TrimSpace(state.Config.BearerToken)
	if baseURL != "" && !state.Config.SCIMDisabled {
		if len(state.Apps) == 0 {
			state.Apps = append(state.Apps, App{ID: "app_legacy_scim", Name: "SCIM", Slug: "scim", Protocol: "scim"})
		}
		for i := range state.Apps {
			if state.Apps[i].SCIMEnabled {
				continue
			}
			state.Apps[i].SCIMEnabled = true
			state.Apps[i].SCIMBaseURL = baseURL
			state.Apps[i].SCIMBearerToken = token
			state.Apps[i].SCIMAutoOpenTrace = state.Config.AutoOpenSyncTrace
			if state.UserSync == nil {
				state.UserSync = make(map[string]map[string]ResourceSyncState)
			}
			state.UserSync[state.Apps[i].ID] = make(map[string]ResourceSyncState, len(state.Users))
			for _, user := range state.Users {
				state.UserSync[state.Apps[i].ID][user.ID] = ResourceSyncState{RemoteID: user.RemoteID, Dirty: user.Dirty, Deleted: user.Deleted, LastError: user.LastError}
			}
			if state.GroupSync == nil {
				state.GroupSync = make(map[string]map[string]ResourceSyncState)
			}
			state.GroupSync[state.Apps[i].ID] = make(map[string]ResourceSyncState, len(state.Groups))
			for _, group := range state.Groups {
				state.GroupSync[state.Apps[i].ID][group.ID] = ResourceSyncState{RemoteID: group.RemoteID, Dirty: group.Dirty, Deleted: group.Deleted, LastError: group.LastError}
			}
		}
	}
	state.Config.BaseURL = ""
	state.Config.BearerToken = ""
	state.Config.AutoOpenSyncTrace = false
	state.Config.SCIMDisabled = false
}

// AppByID finds an app by its stable local ID.
func AppByID(apps []App, id string) (App, bool) {
	for _, app := range apps {
		if app.ID == id {
			return app, true
		}
	}
	return App{}, false
}

// StateForApp projects the global directory into the legacy shape consumed by
// the SCIM engine. Remote IDs and sync status belong to the selected app.
func StateForApp(state AppState, appID string) (AppState, error) {
	app, ok := AppByID(state.Apps, appID)
	if !ok {
		return AppState{}, fmt.Errorf("app %q not found", appID)
	}
	projected := state
	projected.Users = append([]User(nil), state.Users...)
	projected.Groups = append([]Group(nil), state.Groups...)
	for i := range projected.Groups {
		projected.Groups[i].MemberIDs = append([]string(nil), state.Groups[i].MemberIDs...)
	}
	projected.Config.BaseURL = app.SCIMBaseURL
	projected.Config.BearerToken = app.SCIMBearerToken
	projected.Config.AutoOpenSyncTrace = app.SCIMAutoOpenTrace
	projected.Config.SCIMDisabled = !app.SCIMEnabled
	projected.UserOperations = operationLogsForApp(state.UserOperations, appID)
	projected.GroupOperations = operationLogsForApp(state.GroupOperations, appID)
	if !app.SCIMEnabled {
		return projected, nil
	}
	deletedUserIDs := make(map[string]bool)
	for i := range projected.Users {
		syncState, exists := state.UserSync[appID][projected.Users[i].ID]
		if !exists {
			syncState.Dirty = true
		}
		projected.Users[i].RemoteID = syncState.RemoteID
		projected.Users[i].Dirty = syncState.Dirty
		projected.Users[i].Deleted = projected.Users[i].Deleted || syncState.Deleted
		projected.Users[i].LastError = syncState.LastError
		if projected.Users[i].Deleted {
			deletedUserIDs[projected.Users[i].ID] = true
		}
	}
	for i := range projected.Groups {
		syncState, exists := state.GroupSync[appID][projected.Groups[i].ID]
		if !exists {
			syncState.Dirty = true
		}
		projected.Groups[i].RemoteID = syncState.RemoteID
		projected.Groups[i].Dirty = syncState.Dirty
		projected.Groups[i].Deleted = projected.Groups[i].Deleted || syncState.Deleted
		projected.Groups[i].LastError = syncState.LastError
		members := make([]string, 0, len(projected.Groups[i].MemberIDs))
		for _, userID := range projected.Groups[i].MemberIDs {
			if !deletedUserIDs[userID] {
				members = append(members, userID)
			}
		}
		projected.Groups[i].MemberIDs = members
	}
	return projected, nil
}

func operationLogsForApp(logs map[string][]OperationLog, appID string) map[string][]OperationLog {
	filtered := make(map[string][]OperationLog, len(logs))
	for resourceID, entries := range logs {
		for _, entry := range entries {
			if entry.Kind != "local" && entry.AppID != appID {
				continue
			}
			filtered[resourceID] = append(filtered[resourceID], entry)
		}
	}
	return filtered
}

// DropAppOperationLogs removes the sync log entries recorded for one app.
// Local entries carry no app ID and are kept.
func DropAppOperationLogs(state *AppState, appID string) {
	if appID == "" {
		return
	}
	dropFrom := func(logs map[string][]OperationLog) {
		for resourceID, entries := range logs {
			kept := entries[:0]
			for _, entry := range entries {
				if entry.AppID != appID {
					kept = append(kept, entry)
				}
			}
			if len(kept) == 0 {
				delete(logs, resourceID)
				continue
			}
			logs[resourceID] = kept
		}
	}
	dropFrom(state.UserOperations)
	dropFrom(state.GroupOperations)
}

// MarkUserDirtyForApps schedules a user change for every sync-enabled app.
func MarkUserDirtyForApps(state *AppState, userID string, deleted bool) {
	if state.UserSync == nil {
		state.UserSync = make(map[string]map[string]ResourceSyncState)
	}
	for _, app := range state.Apps {
		if !app.SCIMEnabled {
			continue
		}
		if state.UserSync[app.ID] == nil {
			state.UserSync[app.ID] = make(map[string]ResourceSyncState)
		}
		syncState := state.UserSync[app.ID][userID]
		syncState.Dirty = true
		syncState.Deleted = deleted
		syncState.LastError = ""
		state.UserSync[app.ID][userID] = syncState
	}
}

// MarkGroupDirtyForApps schedules a group change for every sync-enabled app.
func MarkGroupDirtyForApps(state *AppState, groupID string, deleted bool) {
	if state.GroupSync == nil {
		state.GroupSync = make(map[string]map[string]ResourceSyncState)
	}
	for _, app := range state.Apps {
		if !app.SCIMEnabled {
			continue
		}
		if state.GroupSync[app.ID] == nil {
			state.GroupSync[app.ID] = make(map[string]ResourceSyncState)
		}
		syncState := state.GroupSync[app.ID][groupID]
		syncState.Dirty = true
		syncState.Deleted = deleted
		syncState.LastError = ""
		state.GroupSync[app.ID][groupID] = syncState
	}
}

// InitializeAppSync resets one app so every directory resource is recreated.
func InitializeAppSync(state *AppState, appID string) {
	if state.UserSync == nil {
		state.UserSync = make(map[string]map[string]ResourceSyncState)
	}
	if state.GroupSync == nil {
		state.GroupSync = make(map[string]map[string]ResourceSyncState)
	}
	state.UserSync[appID] = make(map[string]ResourceSyncState, len(state.Users))
	for _, user := range state.Users {
		state.UserSync[appID][user.ID] = ResourceSyncState{Dirty: true, Deleted: user.Deleted}
	}
	state.GroupSync[appID] = make(map[string]ResourceSyncState, len(state.Groups))
	for _, group := range state.Groups {
		state.GroupSync[appID][group.ID] = ResourceSyncState{Dirty: true, Deleted: group.Deleted}
	}
}

// MergeAppSyncState stores one SCIM result without changing other apps.
func MergeAppSyncState(state *AppState, appID string, synced AppState) {
	if state.UserSync == nil {
		state.UserSync = make(map[string]map[string]ResourceSyncState)
	}
	if state.GroupSync == nil {
		state.GroupSync = make(map[string]map[string]ResourceSyncState)
	}
	userSync := make(map[string]ResourceSyncState, len(state.Users))
	for _, user := range synced.Users {
		userSync[user.ID] = ResourceSyncState{RemoteID: user.RemoteID, Dirty: user.Dirty, Deleted: user.Deleted, LastError: user.LastError}
	}
	for _, user := range state.Users {
		if _, ok := userSync[user.ID]; !ok && user.Deleted {
			userSync[user.ID] = ResourceSyncState{Deleted: true}
		}
	}
	state.UserSync[appID] = userSync

	groupSync := make(map[string]ResourceSyncState, len(state.Groups))
	for _, group := range synced.Groups {
		groupSync[group.ID] = ResourceSyncState{RemoteID: group.RemoteID, Dirty: group.Dirty, Deleted: group.Deleted, LastError: group.LastError}
	}
	for _, group := range state.Groups {
		if _, ok := groupSync[group.ID]; !ok && group.Deleted {
			groupSync[group.ID] = ResourceSyncState{Deleted: true}
		}
	}
	state.GroupSync[appID] = groupSync
}

// MergeAppImportState replaces the directory from one app and schedules the
// resulting changes for every other sync-enabled app.
func MergeAppImportState(state *AppState, appID string, imported AppState) {
	MergeAppSyncState(state, appID, imported)
	if state.UserOperations == nil {
		state.UserOperations = make(map[string][]OperationLog)
	}
	if state.GroupOperations == nil {
		state.GroupOperations = make(map[string][]OperationLog)
	}
	previousUsers := make(map[string]User, len(state.Users))
	for _, user := range state.Users {
		previousUsers[user.ID] = user
	}
	previousGroups := make(map[string]Group, len(state.Groups))
	for _, group := range state.Groups {
		previousGroups[group.ID] = group
	}

	state.Users = imported.Users
	importedUserIDs := make(map[string]bool, len(imported.Users))
	for i := range state.Users {
		importedUserIDs[state.Users[i].ID] = true
		mergeImportOperationLog(state.UserOperations, imported.UserOperations, state.Users[i].ID)
		state.Users[i].RemoteID = ""
		state.Users[i].Dirty = false
		state.Users[i].Deleted = false
		state.Users[i].LastError = ""
	}
	for id, user := range previousUsers {
		if importedUserIDs[id] {
			continue
		}
		user.Deleted = true
		user.RemoteID = ""
		user.Dirty = false
		user.LastError = ""
		state.Users = append(state.Users, user)
	}

	state.Groups = imported.Groups
	importedGroupIDs := make(map[string]bool, len(imported.Groups))
	for i := range state.Groups {
		importedGroupIDs[state.Groups[i].ID] = true
		mergeImportOperationLog(state.GroupOperations, imported.GroupOperations, state.Groups[i].ID)
		state.Groups[i].RemoteID = ""
		state.Groups[i].Dirty = false
		state.Groups[i].Deleted = false
		state.Groups[i].LastError = ""
	}
	for id, group := range previousGroups {
		if importedGroupIDs[id] {
			continue
		}
		group.Deleted = true
		group.RemoteID = ""
		group.Dirty = false
		group.LastError = ""
		state.Groups = append(state.Groups, group)
	}

	for _, app := range state.Apps {
		if !app.SCIMEnabled || app.ID == appID {
			continue
		}
		for _, user := range state.Users {
			markResourceDirty(state.UserSync, app.ID, user.ID, user.Deleted)
		}
		for _, group := range state.Groups {
			markResourceDirty(state.GroupSync, app.ID, group.ID, group.Deleted)
		}
	}
}

func mergeImportOperationLog(destination map[string][]OperationLog, imported map[string][]OperationLog, resourceID string) {
	for _, entry := range imported[resourceID] {
		if entry.Kind != "local" || entry.Summary != "Imported from SCIM" {
			continue
		}
		destination[resourceID] = append([]OperationLog{entry}, destination[resourceID]...)
		return
	}
}

func markResourceDirty(syncStates map[string]map[string]ResourceSyncState, appID string, resourceID string, deleted bool) {
	if syncStates[appID] == nil {
		syncStates[appID] = make(map[string]ResourceSyncState)
	}
	syncState := syncStates[appID][resourceID]
	syncState.Dirty = true
	syncState.Deleted = deleted
	syncState.LastError = ""
	syncStates[appID][resourceID] = syncState
}

// PurgeFullySyncedDeletions removes resources deleted from every enabled app.
func PurgeFullySyncedDeletions(state *AppState) {
	userDeletedEverywhere := func(userID string) bool {
		for _, app := range state.Apps {
			if !app.SCIMEnabled {
				continue
			}
			syncState, ok := state.UserSync[app.ID][userID]
			if !ok || syncState.Dirty {
				return false
			}
		}
		return true
	}
	keptUsers := state.Users[:0]
	for _, user := range state.Users {
		if user.Deleted && userDeletedEverywhere(user.ID) {
			delete(state.UserOperations, user.ID)
			for appID := range state.UserSync {
				delete(state.UserSync[appID], user.ID)
			}
			for i := range state.Groups {
				state.Groups[i].MemberIDs = removeValue(state.Groups[i].MemberIDs, user.ID)
			}
			continue
		}
		keptUsers = append(keptUsers, user)
	}
	state.Users = keptUsers

	groupDeletedEverywhere := func(groupID string) bool {
		for _, app := range state.Apps {
			if !app.SCIMEnabled {
				continue
			}
			syncState, ok := state.GroupSync[app.ID][groupID]
			if !ok || syncState.Dirty {
				return false
			}
		}
		return true
	}
	keptGroups := state.Groups[:0]
	for _, group := range state.Groups {
		if group.Deleted && groupDeletedEverywhere(group.ID) {
			delete(state.GroupOperations, group.ID)
			for appID := range state.GroupSync {
				delete(state.GroupSync[appID], group.ID)
			}
			continue
		}
		keptGroups = append(keptGroups, group)
	}
	state.Groups = keptGroups
}

func removeValue(values []string, value string) []string {
	kept := values[:0]
	for _, candidate := range values {
		if candidate != value {
			kept = append(kept, candidate)
		}
	}
	return kept
}

func AppendOperationLogs(state *AppState, appID string, traces []SyncTraceEntry) {
	if state.UserOperations == nil {
		state.UserOperations = make(map[string][]OperationLog)
	}
	if state.GroupOperations == nil {
		state.GroupOperations = make(map[string][]OperationLog)
	}

	for _, trace := range traces {
		entry := OperationLog{
			AppID:              appID,
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

func ValidateUser(givenName string, email string, username string) error {
	givenName = strings.TrimSpace(givenName)
	email = strings.TrimSpace(email)

	switch {
	case givenName == "":
		return fmt.Errorf("given name is required")
	case email == "":
		return fmt.Errorf("email is required")
	case !strings.Contains(email, "@"):
		return fmt.Errorf("email must look like an email address")
	default:
		return nil
	}
}

// ValidateUserUnique rejects emails and usernames already used by another
// non-deleted user, so duplicates fail at save time instead of as SCIM
// conflicts during sync.
func ValidateUserUnique(users []User, id string, email string, username string) error {
	email = strings.TrimSpace(email)
	username = strings.TrimSpace(username)
	for _, existing := range users {
		if existing.ID == id || existing.Deleted {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(existing.Email), email) {
			return fmt.Errorf("email %q is already used by %s", email, UserLabel(existing))
		}
		if strings.EqualFold(strings.TrimSpace(existing.Username), username) {
			return fmt.Errorf("username %q is already used by %s", username, UserLabel(existing))
		}
	}
	return nil
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
	if app.Protocol != "oidc" && app.Protocol != "saml" && app.Protocol != "both" && app.Protocol != "scim" {
		return fmt.Errorf("protocol must be oidc, saml, both, or scim")
	}
	for _, existing := range apps {
		if existing.ID != app.ID && strings.EqualFold(existing.Slug, app.Slug) {
			if existing.EnvironmentName != "" {
				return fmt.Errorf("app slug %q is already in use by environment %s", app.Slug, existing.EnvironmentName)
			}
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
		return parts[0], ""
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
