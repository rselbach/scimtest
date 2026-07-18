package core

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
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

// ErrAppNotFound marks lookups for an unknown app slug so handlers can
// answer 404 without matching on error text.
var ErrAppNotFound = errors.New("app not found")

var currentTime = time.Now

const DefaultSAMLEmailAttributeName = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
const DefaultSAMLNameIDField = "email"
const SAMLNameIDFormatEmail = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
const (
	// ChooserModeList displays every active user on the sign-in page.
	ChooserModeList = "list"
	// ChooserModeIdentifier asks for an exact username or email match.
	ChooserModeIdentifier = "identifier"
)

// DefaultOIDCClaimMappings returns the standard profile claim names.
func DefaultOIDCClaimMappings() OIDCClaimMappings {
	return OIDCClaimMappings{
		Name: "name", GivenName: "given_name", FamilyName: "family_name",
		Username: "preferred_username", Email: "email", Groups: "groups",
	}
}

// DefaultSAMLAttributeMappings returns the legacy assertion attribute names.
func DefaultSAMLAttributeMappings() SAMLAttributeMappings {
	return SAMLAttributeMappings{
		GivenName: "firstName", FamilyName: "lastName", Username: "username",
		Email: DefaultSAMLEmailAttributeName, Groups: "groups",
	}
}

// OIDCClaimMappingsForApp fills missing mappings with compatible defaults.
func OIDCClaimMappingsForApp(app App) OIDCClaimMappings {
	mappings := app.OIDCClaimMappings
	defaults := DefaultOIDCClaimMappings()
	fillClaimMappingDefaults(&mappings.Name, defaults.Name)
	fillClaimMappingDefaults(&mappings.GivenName, defaults.GivenName)
	fillClaimMappingDefaults(&mappings.FamilyName, defaults.FamilyName)
	fillClaimMappingDefaults(&mappings.Username, defaults.Username)
	fillClaimMappingDefaults(&mappings.Email, defaults.Email)
	fillClaimMappingDefaults(&mappings.Groups, defaults.Groups)
	return mappings
}

// SAMLAttributeMappingsForApp fills missing mappings with compatible defaults.
func SAMLAttributeMappingsForApp(app App) SAMLAttributeMappings {
	mappings := app.SAMLAttributeMappings
	defaults := DefaultSAMLAttributeMappings()
	if strings.TrimSpace(mappings.Email) == "" && strings.TrimSpace(app.SAMLEmailAttributeName) != "" {
		mappings.Email = app.SAMLEmailAttributeName
	}
	fillClaimMappingDefaults(&mappings.GivenName, defaults.GivenName)
	fillClaimMappingDefaults(&mappings.FamilyName, defaults.FamilyName)
	fillClaimMappingDefaults(&mappings.Username, defaults.Username)
	fillClaimMappingDefaults(&mappings.Email, defaults.Email)
	fillClaimMappingDefaults(&mappings.Groups, defaults.Groups)
	return mappings
}

func fillClaimMappingDefaults(value *string, fallback string) {
	if strings.TrimSpace(*value) == "" {
		*value = fallback
		return
	}
	*value = strings.TrimSpace(*value)
}

const SAMLNameIDFormatUnspecified = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
const DefaultEnvironmentID = "env_default"

// EnsureTunnelInstanceID returns the stable identity used for tunnel
// reservations, generating and persisting it when necessary.
func EnsureTunnelInstanceID() (string, error) {
	db, err := openStateDB()
	if err != nil {
		return "", err
	}
	instanceID, err := newUUID()
	if err != nil {
		return "", err
	}
	if _, err := db.Exec(`
		INSERT OR IGNORE INTO config(key, value)
		SELECT 'tunnel_instance_id', value FROM config WHERE key = 'rgrok_instance_id'
	`); err != nil {
		return "", fmt.Errorf("migrate tunnel instance id: %w", err)
	}
	if _, err := db.Exec(`INSERT OR IGNORE INTO config(key, value) VALUES('tunnel_instance_id', ?)`, instanceID); err != nil {
		return "", fmt.Errorf("persist tunnel instance id: %w", err)
	}

	var saved string
	if err := db.QueryRow(`SELECT value FROM config WHERE key = 'tunnel_instance_id'`).Scan(&saved); err != nil {
		return "", fmt.Errorf("load tunnel instance id: %w", err)
	}
	if validUUID(saved) {
		return saved, nil
	}

	result, err := db.Exec(`UPDATE config SET value = ? WHERE key = 'tunnel_instance_id' AND value = ?`, instanceID, saved)
	if err != nil {
		return "", fmt.Errorf("repair tunnel instance id: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return "", fmt.Errorf("check repaired tunnel instance id: %w", err)
	}
	if changed == 0 {
		if err := db.QueryRow(`SELECT value FROM config WHERE key = 'tunnel_instance_id'`).Scan(&saved); err != nil {
			return "", fmt.Errorf("reload tunnel instance id: %w", err)
		}
		if !validUUID(saved) {
			return "", fmt.Errorf("reload tunnel instance id: invalid concurrent value %q", saved)
		}
		return saved, nil
	}
	return instanceID, nil
}

func newUUID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate tunnel instance id: %w", err)
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
	return AppState{}, fmt.Errorf("app slug %q: %w", slug, ErrAppNotFound)
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

	// busy_timeout makes concurrent connections wait instead of failing with
	// SQLITE_BUSY (which could discard a finished sync's state write while a
	// status poll held a read lock); WAL lets readers and the writer proceed
	// concurrently.
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
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
			scim_auto_open_trace INTEGER NOT NULL DEFAULT 0,
			scim_capabilities_known INTEGER NOT NULL DEFAULT 0,
			scim_patch_supported INTEGER NOT NULL DEFAULT 0,
			scim_filter_supported INTEGER NOT NULL DEFAULT 0,
			oidc_claim_mappings TEXT NOT NULL DEFAULT '',
			saml_attribute_mappings TEXT NOT NULL DEFAULT '',
			chooser_mode TEXT NOT NULL DEFAULT 'list'
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
		`ALTER TABLE apps ADD COLUMN scim_capabilities_known INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE apps ADD COLUMN scim_patch_supported INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE apps ADD COLUMN scim_filter_supported INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE apps ADD COLUMN oidc_claim_mappings TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE apps ADD COLUMN saml_attribute_mappings TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE apps ADD COLUMN chooser_mode TEXT NOT NULL DEFAULT 'list'`,
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

	legacyTunnelInstanceID := ""
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
		case "tunnel_instance_id":
			state.Config.TunnelInstanceID = value
		case "rgrok_instance_id":
			legacyTunnelInstanceID = value
		case "signing_private_key_pem":
			state.Config.SigningPrivateKeyPEM = value
		case "signing_certificate_pem":
			state.Config.SigningCertificatePEM = value
		}
	}
	if err := configRows.Err(); err != nil {
		return AppState{}, fmt.Errorf("iterate sqlite config rows: %w", err)
	}
	if state.Config.TunnelInstanceID == "" {
		state.Config.TunnelInstanceID = legacyTunnelInstanceID
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

	appRows, err := db.Query(`SELECT id, name, slug, protocol, oidc_client_id, oidc_client_secret, oidc_public_client, oidc_redirect_uris, saml_entity_id, saml_acs_url, saml_audience, saml_name_id_field, saml_name_id_format, saml_email_attribute_name, include_groups_claim, allow_any_oidc_redirect, scim_enabled, scim_base_url, scim_bearer_token, scim_auto_open_trace, scim_capabilities_known, scim_patch_supported, scim_filter_supported, oidc_claim_mappings, saml_attribute_mappings, chooser_mode FROM apps WHERE environment_id = ? ORDER BY rowid`, environmentID)
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
		var scimCapabilitiesKnown int
		var scimPatchSupported int
		var scimFilterSupported int
		var oidcClaimMappings string
		var samlAttributeMappings string
		if err := appRows.Scan(&app.ID, &app.Name, &app.Slug, &app.Protocol, &app.OIDCClientID, &app.OIDCClientSecret, &publicClient, &redirectURIs, &app.SAMLEntityID, &app.SAMLACSURL, &app.SAMLAudience, &app.SAMLNameIDField, &app.SAMLNameIDFormat, &app.SAMLEmailAttributeName, &includeGroups, &allowAnyRedirect, &scimEnabled, &app.SCIMBaseURL, &app.SCIMBearerToken, &scimAutoOpenTrace, &scimCapabilitiesKnown, &scimPatchSupported, &scimFilterSupported, &oidcClaimMappings, &samlAttributeMappings, &app.ChooserMode); err != nil {
			return AppState{}, fmt.Errorf("scan sqlite app row: %w", err)
		}
		app.OIDCRedirectURIs = Lines(redirectURIs)
		app.IncludeGroupsClaim = includeGroups != 0
		app.AllowAnyOIDCRedirect = allowAnyRedirect != 0
		app.OIDCPublicClient = publicClient != 0
		app.SCIMEnabled = scimEnabled != 0
		app.SCIMAutoOpenTrace = scimAutoOpenTrace != 0
		app.SCIMCapabilitiesKnown = scimCapabilitiesKnown != 0
		app.SCIMPatchSupported = scimPatchSupported != 0
		app.SCIMFilterSupported = scimFilterSupported != 0
		if oidcClaimMappings != "" {
			if err := json.Unmarshal([]byte(oidcClaimMappings), &app.OIDCClaimMappings); err != nil {
				return AppState{}, fmt.Errorf("decode OIDC claim mappings for app %s: %w", app.ID, err)
			}
		}
		if samlAttributeMappings != "" {
			if err := json.Unmarshal([]byte(samlAttributeMappings), &app.SAMLAttributeMappings); err != nil {
				return AppState{}, fmt.Errorf("decode SAML attribute mappings for app %s: %w", app.ID, err)
			}
		}
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

	if global {
		for _, table := range []string{"environment_config", "app_user_sync", "app_group_sync", "group_members", "operation_logs"} {
			if _, err := tx.Exec(`DELETE FROM ` + table); err != nil {
				return fmt.Errorf("clear sqlite %s: %w", table, err)
			}
		}
		if _, err := tx.Exec(`DELETE FROM environments WHERE id != ?`, DefaultEnvironmentID); err != nil {
			return fmt.Errorf("remove migrated environments: %w", err)
		}
		for _, table := range []string{"apps", "groups", "users"} {
			if _, err := tx.Exec(`DELETE FROM `+table+` WHERE environment_id != ?`, DefaultEnvironmentID); err != nil {
				return fmt.Errorf("remove migrated sqlite %s: %w", table, err)
			}
		}
	} else {
		if _, err := tx.Exec(`DELETE FROM environment_config WHERE environment_id = ?`, environmentID); err != nil {
			return fmt.Errorf("clear sqlite environment config: %w", err)
		}
		if _, err := tx.Exec(`DELETE FROM app_user_sync WHERE app_id IN (SELECT id FROM apps WHERE environment_id = ?)`, environmentID); err != nil {
			return fmt.Errorf("clear sqlite app user sync: %w", err)
		}
		if _, err := tx.Exec(`DELETE FROM app_group_sync WHERE app_id IN (SELECT id FROM apps WHERE environment_id = ?)`, environmentID); err != nil {
			return fmt.Errorf("clear sqlite app group sync: %w", err)
		}
		if _, err := tx.Exec(`DELETE FROM group_members WHERE environment_id = ?`, environmentID); err != nil {
			return fmt.Errorf("clear sqlite group members: %w", err)
		}
		if _, err := tx.Exec(`DELETE FROM operation_logs WHERE environment_id = ?`, environmentID); err != nil {
			return fmt.Errorf("clear sqlite operation logs: %w", err)
		}
	}
	userIDs := make([]string, 0, len(state.Users))
	for _, user := range state.Users {
		userIDs = append(userIDs, user.ID)
	}
	groupIDs := make([]string, 0, len(state.Groups))
	for _, group := range state.Groups {
		groupIDs = append(groupIDs, group.ID)
	}
	appIDs := make([]string, 0, len(state.Apps))
	for _, app := range state.Apps {
		appIDs = append(appIDs, app.ID)
	}
	for _, target := range []struct {
		table string
		key   string
		ids   []string
	}{
		{table: "apps", key: "id", ids: appIDs},
		{table: "groups", key: "id", ids: groupIDs},
		{table: "users", key: "id", ids: userIDs},
	} {
		if err := deleteMissingRows(tx, target.table, target.key, environmentID, target.ids); err != nil {
			return err
		}
	}

	configStmt, err := tx.Prepare(`INSERT INTO config(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`)
	if err != nil {
		return fmt.Errorf("prepare sqlite config insert: %w", err)
	}
	defer closeStmt(configStmt)

	configEntries := map[string]string{
		"app_scim_migrated":       "1",
		"idp_base_url":            state.Config.IDPBaseURL,
		"trust_forwarded_headers": BoolString(state.Config.TrustForwardedHeaders),
		"tunnel_instance_id":      state.Config.TunnelInstanceID,
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
			if _, err := tx.Exec(`INSERT INTO environment_config(environment_id, key, value) VALUES(?, ?, ?) ON CONFLICT(environment_id, key) DO UPDATE SET value = excluded.value`, environmentID, key, value); err != nil {
				return fmt.Errorf("insert environment config %s: %w", key, err)
			}
		}
	}

	userStmt, err := tx.Prepare(`INSERT INTO users(id, environment_id, given_name, family_name, email, username, active, remote_id, dirty, deleted, last_error) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET environment_id = excluded.environment_id, given_name = excluded.given_name, family_name = excluded.family_name, email = excluded.email, username = excluded.username, active = excluded.active, remote_id = excluded.remote_id, dirty = excluded.dirty, deleted = excluded.deleted, last_error = excluded.last_error`)
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

	groupStmt, err := tx.Prepare(`INSERT INTO groups(id, environment_id, display_name, remote_id, dirty, deleted, last_error) VALUES(?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET environment_id = excluded.environment_id, display_name = excluded.display_name, remote_id = excluded.remote_id, dirty = excluded.dirty, deleted = excluded.deleted, last_error = excluded.last_error`)
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

	appStmt, err := tx.Prepare(`INSERT INTO apps(id, environment_id, name, slug, protocol, oidc_client_id, oidc_client_secret, oidc_public_client, oidc_redirect_uris, saml_entity_id, saml_acs_url, saml_audience, saml_name_id_field, saml_name_id_format, saml_email_attribute_name, include_groups_claim, allow_any_oidc_redirect, scim_enabled, scim_base_url, scim_bearer_token, scim_auto_open_trace, scim_capabilities_known, scim_patch_supported, scim_filter_supported, oidc_claim_mappings, saml_attribute_mappings, chooser_mode) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET environment_id = excluded.environment_id, name = excluded.name, slug = excluded.slug, protocol = excluded.protocol, oidc_client_id = excluded.oidc_client_id, oidc_client_secret = excluded.oidc_client_secret, oidc_public_client = excluded.oidc_public_client, oidc_redirect_uris = excluded.oidc_redirect_uris, saml_entity_id = excluded.saml_entity_id, saml_acs_url = excluded.saml_acs_url, saml_audience = excluded.saml_audience, saml_name_id_field = excluded.saml_name_id_field, saml_name_id_format = excluded.saml_name_id_format, saml_email_attribute_name = excluded.saml_email_attribute_name, include_groups_claim = excluded.include_groups_claim, allow_any_oidc_redirect = excluded.allow_any_oidc_redirect, scim_enabled = excluded.scim_enabled, scim_base_url = excluded.scim_base_url, scim_bearer_token = excluded.scim_bearer_token, scim_auto_open_trace = excluded.scim_auto_open_trace, scim_capabilities_known = excluded.scim_capabilities_known, scim_patch_supported = excluded.scim_patch_supported, scim_filter_supported = excluded.scim_filter_supported, oidc_claim_mappings = excluded.oidc_claim_mappings, saml_attribute_mappings = excluded.saml_attribute_mappings, chooser_mode = excluded.chooser_mode`)
	if err != nil {
		return fmt.Errorf("prepare sqlite app insert: %w", err)
	}
	defer closeStmt(appStmt)

	for _, app := range state.Apps {
		oidcClaimMappings, err := json.Marshal(app.OIDCClaimMappings)
		if err != nil {
			return fmt.Errorf("encode OIDC claim mappings for app %s: %w", app.ID, err)
		}
		samlAttributeMappings, err := json.Marshal(app.SAMLAttributeMappings)
		if err != nil {
			return fmt.Errorf("encode SAML attribute mappings for app %s: %w", app.ID, err)
		}
		if _, err := appStmt.Exec(app.ID, environmentID, app.Name, app.Slug, app.Protocol, app.OIDCClientID, app.OIDCClientSecret, boolToInt(app.OIDCPublicClient), JoinLines(app.OIDCRedirectURIs), app.SAMLEntityID, app.SAMLACSURL, app.SAMLAudience, app.SAMLNameIDField, app.SAMLNameIDFormat, app.SAMLEmailAttributeName, boolToInt(app.IncludeGroupsClaim), boolToInt(app.AllowAnyOIDCRedirect), boolToInt(app.SCIMEnabled), app.SCIMBaseURL, app.SCIMBearerToken, boolToInt(app.SCIMAutoOpenTrace), boolToInt(app.SCIMCapabilitiesKnown), boolToInt(app.SCIMPatchSupported), boolToInt(app.SCIMFilterSupported), string(oidcClaimMappings), string(samlAttributeMappings), app.ChooserMode); err != nil {
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

func deleteMissingRows(tx *sql.Tx, table string, key string, environmentID string, ids []string) error {
	query := `DELETE FROM ` + table + ` WHERE environment_id = ?`
	args := []any{environmentID}
	if len(ids) > 0 {
		placeholders := make([]string, len(ids))
		for i, id := range ids {
			placeholders[i] = "?"
			args = append(args, id)
		}
		query += ` AND ` + key + ` NOT IN (` + strings.Join(placeholders, ",") + `)`
	}
	if _, err := tx.Exec(query, args...); err != nil {
		return fmt.Errorf("delete missing sqlite %s: %w", table, err)
	}
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

// StateFilePath returns the resolved SQLite state file path.
func StateFilePath() (string, error) {
	return stateFilePath()
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
	state.Config.TunnelInstanceID = strings.TrimSpace(state.Config.TunnelInstanceID)

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
		state.Apps[i].OIDCClaimMappings = OIDCClaimMappingsForApp(state.Apps[i])
		state.Apps[i].SAMLAttributeMappings = SAMLAttributeMappingsForApp(state.Apps[i])
		state.Apps[i].ChooserMode = NormalizeChooserMode(state.Apps[i].ChooserMode)
		if SupportsSAML(state.Apps[i]) {
			state.Apps[i].SAMLEmailAttributeName = state.Apps[i].SAMLAttributeMappings.Email
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
	if NormalizeChooserMode(app.ChooserMode) != app.ChooserMode && strings.TrimSpace(app.ChooserMode) != "" {
		return fmt.Errorf("chooser mode must be list or identifier")
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
		mappings := OIDCClaimMappingsForApp(app)
		if err := validateMappedNames("OIDC claim", []string{mappings.Name, mappings.GivenName, mappings.FamilyName, mappings.Username, mappings.Email, mappings.Groups}, "sub", "iss", "aud", "iat", "exp", "nonce", "email_verified"); err != nil {
			return err
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
		mappings := SAMLAttributeMappingsForApp(app)
		if err := validateMappedNames("SAML attribute", []string{mappings.GivenName, mappings.FamilyName, mappings.Username, mappings.Email, mappings.Groups}); err != nil {
			return err
		}
	}
	if SupportsSAML(app) && strings.TrimSpace(app.SAMLNameIDField) != "" && NormalizeSAMLNameIDField(app.SAMLNameIDField) != app.SAMLNameIDField {
		return fmt.Errorf("SAML NameID field must be email, username, firstName, or lastName")
	}
	return nil
}

// NormalizeChooserMode returns a supported chooser privacy mode.
func NormalizeChooserMode(mode string) string {
	if strings.TrimSpace(mode) == ChooserModeIdentifier {
		return ChooserModeIdentifier
	}
	return ChooserModeList
}

func validateMappedNames(kind string, names []string, reserved ...string) error {
	seen := make(map[string]bool, len(names))
	reservedNames := make(map[string]bool, len(reserved))
	for _, name := range reserved {
		seen[name] = true
		reservedNames[name] = true
	}
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			return fmt.Errorf("%s names are required", kind)
		}
		if seen[name] {
			if reservedNames[name] {
				return fmt.Errorf("%s name %q is reserved", kind, name)
			}
			return fmt.Errorf("%s name %q is configured more than once", kind, name)
		}
		seen[name] = true
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
