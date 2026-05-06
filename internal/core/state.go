package core

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

var currentTime = time.Now

type Config struct {
	BaseURL           string `json:"base_url"`
	BearerToken       string `json:"bearer_token"`
	AutoOpenSyncTrace bool   `json:"auto_open_sync_trace"`
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
	UserOperations  map[string][]OperationLog `json:"-"`
	GroupOperations map[string][]OperationLog `json:"-"`
}

type OperationLog struct {
	Kind         string
	Summary      string
	Operation    string
	Method       string
	Path         string
	RequestBody  string
	Status       string
	ResponseBody string
	Err          string
	CreatedAt    string
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

	if err := saveStateToDB(db, legacyState); err != nil {
		return AppState{}, err
	}

	return loadStateFromDB(db)
}

func SaveState(state AppState) error {
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

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create state directory: %w", err)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite state db %s: %w", path, err)
	}

	if err := initStateDB(db); err != nil {
		_ = db.Close()
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

	logRows, err := db.Query(`SELECT resource_type, resource_id, kind, summary, operation, method, path, request_body, status, response_body, error_text, created_at FROM operation_logs ORDER BY id DESC`)
	if err != nil {
		return AppState{}, fmt.Errorf("load operation logs from sqlite: %w", err)
	}
	defer closeRows(logRows)

	for logRows.Next() {
		var resourceType string
		var resourceID string
		var entry OperationLog
		if err := logRows.Scan(&resourceType, &resourceID, &entry.Kind, &entry.Summary, &entry.Operation, &entry.Method, &entry.Path, &entry.RequestBody, &entry.Status, &entry.ResponseBody, &entry.Err, &entry.CreatedAt); err != nil {
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
		"base_url":             state.Config.BaseURL,
		"bearer_token":         state.Config.BearerToken,
		"auto_open_sync_trace": BoolString(state.Config.AutoOpenSyncTrace),
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

	logStmt, err := tx.Prepare(`INSERT INTO operation_logs(resource_type, resource_id, label, kind, summary, operation, method, path, request_body, status, response_body, error_text, created_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
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

	for resourceID, entries := range state.UserOperations {
		label := resourceID
		if User, ok := UserByID(state.Users, resourceID); ok {
			label = UserLabel(User)
		}
		for _, entry := range entries {
			if _, err := logStmt.Exec("user", resourceID, label, entry.Kind, entry.Summary, entry.Operation, entry.Method, entry.Path, entry.RequestBody, entry.Status, entry.ResponseBody, entry.Err, entry.CreatedAt); err != nil {
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
			if _, err := logStmt.Exec("group", resourceID, label, entry.Kind, entry.Summary, entry.Operation, entry.Method, entry.Path, entry.RequestBody, entry.Status, entry.ResponseBody, entry.Err, entry.CreatedAt); err != nil {
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
	return state.Config == (Config{}) && len(state.Users) == 0 && len(state.Groups) == 0
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
			Kind:         "sync",
			Summary:      summarizeSyncTrace(trace),
			Operation:    trace.Operation,
			Method:       trace.Method,
			Path:         trace.Path,
			RequestBody:  trace.RequestBody,
			Status:       trace.Status,
			ResponseBody: trace.ResponseBody,
			Err:          trace.Err,
			CreatedAt:    trace.CreatedAt,
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
