package web

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBackupDownloadAndRestore(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{Users: []user{{ID: "troy", GivenName: "Troy", Email: "troy@greendale.edu", Username: "troy", Active: true}}}))
	app := newTestIDPApp(t)
	download := httptest.NewRecorder()
	app.routes().ServeHTTP(download, httptest.NewRequest(http.MethodGet, "/backup", nil))
	r.Equal(http.StatusOK, download.Code)
	r.Equal("application/json", download.Header().Get("Content-Type"))
	r.Contains(download.Header().Get("Content-Disposition"), "scimtest-backup-")
	var backup stateBackup
	r.NoError(json.Unmarshal(download.Body.Bytes(), &backup))
	backup.State.Users[0].GivenName = "Inspector"

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("backup", "greendale-backup.json")
	r.NoError(err)
	r.NoError(json.NewEncoder(part).Encode(backup))
	r.NoError(writer.Close())
	restore := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/restore", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	app.routes().ServeHTTP(restore, req)
	r.Equal(http.StatusSeeOther, restore.Code)

	state, err := loadState()
	r.NoError(err)
	r.Equal("Inspector", state.Users[0].GivenName)
	statePath := os.Getenv("SCIMTEST_STATE_FILE")
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(statePath), "backups", "pre-restore-*.json"))
	r.NoError(err)
	r.Len(matches, 1)
}
