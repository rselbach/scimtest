package web

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

const maxBackupBytes = 25 << 20

func (a *webApp) handleBackupDownload(w http.ResponseWriter, r *http.Request) {
	state, err := loadRequestState(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="scimtest-backup-%s.json"`, time.Now().UTC().Format("20060102T150405Z")))
	if err := json.NewEncoder(w).Encode(newStateBackup(state)); err != nil {
		log.Printf("write state backup: %v", err)
	}
}

func (a *webApp) handleBackupRestore(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	r.Body = http.MaxBytesReader(w, r.Body, maxBackupBytes)
	if err := r.ParseMultipartForm(maxBackupBytes); err != nil {
		a.redirectError(w, r, "apps", fmt.Errorf("read backup upload: %w", err))
		return
	}
	if r.MultipartForm != nil {
		defer func() {
			if err := r.MultipartForm.RemoveAll(); err != nil {
				log.Printf("remove backup upload temporary files: %v", err)
			}
		}()
	}
	file, _, err := r.FormFile("backup")
	if err != nil {
		a.redirectError(w, r, "apps", fmt.Errorf("open backup upload: %w", err))
		return
	}
	var backup stateBackup
	decodeErr := json.NewDecoder(file).Decode(&backup)
	closeErr := file.Close()
	if decodeErr != nil {
		a.redirectError(w, r, "apps", fmt.Errorf("decode backup: %w", decodeErr))
		return
	}
	if closeErr != nil {
		a.redirectError(w, r, "apps", fmt.Errorf("close backup upload: %w", closeErr))
		return
	}
	restored, err := backup.RestoredState()
	if err != nil {
		a.redirectError(w, r, "apps", err)
		return
	}
	current, err := loadRequestState(r)
	if err != nil {
		a.redirectError(w, r, "apps", err)
		return
	}
	if current.Environment.ID != "" && current.Environment.ID != defaultEnvironmentID && restored.Environment.ID != current.Environment.ID {
		a.redirectError(w, r, "apps", fmt.Errorf("backup belongs to a different environment"))
		return
	}
	safetyPath, err := writeSafetyBackup(current)
	if err != nil {
		a.redirectError(w, r, "apps", err)
		return
	}
	if err := saveRequestState(restored); err != nil {
		a.redirectError(w, r, "apps", err)
		return
	}
	redirectWithFlash(w, r, dashboardURL("apps", nil), flashMessage{Kind: "success", Message: "backup restored; pre-restore copy saved to " + safetyPath})
}
