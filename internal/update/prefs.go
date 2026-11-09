package update

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

// prefs is what the updater remembers between launches.
type prefs struct {
	LastCheck   time.Time `json:"last_check"`
	LastVersion string    `json:"last_version"`
}

func loadPrefs(path string) prefs {
	var loaded prefs
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return loaded
	}
	if err != nil {
		log.Printf("read update state: %v", err)
		return loaded
	}
	if err := json.Unmarshal(data, &loaded); err != nil {
		log.Printf("parse update state: %v", err)
		return prefs{}
	}
	return loaded
}

func (p prefs) save(path string) error {
	data, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("encode update state: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".updater-*.json")
	if err != nil {
		return fmt.Errorf("create update state: %w", err)
	}
	_, writeErr := temporary.Write(data)
	closeErr := temporary.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		removeFile(temporary.Name())
		return fmt.Errorf("write update state: %w", err)
	}
	if err := os.Rename(temporary.Name(), path); err != nil {
		removeFile(temporary.Name())
		return fmt.Errorf("replace update state: %w", err)
	}
	return nil
}
