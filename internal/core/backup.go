package core

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const StateBackupVersion = 1

// StateBackup is a versioned, complete export of local scimtest state.
type StateBackup struct {
	Version         int                                     `json:"version"`
	ExportedAt      string                                  `json:"exported_at"`
	State           AppState                                `json:"state"`
	UserOperations  map[string][]OperationLog               `json:"user_operations,omitempty"`
	GroupOperations map[string][]OperationLog               `json:"group_operations,omitempty"`
	UserSync        map[string]map[string]ResourceSyncState `json:"user_sync,omitempty"`
	GroupSync       map[string]map[string]ResourceSyncState `json:"group_sync,omitempty"`
}

// NewStateBackup creates a complete export, including state omitted by AppState JSON.
func NewStateBackup(state AppState) StateBackup {
	return StateBackup{
		Version:         StateBackupVersion,
		ExportedAt:      NowTimestamp(),
		State:           state,
		UserOperations:  state.UserOperations,
		GroupOperations: state.GroupOperations,
		UserSync:        state.UserSync,
		GroupSync:       state.GroupSync,
	}
}

// RestoredState validates the backup version and reconstructs complete state.
func (b StateBackup) RestoredState() (AppState, error) {
	if b.Version != StateBackupVersion {
		return AppState{}, fmt.Errorf("unsupported backup version %d", b.Version)
	}
	state := b.State
	state.UserOperations = b.UserOperations
	state.GroupOperations = b.GroupOperations
	state.UserSync = b.UserSync
	state.GroupSync = b.GroupSync
	return state, nil
}

// ValidateRestoredState validates an imported backup before it is saved to
// SQLite. It enforces environment sync scoping, canonical app slugs, URL and
// directory invariants, signing-key PEM validity, and strips orphan operation
// log keys.
func ValidateRestoredState(state *AppState, otherApps []App) error {
	if state == nil {
		return fmt.Errorf("backup state is required")
	}
	if err := validateEnvironmentSyncScope(*state); err != nil {
		return err
	}
	allApps := make([]App, 0, len(otherApps)+len(state.Apps))
	allApps = append(allApps, otherApps...)
	seenAppIDs := make(map[string]bool, len(state.Apps))
	for _, app := range state.Apps {
		if strings.TrimSpace(app.ID) == "" {
			return fmt.Errorf("app ID is required")
		}
		if seenAppIDs[app.ID] {
			return fmt.Errorf("duplicate app ID %q", app.ID)
		}
		seenAppIDs[app.ID] = true
		if slug := strings.TrimSpace(app.Slug); slug == "" || Slugify(slug) != slug {
			return fmt.Errorf("app slug %q must be a canonical URL slug", app.Slug)
		}
		if err := ValidateApp(app, allApps); err != nil {
			return err
		}
		if err := ValidateHTTPBaseURL("SCIM base URL", app.SCIMBaseURL, false); err != nil {
			return err
		}
		allApps = append(allApps, app)
	}

	seenUserIDs := make(map[string]bool, len(state.Users))
	for _, u := range state.Users {
		if strings.TrimSpace(u.ID) == "" {
			return fmt.Errorf("user ID is required")
		}
		if seenUserIDs[u.ID] {
			return fmt.Errorf("duplicate user ID %q", u.ID)
		}
		seenUserIDs[u.ID] = true
		if !u.Deleted {
			if err := ValidateUser(u.GivenName, u.Email, u.Username); err != nil {
				return err
			}
			if err := ValidateUserUnique(state.Users, u.ID, u.Email, u.Username); err != nil {
				return err
			}
		}
		if err := ValidateCustomAttributes(u.Attributes); err != nil {
			return err
		}
		if u.ManagerID != "" && u.ManagerID == u.ID {
			return fmt.Errorf("user %q cannot manage themselves", u.ID)
		}
	}

	seenGroupIDs := make(map[string]bool, len(state.Groups))
	for _, g := range state.Groups {
		if strings.TrimSpace(g.ID) == "" {
			return fmt.Errorf("group ID is required")
		}
		if seenGroupIDs[g.ID] {
			return fmt.Errorf("duplicate group ID %q", g.ID)
		}
		seenGroupIDs[g.ID] = true
		if !g.Deleted {
			if err := ValidateGroup(g.DisplayName); err != nil {
				return err
			}
		}
	}

	if err := validateStoredSigningPair("signing key", state.Config.SigningPrivateKeyPEM, state.Config.SigningCertificatePEM, true); err != nil {
		return err
	}
	for _, key := range state.Config.SigningKeys {
		if strings.TrimSpace(key.ID) == "" {
			return fmt.Errorf("signing key ID is required")
		}
		if err := validateStoredSigningPair("signing key "+key.ID, key.PrivateKeyPEM, key.CertificatePEM, false); err != nil {
			return err
		}
	}

	for id := range state.UserOperations {
		if !seenUserIDs[id] {
			delete(state.UserOperations, id)
		}
	}
	for id := range state.GroupOperations {
		if !seenGroupIDs[id] {
			delete(state.GroupOperations, id)
		}
	}
	return nil
}

func validateStoredSigningPair(label string, keyPEM string, certPEM string, allowEmpty bool) error {
	keyPEM = strings.TrimSpace(keyPEM)
	certPEM = strings.TrimSpace(certPEM)
	if keyPEM == "" && certPEM == "" {
		if allowEmpty {
			return nil
		}
		return fmt.Errorf("%s private key and certificate are required", label)
	}
	if keyPEM == "" || certPEM == "" {
		return fmt.Errorf("%s must include both private key and certificate", label)
	}
	keyBlock, keyRest := pem.Decode([]byte(keyPEM))
	if keyBlock == nil || strings.TrimSpace(string(keyRest)) != "" {
		return fmt.Errorf("%s private key PEM is invalid", label)
	}
	var privKey *rsa.PrivateKey
	if parsed, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes); err == nil {
		privKey = parsed
	} else if parsedAny, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes); err == nil {
		rsaKey, ok := parsedAny.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("%s private key must be RSA", label)
		}
		privKey = rsaKey
	} else {
		return fmt.Errorf("%s private key is invalid: %w", label, err)
	}

	certBlock, certRest := pem.Decode([]byte(certPEM))
	if certBlock == nil || certBlock.Type != "CERTIFICATE" || strings.TrimSpace(string(certRest)) != "" {
		return fmt.Errorf("%s certificate PEM is invalid", label)
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("%s certificate is invalid: %w", label, err)
	}
	pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("%s certificate public key must be RSA", label)
	}
	if !privKey.PublicKey.Equal(pubKey) {
		return fmt.Errorf("%s certificate does not match private key", label)
	}
	return nil
}

// WriteSafetyBackup stores a private snapshot beside the state database.
func WriteSafetyBackup(state AppState) (string, error) {
	statePath, err := stateFilePath()
	if err != nil {
		return "", err
	}
	directory := filepath.Join(filepath.Dir(statePath), "backups")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", fmt.Errorf("create backup directory: %w", err)
	}
	data, err := json.MarshalIndent(NewStateBackup(state), "", "  ")
	if err != nil {
		return "", fmt.Errorf("encode safety backup: %w", err)
	}
	name := fmt.Sprintf("pre-restore-%s.json", time.Now().UTC().Format("20060102T150405.000000000Z"))
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return "", fmt.Errorf("write safety backup: %w", err)
	}
	return path, nil
}
