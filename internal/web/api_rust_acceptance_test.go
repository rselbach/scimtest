package web

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRustAPIAcceptance(t *testing.T) {
	binary := os.Getenv("SCIMTEST_ACCEPTANCE_RUST_BIN")
	if binary == "" {
		t.Skip("cargo test -p scimtest-core runs the shared suite with the Rust executable")
	}
	tests := map[string]func(*testing.T, http.Handler){
		"partial SCIM configuration": acceptancePartialSCIMConfiguration,
		"SCIM deletion history":      acceptanceSCIMDeletionHistory,
		"recording disables secrets": acceptanceRecordingDisablesSecrets,
		"directory and backup":       acceptanceDirectoryAndBackup,
		"sign-in protocols":          acceptanceSignInProtocols,
		"SCIM sync and import":       acceptanceSCIMSyncAndImport,
		"user attributes":            acceptanceUserAttributes,
		"Entra groups overage":       acceptanceEntraGroupsOverage,
		"persona settings persist":   acceptancePersonaSettingsPersist,
		"API guards": func(t *testing.T, handler http.Handler) {
			acceptanceGuards(t, handler)
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			tc(t, rustAcceptanceAPI(t, binary))
		})
	}
	t.Run("provider personas", func(t *testing.T) {
		acceptancePersonaClaims(t, func(t *testing.T) http.Handler {
			return rustAcceptanceAPI(t, binary)
		})
	})
}

func rustAcceptanceAPI(t *testing.T, binary string) http.Handler {
	t.Helper()
	r := require.New(t)
	directory := t.TempDir()
	state := filepath.Join(directory, "state.db")
	log, err := os.Create(filepath.Join(directory, "runtime.log"))
	r.NoError(err)
	t.Cleanup(func() { r.NoError(log.Close()) })
	command := exec.Command(binary, "--no-open", "--state-file", state)
	command.Stdout = log
	command.Stderr = log
	command.Env = append(os.Environ(), "SCIMTEST_PORT=", "PORT=")
	r.NoError(command.Start())
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	t.Cleanup(func() {
		select {
		case err := <-done:
			t.Errorf("Rust runtime exited before cleanup: %v", err)
		default:
			r.NoError(command.Process.Signal(syscall.SIGTERM))
			select {
			case err := <-done:
				r.NoError(err)
			case <-time.After(10 * time.Second):
				r.NoError(command.Process.Kill())
				r.Error(<-done)
				t.Error("Rust runtime did not shut down within ten seconds")
			}
		}
		if t.Failed() {
			contents, err := os.ReadFile(log.Name())
			r.NoError(err)
			t.Logf("Rust runtime: %s", contents)
		}
	})
	transport := &http.Transport{ResponseHeaderTimeout: 30 * time.Second}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	var metadata struct {
		URL   string `json:"url"`
		Token string `json:"token"`
	}
	r.Eventually(func() bool {
		contents, err := os.ReadFile(state + ".lock")
		if err != nil || json.Unmarshal(contents, &metadata) != nil || metadata.URL == "" || metadata.Token == "" {
			return false
		}
		req, err := http.NewRequest(http.MethodGet, metadata.URL+"/-/ready", nil)
		if err != nil {
			return false
		}
		req.Header.Set(instanceTokenHeader, metadata.Token)
		response, err := client.Do(req)
		if err != nil {
			return false
		}
		err = response.Body.Close()
		return err == nil && response.StatusCode == http.StatusNoContent
	}, 10*time.Second, 10*time.Millisecond)
	base, err := url.Parse(metadata.URL)
	r.NoError(err)
	return acceptanceHTTPHandler(t, client, base, metadata.Token)
}

func acceptanceHTTPHandler(t *testing.T, client *http.Client, base *url.URL, token string) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		forward := req.Clone(req.Context())
		forward.URL.Scheme = base.Scheme
		forward.URL.Host = base.Host
		forward.RequestURI = ""
		if forward.Host == "127.0.0.1:8080" {
			forward.Host = base.Host
		}
		if forward.Header.Get(instanceTokenHeader) == "greendale-local-instance" {
			forward.Header.Set(instanceTokenHeader, token)
		}
		response, err := client.Do(forward)
		if err != nil {
			t.Errorf("forward shared acceptance request: %v", err)
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer func() {
			if err := response.Body.Close(); err != nil {
				t.Errorf("close shared acceptance response: %v", err)
			}
		}()
		for name, values := range response.Header {
			for _, value := range values {
				w.Header().Add(name, value)
			}
		}
		w.WriteHeader(response.StatusCode)
		if _, err := io.Copy(w, response.Body); err != nil {
			t.Errorf("copy shared acceptance response: %v", err)
		}
	})
}
