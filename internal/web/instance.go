package web

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	instanceReadyPath      = "/-/ready"
	instanceTokenHeader    = "X-Scimtest-Instance-Token"
	instanceHandoffTimeout = 5 * time.Second
)

type instanceMetadata struct {
	URL   string `json:"url"`
	Token string `json:"token"`
}

type instanceLease struct {
	path   string
	file   *os.File
	unlock func() error
}

func acquireInstanceLease(statePath string) (*instanceLease, bool, error) {
	path, err := instanceLockPath(statePath)
	if err != nil {
		return nil, false, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, false, fmt.Errorf("create instance lock directory: %w", err)
	}
	file, err := openInstanceFile(path)
	if err != nil {
		return nil, false, fmt.Errorf("open instance lock %s: %w", path, err)
	}
	lease := &instanceLease{path: path, file: file}
	acquired, err := lease.TryAcquire()
	if err != nil {
		if closeErr := file.Close(); closeErr != nil {
			return nil, false, fmt.Errorf("lock instance file: %w; close instance lock file: %v", err, closeErr)
		}
		return nil, false, fmt.Errorf("lock instance file: %w", err)
	}
	return lease, acquired, nil
}

func instanceLockPath(statePath string) (string, error) {
	absPath, err := filepath.Abs(statePath)
	if err != nil {
		return "", fmt.Errorf("resolve absolute state path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(absPath), 0o700); err != nil {
		return "", fmt.Errorf("create state directory for instance lock: %w", err)
	}
	resolvedParent, err := filepath.EvalSymlinks(filepath.Dir(absPath))
	if err != nil {
		return "", fmt.Errorf("resolve state directory for instance lock: %w", err)
	}
	canonicalPath := filepath.Join(resolvedParent, filepath.Base(absPath))
	if _, err := os.Lstat(canonicalPath); err == nil {
		resolvedPath, resolveErr := filepath.EvalSymlinks(canonicalPath)
		if resolveErr != nil {
			return "", fmt.Errorf("resolve state file for instance lock: %w", resolveErr)
		}
		canonicalPath = resolvedPath
		if err := validateStateFile(canonicalPath); err != nil {
			return "", err
		}
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("inspect state file for instance lock: %w", err)
	}
	return canonicalPath + ".lock", nil
}

func (l *instanceLease) TryAcquire() (bool, error) {
	unlock, acquired, err := tryLockInstanceFile(l.file)
	if err != nil || !acquired {
		return acquired, err
	}
	l.unlock = unlock
	if err := l.file.Truncate(0); err != nil {
		unlockErr := l.unlock()
		l.unlock = nil
		if unlockErr != nil {
			return false, fmt.Errorf("clear instance metadata: %w; unlock instance file: %v", err, unlockErr)
		}
		return false, fmt.Errorf("clear instance metadata: %w", err)
	}
	return true, nil
}

func (l *instanceLease) Publish(metadata instanceMetadata) error {
	data, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("encode instance metadata: %w", err)
	}
	data = append(data, '\n')
	if err := l.file.Truncate(0); err != nil {
		return fmt.Errorf("clear instance metadata: %w", err)
	}
	if _, err := l.file.WriteAt(data, 0); err != nil {
		return fmt.Errorf("write instance metadata: %w", err)
	}
	if err := l.file.Sync(); err != nil {
		return fmt.Errorf("sync instance metadata: %w", err)
	}
	return nil
}

func (l *instanceLease) Close() error {
	var unlockErr error
	if l.unlock != nil {
		unlockErr = l.unlock()
	}
	closeErr := l.file.Close()
	switch {
	case unlockErr != nil && closeErr != nil:
		return fmt.Errorf("unlock instance file: %v; close instance file: %w", unlockErr, closeErr)
	case unlockErr != nil:
		return fmt.Errorf("unlock instance file: %w", unlockErr)
	case closeErr != nil:
		return fmt.Errorf("close instance file: %w", closeErr)
	}
	return nil
}

func newInstanceToken() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate instance token: %w", err)
	}
	return hex.EncodeToString(value), nil
}

func waitForRunningInstance(ctx context.Context, lease *instanceLease) (instanceMetadata, bool, error) {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	var lastErr error
	for {
		acquired, err := lease.TryAcquire()
		if err != nil {
			return instanceMetadata{}, false, fmt.Errorf("retry instance lock: %w", err)
		}
		if acquired {
			return instanceMetadata{}, true, nil
		}
		metadata, err := readInstanceMetadata(lease.file)
		if err == nil {
			err = checkRunningInstance(ctx, metadata)
		}
		if err == nil {
			return metadata, false, nil
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return instanceMetadata{}, false, fmt.Errorf("another scimtest process is running but its admin UI is unavailable: %w", lastErr)
		case <-ticker.C:
		}
	}
}

func readInstanceMetadata(file *os.File) (instanceMetadata, error) {
	info, err := file.Stat()
	if err != nil {
		return instanceMetadata{}, fmt.Errorf("inspect instance metadata: %w", err)
	}
	if info.Size() < 1 || info.Size() > 4096 {
		return instanceMetadata{}, fmt.Errorf("instance metadata has invalid size %d", info.Size())
	}
	data := make([]byte, info.Size())
	if _, err := file.ReadAt(data, 0); err != nil {
		return instanceMetadata{}, fmt.Errorf("read instance metadata: %w", err)
	}
	var metadata instanceMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return instanceMetadata{}, fmt.Errorf("decode instance metadata: %w", err)
	}
	parsed, err := url.Parse(metadata.URL)
	if err != nil || parsed.Scheme != "http" || parsed.Host == "" {
		return instanceMetadata{}, fmt.Errorf("instance metadata contains invalid admin URL %q", metadata.URL)
	}
	host := parsed.Hostname()
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return instanceMetadata{}, fmt.Errorf("instance metadata contains non-loopback admin URL %q", metadata.URL)
	}
	if strings.TrimSpace(metadata.Token) == "" {
		return instanceMetadata{}, fmt.Errorf("instance metadata is missing its token")
	}
	return metadata, nil
}

func checkRunningInstance(ctx context.Context, metadata instanceMetadata) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(metadata.URL, "/")+instanceReadyPath, nil)
	if err != nil {
		return fmt.Errorf("create instance readiness request: %w", err)
	}
	request.Header.Set(instanceTokenHeader, metadata.Token)
	client := &http.Client{
		Timeout: 250 * time.Millisecond,
		Transport: &http.Transport{
			Proxy:             nil,
			DisableKeepAlives: true,
			DialContext: (&net.Dialer{
				Timeout: 250 * time.Millisecond,
			}).DialContext,
		},
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("contact running instance: %w", err)
	}
	_, readErr := io.Copy(io.Discard, response.Body)
	closeErr := response.Body.Close()
	if readErr != nil {
		return fmt.Errorf("read readiness response: %w", readErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close readiness response: %w", closeErr)
	}
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("running instance readiness returned %s", response.Status)
	}
	return nil
}

func (a *webApp) handleInstanceReady(w http.ResponseWriter, r *http.Request) {
	provided := r.Header.Get(instanceTokenHeader)
	if a.instanceToken == "" || subtle.ConstantTimeCompare([]byte(provided), []byte(a.instanceToken)) != 1 {
		http.NotFound(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
