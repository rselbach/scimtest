package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// redirectHosts are the hosts the feed and downloads may redirect to;
// GitHub serves release assets from separate storage hosts.
var redirectHosts = map[string]bool{
	"github.com":                           true,
	"objects.githubusercontent.com":        true,
	"release-assets.githubusercontent.com": true,
	"rselbach.github.io":                   true,
}

// integrityError means a download did not match the signed size or SHA-256.
type integrityError struct {
	reason string
}

func (e *integrityError) Error() string {
	return e.reason
}

func newHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ResponseHeaderTimeout = 30 * time.Second
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("too many redirects")
			}
			if request.URL.Scheme != "https" || request.URL.User != nil || !redirectHosts[request.URL.Hostname()] {
				return fmt.Errorf("refuse to follow a redirect to %s", request.URL.Redacted())
			}
			return nil
		},
	}
}

// download fetches artifact into dir, resuming an earlier partial download,
// and returns the file once its size and SHA-256 match. Other files in dir
// are removed.
func download(ctx context.Context, client *http.Client, artifact Artifact, dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create download directory: %w", err)
	}
	path := filepath.Join(dir, artifact.SHA256+".partial")
	pruneDownloads(dir, filepath.Base(path))

	var offset int64
	if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() && info.Size() < artifact.Size {
		offset = info.Size()
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, artifact.URL, nil)
	if err != nil {
		return "", err
	}
	if offset > 0 {
		request.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
	}
	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("download update: %w", err)
	}
	defer response.Body.Close()

	flags := os.O_CREATE | os.O_WRONLY
	switch {
	case response.StatusCode == http.StatusPartialContent && offset > 0 && rangeStart(response) == offset:
		flags |= os.O_APPEND
	case response.StatusCode == http.StatusOK:
		offset = 0
		flags |= os.O_TRUNC
	default:
		return "", fmt.Errorf("download update: %s", response.Status)
	}
	file, err := os.OpenFile(path, flags, 0o600)
	if err != nil {
		return "", fmt.Errorf("open download: %w", err)
	}
	remaining := artifact.Size - offset
	written, copyErr := io.Copy(file, io.LimitReader(response.Body, remaining+1))
	closeErr := file.Close()
	switch {
	case written > remaining:
		removeFile(path)
		return "", &integrityError{reason: "the download is larger than the signed size"}
	case copyErr != nil:
		return "", fmt.Errorf("download update: %w", copyErr)
	case closeErr != nil:
		return "", fmt.Errorf("write download: %w", closeErr)
	case written < remaining:
		return "", fmt.Errorf("download update: got %d of %d bytes", offset+written, artifact.Size)
	}

	sum, err := sha256File(path)
	if err != nil {
		return "", err
	}
	if sum != artifact.SHA256 {
		removeFile(path)
		return "", &integrityError{reason: "the download does not match the signed SHA-256"}
	}
	return path, nil
}

// rangeStart returns the first byte of a 206 response's Content-Range, or -1.
func rangeStart(response *http.Response) int64 {
	value, ok := strings.CutPrefix(response.Header.Get("Content-Range"), "bytes ")
	if !ok {
		return -1
	}
	start, _, ok := strings.Cut(value, "-")
	if !ok {
		return -1
	}
	offset, err := strconv.ParseInt(start, 10, 64)
	if err != nil {
		return -1
	}
	return offset
}

func sha256File(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open download: %w", err)
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("hash download: %w", err)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func pruneDownloads(dir, keep string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.Name() != keep && entry.Type().IsRegular() {
			removeFile(filepath.Join(dir, entry.Name()))
		}
	}
}

func removeFile(path string) {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintf(os.Stderr, "remove %v\n", err)
	}
}
