package update

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// handlerTransport serves every request from handler without a network.
type handlerTransport struct {
	handler http.Handler
}

func (h handlerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	recorder := httptest.NewRecorder()
	h.handler.ServeHTTP(recorder, request)
	response := recorder.Result()
	response.Request = request
	return response, nil
}

func testClient(handler http.Handler) *http.Client {
	client := newHTTPClient()
	client.Transport = handlerTransport{handler: handler}
	return client
}

func artifactFor(body []byte) Artifact {
	sum := sha256.Sum256(body)
	return Artifact{
		OS:        "macos",
		Arch:      "arm64",
		Kind:      KindAppZip,
		MinimumOS: "26.0",
		URL:       artifactPrefix + "v2.6.0/scimtest-desktop_2.6.0_arm64.zip",
		Size:      int64(len(body)),
		SHA256:    hex.EncodeToString(sum[:]),
	}
}

func TestDownloadResumesPartialFile(t *testing.T) {
	r := require.New(t)
	body := bytes.Repeat([]byte("greendale"), 1000)
	artifact := artifactFor(body)
	dir := t.TempDir()
	r.NoError(os.WriteFile(filepath.Join(dir, artifact.SHA256+".partial"), body[:4000], 0o600))
	r.NoError(os.WriteFile(filepath.Join(dir, "stale.partial"), []byte("old"), 0o600))
	var gotRange string
	client := testClient(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		gotRange = request.Header.Get("Range")
		http.ServeContent(w, request, "scimtest.zip", time.Time{}, bytes.NewReader(body))
	}))

	path, err := download(context.Background(), client, artifact, dir)
	r.NoError(err)
	r.Equal("bytes=4000-", gotRange)
	got, err := os.ReadFile(path)
	r.NoError(err)
	r.Equal(body, got)
	r.NoFileExists(filepath.Join(dir, "stale.partial"))
}

func TestDownloadRejectsWrongBytes(t *testing.T) {
	tests := map[string]struct {
		served []byte
	}{
		"different bytes": {served: bytes.Repeat([]byte("x"), 9000)},
		"too many bytes":  {served: bytes.Repeat([]byte("greendale"), 1001)},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			artifact := artifactFor(bytes.Repeat([]byte("greendale"), 1000))
			dir := t.TempDir()
			client := testClient(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if _, err := w.Write(tc.served); err != nil {
					t.Errorf("write response: %v", err)
				}
			}))

			_, err := download(context.Background(), client, artifact, dir)
			var mismatch *integrityError
			r.True(errors.As(err, &mismatch), "error = %v", err)
			r.NoFileExists(filepath.Join(dir, artifact.SHA256+".partial"))
		})
	}
}

func TestDownloadKeepsShortFileForResume(t *testing.T) {
	r := require.New(t)
	body := bytes.Repeat([]byte("greendale"), 1000)
	artifact := artifactFor(body)
	dir := t.TempDir()
	client := testClient(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write(body[:100]); err != nil {
			t.Errorf("write response: %v", err)
		}
	}))

	_, err := download(context.Background(), client, artifact, dir)
	r.ErrorContains(err, "got 100 of 9000 bytes")
	r.FileExists(filepath.Join(dir, artifact.SHA256+".partial"))
}

func TestRedirectsStayOnGitHub(t *testing.T) {
	tests := map[string]struct {
		target  string
		wantErr bool
	}{
		"release assets": {target: "https://release-assets.githubusercontent.com/a"},
		"objects":        {target: "https://objects.githubusercontent.com/a"},
		"other host":     {target: "https://troy-and-abed.example/a", wantErr: true},
		"plain http":     {target: "http://objects.githubusercontent.com/a", wantErr: true},
		"credentials":    {target: "https://user:secret@github.com/a", wantErr: true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			request, err := http.NewRequest(http.MethodGet, tc.target, nil)
			r.NoError(err)
			err = newHTTPClient().CheckRedirect(request, nil)
			if tc.wantErr {
				r.Error(err)
				return
			}
			r.NoError(err)
		})
	}
}
