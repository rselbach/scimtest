package web

import (
	"bytes"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAppTestsUnsavedSCIMSettings(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.Equal("Bearer unsaved-token", req.Header.Get("Authorization"))
		_, err := fmt.Fprint(w, `{"patch":{"supported":false}}`)
		r.NoError(err)
	}))
	defer server.Close()
	r.NoError(saveState(appState{Apps: []app{{ID: "app-1", Name: "Greendale", Slug: "greendale", Protocol: "scim", SCIMEnabled: true, SCIMBaseURL: "https://saved.invalid", SCIMBearerToken: "saved-token"}}}))
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	r.NoError(writer.WriteField("id", "app-1"))
	r.NoError(writer.WriteField("scim_base_url", server.URL))
	r.NoError(writer.WriteField("scim_bearer_token", "unsaved-token"))
	r.NoError(writer.Close())
	req := httptest.NewRequest(http.MethodPost, "/apps/test-scim", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rec := httptest.NewRecorder()

	newTestIDPApp(t).routes().ServeHTTP(rec, req)

	r.Equal(http.StatusOK, rec.Code)
	r.JSONEq(`{"message":"Connection successful. PATCH is not supported."}`, rec.Body.String())
	state, err := loadState()
	r.NoError(err)
	r.Equal("https://saved.invalid", state.Apps[0].SCIMBaseURL)
}
