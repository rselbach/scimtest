package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAppDiscoversAndPersistsSCIMCapabilities(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := fmt.Fprint(w, `{"patch":{"supported":true}}`)
		r.NoError(err)
	}))
	defer server.Close()
	r.NoError(saveState(appState{Apps: []app{{ID: "app-1", Name: "Greendale", Slug: "greendale", Protocol: "scim", SCIMEnabled: true, SCIMBaseURL: server.URL, SCIMBearerToken: "chang-secret"}}}))
	app := newTestIDPApp(t)
	rec := httptest.NewRecorder()

	app.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/apps/app-1/discover-scim", nil))

	r.Equal(http.StatusSeeOther, rec.Code)
	state, err := loadState()
	r.NoError(err)
	r.True(state.Apps[0].SCIMCapabilitiesKnown)
	r.True(state.Apps[0].SCIMPatchSupported)
}
