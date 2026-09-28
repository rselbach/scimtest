package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAPIRequiresInstanceToken(t *testing.T) {
	app := &webApp{}
	app.instanceToken = "local-token"

	request := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	response := httptest.NewRecorder()
	app.adminRoutes().ServeHTTP(response, request)

	require.Equal(t, http.StatusUnauthorized, response.Code)
	require.Equal(t, "application/json", response.Header().Get("Content-Type"))
}

func TestAPIRejectsInvalidJSONBoundary(t *testing.T) {
	app := &webApp{}
	app.instanceToken = "local-token"
	handler := app.adminRoutes()

	tests := map[string]struct {
		contentType string
		body        string
		want        int
	}{
		"content type":    {contentType: "text/plain", body: `{}`, want: http.StatusUnsupportedMediaType},
		"unknown field":   {contentType: "application/json", body: `{"unknown":true}`, want: http.StatusBadRequest},
		"trailing object": {contentType: "application/json", body: `{} {}`, want: http.StatusBadRequest},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/api/v1/environments", strings.NewReader(tc.body))
			request.Header.Set(instanceTokenHeader, "local-token")
			request.Header.Set("Content-Type", tc.contentType)
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			require.Equal(t, tc.want, response.Code)
			require.Equal(t, "application/json", response.Header().Get("Content-Type"))
		})
	}
}

func TestAPIFailsClosedWithEmptyConfiguredToken(t *testing.T) {
	app := &webApp{}
	request := httptest.NewRequest(http.MethodGet, "/api/v1", nil)
	response := httptest.NewRecorder()

	app.adminRoutes().ServeHTTP(response, request)

	require.Equal(t, http.StatusUnauthorized, response.Code)
}
