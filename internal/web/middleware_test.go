package web

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRecoverPanicsTurnsPanicInto500(t *testing.T) {
	r := require.New(t)
	handler := recoverPanics(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	r.Equal(http.StatusInternalServerError, rec.Code)
	r.Contains(rec.Body.String(), "boom")
}

func TestRecoverPanicsPassesAbortHandlerThrough(t *testing.T) {
	r := require.New(t)
	handler := recoverPanics(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic(http.ErrAbortHandler)
	}))
	r.PanicsWithValue(http.ErrAbortHandler, func() {
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	})
}
