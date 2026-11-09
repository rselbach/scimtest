package core

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDiscoverSCIMCapabilities(t *testing.T) {
	r := require.New(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.Equal("/ServiceProviderConfig", req.URL.Path)
		_, err := fmt.Fprint(w, `{"patch":{"supported":true},"filter":{"supported":true}}`)
		r.NoError(err)
	}))
	defer server.Close()

	capabilities, err := DiscoverSCIMCapabilities(Config{BaseURL: server.URL, BearerToken: "chang-secret"})

	r.NoError(err)
	r.True(capabilities.PatchSupported)
	r.True(capabilities.FilterSupported)
	r.Len(capabilities.Traces, 1)
	r.Equal("discover", capabilities.Traces[0].Operation)
}
