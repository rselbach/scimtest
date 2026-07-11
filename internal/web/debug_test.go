package web

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDebugRedaction(t *testing.T) {
	tests := map[string]struct {
		got  string
		want string
	}{
		"form credentials": {
			got: debugBody("application/x-www-form-urlencoded", []byte(url.Values{
				"client_id":     {"greendale"},
				"client_secret": {"chang-secret"},
				"code":          {"paintball"},
			}.Encode()), false),
			want: "client_id=greendale&client_secret=%5BREDACTED%5D&code=%5BREDACTED%5D",
		},
		"JSON tokens": {
			got:  debugResponseBody("application/json", `{"access_token":"paintball","token_type":"Bearer"}`, false),
			want: "{\n  \"access_token\": \"[REDACTED]\",\n  \"token_type\": \"Bearer\"\n}",
		},
		"SAML postback": {
			got:  debugResponseBody("text/html", `<input name="SAMLResponse" value="assertion">`, false),
			want: `<input name="SAMLResponse" value="[REDACTED]">`,
		},
		"explicit secrets": {
			got:  debugBody("application/x-www-form-urlencoded", []byte("client_secret=chang-secret"), true),
			want: "client_secret=chang-secret",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			r.Equal(tc.want, tc.got)
		})
	}
}

func TestSensitiveDebugHeaders(t *testing.T) {
	tests := map[string]bool{
		"Authorization":       true,
		"cookie":              true,
		"Proxy-Authorization": true,
		"Content-Type":        false,
	}

	for header, want := range tests {
		t.Run(header, func(t *testing.T) {
			r := require.New(t)
			r.Equal(want, isSensitiveHeader(http.CanonicalHeaderKey(header)))
		})
	}
}
