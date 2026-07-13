package web

import (
	"bytes"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDebugSAMLResponseRequiresExplicitSecrets(t *testing.T) {
	assertion := `<saml:Assertion><saml:NameID>troy@greendale.edu</saml:NameID></saml:Assertion>`
	body := `<form><input name="SAMLResponse" value="` +
		base64.StdEncoding.EncodeToString([]byte(assertion)) + `"></form>`

	tests := map[string]struct {
		includeSecrets bool
		wantAssertion  bool
	}{
		"redacted by default": {
			wantAssertion: false,
		},
		"included when requested": {
			includeSecrets: true,
			wantAssertion:  true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			response := &debugResponseWriter{ResponseWriter: httptest.NewRecorder()}
			response.Header().Set("Content-Type", "text/html")
			response.body.WriteString(body)
			var output bytes.Buffer

			(&webApp{debugSecrets: tc.includeSecrets}).writeDebugHTTPResponse(&output, response)

			r.Equal(tc.wantAssertion, bytes.Contains(output.Bytes(), []byte(assertion)))
			if !tc.includeSecrets {
				r.NotContains(output.String(), "troy@greendale.edu")
				r.Contains(output.String(), `value="[REDACTED]"`)
			}
		})
	}
}

func TestDebugHandlerRejectsOversizedRequestBody(t *testing.T) {
	r := require.New(t)
	app := &webApp{debugRP: true}
	handler := app.debugRPHandler(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	req := httptest.NewRequest(http.MethodPost, "/oidc/example/token", io.LimitReader(zeroReader{}, maxRPDebugBodyBytes+1))
	req.ContentLength = maxRPDebugBodyBytes + 1
	rec := httptest.NewRecorder()

	handler(rec, req)

	r.Equal(http.StatusRequestEntityTooLarge, rec.Code)
	r.Contains(rec.Body.String(), "exceeds 10485760 bytes")
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

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
