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

			debugApp(false, tc.includeSecrets).writeDebugHTTPResponse(&output, response)

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
	app := debugApp(true, false)
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

func TestDebugOIDCTokenPayload(t *testing.T) {
	tests := map[string]struct {
		debug bool
		want  string
	}{
		"disabled": {},
		"enabled": {
			debug: true,
			want: "\n===== OIDC ID token payload =====\n" +
				`{"aud":"greendale-client","sub":"troy"}` +
				"\n===== end OIDC ID token payload =====\n",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			var output bytes.Buffer
			app := debugApp(tc.debug, false)

			app.writeDebugOIDCTokenPayload(&output, "ID token", []byte(`{"aud":"greendale-client","sub":"troy"}`))

			r.Equal(tc.want, output.String())
		})
	}
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

func TestDebugRedactsAuthorizationCodeInLocationHeader(t *testing.T) {
	r := require.New(t)
	response := &debugResponseWriter{ResponseWriter: httptest.NewRecorder(), status: http.StatusFound}
	response.Header().Set("Location", "https://rp.example/callback?code=paintball&state=xyz")
	var output bytes.Buffer

	(&webApp{}).writeDebugHTTPResponse(&output, response)

	r.NotContains(output.String(), "paintball")
	r.Contains(output.String(), "code=%5BREDACTED%5D")
	r.Contains(output.String(), "state=xyz")

	var secretsOutput bytes.Buffer
	debugApp(false, true).writeDebugHTTPResponse(&secretsOutput, response)
	r.Contains(secretsOutput.String(), "code=paintball")
}

func TestDebugRequestURIRedaction(t *testing.T) {
	for name, tc := range map[string]struct {
		query          string
		includeSecrets bool
		want           string
	}{
		"credentials": {
			query: "code=troy-code&client_secret=greendale-secret&state=study-group",
			want:  "client_secret=%5BREDACTED%5D&code=%5BREDACTED%5D&state=study-group",
		},
		"encoded and repeated keys": {
			query: "%63ode=troy-code&code=abed-code&CLIENT_SECRET=greendale-secret",
			want:  "CLIENT_SECRET=%5BREDACTED%5D&code=%5BREDACTED%5D",
		},
		"PKCE verifier": {
			query: "code_verifier=greendale-verifier&code_challenge=public-challenge",
			want:  "code_challenge=public-challenge&code_verifier=%5BREDACTED%5D",
		},
		"malformed query": {
			query: "client_secret=greendale-secret%zz&code=troy-code",
			want:  "POST [REDACTED] HTTP/1.1",
		},
		"explicit secrets": {
			query:          "code=troy-code&client_secret=greendale-secret",
			includeSecrets: true,
			want:           "code=troy-code&client_secret=greendale-secret",
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			app := debugApp(false, tc.includeSecrets)
			app.trafficRecord.Store(true)
			req := httptest.NewRequest(http.MethodPost, "/oidc/greendale/token?"+tc.query, nil)
			var output bytes.Buffer
			app.writeDebugHTTPRequest(&output, req, nil)
			r.Contains(output.String(), tc.want)
			handler := app.debugRPHandler(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadRequest) })
			handler(httptest.NewRecorder(), req)
			entries := app.traffic.snapshot()
			r.Len(entries, 1)
			r.Contains(entries[0], tc.want)
			if !tc.includeSecrets {
				for _, secret := range []string{"troy-code", "abed-code", "greendale-secret", "greendale-verifier"} {
					r.NotContains(output.String(), secret)
					r.NotContains(entries[0], secret)
				}
			}
		})
	}
}

func debugApp(debugRP, debugSecrets bool) *webApp {
	app := &webApp{}
	app.debugRP.Store(debugRP)
	app.debugSecrets.Store(debugSecrets)
	return app
}
