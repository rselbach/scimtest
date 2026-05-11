package web

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/stretchr/testify/require"
)

func TestOIDCAuthorizationCodeFlowUsesSharedDirectory(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	svc := newTestIDPApp(t)
	state := appState{
		Config: config{IDPBaseURL: "http://idp.test"},
		Users: []user{{
			ID:         "usr-1",
			GivenName:  "Riley",
			FamilyName: "Stone",
			Email:      "riley@example.test",
			Username:   "riley",
			Active:     true,
		}},
		Groups: []group{{
			ID:          "grp-1",
			DisplayName: "Engineering",
			MemberIDs:   []string{"usr-1"},
		}},
		Apps: []app{{
			ID:                 "app-1",
			Name:               "Example",
			Slug:               "example",
			Protocol:           "oidc",
			OIDCClientID:       "example-client",
			OIDCClientSecret:   "secret",
			OIDCRedirectURIs:   []string{"http://client.test/callback"},
			IncludeGroupsClaim: true,
		}},
	}
	r.NoError(saveState(state))

	discovery := httptest.NewRecorder()
	svc.routes().ServeHTTP(discovery, httptest.NewRequest(http.MethodGet, "/oidc/example/.well-known/openid-configuration", nil))
	r.Equal(http.StatusOK, discovery.Code)
	var metadata map[string]any
	r.NoError(json.Unmarshal(discovery.Body.Bytes(), &metadata))
	r.Equal("http://idp.test/oidc/example", metadata["issuer"])

	form := url.Values{
		"response_type": {"code"},
		"client_id":     {"example-client"},
		"redirect_uri":  {"http://client.test/callback"},
		"scope":         {"openid profile email groups"},
		"user_id":       {"usr-1"},
		"state":         {"abc"},
	}
	authorize := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/oidc/example/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	svc.routes().ServeHTTP(authorize, req)
	r.Equal(http.StatusFound, authorize.Code)
	location, err := url.Parse(authorize.Header().Get("Location"))
	r.NoError(err)
	code := location.Query().Get("code")
	r.NotEmpty(code)
	r.Equal("abc", location.Query().Get("state"))

	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"http://client.test/callback"},
		"client_id":     {"example-client"},
		"client_secret": {"secret"},
	}
	token := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/oidc/example/token", strings.NewReader(tokenForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	svc.routes().ServeHTTP(token, req)
	r.Equal(http.StatusOK, token.Code)
	var tokenBody map[string]any
	r.NoError(json.Unmarshal(token.Body.Bytes(), &tokenBody))
	r.NotEmpty(tokenBody["access_token"])
	r.NotEmpty(tokenBody["id_token"])
}

func TestSignedSAMLResponseUsesSharedGroups(t *testing.T) {
	r := require.New(t)
	svc := newTestIDPApp(t)
	state := appState{
		Config: config{IDPBaseURL: "http://idp.test"},
		Users: []user{{
			ID:       "usr-1",
			Email:    "riley@example.test",
			Username: "riley",
			Active:   true,
		}},
		Groups: []group{{
			ID:          "grp-1",
			DisplayName: "Engineering",
			MemberIDs:   []string{"usr-1"},
		}},
		Apps: []app{{
			ID:                     "app-1",
			Name:                   "Example",
			Slug:                   "example",
			Protocol:               "saml",
			SAMLACSURL:             "http://client.test/saml/acs",
			SAMLEntityID:           "urn:client:test",
			SAMLNameIDFormat:       defaultSAMLEmailNameIDFormat,
			SAMLEmailAttributeName: defaultSAMLEmailAttributeName,
			IncludeGroupsClaim:     true,
		}},
	}

	response, err := svc.buildSignedSAMLResponse(state, state.Config.IDPBaseURL, state.Apps[0], state.Users[0])
	r.NoError(err)
	r.Contains(response, "<ds:Signature")
	r.Contains(response, `Name="groups"`)
	r.Contains(response, "Engineering")
	r.Contains(response, `Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"`)

	doc := etree.NewDocument()
	r.NoError(doc.ReadFromString(response))
	assertion := findElementByLocalName(doc.Root(), "Assertion")
	r.NotNil(assertion)
	cert, err := x509.ParseCertificate(svc.certDER)
	r.NoError(err)
	validator := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{cert},
	})
	_, err = validator.Validate(assertion)
	r.NoError(err)
}

func newTestIDPApp(t *testing.T) *webApp {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	certDER, err := selfSignedCert(key)
	require.NoError(t, err)
	return &webApp{
		signingKey:   key,
		certDER:      certDER,
		authCodes:    make(map[string]authCode),
		accessTokens: make(map[string]accessToken),
	}
}
