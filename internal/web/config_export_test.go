package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func exportTestState() appState {
	return appState{
		Apps: []app{{
			ID:               "app-1",
			Name:             "Greendale",
			Slug:             "greendale",
			Protocol:         "oidc+saml",
			OIDCClientID:     "greendale-client",
			OIDCClientSecret: "secret",
			OIDCRedirectURIs: []string{"http://client.test/callback"},
			SAMLACSURL:       "http://client.test/saml/acs",
			SAMLEntityID:     "client-sp",
		}},
	}
}

func TestAppConfigJSONExportsConnectionValues(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(exportTestState()))
	svc := newTestIDPApp(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/apps/app-1/config.json", nil)
	svc.routes().ServeHTTP(rec, req)

	r.Equal(http.StatusOK, rec.Code)
	var export appConfigExport
	r.NoError(json.Unmarshal(rec.Body.Bytes(), &export))
	r.Equal("Greendale", export.Environment)
	r.Equal("greendale", export.Slug)
	r.NotNil(export.OIDC)
	r.Equal("greendale-client", export.OIDC.ClientID)
	r.Equal("secret", export.OIDC.ClientSecret)
	r.Contains(export.OIDC.Issuer, "/oidc/greendale")
	r.Contains(export.OIDC.DiscoveryURL, "/.well-known/openid-configuration")
	r.NotNil(export.SAML)
	r.Contains(export.SAML.SSOURL, "/saml/greendale/sso")
	r.Contains(export.SAML.CertificatePEM, "BEGIN CERTIFICATE")
	r.Equal("client-sp", export.SAML.SPEntityID)
}

func TestAppConfigJSONUnknownApp(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(exportTestState()))
	svc := newTestIDPApp(t)

	rec := httptest.NewRecorder()
	svc.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/apps/nope/config.json", nil))

	r.Equal(http.StatusNotFound, rec.Code)
}

func TestSAMLMetadataDownloadAndCertificate(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(exportTestState()))
	svc := newTestIDPApp(t)

	rec := httptest.NewRecorder()
	svc.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/saml/greendale/metadata?download=1", nil))
	r.Equal(http.StatusOK, rec.Code)
	r.Contains(rec.Header().Get("Content-Disposition"), "scimtest-greendale-idp-metadata.xml")
	r.Contains(rec.Body.String(), "EntityDescriptor")
	r.Contains(rec.Body.String(), `use="signing"`)
	r.NotContains(rec.Body.String(), `use="encryption"`)

	rec = httptest.NewRecorder()
	svc.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/saml/greendale/metadata", nil))
	r.Equal(http.StatusOK, rec.Code)
	r.Empty(rec.Header().Get("Content-Disposition"))

	rec = httptest.NewRecorder()
	svc.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/saml/greendale/certificate.pem", nil))
	r.Equal(http.StatusOK, rec.Code)
	r.Contains(rec.Header().Get("Content-Disposition"), "scimtest-greendale.pem")
	r.Contains(rec.Body.String(), "BEGIN CERTIFICATE")
}

func TestOIDCDiscoveryPathInsertionAliasAndScopes(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	state := exportTestState()
	state.Apps[0].IncludeGroupsClaim = true
	r.NoError(saveState(state))
	svc := newTestIDPApp(t)

	for _, path := range []string{
		"/oidc/greendale/.well-known/openid-configuration",
		"/.well-known/openid-configuration/oidc/greendale",
	} {
		rec := httptest.NewRecorder()
		svc.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		r.Equal(http.StatusOK, rec.Code, path)
		var discovery struct {
			Issuer string   `json:"issuer"`
			Scopes []string `json:"scopes_supported"`
		}
		r.NoError(json.Unmarshal(rec.Body.Bytes(), &discovery))
		r.Contains(discovery.Issuer, "/oidc/greendale")
		r.Contains(discovery.Scopes, "groups")
	}

	// Without the groups claim, the groups scope is not advertised.
	state.Apps[0].IncludeGroupsClaim = false
	r.NoError(saveState(state))
	rec := httptest.NewRecorder()
	svc.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oidc/greendale/.well-known/openid-configuration", nil))
	var discovery struct {
		Scopes []string `json:"scopes_supported"`
	}
	r.NoError(json.Unmarshal(rec.Body.Bytes(), &discovery))
	r.NotContains(discovery.Scopes, "groups")
}
