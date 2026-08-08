package web

import (
	"net/http"
)

// appConfigExport is the machine-readable connection bundle served at
// /apps/{id}/config.json so test suites and CI can configure a relying
// party or service provider without scraping the admin UI.
type appConfigExport struct {
	Environment string            `json:"environment"`
	Slug        string            `json:"slug"`
	OIDC        *oidcConfigExport `json:"oidc,omitempty"`
	SAML        *samlConfigExport `json:"saml,omitempty"`
}

type oidcConfigExport struct {
	Issuer       string   `json:"issuer"`
	DiscoveryURL string   `json:"discovery_url"`
	AuthorizeURL string   `json:"authorize_url"`
	TokenURL     string   `json:"token_url"`
	UserinfoURL  string   `json:"userinfo_url"`
	JWKSURL      string   `json:"jwks_url"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret,omitempty"`
	PublicClient bool     `json:"public_client"`
	RedirectURIs []string `json:"redirect_uris,omitempty"`
}

type samlConfigExport struct {
	SSOURL         string `json:"sso_url"`
	IDPEntityID    string `json:"idp_entity_id"`
	MetadataURL    string `json:"metadata_url"`
	CertificatePEM string `json:"certificate_pem"`
	SPEntityID     string `json:"sp_entity_id,omitempty"`
	ACSURL         string `json:"acs_url,omitempty"`
	Audience       string `json:"audience,omitempty"`
	NameIDFormat   string `json:"name_id_format,omitempty"`
}

// handleAppConfigJSON serves an environment's connection values as JSON.
// It is an admin route: the export includes the client secret, exactly as
// the setup panel already shows it on the loopback listener.
func (a *webApp) handleAppConfigJSON(w http.ResponseWriter, r *http.Request) {
	state, err := loadState()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	foundApp, ok := appByID(state.Apps, r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}

	baseURL := a.effectiveIDPBaseURL(r, state)
	export := appConfigExport{Environment: foundApp.Name, Slug: foundApp.Slug}
	if supportsOIDC(foundApp) {
		issuer := oidcIssuer(baseURL, foundApp)
		export.OIDC = &oidcConfigExport{
			Issuer:       issuer,
			DiscoveryURL: issuer + "/.well-known/openid-configuration",
			AuthorizeURL: issuer + "/authorize",
			TokenURL:     issuer + "/token",
			UserinfoURL:  issuer + "/userinfo",
			JWKSURL:      issuer + "/jwks",
			ClientID:     foundApp.OIDCClientID,
			ClientSecret: foundApp.OIDCClientSecret,
			PublicClient: foundApp.OIDCPublicClient,
			RedirectURIs: foundApp.OIDCRedirectURIs,
		}
		if foundApp.OIDCPublicClient {
			export.OIDC.ClientSecret = ""
		}
	}
	if supportsSAML(foundApp) {
		metadataURL := baseURL + "/saml/" + foundApp.Slug + "/metadata"
		nameIDFormat := foundApp.SAMLNameIDFormat
		if nameIDFormat == "" {
			nameIDFormat = samlNameIDFormatForField(foundApp.SAMLNameIDField)
		}
		export.SAML = &samlConfigExport{
			SSOURL:         baseURL + "/saml/" + foundApp.Slug + "/sso",
			IDPEntityID:    metadataURL,
			MetadataURL:    metadataURL,
			CertificatePEM: certificatePEM(a.certDER),
			SPEntityID:     foundApp.SAMLEntityID,
			ACSURL:         foundApp.SAMLACSURL,
			Audience:       foundApp.SAMLAudience,
			NameIDFormat:   nameIDFormat,
		}
	}

	writeJSON(w, export)
}

// handleSAMLCertificate serves the IDP signing certificate as a PEM file,
// for service providers that want a certificate upload instead of a paste.
func (a *webApp) handleSAMLCertificate(w http.ResponseWriter, r *http.Request) {
	_, foundApp, ok := appForProtocol(w, r, supportsSAML)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="scimtest-`+foundApp.Slug+`.pem"`)
	if _, err := w.Write([]byte(certificatePEM(a.certDER))); err != nil {
		return
	}
}
