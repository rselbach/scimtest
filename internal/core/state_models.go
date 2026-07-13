package core

import (
	"encoding/json"
	"strings"
)

type Environment struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Slug string `json:"slug"`
}

type Config struct {
	BaseURL               string `json:"base_url"`
	BearerToken           string `json:"bearer_token"`
	AutoOpenSyncTrace     bool   `json:"auto_open_sync_trace"`
	SCIMDisabled          bool   `json:"scim_disabled,omitempty"`
	IDPBaseURL            string `json:"idp_base_url,omitempty"`
	TrustForwardedHeaders bool   `json:"trust_forwarded_headers,omitempty"`
	RgrokInstanceID       string `json:"rgrok_instance_id,omitempty"`
	SigningPrivateKeyPEM  string `json:"signing_private_key_pem,omitempty"`
	SigningCertificatePEM string `json:"signing_certificate_pem,omitempty"`
}

type User struct {
	ID         string `json:"id"`
	GivenName  string `json:"given_name,omitempty"`
	FamilyName string `json:"family_name,omitempty"`
	Email      string `json:"email"`
	Username   string `json:"username"`
	Active     bool   `json:"active"`
	RemoteID   string `json:"remote_id,omitempty"`
	Dirty      bool   `json:"dirty"`
	Deleted    bool   `json:"deleted"`
	LastError  string `json:"last_error,omitempty"`
}

func (u *User) UnmarshalJSON(data []byte) error {
	type alias User
	aux := struct {
		alias
		LegacyName string `json:"name,omitempty"`
		Active     *bool  `json:"active"`
	}{}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	*u = User(aux.alias)
	if aux.Active != nil {
		u.Active = *aux.Active
	}

	if strings.TrimSpace(aux.LegacyName) == "" {
		if aux.Active == nil {
			u.Active = true
		}

		return nil
	}

	givenName, familyName := SplitName(aux.LegacyName)
	if strings.TrimSpace(u.GivenName) == "" {
		u.GivenName = givenName
	}
	if strings.TrimSpace(u.FamilyName) == "" {
		u.FamilyName = familyName
	}
	if aux.Active == nil {
		u.Active = true
	}

	return nil
}

type AppState struct {
	Environment     Environment                             `json:"environment"`
	Environments    []Environment                           `json:"environments,omitempty"`
	Config          Config                                  `json:"config"`
	Users           []User                                  `json:"users"`
	Groups          []Group                                 `json:"groups"`
	Apps            []App                                   `json:"apps"`
	UserOperations  map[string][]OperationLog               `json:"-"`
	GroupOperations map[string][]OperationLog               `json:"-"`
	UserSync        map[string]map[string]ResourceSyncState `json:"-"`
	GroupSync       map[string]map[string]ResourceSyncState `json:"-"`
}

// ResourceSyncState is one app's remote state for a directory resource.
type ResourceSyncState struct {
	RemoteID  string
	Dirty     bool
	Deleted   bool
	LastError string
}

type OperationLog struct {
	AppID              string
	Kind               string
	Summary            string
	Operation          string
	Method             string
	Path               string
	RequestBody        string
	Status             string
	ResponseRetryAfter string
	ResponseBody       string
	Err                string
	CreatedAt          string
}

type Group struct {
	ID          string   `json:"id"`
	DisplayName string   `json:"display_name"`
	MemberIDs   []string `json:"member_ids,omitempty"`
	RemoteID    string   `json:"remote_id,omitempty"`
	Dirty       bool     `json:"dirty"`
	Deleted     bool     `json:"deleted"`
	LastError   string   `json:"last_error,omitempty"`
}

type App struct {
	EnvironmentName        string   `json:"-"`
	ID                     string   `json:"id"`
	Name                   string   `json:"name"`
	Slug                   string   `json:"slug"`
	Protocol               string   `json:"protocol"`
	OIDCClientID           string   `json:"oidc_client_id,omitempty"`
	OIDCClientSecret       string   `json:"oidc_client_secret,omitempty"`
	OIDCPublicClient       bool     `json:"oidc_public_client,omitempty"`
	OIDCRedirectURIs       []string `json:"oidc_redirect_uris,omitempty"`
	AllowAnyOIDCRedirect   bool     `json:"allow_any_oidc_redirect,omitempty"`
	SAMLEntityID           string   `json:"saml_entity_id,omitempty"`
	SAMLACSURL             string   `json:"saml_acs_url,omitempty"`
	SAMLAudience           string   `json:"saml_audience,omitempty"`
	SAMLNameIDField        string   `json:"saml_name_id_field,omitempty"`
	SAMLNameIDFormat       string   `json:"saml_name_id_format,omitempty"`
	SAMLEmailAttributeName string   `json:"saml_email_attribute_name,omitempty"`
	IncludeGroupsClaim     bool     `json:"include_groups_claim"`
	SCIMEnabled            bool     `json:"scim_enabled,omitempty"`
	SCIMBaseURL            string   `json:"scim_base_url,omitempty"`
	SCIMBearerToken        string   `json:"scim_bearer_token,omitempty"`
	SCIMAutoOpenTrace      bool     `json:"scim_auto_open_trace,omitempty"`
	SCIMCapabilitiesKnown  bool     `json:"scim_capabilities_known,omitempty"`
	SCIMPatchSupported     bool     `json:"scim_patch_supported,omitempty"`
}
