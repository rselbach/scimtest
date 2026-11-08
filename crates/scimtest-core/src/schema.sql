CREATE TABLE IF NOT EXISTS environments (
id TEXT PRIMARY KEY,
name TEXT NOT NULL,
slug TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS environment_config (
environment_id TEXT NOT NULL,
key TEXT NOT NULL,
value TEXT NOT NULL,
PRIMARY KEY (environment_id, key)
);

CREATE TABLE IF NOT EXISTS config (
key TEXT PRIMARY KEY,
value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
id TEXT NOT NULL,
environment_id TEXT NOT NULL DEFAULT 'env_default',
given_name TEXT NOT NULL,
family_name TEXT NOT NULL,
email TEXT NOT NULL,
username TEXT NOT NULL,
active INTEGER NOT NULL,
remote_id TEXT NOT NULL DEFAULT '',
dirty INTEGER NOT NULL,
deleted INTEGER NOT NULL,
last_error TEXT NOT NULL DEFAULT '',
employee_number TEXT NOT NULL DEFAULT '',
cost_center TEXT NOT NULL DEFAULT '',
organization TEXT NOT NULL DEFAULT '',
division TEXT NOT NULL DEFAULT '',
department TEXT NOT NULL DEFAULT '',
manager_id TEXT NOT NULL DEFAULT '',
attributes TEXT NOT NULL DEFAULT '',
PRIMARY KEY (environment_id, id)
);

CREATE TABLE IF NOT EXISTS groups (
id TEXT NOT NULL,
environment_id TEXT NOT NULL DEFAULT 'env_default',
display_name TEXT NOT NULL,
remote_id TEXT NOT NULL DEFAULT '',
dirty INTEGER NOT NULL,
deleted INTEGER NOT NULL,
last_error TEXT NOT NULL DEFAULT '',
PRIMARY KEY (environment_id, id)
);

CREATE TABLE IF NOT EXISTS apps (
id TEXT PRIMARY KEY,
environment_id TEXT NOT NULL DEFAULT 'env_default',
name TEXT NOT NULL,
slug TEXT NOT NULL,
protocol TEXT NOT NULL,
oidc_client_id TEXT NOT NULL DEFAULT '',
oidc_client_secret TEXT NOT NULL DEFAULT '',
oidc_public_client INTEGER NOT NULL DEFAULT 0,
oidc_redirect_uris TEXT NOT NULL DEFAULT '',
saml_entity_id TEXT NOT NULL DEFAULT '',
saml_acs_url TEXT NOT NULL DEFAULT '',
saml_audience TEXT NOT NULL DEFAULT '',
saml_name_id_field TEXT NOT NULL DEFAULT 'email',
saml_name_id_format TEXT NOT NULL DEFAULT '',
saml_email_attribute_name TEXT NOT NULL DEFAULT '',
saml_verify_requests INTEGER NOT NULL DEFAULT 0,
saml_request_certificate_pem TEXT NOT NULL DEFAULT '',
saml_encryption_certificate_pem TEXT NOT NULL DEFAULT '',
saml_encryption_algorithm TEXT NOT NULL DEFAULT 'aes256-gcm',
saml_signing_mode TEXT NOT NULL DEFAULT 'assertion',
include_groups_claim INTEGER NOT NULL DEFAULT 0,
allow_any_oidc_redirect INTEGER NOT NULL DEFAULT 1,
scim_enabled INTEGER NOT NULL DEFAULT 0,
scim_base_url TEXT NOT NULL DEFAULT '',
scim_bearer_token TEXT NOT NULL DEFAULT '',
scim_auto_open_trace INTEGER NOT NULL DEFAULT 0,
scim_capabilities_known INTEGER NOT NULL DEFAULT 0,
scim_patch_supported INTEGER NOT NULL DEFAULT 0,
scim_filter_supported INTEGER NOT NULL DEFAULT 0,
oidc_claim_mappings TEXT NOT NULL DEFAULT '',
saml_attribute_mappings TEXT NOT NULL DEFAULT '',
chooser_mode TEXT NOT NULL DEFAULT 'list',
oidc_jwt_access_tokens INTEGER NOT NULL DEFAULT 0,
oidc_access_token_audience TEXT NOT NULL DEFAULT '',
oidc_backchannel_logout_uri TEXT NOT NULL DEFAULT '',
oidc_backchannel_logout_session_required INTEGER NOT NULL DEFAULT 0,
persona TEXT NOT NULL DEFAULT 'generic',
groups_overage_threshold INTEGER NOT NULL DEFAULT 0,
saml_slo_url TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS app_user_sync (
app_id TEXT NOT NULL,
user_id TEXT NOT NULL,
remote_id TEXT NOT NULL DEFAULT '',
dirty INTEGER NOT NULL DEFAULT 1,
deleted INTEGER NOT NULL DEFAULT 0,
last_error TEXT NOT NULL DEFAULT '',
PRIMARY KEY (app_id, user_id)
);

CREATE TABLE IF NOT EXISTS app_group_sync (
app_id TEXT NOT NULL,
group_id TEXT NOT NULL,
remote_id TEXT NOT NULL DEFAULT '',
dirty INTEGER NOT NULL DEFAULT 1,
deleted INTEGER NOT NULL DEFAULT 0,
last_error TEXT NOT NULL DEFAULT '',
PRIMARY KEY (app_id, group_id)
);

CREATE TABLE IF NOT EXISTS group_members (
group_id TEXT NOT NULL,
environment_id TEXT NOT NULL DEFAULT 'env_default',
user_id TEXT NOT NULL,
position INTEGER NOT NULL,
PRIMARY KEY (environment_id, group_id, user_id)
);

CREATE TABLE IF NOT EXISTS operation_logs (
id INTEGER PRIMARY KEY AUTOINCREMENT,
environment_id TEXT NOT NULL DEFAULT 'env_default',
app_id TEXT NOT NULL DEFAULT '',
resource_type TEXT NOT NULL,
resource_id TEXT NOT NULL,
label TEXT NOT NULL,
kind TEXT NOT NULL DEFAULT 'sync',
summary TEXT NOT NULL DEFAULT '',
operation TEXT NOT NULL,
method TEXT NOT NULL,
path TEXT NOT NULL,
request_body TEXT NOT NULL,
status TEXT NOT NULL,
response_retry_after TEXT NOT NULL DEFAULT '',
response_body TEXT NOT NULL,
error_text TEXT NOT NULL,
created_at TEXT NOT NULL
);
