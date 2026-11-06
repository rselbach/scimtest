use super::*;
use crate::{configuration::ClaimMappings, model::Environment};
use sha2::{Digest, Sha256};

pub const PASSWORD_CONTEXTS: &[&str] = &[
    "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:Password",
    "https://refeds.org/profile/sfa",
];
pub const MFA_CONTEXTS: &[&str] = &[
    "https://refeds.org/profile/mfa",
    "http://schemas.openid.net/pape/policies/2007/06/multi-factor",
    "http://schemas.microsoft.com/claims/multipleauthn",
];
pub fn discovery(environment: &Environment, issuer: &str) -> Value {
    let settings = &environment.settings;
    let mappings = &settings.oidc_claim_mappings;
    let auth = if settings.oidc_public_client {
        vec!["none"]
    } else {
        vec!["client_secret_basic", "client_secret_post"]
    };
    let mut grants = vec!["authorization_code", "refresh_token"];
    if !settings.oidc_public_client {
        grants.push("client_credentials");
    }
    let mut scopes = vec!["openid", "profile", "email", "offline_access"];
    if settings.include_groups_claim {
        scopes.push("groups");
    }
    let mut claims = vec![
        "sub",
        &mappings.name,
        &mappings.given_name,
        &mappings.family_name,
        &mappings.username,
        &mappings.email,
        "email_verified",
        &mappings.groups,
        "auth_time",
        "acr",
        "amr",
        "sid",
        "employeeNumber",
        "costCenter",
        "organization",
        "division",
        "department",
        "manager",
    ];
    match settings.persona.as_str() {
        "entra" => {
            claims.retain(|name| *name != "email_verified");
            claims.extend(["tid", "oid", "upn"]);
        }
        "okta" => claims.push("ver"),
        "google" => claims.push("hd"),
        _ => {}
    }
    json!({"issuer":issuer, "authorization_endpoint":format!("{issuer}/authorize"),
        "token_endpoint":format!("{issuer}/token"), "userinfo_endpoint":format!("{issuer}/userinfo"),
        "jwks_uri":format!("{issuer}/jwks"), "introspection_endpoint":format!("{issuer}/introspect"),
        "revocation_endpoint":format!("{issuer}/revoke"), "end_session_endpoint":format!("{issuer}/logout"),
        "backchannel_logout_supported":true, "backchannel_logout_session_supported":true,
        "response_types_supported":["code"], "grant_types_supported":grants,
        "subject_types_supported":["public"], "id_token_signing_alg_values_supported":["RS256"],
        "scopes_supported":scopes, "claims_supported":claims,
        "acr_values_supported":([PASSWORD_CONTEXTS, MFA_CONTEXTS].concat()),
        "code_challenge_methods_supported":["S256"], "token_endpoint_auth_methods_supported":auth,
        "introspection_endpoint_auth_methods_supported":auth, "revocation_endpoint_auth_methods_supported":auth})
}
pub(super) fn user_claims(directory: &Directory, user: &User, scope: &str, issuer: &str) -> Value {
    let settings = &directory.environment.settings;
    let mappings = &settings.oidc_claim_mappings;
    let fields = &user.fields;
    let mut claims = json!({"sub":user.id});
    if has_scope(scope, "profile") {
        for (name, value) in [
            (&mappings.name, label(user)),
            (&mappings.given_name, fields.given_name.clone()),
            (&mappings.family_name, fields.family_name.clone()),
            (&mappings.username, fields.username.clone()),
        ] {
            claims[name] = json!(value);
        }
    }
    if has_scope(scope, "email") {
        claims[&mappings.email] = json!(fields.email);
        claims["email_verified"] = json!(true);
    }
    if settings.include_groups_claim && has_scope(scope, "groups") {
        claims[&mappings.groups] = json!(groups(directory, &user.id));
    }
    let defaults = ClaimMappings::default();
    let renamed: Vec<&str> = [
        (&mappings.name, &defaults.name),
        (&mappings.given_name, &defaults.given_name),
        (&mappings.family_name, &defaults.family_name),
        (&mappings.username, &defaults.username),
        (&mappings.email, &defaults.email),
        (&mappings.groups, &defaults.groups),
    ]
    .into_iter()
    .filter(|(name, default)| name != default)
    .map(|(name, _)| name.as_str())
    .collect();
    let mut set = |name: &str, value: Value| {
        if !renamed.contains(&name) {
            claims[name] = value;
        }
    };
    match settings.persona.as_str() {
        "entra" => {
            set(
                "tid",
                json!(persona_guid(&["tid", &directory.environment.id])),
            );
            if has_scope(scope, "profile") {
                set("oid", json!(object_id(&directory.environment.id, &user.id)));
                let username = fields.username.trim();
                let domain = email_domain(&fields.email);
                let upn = if username.is_empty() {
                    fields.email.trim().into()
                } else if username.contains('@') || domain.is_empty() {
                    username.into()
                } else {
                    format!("{username}@{domain}")
                };
                set("preferred_username", json!(upn));
                set("upn", json!(upn));
            }
            if !renamed.contains(&"email_verified") {
                claims.as_object_mut().unwrap().remove("email_verified");
            }
            let threshold = if settings.groups_overage_threshold > 0 {
                settings.groups_overage_threshold as usize
            } else {
                200
            };
            if claims[&mappings.groups]
                .as_array()
                .is_some_and(|groups| groups.len() > threshold)
            {
                claims.as_object_mut().unwrap().remove(&mappings.groups);
                claims["_claim_names"] = json!({&mappings.groups:"src1"});
                claims["_claim_sources"] = json!({"src1":{"endpoint":format!("{issuer}/users/{}/getMemberObjects", object_id(&directory.environment.id, &user.id))}});
            }
        }
        "okta" => {
            set("ver", json!(1));
            if let Some(groups) = claims[&mappings.groups].as_array_mut()
                && !groups.iter().any(|value| value == "Everyone")
            {
                groups.insert(0, json!("Everyone"));
            }
        }
        "google" => {
            let domain = email_domain(&fields.email);
            if !domain.is_empty() && !["gmail.com", "googlemail.com"].contains(&domain.as_str()) {
                set("hd", json!(domain));
            }
        }
        _ => {}
    }
    if has_scope(scope, "profile") {
        for (name, value) in [
            ("employeeNumber", &fields.employee_number),
            ("costCenter", &fields.cost_center),
            ("organization", &fields.organization),
            ("division", &fields.division),
            ("department", &fields.department),
        ] {
            if !value.is_empty() {
                claims[name] = json!(value);
            }
        }
        if directory.users.iter().any(|manager| {
            manager.id == fields.manager_id
                && !manager.deleted
                && !directory
                    .user_sync
                    .get(&manager.id)
                    .is_some_and(|sync| sync.deleted)
        }) {
            claims["manager"] = json!(fields.manager_id);
        }
        for (name, value) in &fields.attributes {
            if claims.get(name).is_none() && !crate::directory::reserved_attribute(name) {
                claims[name] = json!(value);
            }
        }
    }
    claims
}
pub(super) fn groups(directory: &Directory, user: &str) -> Vec<String> {
    let mut groups = directory
        .projected_groups()
        .into_iter()
        .filter(|group| {
            !group.deleted && group.fields.member_ids.iter().any(|member| member == user)
        })
        .map(|group| group.fields.display_name)
        .collect::<Vec<_>>();
    groups.sort();
    groups
}
fn email_domain(email: &str) -> String {
    email
        .trim()
        .split_once('@')
        .map(|(_, domain)| domain.to_ascii_lowercase())
        .unwrap_or_default()
}
fn persona_guid(parts: &[&str]) -> String {
    let mut sum = Sha256::digest(format!("scimtest-persona\0{}", parts.join("\0")));
    sum[6] = (sum[6] & 0x0f) | 0x80;
    sum[8] = (sum[8] & 0x3f) | 0x80;
    uuid::Uuid::from_bytes(sum[..16].try_into().unwrap()).to_string()
}
pub fn object_id(environment: &str, user: &str) -> String {
    persona_guid(&["oid", environment, user])
}
