use crate::{Error, model::*, persistence};
use rusqlite::{Connection, params};
use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::{BTreeMap, HashSet},
    fs,
    io::Write,
    path::Path,
};

#[derive(Default, Deserialize)]
#[serde(default)]
struct Config {
    base_url: String,
    bearer_token: String,
    auto_open_sync_trace: bool,
    scim_disabled: bool,
    idp_base_url: String,
    trust_forwarded_headers: bool,
    tunnel_instance_id: String,
    rgrok_instance_id: String,
    signing_private_key_pem: String,
    signing_certificate_pem: String,
}
#[derive(Default, Deserialize)]
#[serde(default)]
struct State {
    config: Config,
    users: Vec<Value>,
    groups: Vec<Group>,
    apps: Vec<Value>,
}

pub(crate) fn import(connection: &mut Connection, path: &Path) -> Result<(), Error> {
    let occupied: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM apps) OR EXISTS(SELECT 1 FROM users) OR EXISTS(SELECT 1 FROM groups) OR EXISTS(SELECT 1 FROM operation_logs) OR EXISTS(SELECT 1 FROM config WHERE key = 'legacy_json_imported' OR (key IN ('idp_base_url','trust_forwarded_headers','tunnel_instance_id','signing_private_key_pem','signing_certificate_pem') AND value NOT IN ('','0')))",[],|row| row.get(0))?;
    if occupied {
        return Ok(());
    }
    let legacy = if path.extension().is_some_and(|extension| extension == "db") {
        path.with_extension("json")
    } else {
        let mut name = path.as_os_str().to_owned();
        name.push(".json");
        name.into()
    };
    let bytes = match fs::read(&legacy) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(Error::Io(std::io::Error::new(
                error.kind(),
                format!("read legacy state {}: {error}", legacy.display()),
            )));
        }
    };
    let mut value: Value = serde_json::from_slice(&bytes).map_err(|error| {
        Error::Validation(format!("decode legacy state {}: {error}", legacy.display()))
    })?;
    if !value.is_object() && !value.is_null() {
        return Err(Error::Validation(
            "legacy state must be a JSON object".into(),
        ));
    }
    remove_null_fields(&mut value);
    let state: State = serde_json::from_value(if value.is_null() {
        serde_json::json!({})
    } else {
        value
    })?;
    let users = state
        .users
        .into_iter()
        .map(user)
        .collect::<Result<Vec<_>, _>>()?;
    let mut groups = state.groups;
    for group in &mut groups {
        let mut seen = HashSet::new();
        group.fields.member_ids = group
            .fields
            .member_ids
            .iter()
            .map(|id| id.trim().to_owned())
            .filter(|id| !id.is_empty() && seen.insert(id.clone()))
            .collect();
    }
    let mut apps = state
        .apps
        .into_iter()
        .map(environment)
        .collect::<Result<Vec<_>, _>>()?;
    let config = state.config;
    let base = config.base_url.trim().trim_end_matches('/');
    let inherited_scim = !base.is_empty() && !config.scim_disabled;
    if apps.is_empty() && inherited_scim {
        apps.push(environment(serde_json::json!({"id":"app_legacy_scim","name":"SCIM","slug":"scim","protocol":"scim"}))?);
    }
    if apps.is_empty() && (!users.is_empty() || !groups.is_empty()) {
        apps.push(environment(serde_json::json!({"id":"env_default","name":"Default","slug":"default","protocol":"none"}))?);
    }
    let mut directories = Vec::new();
    for mut environment in apps {
        let migrated_scim = inherited_scim && !environment.settings.scim_enabled;
        if migrated_scim {
            let settings = &mut environment.settings;
            settings.scim_enabled = true;
            settings.scim_base_url = base.into();
            settings.scim_bearer_token = config.bearer_token.trim().into();
            settings.scim_auto_open_trace = config.auto_open_sync_trace;
        }
        environment.settings.normalize_loaded(&environment.slug);
        let mut directory = Directory {
            environment,
            users: users.clone(),
            groups: groups.clone(),
            ..Default::default()
        };
        if migrated_scim {
            directory.user_sync = users
                .iter()
                .map(|user| {
                    (
                        user.id.clone(),
                        ResourceSyncState {
                            remote_id: user.remote_id.clone(),
                            dirty: user.dirty,
                            deleted: user.deleted,
                            last_error: user.last_error.clone(),
                        },
                    )
                })
                .collect();
            directory.group_sync = groups
                .iter()
                .map(|group| {
                    (
                        group.id.clone(),
                        ResourceSyncState {
                            remote_id: group.remote_id.clone(),
                            dirty: group.dirty,
                            deleted: group.deleted,
                            last_error: group.last_error.clone(),
                        },
                    )
                })
                .collect();
        }
        directories.push(directory);
    }
    // Keep the source intact and commit all imported directories together.
    safety_copy(path, &bytes)?;
    let transaction = connection.transaction()?;
    transaction.execute(
        "INSERT OR IGNORE INTO environments VALUES ('env_default','Default','default')",
        [],
    )?;
    for directory in &directories {
        transaction.execute("UPDATE environments SET slug = '__directory__' WHERE id = 'env_default' AND slug = ?1 AND ?2 != 'env_default'",params![directory.environment.slug,directory.environment.id])?;
        persistence::save_directory(&transaction, directory)?;
    }
    let instance = if config.tunnel_instance_id.is_empty() {
        &config.rgrok_instance_id
    } else {
        &config.tunnel_instance_id
    };
    for (key, value) in [
        (
            "idp_base_url",
            config.idp_base_url.trim().trim_end_matches('/').into(),
        ),
        (
            "trust_forwarded_headers",
            if config.trust_forwarded_headers {
                "1"
            } else {
                "0"
            }
            .into(),
        ),
        ("tunnel_instance_id", instance.trim().into()),
        ("signing_private_key_pem", config.signing_private_key_pem),
        ("signing_certificate_pem", config.signing_certificate_pem),
        ("legacy_json_imported", "1".into()),
    ] {
        transaction.execute(
            "INSERT OR REPLACE INTO config VALUES (?1,?2)",
            params![key, value],
        )?;
    }
    transaction.commit()?;
    Ok(())
}
fn remove_null_fields(value: &mut Value) {
    match value {
        Value::Object(object) => {
            object.retain(|_, value| !value.is_null());
            for value in object.values_mut() {
                remove_null_fields(value);
            }
        }
        Value::Array(values) => {
            for value in values {
                remove_null_fields(value);
            }
        }
        _ => {}
    }
}
fn user(mut value: Value) -> Result<User, Error> {
    if value.is_null() {
        value = serde_json::json!({});
    }
    let legacy_name = value
        .as_object_mut()
        .and_then(|object| object.remove("name"))
        .unwrap_or(Value::String(String::new()));
    let name = legacy_name
        .as_str()
        .ok_or_else(|| Error::Validation("legacy user name must be a string".into()))?;
    let mut user: User = serde_json::from_value(value)?;
    for name in [name, ""] {
        let existing = format!("{} {}", user.fields.given_name, user.fields.family_name);
        let fallback = if !name.trim().is_empty() {
            name
        } else if !existing.trim().is_empty() {
            &existing
        } else {
            &user.fields.username
        };
        let mut parts = fallback.split_whitespace();
        let given = parts.next().unwrap_or_default().to_owned();
        let family = parts.collect::<Vec<_>>().join(" ");
        if user.fields.given_name.trim().is_empty() {
            user.fields.given_name = given;
        }
        if user.fields.family_name.trim().is_empty() {
            user.fields.family_name = family;
        }
    }
    if user.fields.username.trim().is_empty() {
        user.fields.username.clone_from(&user.fields.email);
    }
    Ok(user)
}
fn environment(mut value: Value) -> Result<Environment, Error> {
    if value.is_null() {
        value = serde_json::json!({});
    }
    if let Some(object) = value.as_object_mut() {
        object
            .entry("saml_attribute_mappings")
            .or_insert_with(|| serde_json::json!({}));
        for (key, names) in [
            (
                "oidc_claim_mappings",
                [
                    "name",
                    "given_name",
                    "family_name",
                    "username",
                    "email",
                    "groups",
                ]
                .as_slice(),
            ),
            (
                "saml_attribute_mappings",
                ["given_name", "family_name", "username", "email", "groups"].as_slice(),
            ),
        ] {
            if let Some(Value::Object(mappings)) = object.get_mut(key) {
                mappings.retain(|name, _| names.contains(&name.as_str()));
            }
        }
    }
    let raw: BTreeMap<String, Value> = serde_json::from_value(value.clone())?;
    let mut environment: Environment = serde_json::from_value(value)?;
    if environment.slug.is_empty() {
        environment.slug = environment
            .name
            .to_lowercase()
            .split(|c: char| !c.is_ascii_alphanumeric())
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>()
            .join("-");
    }
    let string = |name: &str| {
        raw.get(name)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    let settings = &mut environment.settings;
    settings.protocol = string("protocol");
    settings.saml_name_id_field = string("saml_name_id_field");
    settings.saml_email_attribute_name = string("saml_email_attribute_name");
    settings.saml_encryption_algorithm = string("saml_encryption_algorithm");
    settings.saml_signing_mode = string("saml_signing_mode");
    Ok(environment)
}
fn safety_copy(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    let directory = path.parent().unwrap_or(Path::new(".")).join("backups");
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&directory)?;
    let copy = directory.join(format!(
        "pre-legacy-json-{}.json",
        uuid::Uuid::new_v4().simple()
    ));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(copy)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
