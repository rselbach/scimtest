use std::{collections::HashSet, fs, path::Path};

use rusqlite::{
    Connection, Row, params, params_from_iter,
    types::{Value as SqlValue, ValueRef},
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Map, Value};

use crate::{Error, configuration::ConfigValues, model::*};

pub(crate) const SCHEMA: &str = include_str!("schema.sql");
const PREVIEW_APPLICATION_ID: i32 = 0x53435253;

pub(crate) fn initialize(connection: &mut Connection, path: &Path) -> Result<(), Error> {
    let version: i32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    let application: i32 = connection.query_row("PRAGMA application_id", [], |row| row.get(0))?;
    let populated: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table')",
        [],
        |row| row.get(0),
    )?;
    match (application, version, populated) {
        (PREVIEW_APPLICATION_ID, 1, true) => migrate_preview(connection, path),
        (0, 8, true) => crate::migrations::validate(connection),
        (0, 0, false) => {
            let transaction = connection.transaction()?;
            transaction.execute_batch(SCHEMA)?;
            crate::migrations::finish(&transaction)?;
            transaction.commit()?;
            Ok(())
        }
        (0, 0..=7, true) => crate::migrations::migrate(connection, path),
        (0, version, true) if version > 8 => Err(Error::Validation(format!(
            "State schema {version} is newer than this build understands"
        ))),
        _ => Err(Error::Validation(
            "Not a supported scimtest state database".into(),
        )),
    }
}

pub(crate) fn safety_copy(
    connection: &Connection,
    path: &Path,
    prefix: &str,
) -> Result<std::path::PathBuf, Error> {
    let directory = path.parent().unwrap_or(Path::new(".")).join("backups");
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&directory)?;
    let copy = directory.join(format!("{prefix}-{}.db", uuid::Uuid::new_v4().simple()));
    let mut options = fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(&copy)?;
    connection.execute("VACUUM INTO ?1", [copy.to_string_lossy().as_ref()])?;
    Ok(copy)
}

fn migrate_preview(connection: &mut Connection, path: &Path) -> Result<(), Error> {
    let mut directories = Vec::new();
    let mut environments =
        connection.prepare("SELECT id, name, slug FROM environments ORDER BY rowid")?;
    let rows = environments.query_map([], |row| {
        Ok(Environment {
            id: row.get(0)?,
            name: row.get(1)?,
            slug: row.get(2)?,
            ..Default::default()
        })
    })?;
    for environment in rows {
        let environment = environment?;
        let mut users = connection
            .prepare("SELECT data FROM users WHERE environment_id = ?1 ORDER BY rowid")?;
        let users = users
            .query_map([&environment.id], |row| row.get::<_, String>(0))?
            .map(|row| Ok(serde_json::from_str(&row?)?))
            .collect::<Result<Vec<User>, Error>>()?;
        let mut groups = connection
            .prepare("SELECT data FROM groups WHERE environment_id = ?1 ORDER BY rowid")?;
        let groups = groups
            .query_map([&environment.id], |row| row.get::<_, String>(0))?
            .map(|row| Ok(serde_json::from_str(&row?)?))
            .collect::<Result<Vec<Group>, Error>>()?;
        directories.push(Directory {
            environment,
            users,
            groups,
            ..Default::default()
        });
    }
    drop(environments);
    safety_copy(connection, path, "pre-rust-preview-migration")?;
    let transaction = connection.transaction()?;
    transaction.execute_batch("DROP TABLE users; DROP TABLE groups;")?;
    transaction.execute_batch(SCHEMA)?;
    for directory in directories {
        save_directory(&transaction, &directory)?;
    }
    crate::migrations::finish(&transaction)?;
    transaction.commit()?;
    Ok(())
}

pub(crate) fn config_values(
    connection: &Connection,
    environment: Option<&str>,
) -> Result<ConfigValues, Error> {
    let (sql, arguments) = match environment {
        Some(id) => (
            "SELECT key, value FROM environment_config WHERE environment_id = ?1",
            vec![id],
        ),
        None => ("SELECT key, value FROM config", vec![]),
    };
    let mut query = connection.prepare(sql)?;
    Ok(query
        .query_map(params_from_iter(arguments), |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?
        .collect::<Result<_, _>>()?)
}

fn json_row(row: &Row<'_>) -> rusqlite::Result<Value> {
    let mut object = Map::new();
    for index in 0..row.as_ref().column_count() {
        let name = row.as_ref().column_name(index)?;
        if ["environment_id", "saml_verify_requests"].contains(&name) {
            continue;
        }
        let value = match row.get_ref(index)? {
            ValueRef::Null => Value::Null,
            ValueRef::Integer(value)
                if [
                    "active",
                    "dirty",
                    "deleted",
                    "oidc_public_client",
                    "allow_any_oidc_redirect",
                    "oidc_jwt_access_tokens",
                    "oidc_backchannel_logout_session_required",
                    "include_groups_claim",
                    "scim_enabled",
                    "scim_auto_open_trace",
                    "scim_capabilities_known",
                    "scim_patch_supported",
                    "scim_filter_supported",
                ]
                .contains(&name) =>
            {
                Value::Bool(value != 0)
            }
            ValueRef::Integer(value) => Value::from(value),
            ValueRef::Real(value) => Value::from(value),
            ValueRef::Text(value) => {
                let text = std::str::from_utf8(value).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        index,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })?;
                match name {
                    "oidc_redirect_uris" => Value::Array(
                        text.lines()
                            .filter(|line| !line.trim().is_empty())
                            .map(|line| Value::String(line.trim().into()))
                            .collect(),
                    ),
                    "attributes" | "oidc_claim_mappings" | "saml_attribute_mappings" => {
                        if text.is_empty() {
                            Value::Object(Map::new())
                        } else {
                            serde_json::from_str(text).map_err(|error| {
                                rusqlite::Error::FromSqlConversionFailure(
                                    index,
                                    rusqlite::types::Type::Text,
                                    Box::new(error),
                                )
                            })?
                        }
                    }
                    _ => Value::String(text.into()),
                }
            }
            ValueRef::Blob(_) => {
                return Err(rusqlite::Error::InvalidColumnType(
                    index,
                    name.into(),
                    rusqlite::types::Type::Blob,
                ));
            }
        };
        object.insert(name.into(), value);
    }
    Ok(Value::Object(object))
}

fn models<T: DeserializeOwned>(
    connection: &Connection,
    sql: &str,
    id: &str,
) -> Result<Vec<T>, Error> {
    let mut query = connection.prepare(sql)?;
    query
        .query_map([id], json_row)?
        .map(|row| Ok(serde_json::from_value(row?)?))
        .collect()
}

pub(crate) fn load_directory(connection: &Connection, id: &str) -> Result<Directory, Error> {
    let mut environments =
        models::<Environment>(connection, "SELECT * FROM apps WHERE id = ?1", id)?;
    let mut environment = environments.pop().ok_or(Error::NotFound("environment"))?;
    environment.settings.normalize_loaded(&environment.slug);
    let mut users: Vec<User> = models(
        connection,
        "SELECT * FROM users WHERE environment_id = ?1 ORDER BY rowid",
        id,
    )?;
    for user in &mut users {
        if user.fields.username.trim().is_empty() {
            user.fields.username.clone_from(&user.fields.email);
        }
    }
    let mut groups: Vec<Group> = models(
        connection,
        "SELECT * FROM groups WHERE environment_id = ?1 ORDER BY rowid",
        id,
    )?;
    for group in &mut groups {
        let mut query = connection.prepare("SELECT user_id FROM group_members WHERE environment_id = ?1 AND group_id = ?2 ORDER BY position")?;
        group.fields.member_ids = query
            .query_map(params![id, group.id], |row| row.get(0))?
            .collect::<Result<_, _>>()?;
    }
    let mut directory = Directory {
        environment,
        users,
        groups,
        config: config_values(connection, Some(id))?,
        ..Default::default()
    };
    for (table, target) in [
        ("app_user_sync", &mut directory.user_sync),
        ("app_group_sync", &mut directory.group_sync),
    ] {
        let resource = if table == "app_user_sync" {
            "user_id"
        } else {
            "group_id"
        };
        let mut query = connection.prepare(&format!("SELECT {resource}, remote_id, dirty, deleted, last_error FROM {table} WHERE app_id = ?1"))?;
        for item in query.query_map([id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                ResourceSyncState {
                    remote_id: row.get(1)?,
                    dirty: row.get(2)?,
                    deleted: row.get(3)?,
                    last_error: row.get(4)?,
                },
            ))
        })? {
            let (id, value) = item?;
            target.insert(id, value);
        }
    }
    let mut query = connection.prepare("SELECT id, resource_type, resource_id, app_id, kind, summary, operation, method, path, request_body, status, response_retry_after, response_body, error_text, created_at FROM operation_logs WHERE environment_id = ?1 ORDER BY created_at DESC, id ASC")?;
    for item in query.query_map([id], |row| {
        Ok((
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            OperationLog {
                storage_id: row.get(0)?,
                app_id: row.get(3)?,
                kind: row.get(4)?,
                summary: row.get(5)?,
                operation: row.get(6)?,
                method: row.get(7)?,
                path: row.get(8)?,
                request_body: row.get(9)?,
                status: row.get(10)?,
                response_retry_after: row.get(11)?,
                response_body: row.get(12)?,
                err: row.get(13)?,
                created_at: row.get(14)?,
            },
        ))
    })? {
        let (kind, id, entry) = item?;
        let target = if kind == "user" {
            &mut directory.user_operations
        } else {
            &mut directory.group_operations
        };
        let entries = target.entry(id).or_default();
        if entries.len() < 100 {
            entries.push(entry);
        }
    }
    Ok(directory)
}

fn upsert(
    connection: &Connection,
    table: &str,
    environment_id: &str,
    value: impl Serialize,
) -> Result<(), Error> {
    let Value::Object(mut object) = serde_json::to_value(value)? else {
        return Err(Error::Validation("State row must be an object".into()));
    };
    object.remove("member_ids");
    if table == "users" {
        for field in [
            "given_name",
            "family_name",
            "employee_number",
            "cost_center",
            "organization",
            "division",
            "department",
            "manager_id",
        ] {
            object
                .entry(field)
                .or_insert_with(|| Value::String(String::new()));
        }
        object
            .entry("attributes")
            .or_insert_with(|| Value::Object(Map::new()));
    }
    if table == "users" || table == "groups" {
        object
            .entry("remote_id")
            .or_insert_with(|| Value::String(String::new()));
        object
            .entry("last_error")
            .or_insert_with(|| Value::String(String::new()));
    }
    object.insert(
        "environment_id".into(),
        Value::String(environment_id.into()),
    );
    if table == "apps" {
        object.insert(
            "saml_verify_requests".into(),
            Value::Bool(
                object
                    .get("saml_request_certificate_pem")
                    .is_some_and(|value| value.as_str().is_some_and(|text| !text.is_empty())),
            ),
        );
    }
    let columns: Vec<_> = object.keys().cloned().collect();
    let values = columns
        .iter()
        .map(|column| match &object[column] {
            Value::Bool(value) => SqlValue::Integer(i64::from(*value)),
            Value::Number(value) => SqlValue::Integer(value.as_i64().unwrap_or_default()),
            Value::String(value) => SqlValue::Text(value.clone()),
            Value::Array(values) if column == "oidc_redirect_uris" => SqlValue::Text(
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join("\n"),
            ),
            value => SqlValue::Text(value.to_string()),
        })
        .collect::<Vec<_>>();
    let conflict = if table == "apps" {
        "id"
    } else {
        "environment_id, id"
    };
    let updates = columns
        .iter()
        .filter(|column| *column != "id" && *column != "environment_id")
        .map(|column| format!("{column} = excluded.{column}"))
        .collect::<Vec<_>>()
        .join(", ");
    let placeholders = vec!["?"; columns.len()].join(", ");
    connection.execute(&format!("INSERT INTO {table} ({}) VALUES ({placeholders}) ON CONFLICT({conflict}) DO UPDATE SET {updates}", columns.join(", ")), params_from_iter(values))?;
    Ok(())
}

pub(crate) fn save_directory(connection: &Connection, directory: &Directory) -> Result<(), Error> {
    let environment = &directory.environment;
    let id = &environment.id;
    connection.execute("INSERT INTO environments(id, name, slug) VALUES (?1, ?2, ?3) ON CONFLICT(id) DO UPDATE SET name = excluded.name, slug = excluded.slug", params![id, environment.name, environment.slug])?;
    let Value::Object(mut row) = serde_json::to_value(environment)? else {
        return Err(Error::Validation(
            "Environment row must be an object".into(),
        ));
    };
    row.extend(environment.settings.storage_fields()?);
    upsert(connection, "apps", id, row)?;
    for (table, ids) in [
        (
            "users",
            directory
                .users
                .iter()
                .map(|user| user.id.as_str())
                .collect::<HashSet<_>>(),
        ),
        (
            "groups",
            directory
                .groups
                .iter()
                .map(|group| group.id.as_str())
                .collect::<HashSet<_>>(),
        ),
    ] {
        let mut query =
            connection.prepare(&format!("SELECT id FROM {table} WHERE environment_id = ?1"))?;
        let existing = query
            .query_map([id], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        for removed in existing
            .iter()
            .filter(|value| !ids.contains(value.as_str()))
        {
            connection.execute(
                &format!("DELETE FROM {table} WHERE environment_id = ?1 AND id = ?2"),
                params![id, removed],
            )?;
        }
    }
    for user in &directory.users {
        let mut user = user.clone();
        user.remote_id.clear();
        user.dirty = false;
        user.last_error.clear();
        upsert(connection, "users", id, user)?;
    }
    connection.execute("DELETE FROM group_members WHERE environment_id = ?1", [id])?;
    for group in &directory.groups {
        let mut stored = group.clone();
        stored.remote_id.clear();
        stored.dirty = false;
        stored.last_error.clear();
        upsert(connection, "groups", id, stored)?;
        for (position, user) in group.fields.member_ids.iter().enumerate() {
            connection.execute(
                "INSERT INTO group_members(group_id, environment_id, user_id, position) VALUES (?1, ?2, ?3, ?4)",
                params![group.id, id, user, position as i64],
            )?;
        }
    }
    for (key, value) in &directory.config {
        connection.execute("INSERT INTO environment_config VALUES (?1, ?2, ?3) ON CONFLICT(environment_id, key) DO UPDATE SET value = excluded.value", params![id, key, value])?;
    }
    if directory.users.iter().any(|user| {
        !user.deleted
            && [
                &user.fields.employee_number,
                &user.fields.cost_center,
                &user.fields.organization,
                &user.fields.division,
                &user.fields.department,
                &user.fields.manager_id,
            ]
            .iter()
            .any(|value| !value.is_empty())
    }) {
        connection.execute("INSERT INTO environment_config VALUES (?1, 'scim_enterprise_used', '1') ON CONFLICT(environment_id, key) DO UPDATE SET value = '1'", [id])?;
    }
    for (table, states) in [
        ("app_user_sync", &directory.user_sync),
        ("app_group_sync", &directory.group_sync),
    ] {
        connection.execute(&format!("DELETE FROM {table} WHERE app_id = ?1"), [id])?;
        for (resource, state) in states {
            connection.execute(
                &format!("INSERT INTO {table} VALUES (?1, ?2, ?3, ?4, ?5, ?6)"),
                params![
                    id,
                    resource,
                    state.remote_id,
                    state.dirty,
                    state.deleted,
                    state.last_error
                ],
            )?;
        }
    }
    for (kind, operations) in [
        ("user", &directory.user_operations),
        ("group", &directory.group_operations),
    ] {
        let mut query = connection.prepare("SELECT DISTINCT resource_id FROM operation_logs WHERE environment_id = ?1 AND resource_type = ?2")?;
        let existing = query
            .query_map(params![id, kind], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        for resource in existing
            .iter()
            .filter(|resource| !operations.contains_key(*resource))
        {
            connection.execute("DELETE FROM operation_logs WHERE environment_id = ?1 AND resource_type = ?2 AND resource_id = ?3", params![id, kind, resource])?;
        }
        for (resource, entries) in operations {
            if !entries.iter().any(|entry| entry.storage_id == 0) {
                continue;
            }
            connection.execute("DELETE FROM operation_logs WHERE environment_id = ?1 AND resource_type = ?2 AND resource_id = ?3", params![id, kind, resource])?;
            for entry in entries.iter().take(100) {
                connection.execute("INSERT INTO operation_logs(environment_id, resource_type, resource_id, label, app_id, kind, summary, operation, method, path, request_body, status, response_retry_after, response_body, error_text, created_at) VALUES (?1, ?2, ?3, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)", params![id, kind, resource, entry.app_id, entry.kind, entry.summary, entry.operation, entry.method, entry.path, entry.request_body, entry.status, entry.response_retry_after, entry.response_body, entry.err, entry.created_at])?;
            }
        }
    }
    Ok(())
}
