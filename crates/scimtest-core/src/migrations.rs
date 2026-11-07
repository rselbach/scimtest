use std::{collections::HashSet, path::Path};

use rusqlite::{Connection, OptionalExtension, params};

use crate::{
    Error,
    persistence::{SCHEMA, safety_copy},
};

pub(crate) const TABLES: &[&str] = &[
    "environments",
    "environment_config",
    "config",
    "users",
    "groups",
    "apps",
    "app_user_sync",
    "app_group_sync",
    "group_members",
    "operation_logs",
];

struct Column {
    name: String,
    kind: String,
    required: bool,
    default: Option<String>,
    key: i64,
}

fn columns(connection: &Connection, table: &str) -> Result<Vec<Column>, Error> {
    let mut query = connection.prepare(&format!("PRAGMA table_info({table})"))?;
    Ok(query
        .query_map([], |row| {
            Ok(Column {
                name: row.get(1)?,
                kind: row.get(2)?,
                required: row.get(3)?,
                default: row.get(4)?,
                key: row.get(5)?,
            })
        })?
        .collect::<Result<_, _>>()?)
}

fn reference() -> Result<Connection, Error> {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch(SCHEMA)?;
    Ok(connection)
}

pub(crate) fn validate(connection: &Connection) -> Result<(), Error> {
    let reference = reference()?;
    for table in TABLES {
        let actual = columns(connection, table)?;
        for column in columns(&reference, table)? {
            if !actual
                .iter()
                .any(|value| value.name == column.name && value.key == column.key)
            {
                return Err(Error::Validation(format!(
                    "Not a supported scimtest state database: missing {table}.{}",
                    column.name
                )));
            }
        }
    }
    Ok(())
}

pub(crate) fn migrate(connection: &mut Connection, path: &Path) -> Result<(), Error> {
    for table in ["config", "users", "groups"] {
        if columns(connection, table)?.is_empty() {
            return Err(Error::Validation(
                "Not a supported scimtest state database".into(),
            ));
        }
    }
    safety_copy(connection, path, "pre-migrate")?;
    let reference = reference()?;
    let transaction = connection.transaction()?;
    transaction.execute_batch(SCHEMA)?;
    for table in TABLES {
        let actual: HashSet<_> = columns(&transaction, table)?
            .into_iter()
            .map(|value| value.name)
            .collect();
        for column in columns(&reference, table)? {
            if actual.contains(&column.name) {
                continue;
            }
            if column.required && column.default.is_none() {
                return Err(Error::Validation(format!(
                    "Not a supported scimtest state database: missing {table}.{}",
                    column.name
                )));
            }
            let default = column
                .default
                .map(|value| format!(" DEFAULT {value}"))
                .unwrap_or_default();
            let required = if column.required { " NOT NULL" } else { "" };
            transaction.execute_batch(&format!(
                "ALTER TABLE {table} ADD COLUMN {} {}{required}{default}",
                column.name, column.kind
            ))?;
        }
    }
    for table in ["users", "groups", "group_members"] {
        if columns(&transaction, table)?
            .iter()
            .filter(|value| value.key > 0)
            .count()
            == columns(&reference, table)?
                .iter()
                .filter(|value| value.key > 0)
                .count()
        {
            continue;
        }
        let create: String = reference.query_row(
            "SELECT sql FROM sqlite_master WHERE name = ?1",
            [table],
            |row| row.get(0),
        )?;
        let temporary = format!("{table}_scoped");
        transaction.execute_batch(&create.replacen(table, &temporary, 1))?;
        let names = columns(&reference, table)?
            .into_iter()
            .map(|value| value.name)
            .collect::<Vec<_>>()
            .join(", ");
        transaction.execute_batch(&format!("INSERT INTO {temporary} ({names}) SELECT {names} FROM {table}; DROP TABLE {table}; ALTER TABLE {temporary} RENAME TO {table};"))?;
    }
    transaction.execute(
        "INSERT OR IGNORE INTO environments VALUES ('env_default', 'Default', 'default')",
        [],
    )?;
    transaction.execute("INSERT OR IGNORE INTO environment_config SELECT 'env_default', key, value FROM config WHERE key IN ('base_url', 'bearer_token', 'auto_open_sync_trace', 'scim_disabled')", [])?;
    if !migrated(&transaction, "app_scim_migrated")? {
        transaction.execute_batch(include_str!("migrate_scim.sql"))?;
    }
    if !migrated(&transaction, "directory_per_environment_migrated")? {
        distribute(&transaction)?;
    }
    finish(&transaction)?;
    validate(&transaction)?;
    transaction.commit()?;
    Ok(())
}

fn migrated(connection: &Connection, key: &str) -> Result<bool, Error> {
    let value = connection
        .query_row("SELECT value FROM config WHERE key = ?1", [key], |row| {
            row.get::<_, String>(0)
        })
        .optional()?;
    Ok(value.as_deref() == Some("1"))
}

pub(crate) fn finish(connection: &Connection) -> Result<(), Error> {
    connection.execute_batch(
        "CREATE INDEX IF NOT EXISTS users_environment_id ON users(environment_id);
        CREATE INDEX IF NOT EXISTS groups_environment_id ON groups(environment_id);
        CREATE INDEX IF NOT EXISTS apps_environment_id ON apps(environment_id);
        CREATE UNIQUE INDEX IF NOT EXISTS apps_slug ON apps(slug);
        CREATE INDEX IF NOT EXISTS operation_logs_environment_id ON operation_logs(environment_id);
        INSERT OR REPLACE INTO config VALUES ('app_scim_migrated', '1');
        INSERT OR REPLACE INTO config VALUES ('directory_per_environment_migrated', '1');
        PRAGMA application_id = 0; PRAGMA user_version = 8;",
    )?;
    Ok(())
}

fn distribute(connection: &Connection) -> Result<(), Error> {
    connection.execute("INSERT INTO apps (id, environment_id, name, slug, protocol)
        SELECT 'env_default', 'env_default', 'Default', 'default', 'none'
        WHERE NOT EXISTS (SELECT 1 FROM apps) AND ((SELECT COUNT(*) FROM users) + (SELECT COUNT(*) FROM groups)) > 0", [])?;
    let mut query =
        connection.prepare("SELECT id, environment_id, name, slug FROM apps ORDER BY rowid")?;
    let apps = query
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    for (id, source, name, slug) in apps {
        connection.execute("UPDATE environments SET slug = '__directory__' WHERE id = 'env_default' AND slug = ?1 AND ?2 != 'env_default'", params![slug, id])?;
        connection.execute("DELETE FROM environments WHERE slug = ?1 AND id != ?2 AND id NOT IN (SELECT id FROM apps)", params![slug, id])?;
        connection.execute("INSERT INTO environments VALUES (?1, ?2, ?3) ON CONFLICT(id) DO UPDATE SET name = excluded.name, slug = excluded.slug", params![id, name, slug])?;
        if source != id {
            connection.execute("INSERT OR IGNORE INTO users(id, environment_id, given_name, family_name, email, username, active, remote_id, dirty, deleted, last_error, employee_number, cost_center, organization, division, department, manager_id, attributes) SELECT id, ?1, given_name, family_name, email, username, active, '', 0, deleted, '', employee_number, cost_center, organization, division, department, manager_id, attributes FROM users WHERE environment_id = ?2", params![id, source])?;
            connection.execute("INSERT OR IGNORE INTO groups(id, environment_id, display_name, remote_id, dirty, deleted, last_error) SELECT id, ?1, display_name, '', 0, deleted, '' FROM groups WHERE environment_id = ?2", params![id, source])?;
            connection.execute("INSERT OR IGNORE INTO group_members(group_id, environment_id, user_id, position) SELECT group_id, ?1, user_id, position FROM group_members WHERE environment_id = ?2", params![id, source])?;
            connection.execute("INSERT INTO operation_logs(environment_id, app_id, resource_type, resource_id, label, kind, summary, operation, method, path, request_body, status, response_retry_after, response_body, error_text, created_at)
                SELECT ?1, app_id, resource_type, resource_id, label, kind, summary, operation, method, path, request_body, status, response_retry_after, response_body, error_text, created_at FROM operation_logs WHERE environment_id = ?2 AND (app_id = '' OR app_id = ?1)", params![id, source])?;
        }
        connection.execute("UPDATE apps SET environment_id = ?1 WHERE id = ?1", [&id])?;
    }
    for table in ["group_members", "operation_logs", "groups", "users"] {
        connection.execute(
            &format!("DELETE FROM {table} WHERE environment_id NOT IN (SELECT id FROM apps)"),
            [],
        )?;
    }
    for (sync, resources, key) in [
        ("app_user_sync", "users", "user_id"),
        ("app_group_sync", "groups", "group_id"),
    ] {
        connection.execute(&format!("DELETE FROM {sync} WHERE NOT EXISTS (SELECT 1 FROM {resources} WHERE environment_id = {sync}.app_id AND id = {sync}.{key})"), [])?;
    }
    connection.execute(
        "DELETE FROM environments WHERE id != 'env_default' AND id NOT IN (SELECT id FROM apps)",
        [],
    )?;
    Ok(())
}
