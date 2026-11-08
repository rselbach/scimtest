use std::{
    fs::{self, OpenOptions},
    path::Path,
    sync::{Arc, Mutex, MutexGuard},
};

use crate::persistence::{load_directory, save_directory};
use rusqlite::{Connection, params};
use tokio::sync::watch;
use uuid::Uuid;

use crate::model::*;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Crypto(String),
    #[error("{0}")]
    Validation(String),
    #[error("{0} not found")]
    NotFound(&'static str),
    #[error("{0}")]
    Conflict(String),
    #[error("{0}")]
    Database(#[from] rusqlite::Error),
    #[error("{0}")]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("database lock is unavailable")]
    Lock,
}

struct Inner {
    connection: Mutex<Connection>,
    revision: watch::Sender<u64>,
    path: std::path::PathBuf,
    sync_active: Mutex<bool>,
}

#[derive(Clone)]
pub struct Store(Arc<Inner>);

impl Store {
    pub fn open(path: &Path) -> Result<Self, Error> {
        if let Some(parent) = path.parent().filter(|path| !path.as_os_str().is_empty())
            && !parent.exists()
        {
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(parent)?;
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(path)?;
        let mut connection = Connection::open(path)?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        crate::persistence::initialize(&mut connection, path)?;
        crate::legacy::import(&mut connection, path)?;
        connection.execute_batch("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;")?;
        let (revision, _) = watch::channel(0);
        Ok(Self(Arc::new(Inner {
            connection: Mutex::new(connection),
            revision,
            path: path.to_path_buf(),
            sync_active: Mutex::new(false),
        })))
    }

    pub(crate) fn connection(&self) -> Result<MutexGuard<'_, Connection>, Error> {
        self.0.connection.lock().map_err(|_| Error::Lock)
    }

    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.0.revision.subscribe()
    }

    pub(crate) fn changed(&self) {
        self.0
            .revision
            .send_modify(|revision| *revision = revision.wrapping_add(1));
    }

    pub fn snapshot(&self) -> Result<Vec<Directory>, Error> {
        let connection = self.connection()?;
        let mut statement = connection.prepare("SELECT id FROM apps ORDER BY rowid")?;
        let ids = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        ids.iter()
            .map(|id| load_directory(&connection, id))
            .collect()
    }

    pub fn directory(&self, id: &str) -> Result<Directory, Error> {
        let connection = self.connection()?;
        load_directory(&connection, id)
    }

    pub fn directory_by_slug(&self, slug: &str) -> Result<Directory, Error> {
        let connection = self.connection()?;
        let id = connection
            .query_row("SELECT id FROM apps WHERE slug = ?1", [slug], |row| {
                row.get::<_, String>(0)
            })
            .map_err(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => Error::NotFound("environment"),
                other => other.into(),
            })?;
        load_directory(&connection, &id)
    }

    pub fn create_environment(&self, input: EnvironmentInput) -> Result<Environment, Error> {
        let _mutation = self.mutation()?;
        let name = input.name.trim().to_owned();
        let slug = slugify(if input.slug.trim().is_empty() {
            &name
        } else {
            &input.slug
        });
        validate_environment(&name, &slug)?;
        let mut environment = Environment {
            id: new_id("app"),
            name,
            slug,
            ..Default::default()
        };
        environment
            .settings
            .apply(input.settings, &environment.slug)?;
        let mut connection = self.connection()?;
        ensure_slug_available(&connection, &environment.slug, "")?;
        ensure_client_available(&connection, &environment)?;
        let transaction = connection.transaction()?;
        save_directory(
            &transaction,
            &Directory {
                environment: environment.clone(),
                ..Default::default()
            },
        )?;
        transaction.commit()?;
        self.changed();
        Ok(environment)
    }

    pub fn update_environment(
        &self,
        id: &str,
        patch: EnvironmentPatch,
    ) -> Result<Environment, Error> {
        let _mutation = self.mutation()?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        let mut directory = load_directory(&transaction, id)?;
        let old_endpoint = directory
            .environment
            .settings
            .scim_base_url
            .trim_end_matches('/')
            .to_owned();
        if let Some(name) = patch.name {
            directory.environment.name = name.trim().to_owned();
        }
        if let Some(slug) = patch.slug {
            directory.environment.slug = slugify(&slug);
        }
        let environment = &mut directory.environment;
        if environment.slug.is_empty() {
            environment.slug = slugify(&environment.name);
        }
        validate_environment(&environment.name, &environment.slug)?;
        ensure_slug_available(&transaction, &environment.slug, id)?;
        environment
            .settings
            .apply(patch.settings, &environment.slug)?;
        ensure_client_available(&transaction, environment)?;
        let endpoint_changed =
            old_endpoint != environment.settings.scim_base_url.trim_end_matches('/');
        if endpoint_changed {
            environment.settings.scim_capabilities_known = false;
            environment.settings.scim_patch_supported = false;
            environment.settings.scim_filter_supported = false;
        }
        if environment.settings.scim_enabled
            && (endpoint_changed
                || directory.user_sync.is_empty() && directory.group_sync.is_empty())
        {
            directory.user_sync = directory
                .users
                .iter()
                .map(|user| {
                    (
                        user.id.clone(),
                        ResourceSyncState {
                            dirty: true,
                            deleted: user.deleted,
                            ..Default::default()
                        },
                    )
                })
                .collect();
            directory.group_sync = directory
                .groups
                .iter()
                .map(|group| {
                    (
                        group.id.clone(),
                        ResourceSyncState {
                            dirty: true,
                            deleted: group.deleted,
                            ..Default::default()
                        },
                    )
                })
                .collect();
        }
        save_directory(&transaction, &directory)?;
        transaction.commit()?;
        self.changed();
        Ok(directory.environment)
    }

    pub fn delete_environment(&self, id: &str) -> Result<(), Error> {
        let _mutation = self.mutation()?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        load_directory(&transaction, id)?;
        for table in [
            "users",
            "groups",
            "group_members",
            "environment_config",
            "operation_logs",
        ] {
            transaction.execute(
                &format!("DELETE FROM {table} WHERE environment_id = ?1"),
                [id],
            )?;
        }
        for table in ["app_user_sync", "app_group_sync"] {
            transaction.execute(&format!("DELETE FROM {table} WHERE app_id = ?1"), [id])?;
        }
        transaction.execute("DELETE FROM apps WHERE id = ?1", [id])?;
        transaction.execute("DELETE FROM environments WHERE id = ?1", [id])?;
        transaction.commit()?;
        self.changed();
        Ok(())
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0.path
    }

    pub(crate) fn edit<T>(
        &self,
        id: &str,
        edit: impl FnOnce(&mut Directory) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let _mutation = self.mutation()?;
        self.edit_internal(id, edit)
    }

    /// Refuses an operation that must wait for active provisioning to finish.
    pub fn check_idle(&self) -> Result<(), Error> {
        drop(self.mutation()?);
        Ok(())
    }

    pub(crate) fn mutation(&self) -> Result<MutexGuard<'_, bool>, Error> {
        let active = self.0.sync_active.lock().map_err(|_| Error::Lock)?;
        if *active {
            return Err(Error::Conflict(
                "a sync is running; wait for it to finish or cancel it".into(),
            ));
        }
        Ok(active)
    }

    pub(crate) fn begin_sync(&self) -> Result<SyncLease, Error> {
        let mut active = self.mutation()?;
        *active = true;
        Ok(SyncLease(self.clone()))
    }

    pub(crate) fn edit_internal<T>(
        &self,
        id: &str,
        edit: impl FnOnce(&mut Directory) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        let mut directory = load_directory(&transaction, id)?;
        let result = edit(&mut directory)?;
        save_directory(&transaction, &directory)?;
        transaction.commit()?;
        self.changed();
        Ok(result)
    }
}

pub(crate) fn new_id(prefix: &str) -> String {
    format!("{prefix}_{}", Uuid::new_v4().simple())
}

/// The endpoint name scimtest derives from `name`: its ASCII letters and digits, lowercased,
/// with every other run of characters replaced by one hyphen.
pub fn slugify(name: &str) -> String {
    name.to_ascii_lowercase()
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

fn validate_environment(name: &str, slug: &str) -> Result<(), Error> {
    if name.is_empty() {
        return Err(Error::Validation("app name is required".into()));
    }
    if slug.is_empty()
        || slug.starts_with('-')
        || slug.ends_with('-')
        || !slug
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
    {
        return Err(Error::Validation(
            "Endpoint name must use lowercase letters, numbers, and internal hyphens".into(),
        ));
    }
    Ok(())
}

fn ensure_slug_available(connection: &Connection, slug: &str, id: &str) -> Result<(), Error> {
    let exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM apps WHERE slug = ?1 COLLATE NOCASE AND id != ?2)",
        params![slug, id],
        |row| row.get(0),
    )?;
    if exists {
        return Err(Error::Validation("app slug is already in use".into()));
    }
    Ok(())
}

fn ensure_client_available(
    connection: &Connection,
    environment: &Environment,
) -> Result<(), Error> {
    let client = &environment.settings.oidc_client_id;
    if client.is_empty() {
        return Ok(());
    }
    let exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM apps WHERE oidc_client_id = ?1 AND id != ?2)",
        params![client, environment.id],
        |row| row.get(0),
    )?;
    if exists {
        return Err(Error::Validation(format!(
            "OIDC client ID {client:?} is already in use"
        )));
    }
    Ok(())
}

pub(crate) struct SyncLease(Store);
impl Drop for SyncLease {
    fn drop(&mut self) {
        match self.0.0.sync_active.lock() {
            Ok(mut active) => *active = false,
            Err(error) => eprintln!("Release SCIM mutation guard: {error}"),
        }
    }
}
