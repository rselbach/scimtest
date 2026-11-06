use std::{
    collections::BTreeMap,
    io::Write,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{Error, Store, configuration::ConfigValues, model::*, persistence};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct EnvironmentDescriptor {
    pub id: String,
    pub name: String,
    pub slug: String,
}

impl From<&Environment> for EnvironmentDescriptor {
    fn from(environment: &Environment) -> Self {
        Self {
            id: environment.id.clone(),
            name: environment.name.clone(),
            slug: environment.slug.clone(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct BackupConfig {
    pub base_url: String,
    pub bearer_token: String,
    pub auto_open_sync_trace: bool,
    pub scim_disabled: bool,
    pub idp_base_url: String,
    pub trust_forwarded_headers: bool,
    pub tunnel_instance_id: String,
    pub signing_private_key_pem: String,
    pub signing_certificate_pem: String,
    pub filter_supported: bool,
    pub patch_supported: bool,
    pub scim_enterprise_used: bool,
    #[serde(deserialize_with = "crate::model::null_default")]
    pub signing_keys: Vec<serde_json::Value>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct BackupState {
    pub environment: EnvironmentDescriptor,
    #[serde(deserialize_with = "crate::model::null_default")]
    pub environments: Vec<EnvironmentDescriptor>,
    pub config: BackupConfig,
    #[serde(deserialize_with = "crate::model::null_default")]
    pub users: Vec<User>,
    #[serde(deserialize_with = "crate::model::null_default")]
    pub groups: Vec<Group>,
    #[serde(deserialize_with = "crate::model::null_default")]
    pub apps: Vec<Environment>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct StateBackup {
    pub version: i32,
    pub exported_at: String,
    pub state: BackupState,
    #[serde(deserialize_with = "crate::model::null_default")]
    pub user_operations: BTreeMap<String, Vec<OperationLog>>,
    #[serde(deserialize_with = "crate::model::null_default")]
    pub group_operations: BTreeMap<String, Vec<OperationLog>>,
    #[serde(deserialize_with = "crate::model::null_default")]
    pub user_sync: BTreeMap<String, BTreeMap<String, ResourceSyncState>>,
    #[serde(deserialize_with = "crate::model::null_default")]
    pub group_sync: BTreeMap<String, BTreeMap<String, ResourceSyncState>>,
}

impl Store {
    pub fn write_backup(&self, environment: &str, path: &Path) -> Result<(), Error> {
        let data = serde_json::to_vec_pretty(&self.backup(environment)?)?;
        let temporary = path.parent().unwrap_or(Path::new(".")).join(format!(
            ".scimtest-backup-{}",
            uuid::Uuid::new_v4().simple()
        ));
        let mut options = std::fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        let write = (|| {
            file.write_all(&data)?;
            file.sync_all()?;
            std::fs::rename(&temporary, path)
        })();
        if let Err(error) = write {
            std::fs::remove_file(&temporary).map_err(|cleanup| {
                std::io::Error::other(format!("{error}; remove incomplete backup: {cleanup}"))
            })?;
            return Err(error.into());
        }
        Ok(())
    }

    pub fn backup(&self, environment: &str) -> Result<StateBackup, Error> {
        let connection = self.connection()?;
        let directory = persistence::load_directory(&connection, environment)?;
        let mut config = persistence::config_values(&connection, None)?;
        config.extend(directory.config.clone());
        let mut query =
            connection.prepare("SELECT id, name, slug FROM environments ORDER BY rowid")?;
        let environments = query
            .query_map([], |row| {
                Ok(EnvironmentDescriptor {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    slug: row.get(2)?,
                })
            })?
            .collect::<Result<_, _>>()?;
        Ok(StateBackup {
            version: 1,
            exported_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            state: BackupState {
                environment: (&directory.environment).into(),
                environments,
                config: backup_config(config)?,
                users: directory.users,
                groups: directory.groups,
                apps: vec![directory.environment],
            },
            user_operations: directory.user_operations,
            group_operations: directory.group_operations,
            user_sync: BTreeMap::from([(environment.into(), directory.user_sync)]),
            group_sync: BTreeMap::from([(environment.into(), directory.group_sync)]),
        })
    }

    pub fn restore_backup(
        &self,
        environment: &str,
        mut backup: StateBackup,
    ) -> Result<PathBuf, Error> {
        let _mutation = self.mutation()?;
        if backup.version != 1 {
            return Err(Error::Validation(format!(
                "unsupported backup version {}",
                backup.version
            )));
        }
        if backup.state.environment.id != environment {
            return Err(Error::Validation(
                "backup belongs to a different environment".into(),
            ));
        }
        if backup.state.apps.len() != 1 || backup.state.apps[0].id != environment {
            return Err(Error::Validation(
                "backup must contain exactly its own environment".into(),
            ));
        }
        let mut connection = self.connection()?;
        let mut current = persistence::load_directory(&connection, environment)?;
        let config = backup.state.config;
        for (key, value) in [
            ("base_url", config.base_url),
            ("bearer_token", config.bearer_token),
            (
                "auto_open_sync_trace",
                bool_string(config.auto_open_sync_trace),
            ),
            ("scim_disabled", bool_string(config.scim_disabled)),
            (
                "scim_enterprise_used",
                bool_string(config.scim_enterprise_used),
            ),
            ("signing_keys", serde_json::to_string(&config.signing_keys)?),
        ] {
            current.config.insert(key.into(), value);
        }
        let directory = Directory {
            environment: backup.state.apps.remove(0),
            users: backup.state.users,
            groups: backup.state.groups,
            config: current.config,
            user_operations: backup.user_operations,
            group_operations: backup.group_operations,
            user_sync: backup.user_sync.remove(environment).unwrap_or_default(),
            group_sync: backup.group_sync.remove(environment).unwrap_or_default(),
        };
        let safety = persistence::safety_copy(&connection, self.path(), "pre-restore")?;
        let transaction = connection.transaction()?;
        transaction.execute(
            "DELETE FROM operation_logs WHERE environment_id = ?1",
            [environment],
        )?;
        persistence::save_directory(&transaction, &directory)?;
        transaction.commit()?;
        self.changed();
        Ok(safety)
    }
}

fn bool_string(value: bool) -> String {
    if value { "1" } else { "0" }.into()
}

fn backup_config(values: ConfigValues) -> Result<BackupConfig, Error> {
    let mut object = serde_json::Map::new();
    for (key, value) in values {
        let value = match key.as_str() {
            "base_url"
            | "bearer_token"
            | "idp_base_url"
            | "tunnel_instance_id"
            | "signing_private_key_pem"
            | "signing_certificate_pem" => serde_json::Value::String(value),
            "auto_open_sync_trace"
            | "scim_disabled"
            | "trust_forwarded_headers"
            | "filter_supported"
            | "patch_supported"
            | "scim_enterprise_used" => serde_json::Value::Bool(value == "1"),
            "signing_keys" if !value.is_empty() => serde_json::from_str(&value)?,
            _ => continue,
        };
        object.insert(key, value);
    }
    Ok(serde_json::from_value(serde_json::Value::Object(object))?)
}
