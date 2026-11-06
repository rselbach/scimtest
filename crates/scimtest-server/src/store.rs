use crate::application::{
    ApplicationSettings, INSTANCE_MAX_IDLE_DAYS, MAX_INSTANCES, valid_application_id,
};
use crate::null_default;
use anyhow::{Context, Result, bail};
use chrono::{DateTime, Duration, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize, Serializer};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{ErrorKind, Write},
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard},
};

#[cfg(test)]
mod tests;

pub const REVOKED_INSTANCE: &str = "installation revoked";

fn zero_time() -> DateTime<Utc> {
    DateTime::from_timestamp(-62_135_596_800, 0).expect("year 1 is representable")
}

fn serialize_time<S: Serializer>(value: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error> {
    let text = value.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true);
    let text = text
        .trim_end_matches('Z')
        .trim_end_matches('0')
        .trim_end_matches('.');
    serializer.serialize_str(&format!("{text}Z"))
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(default)]
pub struct Session {
    pub id: String,
    pub login: String,
    pub admin: bool,
    pub csrf_token: String,
    #[serde(serialize_with = "serialize_time")]
    pub created_at: DateTime<Utc>,
    #[serde(serialize_with = "serialize_time")]
    pub expires_at: DateTime<Utc>,
}

impl Default for Session {
    fn default() -> Self {
        Self {
            id: String::new(),
            login: String::new(),
            admin: false,
            csrf_token: String::new(),
            created_at: zero_time(),
            expires_at: zero_time(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(default)]
pub struct Instance {
    pub tunnel_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub public_key: String,
    #[serde(skip_serializing_if = "is_zero")]
    pub github_user_id: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub github_login: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub revoked: bool,
    #[serde(serialize_with = "serialize_time")]
    pub created_at: DateTime<Utc>,
    #[serde(serialize_with = "serialize_time")]
    pub last_used_at: DateTime<Utc>,
}

impl Default for Instance {
    fn default() -> Self {
        Self {
            tunnel_id: String::new(),
            public_key: String::new(),
            github_user_id: 0,
            github_login: String::new(),
            revoked: false,
            created_at: zero_time(),
            last_used_at: zero_time(),
        }
    }
}

impl Instance {
    pub fn is_enrolled(&self) -> bool {
        !self.public_key.is_empty()
    }
}

fn is_zero(value: &i64) -> bool {
    *value == 0
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(default)]
pub struct ApplicationProfile {
    pub id: String,
    #[serde(flatten)]
    pub settings: ApplicationSettings,
    pub public_key_fingerprint: String,
    #[serde(
        deserialize_with = "null_default",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub instances: BTreeMap<String, Instance>,
    #[serde(serialize_with = "serialize_time")]
    pub created_at: DateTime<Utc>,
}

impl Default for ApplicationProfile {
    fn default() -> Self {
        Self {
            id: String::new(),
            settings: ApplicationSettings::default(),
            public_key_fingerprint: String::new(),
            instances: BTreeMap::new(),
            created_at: zero_time(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct EnrollmentActor {
    pub github_user_id: i64,
    pub github_login: String,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(default)]
struct StoreData {
    #[serde(deserialize_with = "null_default")]
    sessions: BTreeMap<String, Session>,
    #[serde(deserialize_with = "null_default")]
    application_profiles: BTreeMap<String, ApplicationProfile>,
}

enum Commit<T> {
    Save(T),
    Unchanged(T),
}

pub struct Store {
    path: PathBuf,
    data: Mutex<StoreData>,
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let path = if path.as_os_str().is_empty() {
            Path::new("scimtest-server.json")
        } else {
            path
        };
        let mut data: StoreData = match File::open(path) {
            Ok(file) => StoreData::deserialize(&mut serde_json::Deserializer::from_reader(file))?,
            Err(error) if error.kind() == ErrorKind::NotFound => StoreData::default(),
            Err(error) => return Err(error.into()),
        };
        let mut migrated = false;
        for profile in data.application_profiles.values_mut() {
            for instance in profile.instances.values_mut() {
                if instance.created_at != zero_time() {
                    continue;
                }
                instance.created_at = if instance.last_used_at != zero_time() {
                    instance.last_used_at
                } else {
                    profile.created_at
                };
                migrated = true;
            }
        }
        let store = Self {
            path: path.into(),
            data: Mutex::new(data),
        };
        if migrated {
            store.save(&*store.read()?)?;
        }
        Ok(store)
    }

    fn read(&self) -> Result<MutexGuard<'_, StoreData>> {
        self.data
            .lock()
            .map_err(|_| anyhow::anyhow!("server store lock poisoned"))
    }

    fn transaction<T>(
        &self,
        mutate: impl FnOnce(&mut StoreData) -> Result<Commit<T>>,
    ) -> Result<T> {
        let mut current = self.read()?;
        let mut draft = current.clone();
        match mutate(&mut draft)? {
            Commit::Unchanged(result) => Ok(result),
            Commit::Save(result) => {
                self.save(&draft)?;
                *current = draft;
                Ok(result)
            }
        }
    }

    fn save(&self, data: &StoreData) -> Result<()> {
        let directory = self
            .path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o755);
        }
        builder.create(directory)?;
        let mut file = tempfile::NamedTempFile::new_in(directory)?;
        serde_json::to_writer_pretty(file.as_file_mut(), data)?;
        file.write_all(b"\n")?;
        file.as_file().sync_all()?;
        file.persist(&self.path).context("replace server store")?;
        File::open(directory)?.sync_all()?;
        Ok(())
    }

    pub fn create_session(&self, login: &str, admin: bool) -> Result<Session> {
        let login = login.trim().to_lowercase();
        if login != "rselbach" || !admin {
            bail!("dashboard access is restricted to rselbach");
        }
        let now = Utc::now();
        let session = Session {
            id: random_hex(32)?,
            login,
            admin,
            csrf_token: random_hex(32)?,
            created_at: now,
            expires_at: now + Duration::days(30),
        };
        self.transaction(|data| {
            data.sessions.insert(session.id.clone(), session.clone());
            Ok(Commit::Save(session))
        })
    }

    pub fn session(&self, id: &str) -> Result<Option<Session>> {
        let mut current = self.read()?;
        let Some(session) = current.sessions.get(id) else {
            return Ok(None);
        };
        if session.login == "rselbach"
            && session.admin
            && !session.csrf_token.is_empty()
            && Utc::now() < session.expires_at
        {
            return Ok(Some(session.clone()));
        }
        let mut draft = current.clone();
        draft.sessions.remove(id);
        self.save(&draft)?;
        *current = draft;
        Ok(None)
    }

    pub fn delete_session(&self, id: &str) -> Result<()> {
        self.transaction(|data| {
            data.sessions.remove(id);
            Ok(Commit::Save(()))
        })
    }

    pub fn create_profile(&self, settings: ApplicationSettings) -> Result<ApplicationProfile> {
        let (settings, public_key_fingerprint) = settings.validate()?;
        self.transaction(|data| {
            if data
                .application_profiles
                .values()
                .any(|profile| profile.settings.public_key == settings.public_key)
            {
                bail!("public key is already used by another application");
            }
            let profile = ApplicationProfile {
                id: random_hex(16)?,
                settings,
                public_key_fingerprint,
                instances: BTreeMap::new(),
                created_at: Utc::now(),
            };
            data.application_profiles
                .insert(profile.id.clone(), profile.clone());
            Ok(Commit::Save(profile))
        })
    }

    pub fn update_profile(
        &self,
        id: &str,
        settings: ApplicationSettings,
    ) -> Result<ApplicationProfile> {
        let (settings, public_key_fingerprint) = settings.validate()?;
        self.transaction(|data| {
            if !data.application_profiles.contains_key(id) {
                bail!("application profile not found");
            }
            if data.application_profiles.iter().any(|(other_id, profile)| {
                other_id != id && profile.settings.public_key == settings.public_key
            }) {
                bail!("public key is already used by another application");
            }
            let profile = data
                .application_profiles
                .get_mut(id)
                .expect("checked profile");
            profile.settings = settings;
            profile.public_key_fingerprint = public_key_fingerprint;
            Ok(Commit::Save(profile.clone()))
        })
    }

    pub fn profile(&self, id: &str) -> Result<Option<ApplicationProfile>> {
        if !valid_application_id(id) {
            return Ok(None);
        }
        Ok(self.read()?.application_profiles.get(id).cloned())
    }

    pub fn profiles(&self) -> Result<Vec<ApplicationProfile>> {
        let mut profiles: Vec<_> = self
            .read()?
            .application_profiles
            .values()
            .cloned()
            .collect();
        profiles.sort_by(|left, right| left.settings.name.cmp(&right.settings.name));
        Ok(profiles)
    }

    pub fn delete_profile(&self, id: &str) -> Result<()> {
        self.transaction(|data| {
            if data.application_profiles.remove(id).is_none() {
                bail!("application profile not found");
            }
            Ok(Commit::Save(()))
        })
    }

    pub fn tunnel_id_reserved(&self, id: &str) -> Result<bool> {
        Ok(self.read()?.application_profiles.values().any(|profile| {
            profile
                .instances
                .values()
                .any(|instance| instance.tunnel_id == id)
        }))
    }

    pub fn instance(&self, profile_id: &str, id: &str) -> Result<Option<Instance>> {
        Ok(self
            .read()?
            .application_profiles
            .get(profile_id)
            .and_then(|profile| profile.instances.get(id))
            .cloned())
    }

    pub fn enroll_instance(
        &self,
        profile_id: &str,
        id: &str,
        public_key: &str,
        actor: EnrollmentActor,
    ) -> Result<()> {
        let login = actor.github_login.trim();
        if actor.github_user_id <= 0 || login.is_empty() {
            bail!("github enrollment identity is required");
        }
        self.transaction(|data| {
            let profile = profile_mut(data, profile_id)?;
            let exists = profile.instances.contains_key(id);
            if let Some(existing) = profile
                .instances
                .get(id)
                .filter(|instance| instance.is_enrolled())
            {
                if existing.public_key != public_key {
                    bail!("instance id is already enrolled with a different key");
                }
                if existing.revoked {
                    bail!(REVOKED_INSTANCE);
                }
            }
            let now = Utc::now();
            prune_other_idle(profile, id, now);
            if !exists && profile.instances.len() >= MAX_INSTANCES {
                bail!("application has too many remembered instances");
            }
            let instance = profile.instances.entry(id.into()).or_default();
            if instance.created_at == zero_time() {
                instance.created_at = now;
            }
            instance.public_key = public_key.into();
            instance.github_user_id = actor.github_user_id;
            instance.github_login = login.into();
            instance.last_used_at = now;
            Ok(Commit::Save(()))
        })
    }

    pub fn count_instances_for_user(&self, profile_id: &str, user_id: i64) -> Result<usize> {
        if user_id <= 0 {
            return Ok(0);
        }
        Ok(self
            .read()?
            .application_profiles
            .get(profile_id)
            .map_or(0, |profile| {
                profile
                    .instances
                    .values()
                    .filter(|instance| {
                        instance.is_enrolled()
                            && !instance.revoked
                            && instance.github_user_id == user_id
                    })
                    .count()
            }))
    }

    pub fn prune_idle_instances(
        &self,
        profile_id: &str,
        cutoff: DateTime<Utc>,
        retained: &BTreeSet<String>,
    ) -> Result<usize> {
        self.transaction(|data| {
            let profile = profile_mut(data, profile_id)?;
            let before = profile.instances.len();
            profile.instances.retain(|id, instance| {
                retained.contains(id)
                    || instance.revoked
                    || !instance.is_enrolled()
                    || instance.last_used_at >= cutoff
            });
            let pruned = before - profile.instances.len();
            Ok(if pruned == 0 {
                Commit::Unchanged(0)
            } else {
                Commit::Save(pruned)
            })
        })
    }

    pub fn revoke_instance_for_user(
        &self,
        profile_id: &str,
        id: &str,
        user_id: i64,
    ) -> Result<bool> {
        self.change_instance(profile_id, id, |instance| {
            if !instance.is_enrolled() || instance.revoked || instance.github_user_id != user_id {
                return false;
            }
            instance.revoked = true;
            true
        })
    }

    pub fn set_instance_revoked(&self, profile_id: &str, id: &str, revoked: bool) -> Result<bool> {
        self.change_instance(profile_id, id, |instance| {
            if !instance.is_enrolled() {
                return false;
            }
            instance.revoked = revoked;
            true
        })
    }

    fn change_instance(
        &self,
        profile_id: &str,
        id: &str,
        change: impl FnOnce(&mut Instance) -> bool,
    ) -> Result<bool> {
        self.transaction(|data| {
            let Some(instance) = data
                .application_profiles
                .get_mut(profile_id)
                .and_then(|profile| profile.instances.get_mut(id))
            else {
                return Ok(Commit::Unchanged(false));
            };
            Ok(if change(instance) {
                Commit::Save(true)
            } else {
                Commit::Unchanged(false)
            })
        })
    }

    pub fn tunnel_id(&self, profile_id: &str, id: &str) -> Result<String> {
        Ok(self
            .instance(profile_id, id)?
            .map_or_else(String::new, |instance| instance.tunnel_id))
    }

    pub fn remember_tunnel(
        &self,
        profile_id: &str,
        id: &str,
        tunnel_id: &str,
        require_existing: bool,
    ) -> Result<()> {
        self.transaction(|data| {
            let profile = profile_mut(data, profile_id)?;
            let now = Utc::now();
            prune_other_idle(profile, id, now);
            let exists = profile.instances.contains_key(id);
            if require_existing && !exists {
                bail!("application instance authorization no longer exists");
            }
            if !exists && profile.instances.len() >= MAX_INSTANCES {
                bail!("application has too many remembered instances");
            }
            let instance = profile.instances.entry(id.into()).or_default();
            if instance.is_enrolled() && instance.revoked {
                bail!(REVOKED_INSTANCE);
            }
            if instance.created_at == zero_time() {
                instance.created_at = now;
            }
            instance.tunnel_id = tunnel_id.into();
            instance.last_used_at = now;
            Ok(Commit::Save(()))
        })
    }

    pub fn unreserve_tunnel(&self, profile_id: &str, id: &str) -> Result<bool> {
        self.transaction(|data| {
            let Some(profile) = data.application_profiles.get_mut(profile_id) else {
                return Ok(Commit::Unchanged(false));
            };
            let Some(instance) = profile.instances.get_mut(id) else {
                return Ok(Commit::Unchanged(false));
            };
            if instance.is_enrolled() {
                instance.tunnel_id.clear();
            } else {
                profile.instances.remove(id);
            }
            Ok(Commit::Save(true))
        })
    }
}

fn profile_mut<'a>(data: &'a mut StoreData, id: &str) -> Result<&'a mut ApplicationProfile> {
    data.application_profiles
        .get_mut(id)
        .context("application profile not found")
}

fn prune_other_idle(profile: &mut ApplicationProfile, retained: &str, now: DateTime<Utc>) {
    profile.instances.retain(|id, instance| {
        id == retained
            || instance.revoked
            || now - instance.last_used_at <= Duration::days(INSTANCE_MAX_IDLE_DAYS)
    });
}

fn random_hex(bytes: usize) -> Result<String> {
    let mut random = vec![0; bytes];
    rand::rngs::OsRng.try_fill_bytes(&mut random)?;
    Ok(random
        .into_iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}
