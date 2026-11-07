use std::collections::BTreeMap;

use crate::configuration::{ConfigValues, EnvironmentSettings, SettingsPatch};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Environment {
    pub id: String,
    pub name: String,
    pub slug: String,
    #[serde(flatten)]
    pub settings: EnvironmentSettings,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct EnvironmentInput {
    pub name: String,
    pub slug: String,
    #[serde(flatten)]
    pub settings: SettingsPatch,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EnvironmentPatch {
    pub name: Option<String>,
    pub slug: Option<String>,
    #[serde(flatten)]
    pub settings: SettingsPatch,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct User {
    pub id: String,
    #[serde(flatten)]
    pub fields: UserInput,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub remote_id: String,
    pub dirty: bool,
    pub deleted: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub last_error: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct UserInput {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub given_name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub family_name: String,
    pub email: String,
    pub username: String,
    pub active: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub employee_number: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub cost_center: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub organization: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub division: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub department: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub manager_id: String,
    #[serde(
        deserialize_with = "null_default",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub attributes: BTreeMap<String, String>,
}

impl Default for UserInput {
    fn default() -> Self {
        Self {
            given_name: String::new(),
            family_name: String::new(),
            email: String::new(),
            username: String::new(),
            active: true,
            employee_number: String::new(),
            cost_center: String::new(),
            organization: String::new(),
            division: String::new(),
            department: String::new(),
            manager_id: String::new(),
            attributes: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UserPatch {
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub email: Option<String>,
    pub username: Option<String>,
    pub active: Option<bool>,
    pub employee_number: Option<String>,
    pub cost_center: Option<String>,
    pub organization: Option<String>,
    pub division: Option<String>,
    pub department: Option<String>,
    pub manager_id: Option<String>,
    pub attributes: Option<BTreeMap<String, String>>,
}

impl UserInput {
    pub fn apply(&mut self, patch: UserPatch) {
        macro_rules! apply {
            ($($field:ident),+ $(,)?) => {
                $(if let Some(value) = patch.$field { self.$field = value; })+
            };
        }
        apply!(
            given_name,
            family_name,
            email,
            username,
            active,
            employee_number,
            cost_center,
            organization,
            division,
            department,
            manager_id,
            attributes,
        );
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Group {
    pub id: String,
    #[serde(flatten)]
    pub fields: GroupInput,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub remote_id: String,
    pub dirty: bool,
    pub deleted: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub last_error: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct GroupInput {
    pub display_name: String,
    #[serde(deserialize_with = "null_default")]
    pub member_ids: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GroupPatch {
    pub display_name: Option<String>,
    pub member_ids: Option<Vec<String>>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Directory {
    pub environment: Environment,
    pub users: Vec<User>,
    pub groups: Vec<Group>,
    pub config: ConfigValues,
    pub user_sync: BTreeMap<String, ResourceSyncState>,
    pub group_sync: BTreeMap<String, ResourceSyncState>,
    pub user_operations: BTreeMap<String, Vec<OperationLog>>,
    pub group_operations: BTreeMap<String, Vec<OperationLog>>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct ResourceSyncState {
    #[serde(rename = "RemoteID")]
    pub remote_id: String,
    pub dirty: bool,
    pub deleted: bool,
    pub last_error: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct OperationLog {
    #[serde(skip)]
    pub storage_id: i64,
    #[serde(rename = "AppID")]
    pub app_id: String,
    pub kind: String,
    pub summary: String,
    pub operation: String,
    pub method: String,
    pub path: String,
    pub request_body: String,
    pub status: String,
    pub response_retry_after: String,
    pub response_body: String,
    pub err: String,
    pub created_at: String,
}

impl Directory {
    pub fn projected_users(&self) -> Vec<User> {
        self.users
            .iter()
            .cloned()
            .map(|mut user| {
                if self.environment.settings.scim_enabled {
                    if let Some(sync) = self.user_sync.get(&user.id) {
                        user.remote_id = sync.remote_id.clone();
                        user.dirty = sync.dirty;
                        user.deleted |= sync.deleted;
                        user.last_error = sync.last_error.clone();
                    } else {
                        user.remote_id.clear();
                        user.dirty = true;
                        user.last_error.clear();
                    }
                }
                user
            })
            .collect()
    }

    pub fn projected_groups(&self) -> Vec<Group> {
        let deleted = self
            .projected_users()
            .into_iter()
            .filter(|user| user.deleted)
            .map(|user| user.id)
            .collect::<std::collections::HashSet<_>>();
        self.groups
            .iter()
            .cloned()
            .map(|mut group| {
                if self.environment.settings.scim_enabled {
                    if let Some(sync) = self.group_sync.get(&group.id) {
                        group.remote_id = sync.remote_id.clone();
                        group.dirty = sync.dirty;
                        group.deleted |= sync.deleted;
                        group.last_error = sync.last_error.clone();
                    } else {
                        group.remote_id.clear();
                        group.dirty = true;
                        group.last_error.clear();
                    }
                    group.fields.member_ids.retain(|id| !deleted.contains(id));
                }
                group
            })
            .collect()
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct SeedResult {
    pub users_added: usize,
    pub groups_added: usize,
}

pub(crate) fn null_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}
