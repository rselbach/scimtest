use super::*;
use crate::model::{Group, GroupInput, ResourceSyncState, User, UserInput};
use chrono::{DateTime, Duration, Utc};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

#[derive(Clone)]
pub(super) struct Preview {
    pub view: PreviewView,
    pub users: Vec<User>,
    pub groups: Vec<Group>,
    pub traces: Vec<Trace>,
}
#[derive(Clone, Debug, Serialize)]
pub struct PreviewView {
    pub added: usize,
    pub updated: usize,
    pub removed: usize,
    pub digest: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
}
impl Preview {
    pub fn expired(&self) -> bool {
        Utc::now() - self.view.created_at > Duration::minutes(10)
    }
}
impl Client {
    pub(super) async fn import(
        &mut self,
        directory: &Directory,
    ) -> Result<(Vec<User>, Vec<Group>, usize)> {
        let resources = self.list("/Users", "user", "import").await?;
        let group_resources = self.list("/Groups", "group", "import").await?;
        let existing = directory.projected_users();
        let mut users = Vec::new();
        let mut seen = HashSet::new();
        let mut remote_ids = HashMap::new();
        for resource in &resources {
            let external = string(resource, "externalId");
            let remote = string(resource, "id");
            let matched = existing
                .iter()
                .find(|user| !external.is_empty() && user.id == external)
                .or_else(|| {
                    existing
                        .iter()
                        .find(|user| !remote.is_empty() && user.remote_id == remote)
                });
            let id = if !external.is_empty() {
                external.into()
            } else {
                matched
                    .map(|user| user.id.clone())
                    .unwrap_or_else(|| crate::store::new_id("user"))
            };
            if !seen.insert(id.clone()) {
                return Err(Failure::new(format!(
                    "SCIM /Users returned more than one user with externalId {id:?}"
                )));
            }
            let username = non_empty(&[
                string(resource, "userName"),
                string(resource, "displayName"),
                remote,
            ])
            .to_owned();
            let email = non_empty(&[entra::email(resource), &username]).to_owned();
            let fallback = non_empty(&[string(resource, "displayName"), &username]);
            let parts = fallback.split_whitespace().collect::<Vec<_>>();
            let given = non_empty(&[
                string(&resource["name"], "givenName"),
                parts.first().copied().unwrap_or_default(),
            ])
            .to_owned();
            let family = if string(&resource["name"], "familyName").is_empty() {
                parts.get(1..).unwrap_or_default().join(" ")
            } else {
                string(&resource["name"], "familyName").into()
            };
            let enterprise = &resource[ENTERPRISE_SCHEMA];
            let fields = UserInput {
                given_name: given,
                family_name: family,
                email,
                username,
                active: resource["active"].as_bool().unwrap_or(true),
                employee_number: string(enterprise, "employeeNumber").into(),
                cost_center: string(enterprise, "costCenter").into(),
                organization: string(enterprise, "organization").into(),
                division: string(enterprise, "division").into(),
                department: string(enterprise, "department").into(),
                attributes: matched
                    .map(|user| user.fields.attributes.clone())
                    .unwrap_or_default(),
                ..Default::default()
            };
            if !remote.is_empty() {
                remote_ids.insert(remote.to_owned(), id.clone());
            }
            users.push(User {
                id,
                fields,
                remote_id: remote.into(),
                ..Default::default()
            });
        }
        for (user, resource) in users.iter_mut().zip(&resources) {
            if let Some(manager) =
                remote_ids.get(string(&resource[ENTERPRISE_SCHEMA]["manager"], "value"))
                && manager != &user.id
            {
                user.fields.manager_id = manager.clone();
            }
        }
        let existing_groups = directory.projected_groups();
        let mut groups = Vec::new();
        let mut seen = HashSet::new();
        let mut skipped = 0;
        for resource in group_resources {
            let remote = string(&resource, "id");
            let external = string(&resource, "externalId");
            let id = if !external.is_empty() {
                external.into()
            } else {
                existing_groups
                    .iter()
                    .find(|group| !remote.is_empty() && group.remote_id == remote)
                    .map(|group| group.id.clone())
                    .unwrap_or_else(|| crate::store::new_id("group"))
            };
            if !seen.insert(id.clone()) {
                return Err(Failure::new(format!(
                    "SCIM /Groups returned more than one group with externalId {id:?}"
                )));
            }
            let mut members = Vec::new();
            if let Some(items) = resource["members"].as_array() {
                for member in items {
                    if let Some(id) = remote_ids.get(string(member, "value")) {
                        members.push(id.clone());
                    } else {
                        skipped += 1;
                    }
                }
            }
            groups.push(Group {
                id,
                fields: GroupInput {
                    display_name: string(&resource, "displayName").into(),
                    member_ids: members,
                },
                remote_id: remote.into(),
                ..Default::default()
            });
        }
        Ok((users, groups, skipped))
    }
}
fn non_empty<'a>(values: &[&'a str]) -> &'a str {
    values
        .iter()
        .copied()
        .find(|value| !value.is_empty())
        .unwrap_or_default()
}
pub(super) fn baseline(
    store: &crate::Store,
    id: &str,
) -> std::result::Result<(Directory, String), Error> {
    let directory = store.directory(id)?;
    let encoded = serde_json::to_vec(
        &json!({"config":directory.config,"global":store.global_config()?,"environment":directory.environment,"users":directory.projected_users(),"groups":directory.projected_groups()}),
    )?;
    let digest = Sha256::digest(encoded)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Ok((directory, digest))
}
pub(super) fn changes(
    directory: &Directory,
    users: &[User],
    groups: &[Group],
) -> (usize, usize, usize) {
    let mut current_users = directory
        .projected_users()
        .into_iter()
        .filter(|user| !user.deleted)
        .map(|user| (user.id.clone(), user))
        .collect::<HashMap<_, _>>();
    let mut current_groups = directory
        .projected_groups()
        .into_iter()
        .filter(|group| !group.deleted)
        .map(|group| (group.id.clone(), group))
        .collect::<HashMap<_, _>>();
    let (mut added, mut updated) = (0, 0);
    for user in users {
        match current_users.remove(&user.id) {
            None => added += 1,
            Some(existing)
                if existing.fields.given_name != user.fields.given_name
                    || existing.fields.family_name != user.fields.family_name
                    || existing.fields.email != user.fields.email
                    || existing.fields.username != user.fields.username
                    || existing.fields.active != user.fields.active =>
            {
                updated += 1
            }
            _ => {}
        }
    }
    for group in groups {
        match current_groups.remove(&group.id) {
            None => added += 1,
            Some(existing)
                if existing.fields.display_name != group.fields.display_name
                    || existing.fields.member_ids != group.fields.member_ids =>
            {
                updated += 1
            }
            _ => {}
        }
    }
    (added, updated, current_users.len() + current_groups.len())
}
impl crate::Store {
    pub(super) fn apply_scim_import(
        &self,
        id: &str,
        preview: &Preview,
    ) -> std::result::Result<(), Error> {
        let _mutation = self.mutation()?;
        let (_, digest) = baseline(self, id)?;
        if digest != preview.view.digest {
            return Err(Error::Conflict(
                "directory changed since the import preview; preview it again".into(),
            ));
        }
        {
            let connection = self.connection()?;
            crate::persistence::safety_copy(&connection, self.path(), "pre-scim-import")?;
        }
        self.edit_internal(id, |directory| {
            let users = preview
                .users
                .iter()
                .map(|user| user.id.as_str())
                .collect::<HashSet<_>>();
            let groups = preview
                .groups
                .iter()
                .map(|group| group.id.as_str())
                .collect::<HashSet<_>>();
            let mut imported_users = preview.users.clone();
            let mut imported_groups = preview.groups.clone();
            let user_sync = preview.users.iter().map(|user| {
                (
                    user.id.clone(),
                    ResourceSyncState {
                        remote_id: user.remote_id.clone(),
                        ..Default::default()
                    },
                )
            });
            let group_sync = preview.groups.iter().map(|group| {
                (
                    group.id.clone(),
                    ResourceSyncState {
                        remote_id: group.remote_id.clone(),
                        ..Default::default()
                    },
                )
            });
            directory.user_sync = user_sync.collect();
            directory.group_sync = group_sync.collect();
            for previous in &directory.users {
                if users.contains(previous.id.as_str()) {
                    continue;
                }
                if previous.deleted {
                    directory.user_sync.insert(
                        previous.id.clone(),
                        ResourceSyncState {
                            deleted: true,
                            ..Default::default()
                        },
                    );
                }
                let mut tombstone = previous.clone();
                tombstone.deleted = true;
                tombstone.dirty = false;
                tombstone.remote_id.clear();
                tombstone.last_error.clear();
                imported_users.push(tombstone);
            }
            for previous in &directory.groups {
                if groups.contains(previous.id.as_str()) {
                    continue;
                }
                if previous.deleted {
                    directory.group_sync.insert(
                        previous.id.clone(),
                        ResourceSyncState {
                            deleted: true,
                            ..Default::default()
                        },
                    );
                }
                let mut tombstone = previous.clone();
                tombstone.deleted = true;
                tombstone.dirty = false;
                tombstone.remote_id.clear();
                tombstone.last_error.clear();
                imported_groups.push(tombstone);
            }
            for user in &preview.users {
                directory.local_operation("user", &user.id, "Imported from SCIM");
            }
            for group in &preview.groups {
                directory.local_operation("group", &group.id, "Imported from SCIM");
            }
            for user in &mut imported_users {
                user.remote_id.clear();
            }
            for group in &mut imported_groups {
                group.remote_id.clear();
            }
            directory.users = imported_users;
            directory.groups = imported_groups;
            super::persistence::append_traces(directory, &preview.traces);
            super::persistence::purge(directory);
            Ok(())
        })
    }
}
