use std::collections::HashSet;

use crate::{Error, Store, model::*, store::new_id};

impl Store {
    pub fn create_user(&self, environment: &str, mut fields: UserInput) -> Result<User, Error> {
        normalize_user(&mut fields);
        self.edit(environment, |directory| {
            let user = User {
                id: new_id("user"),
                fields,
                dirty: true,
                ..Default::default()
            };
            validate_user(directory, &user)?;
            validate_manager(directory, &user.id, &user.fields.manager_id)?;
            directory.users.push(user.clone());
            directory.mark_user_dirty(&user.id, false);
            directory.local_operation("user", &user.id, "Created");
            Ok(user)
        })
    }

    pub fn update_user(
        &self,
        environment: &str,
        id: &str,
        patch: UserPatch,
    ) -> Result<User, Error> {
        self.edit(environment, |directory| {
            let index = user_index(directory, id)?;
            let mut user = directory.users[index].clone();
            if user.deleted {
                return Err(Error::Validation(
                    "deleted users must be restored before editing".into(),
                ));
            }
            if let Some(manager) = &patch.manager_id {
                validate_manager(directory, id, manager.trim())?;
            }
            user.fields.apply(patch);
            normalize_user(&mut user.fields);
            validate_user(directory, &user)?;
            let summary = user_summary(&directory.users[index], &user);
            user.dirty = true;
            user.last_error.clear();
            directory.users[index] = user.clone();
            directory.mark_user_dirty(id, false);
            directory.local_operation("user", id, &summary);
            Ok(user)
        })
    }

    pub fn delete_user(&self, environment: &str, id: &str) -> Result<(), Error> {
        self.edit(environment, |directory| {
            let index = user_index(directory, id)?;
            set_user_deleted(directory, index, true, "Marked for deletion");
            Ok(())
        })
    }

    pub fn restore_user(&self, environment: &str, id: &str) -> Result<User, Error> {
        self.edit(environment, |directory| {
            let index = user_index(directory, id)?;
            if !directory.tracks_scim() {
                return Err(Error::Conflict("SCIM is disabled".into()));
            }
            set_user_deleted(directory, index, false, "Restored");
            Ok(directory.users[index].clone())
        })
    }

    pub fn delete_users(&self, environment: &str, ids: &[String]) -> Result<usize, Error> {
        self.edit(environment, |directory| {
            let selected = validate_selection(
                ids,
                |id| {
                    directory
                        .users
                        .iter()
                        .any(|user| user.id == id && !user.deleted)
                },
                "user",
            )?;
            for index in (0..directory.users.len()).rev() {
                if selected.contains(&directory.users[index].id) {
                    set_user_deleted(directory, index, true, "Marked for deletion in bulk");
                }
            }
            Ok(selected.len())
        })
    }

    pub fn create_group(&self, environment: &str, mut fields: GroupInput) -> Result<Group, Error> {
        self.edit(environment, |directory| {
            fields.display_name = fields.display_name.trim().to_owned();
            validate_group(&fields.display_name)?;
            fields.member_ids = valid_members(directory, &fields.member_ids)?;
            let group = Group {
                id: new_id("group"),
                fields,
                dirty: true,
                ..Default::default()
            };
            directory.groups.push(group.clone());
            directory.mark_group_dirty(&group.id, false);
            directory.local_operation("group", &group.id, "Created");
            Ok(group)
        })
    }

    pub fn update_group(
        &self,
        environment: &str,
        id: &str,
        patch: GroupPatch,
    ) -> Result<Group, Error> {
        self.edit(environment, |directory| {
            let index = group_index(directory, id)?;
            let mut group = directory.groups[index].clone();
            if group.deleted {
                return Err(Error::Validation(
                    "deleted groups must be restored before editing".into(),
                ));
            }
            if let Some(name) = patch.display_name {
                group.fields.display_name = name.trim().to_owned();
            }
            if let Some(members) = patch.member_ids {
                group.fields.member_ids = valid_members(directory, &members)?;
            }
            validate_group(&group.fields.display_name)?;
            let old = &directory.groups[index].fields;
            let summary = if old.display_name != group.fields.display_name {
                "Updated name"
            } else if old.member_ids != group.fields.member_ids {
                "Updated members"
            } else {
                "Updated"
            };
            group.dirty = true;
            group.last_error.clear();
            directory.groups[index] = group.clone();
            directory.mark_group_dirty(id, false);
            directory.local_operation("group", id, summary);
            Ok(group)
        })
    }

    pub fn delete_group(&self, environment: &str, id: &str) -> Result<(), Error> {
        self.edit(environment, |directory| {
            let index = group_index(directory, id)?;
            set_group_deleted(directory, index, true, "Marked for deletion");
            Ok(())
        })
    }

    pub fn restore_group(&self, environment: &str, id: &str) -> Result<Group, Error> {
        self.edit(environment, |directory| {
            let index = group_index(directory, id)?;
            if !directory.tracks_scim() {
                return Err(Error::Conflict("SCIM is disabled".into()));
            }
            set_group_deleted(directory, index, false, "Restored");
            Ok(directory.groups[index].clone())
        })
    }

    pub fn delete_groups(&self, environment: &str, ids: &[String]) -> Result<usize, Error> {
        self.edit(environment, |directory| {
            let selected = validate_selection(
                ids,
                |id| {
                    directory
                        .groups
                        .iter()
                        .any(|group| group.id == id && !group.deleted)
                },
                "group",
            )?;
            for index in (0..directory.groups.len()).rev() {
                if selected.contains(&directory.groups[index].id) {
                    set_group_deleted(directory, index, true, "Marked for deletion in bulk");
                }
            }
            Ok(selected.len())
        })
    }

    pub fn seed_sample(&self, environment: &str) -> Result<SeedResult, Error> {
        self.edit(environment, |directory| {
            let users = directory.users.len();
            let groups = directory.groups.len();
            let result = crate::sample::append(directory)?;
            for id in directory.users[users..]
                .iter()
                .map(|user| user.id.clone())
                .collect::<Vec<_>>()
            {
                directory.mark_user_dirty(&id, false);
                directory.local_operation("user", &id, "Created by the Greendale sample");
            }
            for id in directory.groups[groups..]
                .iter()
                .map(|group| group.id.clone())
                .collect::<Vec<_>>()
            {
                directory.mark_group_dirty(&id, false);
                directory.local_operation("group", &id, "Created by the Greendale sample");
            }
            Ok(result)
        })
    }
}

impl Directory {
    pub fn tracks_scim(&self) -> bool {
        self.environment.settings.scim_enabled
            || !self.user_sync.is_empty()
            || !self.group_sync.is_empty()
    }

    pub(crate) fn mark_user_dirty(&mut self, id: &str, deleted: bool) {
        let ids = self
            .users
            .iter()
            .filter(|user| user.id == id || !user.deleted && user.fields.manager_id == id)
            .map(|user| user.id.clone())
            .collect::<Vec<_>>();
        for target in ids {
            if self.environment.settings.scim_enabled || self.user_sync.contains_key(&target) {
                let sync = self.user_sync.entry(target.clone()).or_default();
                sync.dirty = true;
                sync.deleted = deleted && target == id;
                sync.last_error.clear();
            }
        }
    }

    pub(crate) fn mark_group_dirty(&mut self, id: &str, deleted: bool) {
        if self.environment.settings.scim_enabled || self.group_sync.contains_key(id) {
            let sync = self.group_sync.entry(id.into()).or_default();
            sync.dirty = true;
            sync.deleted = deleted;
            sync.last_error.clear();
        }
    }

    pub(crate) fn local_operation(&mut self, kind: &str, id: &str, summary: &str) {
        let target = if kind == "user" {
            &mut self.user_operations
        } else {
            &mut self.group_operations
        };
        let entries = target.entry(id.into()).or_default();
        entries.insert(
            0,
            OperationLog {
                kind: "local".into(),
                summary: summary.into(),
                created_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                ..Default::default()
            },
        );
        entries.truncate(100);
    }
}

fn user_index(directory: &Directory, id: &str) -> Result<usize, Error> {
    directory
        .users
        .iter()
        .position(|user| user.id == id)
        .ok_or(Error::NotFound("user"))
}

fn group_index(directory: &Directory, id: &str) -> Result<usize, Error> {
    directory
        .groups
        .iter()
        .position(|group| group.id == id)
        .ok_or(Error::NotFound("group"))
}

fn set_user_deleted(directory: &mut Directory, index: usize, deleted: bool, summary: &str) {
    let id = directory.users[index].id.clone();
    if !directory.tracks_scim() {
        directory.users.remove(index);
        for group in &mut directory.groups {
            group.fields.member_ids.retain(|member| member != &id);
        }
        return;
    }
    let user = &mut directory.users[index];
    user.deleted = deleted;
    user.dirty = true;
    user.last_error.clear();
    directory.mark_user_dirty(&id, deleted);
    directory.local_operation("user", &id, summary);
}

fn set_group_deleted(directory: &mut Directory, index: usize, deleted: bool, summary: &str) {
    let id = directory.groups[index].id.clone();
    if !directory.tracks_scim() {
        directory.groups.remove(index);
        return;
    }
    let group = &mut directory.groups[index];
    group.deleted = deleted;
    group.dirty = true;
    group.last_error.clear();
    directory.mark_group_dirty(&id, deleted);
    directory.local_operation("group", &id, summary);
}

fn validate_selection(
    ids: &[String],
    available: impl Fn(&str) -> bool,
    kind: &str,
) -> Result<HashSet<String>, Error> {
    if ids.is_empty() {
        return Err(Error::Validation("ids must not be empty".into()));
    }
    let mut selected = HashSet::new();
    for id in ids {
        if !available(id) {
            return Err(Error::Validation(format!(
                "{kind} {id} is not available for deletion"
            )));
        }
        selected.insert(id.clone());
    }
    Ok(selected)
}

fn normalize_user(user: &mut UserInput) {
    for value in [
        &mut user.given_name,
        &mut user.family_name,
        &mut user.email,
        &mut user.username,
        &mut user.employee_number,
        &mut user.cost_center,
        &mut user.organization,
        &mut user.division,
        &mut user.department,
        &mut user.manager_id,
    ] {
        *value = value.trim().to_owned();
    }
    for value in user.attributes.values_mut() {
        *value = value.trim().to_owned();
    }
    if user.username.is_empty() {
        user.username.clone_from(&user.email);
    }
}

pub(crate) fn validate_user(directory: &Directory, user: &User) -> Result<(), Error> {
    let fields = &user.fields;
    if fields.given_name.is_empty() {
        return Err(Error::Validation("given name is required".into()));
    }
    if fields.email.is_empty() {
        return Err(Error::Validation("email is required".into()));
    }
    if !fields.email.contains('@') {
        return Err(Error::Validation(
            "email must look like an email address".into(),
        ));
    }
    for existing in directory
        .users
        .iter()
        .filter(|value| value.id != user.id && !value.deleted)
    {
        let label = if existing.fields.email.is_empty() {
            &existing.fields.username
        } else {
            &existing.fields.email
        };
        for (name, value, other) in [
            ("email", &fields.email, &existing.fields.email),
            ("username", &fields.username, &existing.fields.username),
        ] {
            if crate::casefold::equal(value, other.trim()) {
                return Err(Error::Validation(format!(
                    "{name} {value:?} is already used by {label}"
                )));
            }
        }
    }
    validate_attributes(&fields.attributes)
}

fn validate_manager(directory: &Directory, id: &str, manager: &str) -> Result<(), Error> {
    if manager.is_empty() {
        return Ok(());
    }
    if manager == id {
        return Err(Error::Validation(
            "a user cannot be their own manager".into(),
        ));
    }
    if !directory
        .users
        .iter()
        .any(|user| user.id == manager && !user.deleted)
    {
        return Err(Error::Validation(format!(
            "manager {manager:?} is not a user in this environment"
        )));
    }
    Ok(())
}

pub(crate) fn reserved_attribute(name: &str) -> bool {
    const RESERVED: &[&str] = &[
        "iss",
        "sub",
        "aud",
        "exp",
        "nbf",
        "iat",
        "jti",
        "nonce",
        "auth_time",
        "acr",
        "amr",
        "azp",
        "at_hash",
        "c_hash",
        "s_hash",
        "sid",
        "cnf",
        "client_id",
        "scope",
        "events",
        "_claim_names",
        "_claim_sources",
        "employeeNumber",
        "costCenter",
        "organization",
        "division",
        "department",
        "manager",
    ];
    RESERVED.contains(&name)
}

pub(crate) fn validate_attributes(
    attributes: &std::collections::BTreeMap<String, String>,
) -> Result<(), Error> {
    if attributes.len() > 50 {
        return Err(Error::Validation(
            "a user can have at most 50 custom attributes".into(),
        ));
    }
    for (name, value) in attributes {
        if name.len() > 128
            || !name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
            || !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "_.:/#-".contains(c))
        {
            return Err(Error::Validation(format!(
                "invalid custom attribute name {name:?}"
            )));
        }
        if reserved_attribute(name) {
            return Err(Error::Validation(format!(
                "custom attribute name {name:?} is reserved"
            )));
        }
        if value.len() > 1024 || value.contains(['\r', '\n']) {
            return Err(Error::Validation(format!(
                "custom attribute {name:?} must be a single line of at most 1024 characters"
            )));
        }
    }
    Ok(())
}

fn validate_group(name: &str) -> Result<(), Error> {
    if name.is_empty() {
        return Err(Error::Validation("group name is required".into()));
    }
    Ok(())
}

fn valid_members(directory: &Directory, ids: &[String]) -> Result<Vec<String>, Error> {
    let mut seen = HashSet::new();
    let mut members = Vec::new();
    for id in ids {
        if !directory
            .users
            .iter()
            .any(|user| user.id == *id && !user.deleted)
        {
            return Err(Error::Validation(format!(
                "user {id:?} is not available for membership"
            )));
        }
        if seen.insert(id) {
            members.push(id.clone());
        }
    }
    Ok(members)
}

fn user_summary(old: &User, new: &User) -> String {
    let a = &old.fields;
    let b = &new.fields;
    let enterprise = |fields: &UserInput| {
        [
            fields.employee_number.clone(),
            fields.cost_center.clone(),
            fields.organization.clone(),
            fields.division.clone(),
            fields.department.clone(),
            fields.manager_id.clone(),
        ]
    };
    let summary = if a.given_name != b.given_name || a.family_name != b.family_name {
        "Updated name"
    } else if a.email != b.email {
        "Updated email"
    } else if a.username != b.username {
        "Updated username"
    } else if enterprise(a) != enterprise(b) {
        "Updated enterprise attributes"
    } else if a.attributes != b.attributes {
        "Updated custom attributes"
    } else {
        "Updated"
    };
    if a.active != b.active {
        format!("{summary}; active set to {}", b.active)
    } else {
        summary.into()
    }
}

pub fn parse_custom_attributes(
    text: &str,
) -> Result<std::collections::BTreeMap<String, String>, Error> {
    let mut attributes = std::collections::BTreeMap::new();
    for (number, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once('=').ok_or_else(|| {
            Error::Validation(format!(
                "custom attribute on line {} must look like name=value",
                number + 1
            ))
        })?;
        let name = name.trim();
        if attributes
            .insert(name.into(), value.trim().into())
            .is_some()
        {
            return Err(Error::Validation(format!(
                "custom attribute {name:?} is listed more than once"
            )));
        }
    }
    validate_attributes(&attributes)?;
    Ok(attributes)
}

pub fn format_custom_attributes(attributes: &std::collections::BTreeMap<String, String>) -> String {
    attributes
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("\n")
}
