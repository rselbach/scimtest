use std::collections::HashSet;

use serde::Serialize;

use crate::{Error, Store, model::*, store::new_id};

#[derive(Debug, Default, Serialize)]
pub struct ToolResult {
    pub users_changed: usize,
    pub groups_changed: usize,
}

impl Store {
    pub fn create_users(
        &self,
        environment: &str,
        count: usize,
        domain: &str,
    ) -> Result<ToolResult, Error> {
        if !(1..=10000).contains(&count) {
            return Err(Error::Validation(
                "number of users must be between 1 and 10000".into(),
            ));
        }
        let domain = crate::casefold::lowercase(domain.trim());
        let domain = domain.strip_prefix('@').unwrap_or(&domain);
        if domain.is_empty()
            || domain.contains(['@', ' ', '\t', '\r', '\n', '/', '\\'])
            || domain.starts_with('.')
            || domain.ends_with('.')
        {
            return Err(Error::Validation("email domain is invalid".into()));
        }
        const NAMES: &[(&str, &str)] = &[
            ("Troy", "Barnes"),
            ("Abed", "Nadir"),
            ("Annie", "Edison"),
            ("Britta", "Perry"),
            ("Shirley", "Bennett"),
            ("Jeff", "Winger"),
            ("Dean", "Pelton"),
            ("Señor", "Chang"),
            ("Leonard", "Rodriguez"),
            ("Magnitude", "PopPop"),
        ];
        self.edit(environment, |directory| {
            let mut emails = directory
                .users
                .iter()
                .map(|user| crate::casefold::lowercase(&user.fields.email))
                .collect::<HashSet<_>>();
            let mut usernames = directory
                .users
                .iter()
                .map(|user| crate::casefold::lowercase(&user.fields.username))
                .collect::<HashSet<_>>();
            let mut candidate = 0;
            for index in 0..count {
                let (username, email) = loop {
                    candidate += 1;
                    let username = format!("user{candidate:03}");
                    let email = format!("{username}@{domain}");
                    if !usernames.contains(&username) && !emails.contains(&email) {
                        break (username, email);
                    }
                };
                emails.insert(email.clone());
                usernames.insert(username.clone());
                let (given, family) = NAMES[index % NAMES.len()];
                let id = new_id("user");
                directory.users.push(User {
                    id: id.clone(),
                    fields: UserInput {
                        given_name: given.into(),
                        family_name: family.into(),
                        email,
                        username,
                        ..Default::default()
                    },
                    dirty: true,
                    ..Default::default()
                });
                directory.mark_user_dirty(&id, false);
                directory.local_operation("user", &id, "Created by tools");
            }
            Ok(ToolResult {
                users_changed: count,
                ..Default::default()
            })
        })
    }

    pub fn set_all_active(&self, environment: &str, active: bool) -> Result<ToolResult, Error> {
        self.edit(environment, |directory| {
            let mut result = ToolResult::default();
            for index in 0..directory.users.len() {
                let user = &mut directory.users[index];
                if user.deleted || user.fields.active == active {
                    continue;
                }
                user.fields.active = active;
                user.dirty = true;
                user.last_error.clear();
                let id = user.id.clone();
                directory.mark_user_dirty(&id, false);
                directory.local_operation(
                    "user",
                    &id,
                    if active { "Activated" } else { "Deactivated" },
                );
                result.users_changed += 1;
            }
            Ok(result)
        })
    }

    pub fn delete_all_users(&self, environment: &str) -> Result<ToolResult, Error> {
        self.edit(environment, |directory| {
            let users_changed = directory.users.iter().filter(|user| !user.deleted).count();
            if directory.tracks_scim() {
                for index in 0..directory.users.len() {
                    let user = &mut directory.users[index];
                    if user.deleted {
                        continue;
                    }
                    user.deleted = true;
                    user.dirty = true;
                    let id = user.id.clone();
                    directory.mark_user_dirty(&id, true);
                    directory.local_operation("user", &id, "Marked for deletion by tools");
                }
            } else {
                directory.users.clear();
                for group in &mut directory.groups {
                    group.fields.member_ids.clear();
                }
            }
            Ok(ToolResult {
                users_changed,
                ..Default::default()
            })
        })
    }

    pub fn clear_directory(&self, environment: &str) -> Result<ToolResult, Error> {
        self.edit(environment, |directory| {
            let result = ToolResult {
                users_changed: directory.users.len(),
                groups_changed: directory.groups.len(),
            };
            directory.users.clear();
            directory.groups.clear();
            directory.user_sync.clear();
            directory.group_sync.clear();
            directory.user_operations.clear();
            directory.group_operations.clear();
            Ok(result)
        })
    }
}
