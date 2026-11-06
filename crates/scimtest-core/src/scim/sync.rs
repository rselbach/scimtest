use super::*;
use crate::model::{Group, User};
use std::collections::HashSet;

#[derive(Clone, Debug)]
pub enum Mode {
    Sync,
    Reconcile,
    Push {
        resource_type: String,
        resource_id: String,
    },
}
#[derive(Clone, Default, Debug)]
pub struct Progress {
    pub total: usize,
    pub processed: usize,
    pub target: Target,
    pub phase: String,
    pub status: String,
    pub detail: String,
    pub rate_limited: bool,
}
pub type ProgressCallback = Arc<dyn Fn(Progress) + Send + Sync>;
#[derive(Default, Debug)]
pub struct Counts {
    pub created: usize,
    pub adopted: usize,
    pub updated: usize,
    pub deleted: usize,
    pub failed: usize,
    pub in_sync: usize,
}
pub struct SyncResult {
    pub users: Vec<User>,
    pub groups: Vec<Group>,
    pub enterprise: bool,
    pub traces: Vec<Trace>,
    pub users_count: Counts,
    pub groups_count: Counts,
    pub stopped: Option<Failure>,
}
impl SyncResult {
    pub fn success(&self) -> bool {
        self.stopped.is_none() && self.users_count.failed + self.groups_count.failed == 0
    }
    pub fn status(&self, mode: &Mode) -> String {
        let label = if matches!(mode, Mode::Reconcile) {
            "reconcile"
        } else {
            "sync"
        };
        let describe = |counts: &Counts| {
            let created = if counts.adopted > 0 {
                format!("{} created, {} adopted", counts.created, counts.adopted)
            } else {
                format!("{} created", counts.created)
            };
            let checks = if matches!(mode, Mode::Reconcile) {
                format!(", {} in sync", counts.in_sync)
            } else {
                String::new()
            };
            format!(
                "{created}, {} updated, {} deleted{checks}, {} failed",
                counts.updated, counts.deleted, counts.failed
            )
        };
        let result = format!(
            "{label} finished: users {}; groups {}",
            describe(&self.users_count),
            describe(&self.groups_count)
        );
        self.stopped
            .as_ref()
            .map(|error| format!("{label} stopped: {error}; {result}"))
            .unwrap_or(result)
    }
}
struct Reporter {
    total: usize,
    processed: usize,
    callback: Option<ProgressCallback>,
}
impl Reporter {
    fn emit(&self, target: Target, phase: &str, status: &str, detail: &str) {
        if let Some(callback) = &self.callback {
            callback(Progress {
                total: self.total,
                processed: self.processed,
                target,
                phase: phase.into(),
                status: status.into(),
                detail: detail.into(),
                rate_limited: false,
            });
        }
    }
    fn done(&mut self, target: Target, status: &str, error: Option<&Failure>) {
        self.processed += 1;
        self.emit(
            target,
            if error.is_some() { "failed" } else { "done" },
            status,
            error
                .map(|error| error.message.as_str())
                .unwrap_or_default(),
        );
    }
}
impl Client {
    pub async fn sync(
        mut self,
        directory: &Directory,
        mode: Mode,
        callback: Option<ProgressCallback>,
    ) -> SyncResult {
        let mut users = directory.projected_users();
        let mut groups = directory.projected_groups();
        let selected = |kind: &str, id: &str, dirty: bool| match &mode {
            Mode::Sync => dirty,
            Mode::Reconcile => true,
            Mode::Push {
                resource_type,
                resource_id,
            } => resource_type == kind && resource_id == id,
        };
        let total = users
            .iter()
            .filter(|user| selected("user", &user.id, user.dirty))
            .count()
            + groups
                .iter()
                .filter(|group| selected("group", &group.id, group.dirty))
                .count();
        let mut reporter = Reporter {
            total,
            processed: 0,
            callback,
        };
        let mut users_count = Counts::default();
        let mut groups_count = Counts::default();
        let mut stopped = None;
        let mut awaiting = Vec::new();
        let mut settled = HashSet::new();
        let mut group_followups = HashSet::new();
        let enterprise = directory
            .config
            .get("scim_enterprise_used")
            .is_some_and(|value| value == "1")
            || users
                .iter()
                .filter(|user| !user.deleted)
                .any(resources::has_enterprise);
        reporter.emit(Target::default(), "", "Starting sync", "");
        for index in 0..users.len() {
            let mut user = users[index].clone();
            if !selected("user", &user.id, user.dirty) {
                continue;
            }
            user.last_error.clear();
            let mut operation = if user.deleted {
                "delete"
            } else if user.remote_id.is_empty() {
                "create"
            } else if matches!(mode, Mode::Reconcile) {
                "check"
            } else {
                "update"
            };
            let mut target = resources::user_target(&user, operation);
            reporter.emit(target.clone(), "running", "In progress", "");
            let needs_manager = enterprise
                && !user.fields.manager_id.is_empty()
                && users.iter().any(|manager| {
                    manager.id == user.fields.manager_id
                        && !manager.deleted
                        && manager.remote_id.is_empty()
                });
            let result = self
                .sync_user(
                    &mut user,
                    &users,
                    enterprise,
                    matches!(mode, Mode::Reconcile),
                )
                .await;
            match result {
                Ok(outcome) => {
                    user.dirty = false;
                    let status = outcome.count(&mut users_count);
                    if matches!(outcome, Outcome::Created | Outcome::Adopted) {
                        operation = "create";
                    } else if matches!(outcome, Outcome::Updated) {
                        operation = "update";
                    }
                    target.operation = operation.into();
                    if user.deleted {
                        user.remote_id.clear();
                        settled.insert(user.id.clone());
                        for group in &mut groups {
                            if group
                                .fields
                                .member_ids
                                .iter()
                                .any(|member| member == &user.id)
                            {
                                group.fields.member_ids.retain(|member| member != &user.id);
                                if !selected("group", &group.id, group.dirty)
                                    && group_followups.insert(group.id.clone())
                                {
                                    reporter.total += 1;
                                }
                                group.dirty = true;
                            }
                        }
                    } else if needs_manager {
                        awaiting.push(index);
                    }
                    reporter.done(target, status, None);
                }
                Err(error) => {
                    user.last_error = error.to_string();
                    user.dirty = true;
                    users_count.failed += 1;
                    reporter.done(target, "Failed", Some(&error));
                    if error.stops_sync() {
                        stopped = Some(error);
                    }
                }
            }
            users[index] = user;
            if stopped.is_some() {
                break;
            }
        }
        for (position, index) in awaiting.iter().copied().enumerate() {
            if stopped.is_some() {
                for pending in &awaiting[position..] {
                    users[*pending].dirty = true;
                }
                break;
            }
            let user = users[index].clone();
            let manager = users.iter().find(|manager| {
                manager.id == user.fields.manager_id
                    && !manager.deleted
                    && !settled.contains(&manager.id)
            });
            let Some(manager) = manager else {
                continue;
            };
            if manager.remote_id.is_empty() {
                users[index].dirty = true;
                continue;
            }
            reporter.total += 1;
            let target = resources::user_target(&user, "update");
            reporter.emit(target.clone(), "running", "In progress", "");
            match self.update_user(&user, &users, enterprise).await {
                Ok(()) => {
                    users_count.updated += 1;
                    reporter.done(target, "Updated", None);
                }
                Err(error) => {
                    users[index].dirty = true;
                    users[index].last_error = error.to_string();
                    users_count.failed += 1;
                    reporter.done(target, "Failed", Some(&error));
                    if error.stops_sync() {
                        stopped = Some(error);
                    }
                }
            }
        }
        users.retain(|user| !settled.contains(&user.id));
        let mut settled_groups = HashSet::new();
        if stopped.is_none() {
            for group in &mut groups {
                if !selected("group", &group.id, group.dirty)
                    && !group_followups.contains(&group.id)
                {
                    continue;
                }
                group.last_error.clear();
                let operation = if group.deleted {
                    "delete"
                } else if group.remote_id.is_empty() {
                    "create"
                } else if matches!(mode, Mode::Reconcile) {
                    "check"
                } else {
                    "update"
                };
                let mut target = resources::group_target(group, operation);
                reporter.emit(target.clone(), "running", "In progress", "");
                match self
                    .sync_group(group, &users, matches!(mode, Mode::Reconcile))
                    .await
                {
                    Ok(outcome) => {
                        group.dirty = false;
                        let status = outcome.count(&mut groups_count);
                        if matches!(outcome, Outcome::Created | Outcome::Adopted) {
                            target.operation = "create".into();
                        } else if matches!(outcome, Outcome::Updated) {
                            target.operation = "update".into();
                        }
                        if group.deleted {
                            group.remote_id.clear();
                            settled_groups.insert(group.id.clone());
                        }
                        reporter.done(target, status, None);
                    }
                    Err(error) => {
                        group.dirty = true;
                        group.last_error = error.to_string();
                        groups_count.failed += 1;
                        reporter.done(target, "Failed", Some(&error));
                        if error.stops_sync() {
                            stopped = Some(error);
                            break;
                        }
                    }
                }
            }
        }
        groups.retain(|group| !settled_groups.contains(&group.id));
        SyncResult {
            users,
            groups,
            enterprise,
            traces: self.traces,
            users_count,
            groups_count,
            stopped,
        }
    }
    async fn sync_user(
        &mut self,
        user: &mut User,
        users: &[User],
        enterprise: bool,
        reconcile: bool,
    ) -> Result<Outcome> {
        if user.deleted {
            if user.remote_id.is_empty() {
                return Ok(Outcome::Forgotten);
            }
            self.delete_user(user).await?;
            return Ok(Outcome::Deleted);
        }
        if user.remote_id.is_empty() {
            return self.assign_user(user, users, enterprise).await;
        }
        if reconcile {
            match self.get_user(user).await {
                Ok(remote) if user_matches(&user_resource(user, users, enterprise), &remote) => {
                    return Ok(Outcome::InSync);
                }
                Ok(_) => {}
                Err(error) if error.not_found() => {
                    return self.assign_user(user, users, enterprise).await;
                }
                Err(error) => return Err(error),
            }
        }
        self.update_user(user, users, enterprise).await?;
        Ok(Outcome::Updated)
    }
    async fn assign_user(
        &mut self,
        user: &mut User,
        users: &[User],
        enterprise: bool,
    ) -> Result<Outcome> {
        let (id, adopted) = self.create_user(user, users, enterprise).await?;
        user.remote_id = id;
        Ok(if adopted {
            Outcome::Adopted
        } else {
            Outcome::Created
        })
    }
    async fn sync_group(
        &mut self,
        group: &mut Group,
        users: &[User],
        reconcile: bool,
    ) -> Result<Outcome> {
        if group.deleted {
            if group.remote_id.is_empty() {
                return Ok(Outcome::Forgotten);
            }
            self.delete_group(group).await?;
            return Ok(Outcome::Deleted);
        }
        let create = if group.remote_id.is_empty() {
            true
        } else if reconcile {
            match self.get_group(group).await {
                Ok(remote) if group_matches(&group_resource(group, users)?, &remote) => {
                    return Ok(Outcome::InSync);
                }
                Ok(_) => false,
                Err(error) if error.not_found() => true,
                Err(error) => return Err(error),
            }
        } else {
            false
        };
        if create {
            let (id, adopted) = self.create_group(group, users).await?;
            group.remote_id = id;
            return Ok(if adopted {
                Outcome::Adopted
            } else {
                Outcome::Created
            });
        }
        self.update_group(group, users).await?;
        Ok(Outcome::Updated)
    }
}
enum Outcome {
    Created,
    Adopted,
    Updated,
    Deleted,
    Forgotten,
    InSync,
}
impl Outcome {
    fn count(&self, counts: &mut Counts) -> &'static str {
        match self {
            Self::Created => {
                counts.created += 1;
                "Created"
            }
            Self::Adopted => {
                counts.adopted += 1;
                "Adopted"
            }
            Self::Updated => {
                counts.updated += 1;
                "Updated"
            }
            Self::Deleted => {
                counts.deleted += 1;
                "Deleted"
            }
            Self::Forgotten => {
                counts.deleted += 1;
                "Deleted locally"
            }
            Self::InSync => {
                counts.in_sync += 1;
                "In sync"
            }
        }
    }
}
fn user_matches(desired: &Value, remote: &Value) -> bool {
    for name in ["userName", "displayName", "externalId"] {
        if string(desired, name) != string(remote, name) {
            return false;
        }
    }
    if desired["active"].as_bool().unwrap_or(true) != remote["active"].as_bool().unwrap_or(true) {
        return false;
    }
    for name in ["givenName", "familyName"] {
        if string(&desired["name"], name) != string(&remote["name"], name) {
            return false;
        }
    }
    if entra::email(desired) != entra::email(remote) {
        return false;
    }
    if desired.get(ENTERPRISE_SCHEMA).is_some() {
        for name in [
            "employeeNumber",
            "costCenter",
            "organization",
            "division",
            "department",
        ] {
            if string(&desired[ENTERPRISE_SCHEMA], name) != string(&remote[ENTERPRISE_SCHEMA], name)
            {
                return false;
            }
        }
        if string(&desired[ENTERPRISE_SCHEMA]["manager"], "value")
            != string(&remote[ENTERPRISE_SCHEMA]["manager"], "value")
        {
            return false;
        }
    }
    true
}
fn group_matches(desired: &Value, remote: &Value) -> bool {
    if string(desired, "displayName") != string(remote, "displayName")
        || string(desired, "externalId") != string(remote, "externalId")
    {
        return false;
    }
    let members = |value: &Value| {
        value["members"]
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .map(|item| string(item, "value").to_owned())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    };
    let want = members(desired);
    let have = members(remote);
    want.len() == have.len() && want.iter().all(|member| have.contains(member))
}
