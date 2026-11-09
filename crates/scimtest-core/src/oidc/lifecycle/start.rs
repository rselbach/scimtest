use super::*;
use groups::{change_groups, issued_step};
use pushes::{Push, push_step};

impl Identity {
    pub fn start_joiner(
        &self,
        id: &str,
        input: JoinerInput,
        scim: scim::Service,
    ) -> Result<LifecycleRun> {
        let environment = self.0.store.directory(id)?;
        for group in &input.group_ids {
            if !environment
                .groups
                .iter()
                .any(|existing| existing.id == *group && !existing.deleted)
            {
                return Err(ProtocolError {
                    status: 404,
                    ..ProtocolError::new("not_found", &format!("group {group:?} not found"))
                });
            }
        }
        let user = self.0.store.create_user(
            id,
            UserInput {
                given_name: input.given_name,
                family_name: input.family_name,
                email: input.email,
                username: input.username,
                active: true,
                ..Default::default()
            },
        )?;
        let mut run = LifecycleRun::new("joiner", &user);
        run.steps.push(LifecycleStep::new(
            "create",
            "directory",
            format!("Create {}", run.user),
            LifecycleStatus::Ok,
            format!("Created {} <{}> in scimtest", run.user, user.fields.email),
        ));
        let mut changed = Vec::new();
        if !input.group_ids.is_empty() {
            let mut step = LifecycleStep::new(
                "groups",
                "directory",
                format!("Add {} to groups", run.user),
                LifecycleStatus::Ok,
                "",
            );
            match change_groups(&self.0.store, id, &user.id, &input.group_ids, &[], false) {
                Ok(change) => {
                    step.detail = change.describe();
                    changed = change.added;
                }
                Err(error) => {
                    step.status = LifecycleStatus::Failed;
                    step.detail = error.to_string();
                }
            }
            run.steps.push(step);
        }
        let environment = environment.environment;
        let mut pushes = Vec::new();
        if let Some(reason) = scim_skip(&environment) {
            run.steps.push(LifecycleStep::new(
                "scim",
                "scim",
                format!("Provision {} through SCIM", run.user),
                LifecycleStatus::Skipped,
                reason,
            ));
        } else {
            run.steps.push(LifecycleStep::new(
                "scim-user",
                "scim",
                format!("Provision {} through SCIM", run.user),
                LifecycleStatus::Running,
                "Waiting to push",
            ));
            pushes.push(Push::user(&user.id));
            for group in changed {
                run.steps.push(push_step(&group));
                pushes.push(Push::group(&group.id, "scim-user"));
            }
        }
        self.start_lifecycle(id, run, pushes, scim)
    }
    pub fn start_mover(
        &self,
        id: &str,
        input: MoverInput,
        scim: scim::Service,
    ) -> Result<LifecycleRun> {
        let change = change_groups(
            &self.0.store,
            id,
            &input.user_id,
            &input.add_group_ids,
            &input.remove_group_ids,
            true,
        )?;
        let mut run = LifecycleRun::new("mover", &change.user);
        run.expected_groups = change.groups.clone();
        run.steps.push(LifecycleStep::new(
            "groups",
            "directory",
            format!("Change {}'s groups", run.user),
            LifecycleStatus::Ok,
            change.describe(),
        ));
        let mut pushes = Vec::new();
        if let Some(reason) = scim_skip(&change.environment) {
            run.steps.push(LifecycleStep::new(
                "scim",
                "scim",
                "Push the changed groups through SCIM",
                LifecycleStatus::Skipped,
                reason,
            ));
        } else {
            for group in change.added.iter().chain(&change.removed) {
                run.steps.push(push_step(group));
                pushes.push(Push::group(&group.id, ""));
            }
        }
        for protocol in ["oidc", "saml"] {
            run.steps.push(issued_step(
                &change.environment,
                protocol,
                &run.user,
                &change.groups,
            ));
        }
        self.start_lifecycle(id, run, pushes, scim)
    }
    pub fn start_leaver(
        &self,
        id: &str,
        user_id: &str,
        scim: scim::Service,
    ) -> Result<LifecycleRun> {
        let directory = self.0.store.directory(id)?;
        let user = directory
            .users
            .iter()
            .find(|user| user.id == user_id && !user.deleted)
            .ok_or_else(|| ProtocolError {
                status: 404,
                ..ProtocolError::new("not_found", &format!("user {user_id:?} not found"))
            })?;
        let mut run = LifecycleRun::new("leaver", user);
        let mut memory = self.memory()?;
        memory.prune(Utc::now());
        let mut ended = memory
            .sessions
            .values()
            .filter(|session| session.environment == id && session.user == user_id)
            .cloned()
            .collect::<Vec<_>>();
        ended.sort_by(|left, right| left.id.cmp(&right.id));
        let deactivate = if user.fields.active {
            self.0.store.update_user(
                id,
                user_id,
                crate::model::UserPatch {
                    active: Some(false),
                    ..Default::default()
                },
            )?;
            LifecycleStep::new(
                "deactivate",
                "directory",
                format!("Deactivate {}", run.user),
                LifecycleStatus::Ok,
                "Set active to false in scimtest",
            )
        } else {
            LifecycleStep::new(
                "deactivate",
                "directory",
                format!("Deactivate {}", run.user),
                LifecycleStatus::Skipped,
                format!("{} was already inactive", run.user),
            )
        };
        for session in &ended {
            memory.end_session(&session.id, "user is inactive or missing");
        }
        drop(memory);
        let environment = &directory.environment;
        run.steps.push(deactivate);
        run.steps
            .extend(logout::session_steps(environment, &run.user, &ended));
        let mut revoke = LifecycleStep::new(
            "revoke",
            "oidc",
            format!("Revoke {}'s tokens", run.user),
            LifecycleStatus::Ok,
            "",
        );
        if environment.settings.supports_oidc() {
            let revoked = self.revoke_tokens(id, user_id)?;
            revoke.detail = format!("Revoked {revoked} tokens");
            self.memory()?
                .event(id, "revoke", &run.user, &revoke.detail);
        } else {
            revoke.status = LifecycleStatus::Skipped;
            revoke.detail = "OIDC is not enabled for this environment".into();
        }
        run.steps.push(revoke);
        let mut pushes = Vec::new();
        if let Some(reason) = scim_skip(environment) {
            run.steps.push(LifecycleStep::new(
                "scim",
                "scim",
                "Push active=false through SCIM",
                LifecycleStatus::Skipped,
                reason,
            ));
        } else {
            run.steps.push(LifecycleStep::new(
                "scim-user",
                "scim",
                "Push active=false through SCIM",
                LifecycleStatus::Running,
                "Waiting to push",
            ));
            pushes.push(Push::user(user_id));
        }
        self.start_lifecycle(id, run, pushes, scim)
    }
    fn start_lifecycle(
        &self,
        id: &str,
        mut run: LifecycleRun,
        pushes: Vec<Push>,
        scim: scim::Service,
    ) -> Result<LifecycleRun> {
        run.settle_status();
        let mut memory = self.memory()?;
        let runs = memory.lifecycle.entry(id.into()).or_default();
        runs.insert(0, run.clone());
        runs.truncate(10);
        let kind = format!("{}{}", run.kind[..1].to_ascii_uppercase(), &run.kind[1..]);
        memory.protocol_event(
            id,
            "lifecycle",
            &run.kind,
            "ok",
            &run.user,
            &format!("{kind} scenario started; see its Lifecycle checklist"),
        );
        drop(memory);
        if !pushes.is_empty() {
            self.run_lifecycle_pushes(id, &run.id, pushes, scim)?;
        }
        self.lifecycle_run(id, &run.id)
    }
}
fn scim_skip(environment: &Environment) -> Option<&'static str> {
    if !environment.settings.scim_enabled {
        return Some("SCIM is not enabled for this environment");
    }
    if environment.settings.scim_base_url.trim().is_empty()
        || environment.settings.scim_bearer_token.trim().is_empty()
    {
        return Some("Set the environment's SCIM base URL and bearer token to provision");
    }
    None
}
