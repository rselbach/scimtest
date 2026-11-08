use super::*;
use std::collections::HashSet;

pub(super) struct Push {
    step: String,
    resource_type: String,
    resource_id: String,
    dependency: String,
}
impl Push {
    pub fn user(id: &str) -> Self {
        Self {
            step: "scim-user".into(),
            resource_type: "user".into(),
            resource_id: id.into(),
            dependency: String::new(),
        }
    }
    pub fn group(id: &str, dependency: &str) -> Self {
        Self {
            step: format!("scim-group-{id}"),
            resource_type: "group".into(),
            resource_id: id.into(),
            dependency: dependency.into(),
        }
    }
}
pub(super) fn push_step(group: &Group) -> LifecycleStep {
    LifecycleStep::new(
        &format!("scim-group-{}", group.id),
        "scim",
        format!("Push group {} through SCIM", group.fields.display_name),
        "running",
        "Waiting to push",
    )
}
impl Identity {
    pub(super) fn update_lifecycle_step(
        &self,
        id: &str,
        run: &str,
        step: &str,
        update: impl FnOnce(&mut LifecycleStep),
    ) -> Result<()> {
        let mut memory = self.memory()?;
        if let Some(run) = memory
            .lifecycle
            .get_mut(id)
            .into_iter()
            .flatten()
            .find(|value| value.id == run)
        {
            if let Some(step) = run.steps.iter_mut().find(|value| value.id == step) {
                update(step);
            }
            run.settle_status();
            if let Some(revision) = &memory.revision {
                revision.send_modify(|value| *value = value.wrapping_add(1));
            }
        }
        Ok(())
    }
    pub(super) fn run_lifecycle_pushes(
        &self,
        id: &str,
        run: &str,
        pushes: Vec<Push>,
        scim: scim::Service,
    ) -> Result<()> {
        let Some(runtime) = &self.0.runtime else {
            for push in pushes {
                self.update_lifecycle_step(id, run, &push.step, |step| {
                    step.status = "failed".into();
                    step.detail =
                        "The push did not start: SCIM jobs require an async runtime".into();
                })?;
            }
            return Ok(());
        };
        let base = self
            .0
            .store
            .directory(id)?
            .environment
            .settings
            .scim_base_url;
        let identity = self.clone();
        let id = id.to_owned();
        let run = run.to_owned();
        runtime.spawn(async move {
            let mut failed = HashSet::new();
            for push in pushes {
                let result = if !push.dependency.is_empty() && failed.contains(&push.dependency) {
                    identity.update_lifecycle_step(&id, &run, &push.step, |step| {
                        step.status = "skipped".into();
                        step.detail = "Skipped because the user was not provisioned".into();
                    })
                } else {
                    match identity
                        .lifecycle_push(&id, &run, &push, &scim, &base)
                        .await
                    {
                        Ok(success) => {
                            if !success {
                                failed.insert(push.step.clone());
                            }
                            Ok(())
                        }
                        Err(error) => Err(error),
                    }
                };
                if let Err(error) = result {
                    eprintln!("Record lifecycle SCIM push: {}", error.description);
                }
            }
        });
        Ok(())
    }
    async fn lifecycle_push(
        &self,
        id: &str,
        run: &str,
        push: &Push,
        scim: &scim::Service,
        base: &str,
    ) -> Result<bool> {
        self.update_lifecycle_step(id, run, &push.step, |step| step.detail = "Pushing".into())?;
        let service = scim.clone();
        let environment = id.to_owned();
        let mode = scim::Mode::Push {
            resource_type: push.resource_type.clone(),
            resource_id: push.resource_id.clone(),
        };
        let job = match tokio::task::spawn_blocking(move || service.start(&environment, mode)).await
        {
            Ok(Ok(job)) => job,
            result => {
                let error = match result {
                    Ok(Err(error)) => error.to_string(),
                    Err(error) => error.to_string(),
                    _ => unreachable!(),
                };
                self.update_lifecycle_step(id, run, &push.step, |step| {
                    step.status = "failed".into();
                    step.detail = format!("The push did not start: {error}");
                })?;
                return Ok(false);
            }
        };
        let done = loop {
            let service = scim.clone();
            let environment = id.to_owned();
            let current = tokio::task::spawn_blocking(move || service.status(&environment, 0))
                .await
                .map_err(|error| ProtocolError::new("server_error", &error.to_string()))??;
            match current {
                Some(current) if current.id == job.id && current.done => break Some(current),
                Some(current) if current.id == job.id => {}
                _ => break None,
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        };
        let messages = scim
            .traces(id)?
            .into_iter()
            .filter(|trace| {
                trace.resource_type == push.resource_type && trace.resource_id == push.resource_id
            })
            .map(|trace| {
                let failed = !trace.err.is_empty();
                LifecycleMessage {
                    at: trace.created_at,
                    sent: format!("{} {}", trace.method, trace.path),
                    to: format!("{}{}", base.trim_end_matches('/'), trace.path),
                    body: trace.request_body,
                    response: if failed { trace.err } else { trace.status },
                    outcome: if failed { "failed" } else { "ok" }.into(),
                }
            })
            .collect();
        let success = done.as_ref().is_some_and(|job| job.success);
        self.update_lifecycle_step(id, run, &push.step, |step| {
            step.messages = messages;
            step.status = if success { "ok" } else { "failed" }.into();
            step.detail = done.map(|job| job.message).unwrap_or_else(|| {
                "A later sync replaced this push's result; see the sync trace".into()
            });
        })?;
        Ok(success)
    }
}
