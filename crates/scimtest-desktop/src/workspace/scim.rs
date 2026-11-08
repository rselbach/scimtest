use rune::{El, ScrollSpec, col, el, row};
use rune_kit::{Button, ButtonVariant};
use scimtest_core::{
    Error,
    scim::{Job, Mode, PlanEntry, PreviewView, Trace},
};

use super::{
    Editor, Workspace,
    view::{empty, font_text},
};
use crate::theme::{SEMIBOLD, Ui};

#[derive(Default)]
pub(super) struct Inspector {
    pub job: Option<Job>,
    pub plan: Vec<PlanEntry>,
    pub traces: Vec<Trace>,
    pub preview: Option<PreviewView>,
}

fn card(key: impl Into<String>, label: String, ui: &Ui) -> El {
    col()
        .key(key.into())
        .role("group")
        .label(label)
        .w_full()
        .padding(16.0)
        .fill(ui.p.card)
        .radius(6.0)
        .border(1.0, ui.p.line)
}

impl Workspace {
    pub(super) fn scim_running(&self) -> bool {
        self.scim_view.job.as_ref().is_some_and(|job| job.running)
    }

    pub(super) fn refresh_scim(&mut self) {
        if self.busy || self.scim_refreshing {
            self.scim_refresh_pending = true;
            return;
        }
        let Some(id) = self.selected.clone() else {
            return;
        };
        self.scim_refresh_pending = false;
        let service = self.scim_service.clone();
        let store = self.store.clone();
        let request_id = id.clone();
        self.scim_refreshing = true;
        self.background(
            move || {
                let directory = store.directory(&request_id)?;
                let job = service.status(&request_id, 0)?;
                let traces = service.traces(&request_id)?;
                let preview = match service.import_preview(&request_id) {
                    Ok(value) => Some(value),
                    Err(Error::NotFound(_)) => None,
                    Err(error) => return Err(error),
                };
                Ok::<_, Error>(Inspector {
                    job,
                    plan: scimtest_core::scim::plan(&directory),
                    traces,
                    preview,
                })
            },
            move |view, result| {
                view.scim_refreshing = false;
                if view.selected.as_ref() == Some(&id) {
                    match result {
                        Ok(snapshot) => {
                            if let Some(job) = &snapshot.job
                                && job.done
                                && view
                                    .scim_view
                                    .job
                                    .as_ref()
                                    .is_none_or(|previous| previous.id != job.id || !previous.done)
                            {
                                view.message = job.message.clone();
                                view.failed = !job.success;
                            }
                            view.scim_view = snapshot;
                        }
                        Err(error) => view.fail(error.to_string()),
                    }
                }
                if view.scim_refresh_pending && !view.busy {
                    view.refresh_scim();
                }
            },
        );
    }

    pub(super) fn scim_action(&mut self, action: &'static str, target: Option<(String, String)>) {
        if self.busy {
            return;
        }
        let Some(id) = self.selected.clone() else {
            return;
        };
        let service = self.scim_service.clone();
        let store = self.store.clone();
        let request_id = id.clone();
        self.busy = true;
        self.task(
            async move {
                let id = request_id;
                let message = match action {
                    "sync" => service.start(&id, Mode::Sync)?.message,
                    "reconcile" => service.start(&id, Mode::Reconcile)?.message,
                    "push" => {
                        let (resource_type, resource_id) = target
                            .ok_or_else(|| Error::Validation("select a resource to push".into()))?;
                        service
                            .start(
                                &id,
                                Mode::Push {
                                    resource_type,
                                    resource_id,
                                },
                            )?
                            .message
                    }
                    "cancel" => {
                        service.cancel(&id)?;
                        "Stopping sync".into()
                    }
                    "discover" => {
                        let (patch, filter) = service.discover(id.clone(), true).await?;
                        format!(
                            "SCIM capabilities: PATCH {}; filters {}",
                            if patch { "supported" } else { "unavailable" },
                            if filter { "supported" } else { "unavailable" }
                        )
                    }
                    "test" => {
                        service.discover(id.clone(), false).await?;
                        "SCIM connection succeeded".into()
                    }
                    "preview" => {
                        service.preview_import(id.clone()).await?;
                        "Import preview ready".into()
                    }
                    "apply" => service.apply_import(&id)?,
                    "reset" => {
                        let (users, groups) = store.reset_scim(&id)?;
                        format!("Reset remote tracking for {users} users and {groups} groups")
                    }
                    _ => return Err(Error::Validation("unknown SCIM action".into())),
                };
                Ok::<_, Error>(message)
            },
            move |view, result, _| {
                view.busy = false;
                if view.selected.as_ref() != Some(&id) {
                    return;
                }
                match result {
                    Ok(message) => {
                        view.message = message;
                        view.failed = false;
                    }
                    Err(error) => view.fail(error.to_string()),
                }
                view.refresh_scim();
            },
        );
    }

    fn show_scim_trace(&mut self) {
        let entries = self
            .scim_view
            .traces
            .iter()
            .map(|trace| scimtest_core::model::OperationLog {
                summary: trace.label.clone(),
                kind: "sync".into(),
                operation: trace.operation.clone(),
                method: trace.method.clone(),
                path: trace.path.clone(),
                request_body: trace.request_body.clone(),
                status: trace.status.clone(),
                response_retry_after: trace.response_retry_after.clone(),
                response_body: trace.response_body.clone(),
                err: trace.err.clone(),
                created_at: trace.created_at.clone(),
                ..Default::default()
            })
            .collect();
        self.open_editor(Editor::History {
            noun: "",
            name: "SCIM trace".into(),
            entries,
            expanded: Default::default(),
        });
    }

    pub(super) fn scim_inspector(&self, ui: &Ui, _layer: &mut Vec<El>) -> El {
        let k = &ui.k;
        let p = ui.p;
        let running = self.scim_running();
        let mut controls = row().gap(8.0).center_y();
        for (action, label) in [
            ("reconcile", "Reconcile all"),
            ("discover", "Discover capabilities"),
            ("test", "Test connection"),
            ("preview", "Preview remote import"),
            ("reset", "Reset tracking"),
        ] {
            controls = controls.child(
                Button::new(label)
                    .disabled(self.busy || running)
                    .on_press(move |s: &mut Workspace| s.scim_action(action, None))
                    .build(k)
                    .key(action),
            );
        }
        controls = controls.child(
            Button::new("Cancel")
                .disabled(self.busy || !running)
                .on_press(|s: &mut Workspace| s.scim_action("cancel", None))
                .build(k)
                .key("cancel-sync"),
        );
        let mut body = col().key("scim-body").w_full().gap(16.0).child(controls);
        if let Some(job) = &self.scim_view.job {
            let mut panel = card(
                "scim-job",
                format!(
                    "SCIM job: {} of {} processed, {} percent. {}",
                    job.processed, job.total, job.percent, job.message
                ),
                ui,
            )
            .gap(8.0)
            .child(
                row()
                    .w_full()
                    .gap(12.0)
                    .center_y()
                    .child(
                        font_text(
                            if job.running {
                                "Sync running"
                            } else if job.success {
                                "Sync completed"
                            } else {
                                "Sync stopped"
                            },
                            13.0,
                            SEMIBOLD,
                            p.text,
                            ui,
                        )
                        .key("job-title")
                        .grow(1.0),
                    )
                    .child(font_text(
                        format!("{} / {} · {}%", job.processed, job.total, job.percent),
                        13.0,
                        400.0,
                        p.text,
                        ui,
                    )),
            )
            .child(
                el().key("scim-progress")
                    .role("progressbar")
                    .label("SCIM progress")
                    .range_value(job.percent as f64, 0.0, 100.0)
                    .w_full()
                    .h(4.0)
                    .radius(2.0)
                    .fill(p.soft)
                    .clip_rounded(2.0)
                    .child(
                        el().h_full()
                            .w_frac(job.percent.min(100) as f32 / 100.0)
                            .fill(if job.done && !job.success {
                                p.danger
                            } else {
                                p.accent
                            }),
                    ),
            )
            .child(
                font_text(job.message.clone(), 13.0, 400.0, p.text, ui)
                    .key("job-message")
                    .wrap(),
            );
            if !job.current.is_empty() {
                panel = panel.child(
                    font_text(job.current.clone(), 13.0, 400.0, p.muted, ui)
                        .key("job-current")
                        .wrap(),
                );
            }
            body = body.child(panel);
        }
        if let Some(preview) = &self.scim_view.preview {
            body = body.child(
                card(
                    "scim-import-preview",
                    format!(
                        "Remote import preview: {} added, {} updated, {} removed. {}",
                        preview.added, preview.updated, preview.removed, preview.status
                    ),
                    ui,
                )
                .gap(12.0)
                .child(font_text(
                    "Remote import preview",
                    13.0,
                    SEMIBOLD,
                    p.text,
                    ui,
                ))
                .child(font_text(
                    format!(
                        "{} added · {} updated · {} removed",
                        preview.added, preview.updated, preview.removed
                    ),
                    13.0,
                    400.0,
                    p.text,
                    ui,
                ))
                .child(font_text(preview.status.clone(), 13.0, 400.0, p.muted, ui).wrap())
                .child(
                    Button::new("Apply remote directory")
                        .variant(ButtonVariant::Contrast)
                        .disabled(self.busy || running)
                        .on_press(|s: &mut Workspace| s.scim_action("apply", None))
                        .build(k)
                        .key("apply-scim-import"),
                ),
            );
        }
        body = body.child(
            row()
                .w_full()
                .gap(12.0)
                .center_y()
                .child(font_text("Pending changes", 13.0, SEMIBOLD, p.text, ui).grow(1.0))
                .child(
                    Button::new("Refresh")
                        .variant(ButtonVariant::Ghost)
                        .disabled(self.busy)
                        .on_press(|s: &mut Workspace| s.refresh_scim())
                        .build(k)
                        .key("refresh-scim"),
                )
                .child(
                    Button::new("View request trace")
                        .variant(ButtonVariant::Ghost)
                        .disabled(self.scim_view.traces.is_empty())
                        .on_press(|s: &mut Workspace| s.show_scim_trace())
                        .build(k)
                        .key("scim-trace"),
                ),
        );
        if self.scim_view.plan.is_empty() {
            body = body.child(
                empty(
                    "No pending changes. Reconcile to check the remote directory for drift.",
                    ui,
                )
                .key("scim-plan-empty"),
            );
        }
        let mut plan = col().key("scim-plan").w_full().gap(8.0);
        for entry in &self.scim_view.plan {
            let target = (entry.resource_type.clone(), entry.resource_id.clone());
            plan = plan.child(
                row()
                    .key(format!(
                        "change-{}-{}",
                        entry.resource_type, entry.resource_id
                    ))
                    .role("group")
                    .label(format!(
                        "{} {}: {}",
                        entry.operation, entry.resource_type, entry.label
                    ))
                    .w_full()
                    .gap(16.0)
                    .padding(12.0)
                    .center_y()
                    .fill(p.card)
                    .radius(6.0)
                    .child(
                        font_text(entry.operation.clone(), 13.0, 400.0, p.accent, ui)
                            .w(72.0)
                            .truncate(),
                    )
                    .child(
                        font_text(entry.resource_type.clone(), 13.0, 400.0, p.muted, ui)
                            .w(54.0)
                            .truncate(),
                    )
                    .child(
                        font_text(entry.label.clone(), 13.0, 400.0, p.text, ui)
                            .grow(1.0)
                            .min_w(0.0)
                            .truncate(),
                    )
                    .child(
                        Button::new("Push")
                            .variant(ButtonVariant::Ghost)
                            .disabled(self.busy || running)
                            .on_press(move |s: &mut Workspace| {
                                s.scim_action("push", Some(target.clone()))
                            })
                            .build(k)
                            .label(format!("Push {} to SCIM", entry.label))
                            .key("push-resource"),
                    ),
            );
        }
        if !self.scim_view.plan.is_empty() {
            body = body.child(plan);
        }
        if let Some(job) = &self.scim_view.job {
            body = body.child(font_text("Progress", 13.0, SEMIBOLD, p.text, ui).pt(12.0));
            let mut events = col().key("scim-events").w_full();
            for (index, event) in job.events.iter().enumerate().rev().take(100) {
                let mut item = col()
                    .key(format!("scim-event-{index}"))
                    .role("group")
                    .label(format!(
                        "{} {}: {}. {}",
                        event.operation, event.label, event.phase, event.detail
                    ))
                    .w_full()
                    .gap(4.0)
                    .padding(12.0)
                    .child(
                        font_text(
                            format!("{} · {} · {}", event.operation, event.label, event.phase),
                            13.0,
                            400.0,
                            p.text,
                            ui,
                        )
                        .wrap(),
                    );
                if !event.detail.is_empty() {
                    item = item
                        .child(font_text(event.detail.clone(), 13.0, 400.0, p.muted, ui).wrap());
                }
                events = events.child(item).child(super::view::rule(p));
            }
            body = body.child(events);
        }
        col()
            .key("scim-scroll")
            .w_full()
            .min_h(0.0)
            .scroll(ScrollSpec {
                stick_bottom: false,
            })
            .child(body)
    }
}
