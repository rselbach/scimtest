use super::{Editor, Workspace};
use crate::theme::Palette;
use gpui::{Context, Div, div, prelude::*, px};
use gpui_component::{
    Disableable, StyledExt,
    button::{Button, ButtonVariants},
    scroll::ScrollableElement,
};
use scimtest_core::{
    Error,
    scim::{Job, Mode, PlanEntry, PreviewView, Trace},
};

#[derive(Default)]
pub(super) struct Inspector {
    job: Option<Job>,
    plan: Vec<PlanEntry>,
    traces: Vec<Trace>,
    preview: Option<PreviewView>,
}
impl Workspace {
    pub(super) fn scim_running(&self) -> bool {
        self.scim_view.job.as_ref().is_some_and(|job| job.running)
    }

    pub(super) fn refresh_scim(&mut self, cx: &mut Context<Self>) {
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
        cx.spawn(async move |view, cx| {
            let result = cx
                .background_executor()
                .spawn(async move {
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
                })
                .await;
            let _ =
                view.update(cx, |view, cx| {
                    view.scim_refreshing = false;
                    if view.selected.as_ref() == Some(&id) {
                        match result {
                            Ok(snapshot) => {
                                if let Some(job) = &snapshot.job
                                    && job.done
                                    && view.scim_view.job.as_ref().is_none_or(|previous| {
                                        previous.id != job.id || !previous.done
                                    })
                                {
                                    view.status_revision = view.status_revision.wrapping_add(1);
                                    view.message = job.message.clone();
                                    view.failed = !job.success;
                                }
                                view.scim_view = snapshot;
                            }
                            Err(error) => {
                                view.message = error.to_string();
                                view.failed = true;
                            }
                        }
                    }
                    if view.scim_refresh_pending && !view.busy {
                        view.refresh_scim(cx);
                    }
                    cx.notify();
                });
        })
        .detach();
    }
    pub(super) fn scim_action(
        &mut self,
        action: &'static str,
        target: Option<(String, String)>,
        cx: &mut Context<Self>,
    ) {
        if self.busy {
            return;
        }
        let Some(id) = self.selected.clone() else {
            return;
        };
        let service = self.scim_service.clone();
        let store = self.store.clone();
        let request_id = id.clone();
        let handle = self.executor.clone();
        self.busy = true;
        cx.spawn(async move |view, cx| {
            let result = handle
                .spawn(async move {
                    let id = request_id;
                    let message = match action {
                        "sync" => service.start(&id, Mode::Sync)?.message,
                        "reconcile" => service.start(&id, Mode::Reconcile)?.message,
                        "push" => {
                            let (resource_type, resource_id) = target.ok_or_else(|| {
                                Error::Validation("select a resource to push".into())
                            })?;
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
                })
                .await;
            let _ = view.update(cx, |view, cx| {
                view.busy = false;
                if view.selected.as_ref() == Some(&id) {
                    view.status_revision = view.status_revision.wrapping_add(1);
                    match result {
                        Ok(Ok(message)) => {
                            view.message = message;
                            view.failed = false;
                        }
                        Ok(Err(error)) => {
                            view.message = error.to_string();
                            view.failed = true;
                        }
                        Err(error) => {
                            view.message = error.to_string();
                            view.failed = true;
                        }
                    }
                    view.refresh_scim(cx);
                }
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }
    fn show_scim_trace(&mut self, cx: &mut Context<Self>) {
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
        self.editor = Some(Editor::History {
            noun: "",
            name: "SCIM trace".into(),
            entries,
            expanded: Default::default(),
        });
        cx.notify();
    }
    pub(super) fn scim_inspector(&self, cx: &mut Context<Self>) -> Div {
        let palette = Palette::get(cx);
        let running = self.scim_view.job.as_ref().is_some_and(|job| job.running);
        let mut controls = div().h_flex().gap_2();
        for (action, label) in [
            ("reconcile", "Reconcile all"),
            ("discover", "Discover capabilities"),
            ("test", "Test connection"),
            ("preview", "Preview remote import"),
            ("reset", "Reset tracking"),
        ] {
            controls = controls.child(
                Button::new(action)
                    .label(label)
                    .disabled(self.busy || running)
                    .on_click(
                        cx.listener(move |view, _, _, cx| view.scim_action(action, None, cx)),
                    ),
            );
        }
        controls = controls.child(
            Button::new("cancel-sync")
                .label("Cancel")
                .disabled(self.busy || !running)
                .on_click(cx.listener(|view, _, _, cx| view.scim_action("cancel", None, cx))),
        );
        let mut body = div().v_flex().gap_4().child(controls);
        if let Some(job) = &self.scim_view.job {
            body = body.child(
                div()
                    .id("scim-job")
                    .role(gpui::Role::Group)
                    .aria_label(format!(
                        "SCIM job: {} of {} processed, {} percent. {}",
                        job.processed, job.total, job.percent, job.message
                    ))
                    .v_flex()
                    .gap_2()
                    .p_4()
                    .bg(palette.card)
                    .rounded_md()
                    .border_1()
                    .border_color(palette.line)
                    .child(
                        div()
                            .h_flex()
                            .gap_3()
                            .child(
                                div()
                                    .flex_1()
                                    .font_weight(gpui::FontWeight::SEMIBOLD)
                                    .child(if job.running {
                                        "Sync running"
                                    } else if job.success {
                                        "Sync completed"
                                    } else {
                                        "Sync stopped"
                                    }),
                            )
                            .child(format!(
                                "{} / {} · {}%",
                                job.processed, job.total, job.percent
                            )),
                    )
                    .child(
                        div()
                            .id("scim-progress")
                            .role(gpui::Role::ProgressIndicator)
                            .aria_label("SCIM progress")
                            .aria_numeric_value(job.percent as f64)
                            .aria_min_numeric_value(0.)
                            .aria_max_numeric_value(100.)
                            .h(px(4.))
                            .rounded_md()
                            .bg(palette.soft)
                            .child(
                                div()
                                    .h_full()
                                    .w(gpui::relative(job.percent as f32 / 100.))
                                    .bg(if job.done && !job.success {
                                        palette.danger
                                    } else {
                                        palette.accent
                                    }),
                            ),
                    )
                    .child(super::view::accessible_text(
                        "job-message",
                        job.message.clone(),
                    ))
                    .when(!job.current.is_empty(), |panel| {
                        panel.child(div().text_color(palette.muted).child(
                            super::view::accessible_text("job-current", job.current.clone()),
                        ))
                    }),
            );
        }
        if let Some(preview) = &self.scim_view.preview {
            body = body.child(
                div()
                    .id("scim-import-preview")
                    .role(gpui::Role::Group)
                    .aria_label(format!(
                        "Remote import preview: {} added, {} updated, {} removed. {}",
                        preview.added, preview.updated, preview.removed, preview.status
                    ))
                    .v_flex()
                    .gap_3()
                    .p_4()
                    .bg(palette.card)
                    .border_1()
                    .border_color(palette.line)
                    .rounded_md()
                    .child(
                        div()
                            .font_weight(gpui::FontWeight::SEMIBOLD)
                            .child("Remote import preview"),
                    )
                    .child(format!(
                        "{} added · {} updated · {} removed",
                        preview.added, preview.updated, preview.removed
                    ))
                    .child(
                        div()
                            .text_color(palette.muted)
                            .child(preview.status.clone()),
                    )
                    .child(
                        Button::new("apply-scim-import")
                            .label("Apply remote directory")
                            .primary()
                            .disabled(self.busy || running)
                            .on_click(
                                cx.listener(|view, _, _, cx| view.scim_action("apply", None, cx)),
                            ),
                    ),
            );
        }
        body = body.child(
            div()
                .h_flex()
                .gap_3()
                .child(
                    div()
                        .flex_1()
                        .font_weight(gpui::FontWeight::SEMIBOLD)
                        .child("Pending changes"),
                )
                .child(
                    Button::new("refresh-scim")
                        .label("Refresh")
                        .ghost()
                        .disabled(self.busy)
                        .on_click(cx.listener(|view, _, _, cx| view.refresh_scim(cx))),
                )
                .child(
                    Button::new("scim-trace")
                        .label("View request trace")
                        .ghost()
                        .disabled(self.scim_view.traces.is_empty())
                        .on_click(cx.listener(|view, _, _, cx| view.show_scim_trace(cx))),
                ),
        );
        if self.scim_view.plan.is_empty() {
            body =
                body.child(div().py_3().text_color(palette.muted).child(
                    "No pending changes. Reconcile to check the remote directory for drift.",
                ));
        }
        for (index, entry) in self.scim_view.plan.iter().enumerate() {
            let target = (entry.resource_type.clone(), entry.resource_id.clone());
            body = body.child(
                div()
                    .id(gpui::SharedString::from(format!(
                        "change-{}-{}",
                        entry.resource_type, entry.resource_id
                    )))
                    .role(gpui::Role::Group)
                    .aria_label(format!(
                        "{} {}: {}",
                        entry.operation, entry.resource_type, entry.label
                    ))
                    .h_flex()
                    .gap_4()
                    .p_3()
                    .bg(palette.card)
                    .rounded_md()
                    .child(
                        div()
                            .w(px(72.))
                            .text_color(palette.accent)
                            .child(entry.operation.clone()),
                    )
                    .child(
                        div()
                            .w(px(54.))
                            .text_color(palette.muted)
                            .child(entry.resource_type.clone()),
                    )
                    .child(div().flex_1().child(entry.label.clone()))
                    .child(
                        Button::new(("push-resource", index))
                            .accessibility_label(format!("Push {} to SCIM", entry.label))
                            .label("Push")
                            .ghost()
                            .disabled(self.busy || running)
                            .on_click(cx.listener(move |view, _, _, cx| {
                                view.scim_action("push", Some(target.clone()), cx)
                            })),
                    ),
            );
        }
        if let Some(job) = &self.scim_view.job {
            body = body.child(
                div()
                    .pt_3()
                    .font_weight(gpui::FontWeight::SEMIBOLD)
                    .child("Progress"),
            );
            for (index, event) in job.events.iter().enumerate().rev().take(100) {
                body = body.child(
                    div()
                        .id(("scim-event", index))
                        .role(gpui::Role::Group)
                        .aria_label(format!(
                            "{} {}: {}. {}",
                            event.operation, event.label, event.phase, event.detail
                        ))
                        .v_flex()
                        .gap_1()
                        .p_3()
                        .border_b_1()
                        .border_color(palette.line)
                        .child(format!(
                            "{} · {} · {}",
                            event.operation, event.label, event.phase
                        ))
                        .when(!event.detail.is_empty(), |row| {
                            row.child(div().text_color(palette.muted).child(event.detail.clone()))
                        }),
                );
            }
        }
        div().flex_1().min_h_0().child(
            div()
                .id("scim-scroll")
                .size_full()
                .overflow_y_scrollbar()
                .child(body),
        )
    }
}
