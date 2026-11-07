use std::collections::BTreeSet;

use rune::{Color, El, ScrollSpec, col, row};
use rune_kit::{Button, ButtonVariant};
use scimtest_core::oidc::{JoinerInput, LifecycleRun, MoverInput, ProtocolError};

use super::{
    Editor, Workspace,
    view::{copy_button, empty, font_text, rule},
};
use crate::theme::{MEDIUM, Palette, SEMIBOLD, Ui};

mod form;
pub(super) use form::Form;

#[derive(Default)]
pub(super) struct Inspector {
    pub runs: Vec<LifecycleRun>,
    expanded: BTreeSet<String>,
}

const SCENARIOS: [(&str, &str, &str, &str); 3] = [
    (
        "joiner",
        "JOINER",
        "Create and provision a user",
        "Creates the user, adds them to groups, and pushes them through SCIM.",
    ),
    (
        "mover",
        "MOVER",
        "Change a user's groups",
        "Pushes each changed group through SCIM, then checks that the next ID token, userinfo response, and SAML assertion carry the new groups.",
    ),
    (
        "leaver",
        "LEAVER",
        "Offboard a user everywhere",
        "Deactivates the user, ends their IdP sessions with back-channel logout and SAML Single Logout, revokes their tokens, and pushes active=false through SCIM.",
    ),
];

impl Workspace {
    pub(super) fn edit_lifecycle(&mut self, kind: &'static str) {
        let Some(directory) = self.directory() else {
            return;
        };
        let user = directory
            .projected_users()
            .into_iter()
            .filter(|user| !user.deleted && (kind == "leaver" || user.fields.active))
            .min_by_key(|user| !user.fields.active)
            .map(|user| user.id)
            .unwrap_or_default();
        self.open_editor(Editor::Lifecycle(Form::new(kind, user)));
        self.failed = false;
    }

    pub(super) fn save_lifecycle(&mut self) {
        let Some(Editor::Lifecycle(form)) = &self.editor else {
            return;
        };
        let kind = form.kind;
        let fields = form.values();
        let user = form.user.clone();
        let added = form.added.iter().cloned().collect();
        let removed = form.removed.iter().cloned().collect();
        if kind != "joiner" && user.is_empty() {
            self.fail("Choose a user for this scenario".into());
            return;
        }
        let scim = self.scim_service.clone();
        self.identity_command(move |identity, id| {
            let [given_name, family_name, email, username] = fields;
            let run = match kind {
                "joiner" => identity.start_joiner(
                    &id,
                    JoinerInput {
                        given_name,
                        family_name,
                        email,
                        username,
                        group_ids: added,
                    },
                    scim,
                ),
                "mover" => identity.start_mover(
                    &id,
                    MoverInput {
                        user_id: user,
                        add_group_ids: added,
                        remove_group_ids: removed,
                    },
                    scim,
                ),
                _ => identity.start_leaver(&id, &user, scim),
            }?;
            Ok(format!("{} scenario started for {}", run.kind, run.user))
        });
    }

    /// Stages a lifecycle step's SAML LogoutRequest and opens it in the browser.
    fn send_lifecycle_logout(&mut self, run: String, step: String, binding: &'static str) {
        if self.busy {
            return;
        }
        let Some(directory) = self.directory() else {
            return;
        };
        let id = directory.environment.id.clone();
        let slug = directory.environment.slug.clone();
        let identity = self.identity.clone();
        let tunnel = self.tunnel_service.clone();
        let local_base = self.api_url.clone();
        let request_id = id.clone();
        self.busy = true;
        self.task(
            tokio::task::spawn_blocking(move || {
                let base = tunnel.effective_base(&local_base)?;
                let message =
                    identity.lifecycle_saml_logout(&request_id, &run, &step, binding, &base)?;
                let ticket = identity.stage_saml_delivery(&request_id, message)?;
                Ok::<_, ProtocolError>(format!("{local_base}/saml/{slug}/continue/{ticket}"))
            }),
            move |view, result, tx| {
                view.busy = false;
                match result {
                    Ok(Ok(url)) => match tx.open_url(&url) {
                        Ok(()) => {
                            view.message = "Logout request opened in your browser".into();
                            view.failed = false;
                        }
                        Err(error) => view.fail(error.to_string()),
                    },
                    Ok(Err(error)) => view.fail(error.description),
                    Err(error) => view.fail(error.to_string()),
                }
                if view.selected.as_ref() == Some(&id) {
                    view.refresh_identity();
                }
            },
        );
    }

    pub(super) fn lifecycle_inspector(&self, ui: &Ui, _layer: &mut Vec<El>) -> El {
        let p = ui.p;
        let k = &ui.k;
        let mut scenarios = row().w_full().equal_columns(3).gap(16.0);
        for (kind, tag, title, detail) in SCENARIOS {
            scenarios = scenarios.child(
                col()
                    .key(format!("scenario-{kind}"))
                    .role("group")
                    .label(format!("{title}. {detail}"))
                    .min_w(0.0)
                    .gap(12.0)
                    .padding(16.0)
                    .radius(11.0)
                    .border(1.0, p.line)
                    .fill(p.card)
                    .child(font_text(tag, 11.0, SEMIBOLD, p.accent, ui))
                    .child(font_text(title, 13.0, SEMIBOLD, p.text, ui).wrap())
                    .child(font_text(detail, 12.0, 400.0, p.muted, ui).wrap().grow(1.0))
                    .child(
                        Button::new(format!("Run {kind}"))
                            .variant(ButtonVariant::Contrast)
                            .disabled(self.busy || self.selected.is_none())
                            .on_press(move |s: &mut Workspace| s.edit_lifecycle(kind))
                            .build(k)
                            .key(format!("run-{kind}"))
                            .w_full(),
                    ),
            );
        }
        let mut body = col()
            .key("lifecycle-body")
            .w_full()
            .gap(16.0)
            .child(
                col()
                    .w_full()
                    .gap(4.0)
                    .child(font_text("Run a scenario", 16.0, SEMIBOLD, p.text, ui))
                    .child(
                        font_text(
                            "Each scenario changes the directory, sends every message the change calls for, and records how the app answered. Steps for protocols this environment does not use are skipped.",
                            13.0,
                            400.0,
                            p.muted,
                            ui,
                        )
                        .wrap(),
                    ),
            )
            .child(scenarios);
        if self.lifecycle.runs.is_empty() {
            body = body.child(empty(
                "Run a joiner, mover, or leaver to see each directory change and the app's responses. Runs stay available until scimtest closes.",
                ui,
            ));
        }
        for run in &self.lifecycle.runs {
            body = body.child(self.lifecycle_run(run, ui));
        }
        col()
            .key("lifecycle-scroll")
            .w_full()
            .min_h(0.0)
            .scroll(ScrollSpec {
                stick_bottom: false,
            })
            .child(body)
    }

    fn lifecycle_run(&self, run: &LifecycleRun, ui: &Ui) -> El {
        let p = ui.p;
        let k = &ui.k;
        let mut card = col()
            .key(run.id.clone())
            .role("group")
            .label(format!(
                "{} for {}: {}. {}",
                kind_label(&run.kind),
                run.user,
                status_label(&run.status),
                run.started_at
            ))
            .w_full()
            .gap(12.0)
            .padding(16.0)
            .radius(6.0)
            .border(1.0, p.line)
            .fill(p.card)
            .child(
                row()
                    .w_full()
                    .gap(12.0)
                    .center_y()
                    .child(
                        font_text(
                            format!("{}: {}", kind_label(&run.kind), run.user),
                            13.0,
                            SEMIBOLD,
                            p.text,
                            ui,
                        )
                        .key("run-title")
                        .grow(1.0)
                        .min_w(0.0)
                        .wrap(),
                    )
                    .child(
                        font_text(
                            status_label(&run.status),
                            13.0,
                            400.0,
                            status_color(&run.status, p),
                            ui,
                        )
                        .key("run-status"),
                    )
                    .child(copy_button(
                        format!("copy-{}", run.id),
                        "Copy run",
                        serde_json::to_string_pretty(&run.clone().with_browser_urls(
                            &self.api_url,
                            self.selected.as_deref().unwrap_or_default(),
                        ))
                        .unwrap_or_default(),
                        ui,
                    )),
            )
            .child(font_text(run.started_at.clone(), 13.0, 400.0, p.muted, ui));
        for step in &run.steps {
            let mut item = col()
                .key(step.id.clone())
                .role("group")
                .label(format!(
                    "{}: {}. {}. {}",
                    step.title,
                    status_label(&step.status),
                    step.protocol,
                    step.detail
                ))
                .w_full()
                .gap(8.0)
                .child(rule(p))
                .child(
                    row()
                        .w_full()
                        .gap(12.0)
                        .mt(4.0)
                        .center_y()
                        .child(
                            font_text(step.title.clone(), 13.0, MEDIUM, p.text, ui)
                                .grow(1.0)
                                .min_w(0.0)
                                .wrap(),
                        )
                        .child(font_text(
                            status_label(&step.status),
                            13.0,
                            400.0,
                            status_color(&step.status, p),
                            ui,
                        )),
                )
                .child(
                    font_text(
                        format!("{} · {}", step.protocol, step.detail),
                        13.0,
                        400.0,
                        p.muted,
                        ui,
                    )
                    .w_full()
                    .wrap(),
                );
            if step.can_send_logout() {
                let mut actions = row().gap(8.0);
                for (binding, label) in [
                    ("redirect", "Send LogoutRequest · Redirect"),
                    ("post", "Send LogoutRequest · POST"),
                ] {
                    let run_id = run.id.clone();
                    let step_id = step.id.clone();
                    actions = actions.child(
                        Button::new(label)
                            .disabled(self.busy)
                            .on_press(move |s: &mut Workspace| {
                                s.send_lifecycle_logout(run_id.clone(), step_id.clone(), binding)
                            })
                            .build(k)
                            .key(format!("{}-{}-{binding}", run.id, step.id)),
                    );
                }
                item = item.child(actions);
            }
            if !step.messages.is_empty() {
                let key = format!("{}-{}", run.id, step.id);
                let expanded = self.lifecycle.expanded.contains(&key);
                item = item.child(
                    Button::new(if expanded {
                        "Hide messages"
                    } else {
                        "Show messages"
                    })
                    .variant(ButtonVariant::Ghost)
                    .expanded(expanded)
                    .on_press({
                        let key = key.clone();
                        move |s: &mut Workspace| {
                            if !s.lifecycle.expanded.remove(&key) {
                                s.lifecycle.expanded.insert(key.clone());
                            }
                        }
                    })
                    .build(k)
                    .key(format!("messages-{key}")),
                );
                if expanded {
                    for (index, message) in step.messages.iter().enumerate() {
                        let mut panel = col()
                            .key(format!("message-{index}"))
                            .role("group")
                            .label(format!("{}: {}", message.sent, message.outcome))
                            .w_full()
                            .gap(8.0)
                            .padding(12.0)
                            .radius(6.0)
                            .fill(p.soft)
                            .child(
                                row()
                                    .w_full()
                                    .center_y()
                                    .child(
                                        font_text(
                                            format!("{} · {}", message.sent, message.outcome),
                                            13.0,
                                            400.0,
                                            p.text,
                                            ui,
                                        )
                                        .grow(1.0)
                                        .min_w(0.0)
                                        .wrap(),
                                    )
                                    .child(copy_button(
                                        format!("copy-{key}-{index}"),
                                        "Copy message",
                                        serde_json::to_string_pretty(message).unwrap_or_default(),
                                        ui,
                                    )),
                            )
                            .child(
                                font_text(
                                    format!("{}\n{}", message.to, message.response),
                                    13.0,
                                    400.0,
                                    p.text,
                                    ui,
                                )
                                .key("delivery")
                                .w_full()
                                .wrap_anywhere()
                                .selectable(true),
                            );
                        if !message.body.is_empty() {
                            panel = panel.child(
                                rune::text(message.body.clone())
                                    .key("payload")
                                    .font(ui.k.ty.mono)
                                    .color(p.text)
                                    .w_full()
                                    .wrap_anywhere()
                                    .selectable(true),
                            );
                        }
                        item = item.child(panel);
                    }
                }
            }
            card = card.child(item);
        }
        card
    }
}

fn status_color(status: &str, p: Palette) -> Color {
    match status {
        "ok" => p.success,
        "failed" => p.danger,
        "running" | "waiting" | "needs_browser" => p.accent,
        _ => p.muted,
    }
}

fn kind_label(kind: &str) -> &'static str {
    match kind {
        "joiner" => "Joiner",
        "mover" => "Mover",
        _ => "Leaver",
    }
}

fn status_label(status: &str) -> &'static str {
    match status {
        "ok" => "OK",
        "failed" => "Failed",
        "running" => "Running",
        "waiting" => "Waiting",
        "needs_browser" => "Needs browser",
        _ => "Skipped",
    }
}
