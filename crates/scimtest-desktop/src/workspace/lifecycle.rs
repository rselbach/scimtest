use super::{
    Editor, Workspace,
    oidc::view::{copy_button, empty},
};
use crate::theme::Palette;
use gpui::{Context, Div, SharedString, Window, div, prelude::*};
use gpui_component::{
    Disableable, StyledExt,
    button::{Button, ButtonVariants},
    scroll::ScrollableElement,
};
use scimtest_core::oidc::{JoinerInput, LifecycleRun, MoverInput};
use std::collections::BTreeSet;

mod form;
pub(super) use form::Form;

#[derive(Default)]
pub(super) struct Inspector {
    pub runs: Vec<LifecycleRun>,
    expanded: BTreeSet<String>,
}
impl Workspace {
    pub(super) fn edit_lifecycle(
        &mut self,
        kind: &'static str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
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
        self.editor = Some(Editor::Lifecycle(Form::new(kind, user, window, cx)));
        self.message.clear();
        self.failed = false;
        cx.notify();
    }
    pub(super) fn save_lifecycle(&mut self, cx: &mut Context<Self>) {
        let Some(Editor::Lifecycle(form)) = &self.editor else {
            return;
        };
        let kind = form.kind;
        let fields = form.values(cx);
        let user = form.user.clone();
        let added = form.added.iter().cloned().collect();
        let removed = form.removed.iter().cloned().collect();
        if kind != "joiner" && user.is_empty() {
            self.message = "Choose a user for this scenario".into();
            self.failed = true;
            cx.notify();
            return;
        }
        let scim = self.scim_service.clone();
        self.identity_command(
            move |identity, id| {
                let run = match kind {
                    "joiner" => identity.start_joiner(
                        &id,
                        JoinerInput {
                            given_name: fields[0].clone(),
                            family_name: fields[1].clone(),
                            email: fields[2].clone(),
                            username: fields[3].clone(),
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
            },
            cx,
        );
    }
    pub(super) fn lifecycle_inspector(&self, cx: &mut Context<Self>) -> Div {
        let palette = Palette::get(cx);
        let mut body = div().v_flex().gap_4();
        if self.lifecycle.runs.is_empty() {
            body = body.child(empty("Run a joiner, mover, or leaver to see each directory change and the app's responses. Runs stay available until scimtest closes.",cx));
        }
        for run in &self.lifecycle.runs {
            let mut card = div()
                .id(SharedString::from(run.id.clone()))
                .role(gpui::Role::Group)
                .aria_label(format!(
                    "{} for {}: {}. {}",
                    kind_label(&run.kind),
                    run.user,
                    status_label(&run.status),
                    run.started_at
                ))
                .v_flex()
                .gap_3()
                .p_4()
                .rounded_md()
                .border_1()
                .border_color(palette.line)
                .bg(palette.card)
                .child(
                    div()
                        .h_flex()
                        .gap_3()
                        .child(
                            div()
                                .flex_1()
                                .min_w_0()
                                .font_weight(gpui::FontWeight::SEMIBOLD)
                                .child(format!("{}: {}", kind_label(&run.kind), run.user)),
                        )
                        .child(
                            div()
                                .text_color(status_color(&run.status, palette))
                                .child(status_label(&run.status)),
                        )
                        .child(copy_button(
                            SharedString::from(format!("copy-{}", run.id)),
                            "Copy run",
                            serde_json::to_string_pretty(&run.clone().with_browser_urls(
                                &self.api_url,
                                self.selected.as_deref().unwrap_or_default(),
                            ))
                            .unwrap_or_default(),
                            cx,
                        )),
                )
                .child(
                    div()
                        .text_color(palette.muted)
                        .child(run.started_at.clone()),
                );
            for step in &run.steps {
                let mut row = div()
                    .id(SharedString::from(step.id.clone()))
                    .role(gpui::Role::Group)
                    .aria_label(format!(
                        "{}: {}. {}. {}",
                        step.title,
                        status_label(&step.status),
                        step.protocol,
                        step.detail
                    ))
                    .v_flex()
                    .gap_2()
                    .py_3()
                    .border_t_1()
                    .border_color(palette.line)
                    .child(
                        div()
                            .h_flex()
                            .gap_3()
                            .child(
                                div()
                                    .flex_1()
                                    .min_w_0()
                                    .whitespace_normal()
                                    .font_weight(gpui::FontWeight::MEDIUM)
                                    .child(step.title.clone()),
                            )
                            .child(
                                div()
                                    .text_color(status_color(&step.status, palette))
                                    .child(status_label(&step.status)),
                            ),
                    )
                    .child(
                        div()
                            .whitespace_normal()
                            .text_color(palette.muted)
                            .child(format!("{} · {}", step.protocol, step.detail)),
                    );
                if step.can_send_logout() {
                    let mut actions = div().h_flex().gap_2();
                    for (binding, label) in [
                        ("redirect", "Send LogoutRequest · Redirect"),
                        ("post", "Send LogoutRequest · POST"),
                    ] {
                        let run_id = run.id.clone();
                        let step_id = step.id.clone();
                        actions = actions.child(
                            Button::new(SharedString::from(format!(
                                "{}-{}-{binding}",
                                run.id, step.id
                            )))
                            .label(label)
                            .disabled(self.busy)
                            .on_click(cx.listener(
                                move |view, _, _, cx| {
                                    let run = run_id.clone();
                                    let step = step_id.clone();
                                    view.saml_browser_request(
                                        move |identity, id, base| {
                                            identity.lifecycle_saml_logout(
                                                id, &run, &step, binding, base,
                                            )
                                        },
                                        cx,
                                    );
                                },
                            )),
                        );
                    }
                    row = row.child(actions);
                }
                if !step.messages.is_empty() {
                    let key = format!("{}-{}", run.id, step.id);
                    let expanded = self.lifecycle.expanded.contains(&key);
                    row = row.child(
                        Button::new(SharedString::from(format!("messages-{key}")))
                            .label(if expanded {
                                "Hide messages"
                            } else {
                                "Show messages"
                            })
                            .ghost()
                            .on_click(cx.listener(move |view, _, _, cx| {
                                if !view.lifecycle.expanded.remove(&key) {
                                    view.lifecycle.expanded.insert(key.clone());
                                }
                                cx.notify();
                            })),
                    );
                    if expanded {
                        for (index, message) in step.messages.iter().enumerate() {
                            let text = serde_json::to_string_pretty(message).unwrap_or_default();
                            row = row.child(
                                div()
                                    .id(("message", index))
                                    .role(gpui::Role::Group)
                                    .aria_label(format!("{}: {}", message.sent, message.outcome))
                                    .v_flex()
                                    .gap_2()
                                    .p_3()
                                    .rounded_md()
                                    .bg(palette.soft)
                                    .child(
                                        div()
                                            .h_flex()
                                            .child(
                                                div().flex_1().min_w_0().whitespace_normal().child(
                                                    format!(
                                                        "{} · {}",
                                                        message.sent, message.outcome
                                                    ),
                                                ),
                                            )
                                            .child(copy_button(
                                                SharedString::from(format!(
                                                    "copy-{}-{}-{index}",
                                                    run.id, step.id
                                                )),
                                                "Copy message",
                                                text,
                                                cx,
                                            )),
                                    )
                                    .child(div().whitespace_normal().child(
                                        super::view::accessible_text(
                                            "delivery",
                                            format!("{}\n{}", message.to, message.response),
                                        ),
                                    ))
                                    .when(!message.body.is_empty(), |panel| {
                                        panel.child(
                                            div()
                                                .font_family("monospace")
                                                .whitespace_normal()
                                                .child(super::view::accessible_text(
                                                    "payload",
                                                    message.body.clone(),
                                                )),
                                        )
                                    }),
                            );
                        }
                    }
                }
                card = card.child(row);
            }
            body = body.child(card);
        }
        div().flex_1().min_h_0().child(
            div()
                .id("lifecycle-scroll")
                .size_full()
                .overflow_y_scrollbar()
                .child(body),
        )
    }
}
fn status_color(status: &str, palette: Palette) -> gpui::Hsla {
    match status {
        "ok" => palette.success,
        "failed" => palette.danger,
        "running" | "waiting" | "needs_browser" => palette.accent,
        _ => palette.muted,
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
