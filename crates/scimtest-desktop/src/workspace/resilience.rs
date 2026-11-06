use super::{
    Workspace,
    oidc::view::{copy_button, empty},
};
use crate::dropdown::DropdownMenu;
use crate::theme::Palette;
use gpui::{Context, Div, div, prelude::*};
use gpui_component::{
    Disableable, StyledExt,
    button::{Button, ButtonVariants},
    menu::PopupMenuItem,
    scroll::ScrollableElement,
};
use scimtest_core::oidc::{Faults, ResiliencePreset, ResilienceRun};

#[derive(Default)]
pub(super) struct Inspector {
    pub presets: Vec<ResiliencePreset>,
    pub run: Option<ResilienceRun>,
    pub manual: Faults,
}
impl Workspace {
    pub(super) fn resilience_active(&self) -> bool {
        self.resilience
            .run
            .as_ref()
            .is_some_and(ResilienceRun::active)
    }
    pub(super) fn disarm_resilience(&mut self, cx: &mut Context<Self>) {
        self.identity_command(
            |identity, id| {
                identity.disarm_resilience(&id)?;
                Ok("Fault injection scenario disarmed".into())
            },
            cx,
        );
    }
    fn arm_resilience(&mut self, preset: &'static str, count: i32, cx: &mut Context<Self>) {
        self.identity_command(
            move |identity, id| {
                let run = identity.arm_resilience(&id, preset, count)?;
                identity.disarm_faults(&id)?;
                Ok(format!("Armed {}", run.name))
            },
            cx,
        );
    }
    pub(super) fn resilience_inspector(&self, cx: &mut Context<Self>) -> Div {
        let palette = Palette::get(cx);
        let mut body = div().v_flex().gap_4().child(
            div()
                .h_flex()
                .gap_3()
                .child(
                    div()
                        .flex_1()
                        .min_w_0()
                        .whitespace_normal()
                        .text_color(palette.muted)
                        .child("Test how your app handles identity-provider failures."),
                )
                .child(
                    Button::new("custom-faults")
                        .label("Custom faults…")
                        .disabled(self.busy)
                        .on_click(cx.listener(|view, _, window, cx| view.edit_faults(window, cx))),
                ),
        );
        if self.resilience.manual.active() {
            body = body.child(
                div()
                    .id("manual-fault")
                    .role(gpui::Role::Group)
                    .aria_label(format!(
                        "Armed for next flow: {}",
                        self.resilience.manual.describe()
                    ))
                    .h_flex()
                    .gap_3()
                    .p_3()
                    .rounded_md()
                    .bg(palette.selected)
                    .child(div().flex_1().min_w_0().whitespace_normal().child(format!(
                        "Armed for next flow: {}",
                        self.resilience.manual.describe()
                    )))
                    .child(
                        Button::new("clear-manual-fault")
                            .label("Clear fault")
                            .flex_shrink_0()
                            .ghost()
                            .disabled(self.busy)
                            .on_click(cx.listener(|view, _, _, cx| {
                                view.identity_command(
                                    |identity, id| {
                                        identity.disarm_faults(&id)?;
                                        Ok("Armed faults cleared".into())
                                    },
                                    cx,
                                );
                            })),
                    ),
            );
        }
        if let Some(run) = &self.resilience.run {
            let mut panel = div()
                .id("resilience-run")
                .role(gpui::Role::Group)
                .aria_label(format!(
                    "{}: {}. {}. {} in progress. {}",
                    run.name,
                    run.state,
                    run.progress(),
                    run.in_flight,
                    run.summary
                ))
                .v_flex()
                .gap_2()
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
                                .font_weight(gpui::FontWeight::SEMIBOLD)
                                .child(run.name.clone()),
                        )
                        .child(
                            div()
                                .text_color(if run.active() {
                                    palette.accent
                                } else {
                                    palette.muted
                                })
                                .child(run.state.clone()),
                        )
                        .child(copy_button(
                            "copy-resilience",
                            "Copy run",
                            serde_json::to_string_pretty(run).unwrap_or_default(),
                            cx,
                        )),
                )
                .child(format!(
                    "{} · {} in progress",
                    run.progress(),
                    run.in_flight
                ))
                .child(div().text_color(palette.muted).child(format!(
                    "{} · Expires {}",
                    run.summary,
                    run.expires_at.format("%H:%M:%S UTC")
                )));
            for (index, decision) in run.decisions.iter().enumerate().rev() {
                panel = panel.child(
                    div()
                        .id(("decision", index))
                        .role(gpui::Role::Group)
                        .aria_label(format!(
                            "{} {}: {}. {}",
                            decision.time.format("%H:%M:%S"),
                            decision.phase,
                            decision.outcome,
                            decision.detail
                        ))
                        .v_flex()
                        .gap_1()
                        .pt_2()
                        .child(format!(
                            "{} · {} · {}",
                            decision.time.format("%H:%M:%S"),
                            decision.phase,
                            decision.outcome
                        ))
                        .child(
                            div()
                                .text_color(palette.muted)
                                .child(decision.detail.clone()),
                        ),
                );
            }
            body = body.child(panel);
        } else {
            body = body.child(empty(
                "Choose a scenario below. Scenarios expire after 15 minutes.",
                cx,
            ));
        }
        for preset in &self.resilience.presets {
            let id = preset.id;
            let arm = Button::new(id)
                .accessibility_label(format!("Arm {}", preset.name))
                .label(if preset.allow_count {
                    format!(
                        "Arm {} {}",
                        preset.count,
                        if preset.count == 1 {
                            "injection"
                        } else {
                            "injections"
                        }
                    )
                } else {
                    "Arm scenario".into()
                })
                .primary()
                .disabled(self.busy || self.resilience_active());
            let arm = if preset.allow_count {
                let view = cx.weak_entity();
                arm.dropdown_menu(move |mut menu, _, _| {
                    for count in 1..=20 {
                        let view = view.clone();
                        menu = menu.item(
                            PopupMenuItem::new(format!(
                                "Arm {count} {}",
                                if count == 1 {
                                    "injection"
                                } else {
                                    "injections"
                                }
                            ))
                            .on_click(move |_, _, cx| {
                                let _ =
                                    view.update(cx, |view, cx| view.arm_resilience(id, count, cx));
                            }),
                        );
                    }
                    menu
                })
                .into_any_element()
            } else {
                arm.on_click(cx.listener(move |view, _, _, cx| view.arm_resilience(id, 0, cx)))
                    .into_any_element()
            };
            body = body.child(
                div()
                    .id(gpui::SharedString::from(format!("preset-{id}")))
                    .role(gpui::Role::Group)
                    .aria_label(format!(
                        "{}: {}. {}. {}",
                        preset.name, preset.summary, preset.protocol, preset.behavior
                    ))
                    .h_flex()
                    .gap_4()
                    .p_4()
                    .rounded_md()
                    .border_1()
                    .border_color(palette.line)
                    .bg(palette.card)
                    .child(
                        div()
                            .v_flex()
                            .flex_1()
                            .gap_1()
                            .child(
                                div()
                                    .font_weight(gpui::FontWeight::SEMIBOLD)
                                    .child(preset.name.to_owned()),
                            )
                            .child(preset.summary.to_owned())
                            .child(div().text_color(palette.muted).child(format!(
                                "{} · {}",
                                preset.protocol.to_uppercase(),
                                preset.behavior
                            ))),
                    )
                    .child(arm),
            );
        }
        div().flex_1().min_h_0().child(
            div()
                .id("resilience-scroll")
                .size_full()
                .overflow_y_scrollbar()
                .child(body),
        )
    }
}
