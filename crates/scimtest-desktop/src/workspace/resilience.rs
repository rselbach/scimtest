use std::collections::BTreeMap;

use super::{Workspace, oidc::view::copy_button};
use crate::dropdown::DropdownMenu;
use crate::theme::Palette;
use gpui::{Context, Div, IntoElement, div, prelude::*, px};
use gpui_component::{
    Disableable, StyledExt,
    button::{Button, ButtonVariants},
    scroll::ScrollableElement,
};
use scimtest_core::oidc::{Faults, ResiliencePreset, ResilienceRun};

#[derive(Default)]
pub(super) struct Inspector {
    pub presets: Vec<ResiliencePreset>,
    pub run: Option<ResilienceRun>,
    pub manual: Faults,
    /// Failed-request counts chosen per preset, keyed by preset id.
    pub counts: BTreeMap<&'static str, i32>,
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
                .items_start()
                .child(
                    div()
                        .v_flex()
                        .flex_1()
                        .min_w_0()
                        .gap_1()
                        .child(
                            div()
                                .text_size(px(16.))
                                .font_weight(gpui::FontWeight::SEMIBOLD)
                                .child("Choose a failure"),
                        )
                        .child(
                            div()
                                .text_color(palette.muted)
                                .child("Each scenario applies only to the next matching flow or endpoint requests. Scenarios expire after 15 minutes."),
                        ),
                )
                .child(
                    Button::new("custom-faults")
                        .label("Custom faults…")
                        .h(px(29.))
                        .outline()
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
        }
        let mut grid = div().grid().grid_cols(3).gap_4();
        for preset in &self.resilience.presets {
            grid = grid.child(self.preset_card(preset, cx));
        }
        body = body.child(grid);
        div().flex_1().min_h_0().child(
            div()
                .id("resilience-scroll")
                .size_full()
                .overflow_y_scrollbar()
                .child(body),
        )
    }

    fn preset_card(
        &self,
        preset: &ResiliencePreset,
        cx: &mut Context<Self>,
    ) -> impl IntoElement + use<> {
        let palette = Palette::get(cx);
        let id = preset.id;
        let count = self
            .resilience
            .counts
            .get(id)
            .copied()
            .unwrap_or(preset.count);
        let arm_count = if preset.allow_count { count } else { 0 };
        let view = cx.weak_entity();
        let mut card = div()
            .id(gpui::SharedString::from(format!("preset-{id}")))
            .role(gpui::Role::Group)
            .aria_label(format!(
                "{}: {}. {}. {}",
                preset.name, preset.summary, preset.protocol, preset.behavior
            ))
            .v_flex()
            .gap_3()
            .p_4()
            .rounded_lg()
            .border_1()
            .border_color(palette.line)
            .bg(palette.card)
            .child(
                div()
                    .text_size(px(11.))
                    .font_weight(gpui::FontWeight::SEMIBOLD)
                    .text_color(palette.accent)
                    .child(preset.protocol.to_uppercase()),
            )
            .child(
                div()
                    .font_weight(gpui::FontWeight::SEMIBOLD)
                    .child(preset.name.to_owned()),
            )
            .child(
                div()
                    .text_size(px(12.))
                    .text_color(palette.muted)
                    .child(preset.summary.to_owned()),
            )
            .child(
                div()
                    .h_flex()
                    .gap_3()
                    .pt_3()
                    .border_t_1()
                    .border_color(palette.line)
                    .text_size(px(12.))
                    .child(div().text_color(palette.muted).child("Inject"))
                    .child(
                        div()
                            .font_weight(gpui::FontWeight::SEMIBOLD)
                            .child(preset.behavior.to_owned()),
                    ),
            );
        if preset.allow_count {
            let choices = (1..=20).collect::<Vec<i32>>();
            card = card.child(
                div()
                    .v_flex()
                    .gap_2()
                    .child(
                        div()
                            .text_size(px(12.))
                            .child("Failed requests before recovery"),
                    )
                    .child(
                        Button::new(gpui::SharedString::from(format!("count-{id}")))
                            .accessibility_label(format!(
                                "Failed requests for {}: {count}",
                                preset.name
                            ))
                            .label(count.to_string())
                            .h(px(29.))
                            .justify_between()
                            .border_1()
                            .border_color(palette.line)
                            .rounded_md()
                            .disabled(self.busy || self.resilience_active())
                            .dropdown_menu(move |mut menu, _, _| {
                                for choice in &choices {
                                    let choice = *choice;
                                    let view = view.clone();
                                    menu = menu.item(
                                        gpui_component::menu::PopupMenuItem::new(
                                            choice.to_string(),
                                        )
                                        .on_click(
                                            move |_, _, cx| {
                                                let _ = view.update(cx, |view, cx| {
                                                    view.resilience.counts.insert(id, choice);
                                                    cx.notify();
                                                });
                                            },
                                        ),
                                    );
                                }
                                menu
                            }),
                    ),
            );
        }
        card.child(
            Button::new(gpui::SharedString::from(format!("arm-{id}")))
                .accessibility_label(format!("Arm {}", preset.name))
                .label("Arm scenario")
                .primary()
                .w_full()
                .disabled(self.busy || self.resilience_active())
                .on_click(cx.listener(move |view, _, _, cx| {
                    view.arm_resilience(id, arm_count, cx);
                })),
        )
    }
}
