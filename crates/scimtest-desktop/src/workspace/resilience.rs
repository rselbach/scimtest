use std::collections::BTreeMap;

use rune::{El, ScrollSpec, col, row};
use rune_kit::{Button, ButtonVariant};
use scimtest_core::oidc::{Faults, ResiliencePreset, ResilienceRun};

use super::{
    Workspace,
    view::{Choice, copy_button, dropdown, font_text, rule},
};
use crate::theme::{SEMIBOLD, Ui};

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

    pub(super) fn disarm_resilience(&mut self) {
        self.identity_command(|identity, id| {
            identity.disarm_resilience(&id)?;
            Ok("Fault injection scenario disarmed".into())
        });
    }

    fn arm_resilience(&mut self, preset: &'static str, count: i32) {
        self.identity_command(move |identity, id| {
            let run = identity.arm_resilience(&id, preset, count)?;
            identity.disarm_faults(&id)?;
            Ok(format!("Armed {}", run.name))
        });
    }

    pub(super) fn resilience_inspector(&self, ui: &Ui, layer: &mut Vec<El>) -> El {
        let p = ui.p;
        let k = &ui.k;
        let mut body = col().key("resilience-body").w_full().gap(16.0).child(
            row()
                .w_full()
                .gap(12.0)
                .items_start()
                .child(
                    col()
                        .grow(1.0)
                        .min_w(0.0)
                        .gap(4.0)
                        .child(font_text("Choose a failure", 16.0, SEMIBOLD, p.text, ui))
                        .child(
                            font_text(
                                "Each scenario applies only to the next matching flow or endpoint requests. Scenarios expire after 15 minutes.",
                                13.0,
                                400.0,
                                p.muted,
                                ui,
                            )
                            .wrap(),
                        ),
                )
                .child(
                    Button::new("Custom faults…")
                        .variant(ButtonVariant::Outline)
                        .disabled(self.busy)
                        .on_press(|s: &mut Workspace| s.edit_faults())
                        .build(k)
                        .key("custom-faults"),
                ),
        );
        if self.resilience.manual.active() {
            let armed = format!("Armed for next flow: {}", self.resilience.manual.describe());
            body = body.child(
                row()
                    .key("manual-fault")
                    .role("group")
                    .label(armed.clone())
                    .w_full()
                    .gap(12.0)
                    .padding(12.0)
                    .center_y()
                    .radius(6.0)
                    .fill(p.selected)
                    .child(
                        font_text(armed, 13.0, 400.0, p.text, ui)
                            .grow(1.0)
                            .min_w(0.0)
                            .wrap(),
                    )
                    .child(
                        Button::new("Clear fault")
                            .variant(ButtonVariant::Ghost)
                            .disabled(self.busy)
                            .on_press(|s: &mut Workspace| {
                                s.identity_command(|identity, id| {
                                    identity.disarm_faults(&id)?;
                                    Ok("Armed faults cleared".into())
                                });
                            })
                            .build(k)
                            .key("clear-manual-fault"),
                    ),
            );
        }
        if let Some(run) = &self.resilience.run {
            let mut panel = col()
                .key("resilience-run")
                .role("group")
                .label(format!(
                    "{}: {}. {}. {} in progress. {}",
                    run.name,
                    run.state.as_str(),
                    run.progress(),
                    run.in_flight,
                    run.summary
                ))
                .w_full()
                .gap(8.0)
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
                            font_text(run.name.clone(), 13.0, SEMIBOLD, p.text, ui)
                                .grow(1.0)
                                .min_w(0.0)
                                .wrap(),
                        )
                        .child(font_text(
                            run.state.as_str(),
                            13.0,
                            400.0,
                            if run.active() { p.accent } else { p.muted },
                            ui,
                        ))
                        .child(copy_button(
                            "copy-resilience",
                            "Copy run",
                            serde_json::to_string_pretty(run).unwrap_or_default(),
                            ui,
                        )),
                )
                .child(
                    font_text(
                        format!("{} · {} in progress", run.progress(), run.in_flight),
                        13.0,
                        400.0,
                        p.text,
                        ui,
                    )
                    .wrap(),
                )
                .child(
                    font_text(
                        format!(
                            "{} · Expires {}",
                            run.summary,
                            run.expires_at.format("%H:%M:%S UTC")
                        ),
                        13.0,
                        400.0,
                        p.muted,
                        ui,
                    )
                    .wrap(),
                );
            for (index, decision) in run.decisions.iter().enumerate().rev() {
                panel = panel.child(
                    col()
                        .key(format!("decision-{index}"))
                        .role("group")
                        .label(format!(
                            "{} {}: {}. {}",
                            decision.time.format("%H:%M:%S"),
                            decision.phase,
                            decision.outcome,
                            decision.detail
                        ))
                        .w_full()
                        .gap(4.0)
                        .pt(8.0)
                        .child(
                            font_text(
                                format!(
                                    "{} · {} · {}",
                                    decision.time.format("%H:%M:%S"),
                                    decision.phase,
                                    decision.outcome
                                ),
                                13.0,
                                400.0,
                                p.text,
                                ui,
                            )
                            .wrap(),
                        )
                        .child(font_text(decision.detail.clone(), 13.0, 400.0, p.muted, ui).wrap()),
                );
            }
            body = body.child(panel);
        }
        for presets in self.resilience.presets.chunks(3) {
            let mut grid = row().w_full().equal_columns(3).gap(16.0);
            for preset in presets {
                grid = grid.child(self.preset_card(preset, ui, layer));
            }
            body = body.child(grid);
        }
        col()
            .key("resilience-scroll")
            .w_full()
            .min_h(0.0)
            .scroll(ScrollSpec {
                stick_bottom: false,
            })
            .child(body)
    }

    fn preset_card(&self, preset: &ResiliencePreset, ui: &Ui, layer: &mut Vec<El>) -> El {
        let p = ui.p;
        let id = preset.id;
        let count = self
            .resilience
            .counts
            .get(id)
            .copied()
            .unwrap_or(preset.count);
        let arm_count = if preset.allow_count { count } else { 0 };
        let disabled = self.busy || self.resilience_active();
        let mut card = col()
            .key(format!("preset-{id}"))
            .role("group")
            .label(format!(
                "{}: {}. {}. {}",
                preset.name, preset.summary, preset.protocol, preset.behavior
            ))
            .min_w(0.0)
            .gap(12.0)
            .padding(16.0)
            .radius(11.0)
            .border(1.0, p.line)
            .fill(p.card)
            .child(font_text(
                preset.protocol.to_uppercase(),
                11.0,
                SEMIBOLD,
                p.accent,
                ui,
            ))
            .child(font_text(preset.name, 13.0, SEMIBOLD, p.text, ui).wrap())
            .child(
                font_text(preset.summary, 12.0, 400.0, p.muted, ui)
                    .wrap()
                    .grow(1.0),
            )
            .child(rule(p))
            .child(
                row()
                    .w_full()
                    .gap(12.0)
                    .child(font_text("Inject", 12.0, 400.0, p.muted, ui))
                    .child(
                        font_text(preset.behavior.clone(), 12.0, SEMIBOLD, p.text, ui)
                            .grow(1.0)
                            .min_w(0.0)
                            .wrap(),
                    ),
            );
        if preset.allow_count {
            let choices = (1..=20)
                .map(|choice| {
                    Choice::new(choice.to_string(), move |s: &mut Workspace| {
                        s.resilience.counts.insert(id, choice);
                    })
                    .checked(choice == count)
                })
                .collect();
            card = card.child(
                col()
                    .w_full()
                    .gap(8.0)
                    .child(font_text(
                        "Failed requests before recovery",
                        12.0,
                        400.0,
                        p.text,
                        ui,
                    ))
                    .child(
                        dropdown(
                            self,
                            &format!("count-{id}"),
                            count.to_string(),
                            None,
                            disabled,
                            choices,
                            ui,
                            layer,
                        )
                        .label(format!("Failed requests for {}: {count}", preset.name)),
                    ),
            );
        }
        card.child(
            Button::new("Arm scenario")
                .variant(ButtonVariant::Contrast)
                .disabled(disabled)
                .on_press(move |s: &mut Workspace| s.arm_resilience(id, arm_count))
                .build(&ui.k)
                .key(format!("arm-{id}"))
                .label(format!("Arm {}", preset.name))
                .w_full(),
        )
    }
}
