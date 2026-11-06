use super::{
    Workspace,
    oidc::view::{copy_button, empty},
};
use crate::theme::Palette;
use gpui::{Context, Div, div, prelude::*, px};
use gpui_component::{
    Disableable, StyledExt,
    button::{Button, ButtonVariants},
    scroll::ScrollableElement,
};
use scimtest_core::{Error, diagnostics::Snapshot};

#[derive(Default)]
pub(super) struct Inspector {
    pub snapshot: Snapshot,
    debug: bool,
    selected: usize,
    refreshing: bool,
    pending: bool,
}
impl Workspace {
    pub(super) fn refresh_traffic(&mut self, cx: &mut Context<Self>) {
        if self.traffic.refreshing {
            self.traffic.pending = true;
            return;
        }
        self.traffic.refreshing = true;
        self.traffic.pending = false;
        let diagnostics = self.identity.diagnostics();
        cx.spawn(async move |view, cx| {
            let result = cx
                .background_executor()
                .spawn(async move {
                    Ok::<_, Error>((diagnostics.snapshot()?, diagnostics.settings()?.debug))
                })
                .await;
            let _ = view.update(cx, |view, cx| {
                view.traffic.refreshing = false;
                match result {
                    Ok((snapshot, debug)) => {
                        if view.traffic.selected > 0 {
                            view.traffic.selected = view
                                .traffic
                                .snapshot
                                .entries
                                .get(view.traffic.selected)
                                .and_then(|previous| {
                                    snapshot.entries.iter().position(|entry| entry == previous)
                                })
                                .unwrap_or_default();
                        }
                        view.traffic.snapshot = snapshot;
                        view.traffic.debug = debug;
                    }
                    Err(error) => {
                        view.message = error.to_string();
                        view.failed = true;
                    }
                }
                if view.traffic.pending {
                    view.refresh_traffic(cx);
                }
                cx.notify();
            });
        })
        .detach();
    }
    pub(super) fn traffic_action(&mut self, action: &'static str, cx: &mut Context<Self>) {
        let diagnostics = self.identity.diagnostics();
        let result = match action {
            "record" => diagnostics.update(None, Some(!self.traffic.snapshot.record), None),
            "secrets" => {
                diagnostics.update(None, None, Some(!self.traffic.snapshot.record_secrets))
            }
            "debug" => diagnostics.update(Some(!self.traffic.debug), None, None),
            _ => diagnostics.clear(),
        };
        match result {
            Ok(()) => {
                self.failed = false;
                self.message = if action == "clear" {
                    "Traffic cleared"
                } else {
                    "Traffic settings updated"
                }
                .into();
            }
            Err(error) => {
                self.failed = true;
                self.message = error.to_string();
            }
        }
        self.refresh_traffic(cx);
        cx.notify();
    }
    pub(super) fn traffic_inspector(&self, cx: &mut Context<Self>) -> Div {
        let palette = Palette::get(cx);
        let mut controls = div().h_flex().flex_shrink_0().gap_2().pb_4();
        for (id, label) in [
            (
                "record",
                format!(
                    "Recording: {}",
                    if self.traffic.snapshot.record {
                        "on"
                    } else {
                        "off"
                    }
                ),
            ),
            (
                "secrets",
                format!(
                    "Include secrets: {}",
                    if self.traffic.snapshot.record_secrets {
                        "on"
                    } else {
                        "off"
                    }
                ),
            ),
            (
                "debug",
                format!(
                    "Debug to stdout: {}",
                    if self.traffic.debug { "on" } else { "off" }
                ),
            ),
        ] {
            controls = controls.child(
                Button::new(id)
                    .label(label)
                    .disabled(self.busy || id == "secrets" && !self.traffic.snapshot.record)
                    .on_click(cx.listener(move |view, _, _, cx| view.traffic_action(id, cx))),
            );
        }
        controls = controls.child(
            Button::new("refresh-traffic")
                .label("Refresh")
                .ghost()
                .on_click(cx.listener(|view, _, _, cx| view.refresh_traffic(cx))),
        );
        let mut body = div().flex().flex_row().flex_1().min_h_0().gap_4();
        if self.traffic.snapshot.entries.is_empty() {
            return div().v_flex().flex_1().min_h_0().child(controls).child(empty("No exchanges recorded. Run a sign-in or send an identity request to capture traffic.",cx));
        }
        let mut entries = div().v_flex().gap_2();
        for (index, entry) in self.traffic.snapshot.entries.iter().enumerate() {
            let request = entry
                .lines()
                .find(|line| {
                    ["GET ", "POST ", "DELETE ", "PATCH "]
                        .iter()
                        .any(|method| line.starts_with(method))
                })
                .unwrap_or("SAML Single Logout");
            let label = request.chars().take(42).collect::<String>();
            entries = entries.child(
                Button::new(("traffic-entry", index))
                    .toggled(index == self.traffic.selected)
                    .accessibility_label(format!(
                        "{}. {}",
                        label,
                        entry
                            .lines()
                            .next()
                            .unwrap_or_default()
                            .trim_matches('=')
                            .trim()
                    ))
                    .ghost()
                    .v_flex()
                    .gap_1()
                    .p_3()
                    .rounded_md()
                    .bg(if index == self.traffic.selected {
                        palette.selected
                    } else {
                        palette.card
                    })
                    .cursor_pointer()
                    .child(div().text_size(px(12.)).text_left().child(label))
                    .child(
                        div().text_size(px(10.)).text_color(palette.muted).child(
                            entry
                                .lines()
                                .next()
                                .unwrap_or_default()
                                .trim_matches('=')
                                .trim()
                                .chars()
                                .take(45)
                                .collect::<String>(),
                        ),
                    )
                    .on_click(cx.listener(move |view, _, _, cx| {
                        view.traffic.selected = index;
                        cx.notify();
                    })),
            );
        }
        body = body.child(
            div()
                .id("traffic-list")
                .w(px(260.))
                .h_full()
                .flex_shrink_0()
                .overflow_y_scrollbar()
                .child(entries),
        );
        if let Some(entry) = self.traffic.snapshot.entries.get(self.traffic.selected) {
            body = body.child(
                div()
                    .v_flex()
                    .flex_1()
                    .min_w_0()
                    .min_h_0()
                    .gap_3()
                    .child(
                        div()
                            .h_flex()
                            .flex_shrink_0()
                            .child(
                                div()
                                    .flex_1()
                                    .font_weight(gpui::FontWeight::SEMIBOLD)
                                    .child("Exchange transcript"),
                            )
                            .child(copy_button(
                                "copy-traffic",
                                "Copy transcript",
                                entry.clone(),
                                cx,
                            )),
                    )
                    .child(
                        div()
                            .id("traffic-transcript")
                            .flex_1()
                            .min_h_0()
                            .overflow_y_scrollbar()
                            .child(
                                div()
                                    .p_4()
                                    .rounded_md()
                                    .bg(palette.card)
                                    .font_family("monospace")
                                    .text_size(px(11.))
                                    .child(super::view::accessible_text(
                                        "transcript",
                                        entry.clone(),
                                    )),
                            ),
                    ),
            );
        }
        div()
            .v_flex()
            .flex_1()
            .min_h_0()
            .child(controls)
            .child(body)
    }
}
