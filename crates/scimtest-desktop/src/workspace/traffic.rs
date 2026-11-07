use rune::{El, ScrollSpec, TextStyle, col, el, row};
use rune_kit::{Button, ButtonVariant, Checkbox};
use scimtest_core::{Error, diagnostics::Snapshot};

use super::{
    Tab, Workspace,
    view::{caption, copy_button, font_text, rule, vertical_rule},
};
use crate::theme::{SEMIBOLD, Ui};

#[derive(Default)]
pub(super) struct Inspector {
    pub snapshot: Snapshot,
    pub debug: bool,
    pub selected: usize,
    pub refreshing: bool,
    pub pending: bool,
}

/// Recorded exchanges for the `traffic-sample` preview scene, newest first.
const SAMPLE: [&str; 3] = [
    "===== RP interaction 2026-11-07T11:02:48.104211+00:00 =====
----- request from RP -----
POST /oidc/greendale/token HTTP/1.1
authorization: [redacted]
content-type: application/x-www-form-urlencoded
host: 127.0.0.1:8080

grant_type=authorization_code&code=[redacted]&redirect_uri=https%3A%2F%2Fportal.greendale.edu%2Fcallback
----- response to RP -----
HTTP 200 OK
cache-control: no-store
content-type: application/json

{
  \"access_token\": \"[redacted]\",
  \"expires_in\": 3600,
  \"id_token\": \"[redacted]\",
  \"token_type\": \"Bearer\"
}
===== end RP interaction =====",
    "===== RP interaction 2026-11-07T11:02:47.512930+00:00 =====
----- request from RP -----
GET /oidc/greendale/authorize?client_id=greendale&response_type=code&scope=openid+email&state=[redacted] HTTP/1.1
host: 127.0.0.1:8080
----- response to RP -----
HTTP 303 See Other
location: https://portal.greendale.edu/callback?code=[redacted]&state=[redacted]
===== end RP interaction =====",
    "===== RP interaction 2026-11-07T11:02:46.626808+00:00 =====
----- request from RP -----
GET /oidc/greendale/.well-known/openid-configuration HTTP/1.1
host: 127.0.0.1:8080
----- response to RP -----
HTTP 200 OK
content-type: application/json

{
  \"issuer\": \"http://127.0.0.1:8080/oidc/greendale\",
  \"authorization_endpoint\": \"http://127.0.0.1:8080/oidc/greendale/authorize\",
  \"token_endpoint\": \"http://127.0.0.1:8080/oidc/greendale/token\"
}
===== end RP interaction =====",
];

/// The request line of a transcript, or what it is when it has none.
fn request_line(entry: &str) -> &str {
    entry
        .lines()
        .find(|line| {
            ["GET ", "POST ", "DELETE ", "PATCH "]
                .iter()
                .any(|method| line.starts_with(method))
        })
        .unwrap_or("SAML Single Logout")
}

/// The transcript's title line without its `=====` frame.
fn title_line(entry: &str) -> &str {
    entry
        .lines()
        .next()
        .unwrap_or_default()
        .trim_matches('=')
        .trim()
}

impl Workspace {
    pub(super) fn refresh_traffic(&mut self) {
        if self.traffic.refreshing {
            self.traffic.pending = true;
            return;
        }
        self.traffic.refreshing = true;
        self.traffic.pending = false;
        let diagnostics = self.identity.diagnostics();
        self.background(
            move || Ok::<_, Error>((diagnostics.snapshot()?, diagnostics.settings()?.debug)),
            |view, result| {
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
                    Err(error) => view.fail(error.to_string()),
                }
                if view.traffic.pending {
                    view.refresh_traffic();
                }
            },
        );
    }

    /// Opens the Traffic page on sample exchanges, for previews that run no server.
    pub(super) fn show_traffic_sample(&mut self) {
        self.tab = Tab::Traffic;
        self.traffic.snapshot = Snapshot {
            record: true,
            record_secrets: false,
            entries: SAMPLE.map(String::from).to_vec(),
        };
    }

    pub(super) fn traffic_action(&mut self, action: &'static str) {
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
            Err(error) => self.fail(error.to_string()),
        }
        self.refresh_traffic();
    }

    pub(super) fn traffic_inspector(&self, ui: &Ui, _layer: &mut Vec<El>) -> El {
        let k = &ui.k;
        let p = ui.p;
        let mut settings = row().w_full();
        for (index, (id, label, help, checked)) in [
            (
                "record",
                "Record traffic",
                "Capture OIDC and SAML exchanges as they happen.",
                self.traffic.snapshot.record,
            ),
            (
                "secrets",
                "Include raw secrets",
                "Credentials, tokens, and assertions may contain sensitive data.",
                self.traffic.snapshot.record_secrets,
            ),
            (
                "debug",
                "Debug to stdout",
                "Print OIDC and SAML traffic to the terminal running scimtest.",
                self.traffic.debug,
            ),
        ]
        .into_iter()
        .enumerate()
        {
            if index > 0 {
                settings = settings.child(vertical_rule(p));
            }
            settings = settings.child(
                col()
                    .grow(1.0)
                    .min_w(0.0)
                    .gap(4.0)
                    .padding(16.0)
                    .child(
                        Checkbox::new(checked)
                            .label(label)
                            .disabled(self.busy || id == "secrets" && !self.traffic.snapshot.record)
                            .on_toggle(move |s: &mut Workspace| s.traffic_action(id))
                            .build(k)
                            .key(id),
                    )
                    .child(caption(help, ui).pl(28.0).wrap()),
            );
        }
        let controls = col()
            .w_full()
            .gap(20.0)
            .pb(20.0)
            .child(
                col()
                    .key("capture-settings")
                    .w_full()
                    .radius(11.0)
                    .border(1.0, p.line)
                    .fill(p.card)
                    .clip_rounded(11.0)
                    .child(
                        col()
                            .w_full()
                            .gap(4.0)
                            .px(16.0)
                            .py(12.0)
                            .fill(p.soft)
                            .child(font_text("Capture settings", 13.0, SEMIBOLD, p.text, ui))
                            .child(
                                font_text(
                                    "Choose what is retained in this process. Captured entries are cleared when scimtest restarts.",
                                    12.0,
                                    400.0,
                                    p.muted,
                                    ui,
                                )
                                .wrap(),
                            ),
                    )
                    .child(rule(p))
                    .child(settings),
            )
            .child(
                row()
                    .w_full()
                    .gap(12.0)
                    .child(
                        col()
                            .grow(1.0)
                            .min_w(0.0)
                            .gap(4.0)
                            .child(font_text("Recent exchanges", 16.0, SEMIBOLD, p.text, ui))
                            .child(font_text(
                                "Newest first · refreshes every 5 seconds",
                                12.0,
                                400.0,
                                p.muted,
                                ui,
                            )),
                    )
                    .child(
                        row()
                            .gap(8.0)
                            .center_y()
                            .child(
                                Button::new("Refresh")
                                    .variant(ButtonVariant::Outline)
                                    .on_press(|s: &mut Workspace| s.refresh_traffic())
                                    .build(k)
                                    .key("refresh-traffic"),
                            )
                            .child(
                                Button::new("Clear traffic")
                                    .variant(ButtonVariant::Outline)
                                    .disabled(
                                        self.busy || self.traffic.snapshot.entries.is_empty(),
                                    )
                                    .on_press(|s: &mut Workspace| s.traffic_action("clear"))
                                    .build(k)
                                    .key("clear-traffic"),
                            ),
                    ),
            );
        let page = col().key("traffic").w_full().min_h(0.0).child(controls);
        if self.traffic.snapshot.entries.is_empty() {
            return page.child(
                col()
                    .key("traffic-empty")
                    .w_full()
                    .gap(8.0)
                    .padding(40.0)
                    .center()
                    .radius(11.0)
                    .border(1.0, p.line)
                    .fill(p.card)
                    .child(font_text(
                        "No traffic recorded yet",
                        13.0,
                        SEMIBOLD,
                        p.text,
                        ui,
                    ))
                    .child(font_text(
                        "Run a sign-in flow and the exchange will appear here.",
                        13.0,
                        400.0,
                        p.muted,
                        ui,
                    )),
            );
        }
        let mut entries = col().w_full().gap(8.0);
        for (index, entry) in self.traffic.snapshot.entries.iter().enumerate() {
            let label = request_line(entry).chars().take(42).collect::<String>();
            let title = title_line(entry);
            let selected = index == self.traffic.selected;
            let mut item = col()
                .key(format!("traffic-entry-{index}"))
                .role("button")
                .label(format!("{label}. {title}"))
                .checked(selected)
                .focusable(true)
                .w_full()
                .gap(4.0)
                .padding(12.0)
                .radius(6.0)
                .fill(if selected { p.selected } else { p.card })
                .cursor(rune::Cursor::Pointer)
                .child(
                    font_text(label, 12.0, 400.0, p.text, ui)
                        .truncate()
                        .a11y_hidden(),
                )
                .child(
                    font_text(
                        title.chars().take(45).collect::<String>(),
                        10.0,
                        400.0,
                        p.muted,
                        ui,
                    )
                    .truncate()
                    .a11y_hidden(),
                )
                .on_press(move |s: &mut Workspace| s.traffic.selected = index);
            if !selected {
                item = item.hover(k.c.hover);
            }
            entries = entries.child(item);
        }
        let mut body = row().w_full().grow(1.0).min_h(0.0).gap(16.0).child(
            col()
                .key("traffic-list")
                .w(260.0)
                .h_full()
                .scroll(ScrollSpec {
                    stick_bottom: false,
                })
                .child(entries),
        );
        if let Some(entry) = self.traffic.snapshot.entries.get(self.traffic.selected) {
            body = body.child(
                col()
                    .grow(1.0)
                    .min_w(0.0)
                    .h_full()
                    .min_h(0.0)
                    .gap(12.0)
                    .child(
                        row()
                            .w_full()
                            .center_y()
                            .child(
                                font_text("Exchange transcript", 13.0, SEMIBOLD, p.text, ui)
                                    .grow(1.0),
                            )
                            .child(copy_button(
                                "copy-traffic",
                                "Copy transcript",
                                entry.clone(),
                                ui,
                            )),
                    )
                    .child(
                        col()
                            .key("traffic-transcript")
                            .w_full()
                            .grow(1.0)
                            .min_h(0.0)
                            .scroll(ScrollSpec {
                                stick_bottom: false,
                            })
                            .child(
                                el().w_full().padding(16.0).radius(6.0).fill(p.card).child(
                                    rune::text(entry.clone())
                                        .key("transcript")
                                        .font(
                                            TextStyle::new(11.0, 400.0)
                                                .family(rune::Family::SystemMono),
                                        )
                                        .color(p.text)
                                        .w_full()
                                        .wrap_anywhere()
                                        .selectable(true),
                                ),
                            ),
                    ),
            );
        }
        page.child(body)
    }
}
