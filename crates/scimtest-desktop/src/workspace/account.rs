use rune::{El, LiveRegion, Tx, col, text};
use rune_kit::{Button, ButtonVariant};

use super::{Workspace, view::font_text};
use crate::theme::{SEMIBOLD, Ui};

/// A wrapping status line: announced politely, or assertively when it reports a failure.
fn account_status(key: &str, message: String, failed: bool, ui: &Ui) -> El {
    text(message)
        .key(key.to_owned())
        .role(if failed { "alert" } else { "status" })
        .live_region(if failed {
            LiveRegion::Assertive
        } else {
            LiveRegion::Polite
        })
        .font(ui.font(13.0, 400.0))
        .color(if failed { ui.p.danger } else { ui.p.muted })
        .w_full()
        .wrap()
}

impl Workspace {
    pub(super) fn account_locked(&self) -> bool {
        self.tunnel_service.required() && !self.tunnel_snapshot.connected
    }

    /// Leaves the account screen for the workspace, unless signing in is still required.
    fn close_account(&mut self) {
        if self.account_locked() || self.account_busy {
            return;
        }
        self.account_open = false;
        self.message.clear();
        self.failed = false;
    }

    pub(super) fn account_screen(&self, ui: &Ui, _layer: &mut Vec<El>) -> El {
        let p = ui.p;
        let k = &ui.k;
        let snapshot = &self.tunnel_snapshot;
        let locked = self.account_locked();
        let (title, description) = match snapshot.state() {
            "connected" => (
                "Connected to scimtest",
                "Your public URL is ready for OIDC and SAML integrations.",
            ),
            "authorizing" => (
                "Sign in with GitHub",
                "Authorize this installation in your browser to continue.",
            ),
            "failed" => (
                "Connection interrupted",
                "Retry the connection to continue using your public URL.",
            ),
            "connecting" => (
                "Connecting to scimtest…",
                "Checking this installation and preparing your public URL.",
            ),
            _ => (
                "Local connection",
                "This preview works locally. Public URLs require a build with an application profile.",
            ),
        };
        let mut card = col()
            .key("account-card")
            .role("group")
            .label(format!("{title}. {description}"))
            .w(520.0)
            .gap(16.0)
            .padding(32.0)
            .radius(8.0)
            .border(1.0, p.line)
            .fill(p.card)
            .child(font_text("scimtest", 12.0, SEMIBOLD, p.accent, ui))
            .child(
                font_text(title, 24.0, SEMIBOLD, p.text, ui)
                    .key("account-title")
                    .role("heading")
                    .level(1),
            )
            .child(
                font_text(description, 13.0, 400.0, p.muted, ui)
                    .w_full()
                    .wrap(),
            );
        if snapshot.connected {
            if !snapshot.github_login.is_empty() {
                card = card.child(
                    font_text(
                        format!("Signed in as {}", snapshot.github_login),
                        13.0,
                        400.0,
                        p.text,
                        ui,
                    )
                    .key("github-login"),
                );
            }
            if let Some(url) = &snapshot.public_url {
                card = card.child(
                    col()
                        .key("public-endpoint")
                        .gap(8.0)
                        .child(font_text("Public URL", 13.0, 400.0, p.muted, ui))
                        .child(
                            font_text(url.clone(), 13.0, 400.0, p.accent, ui)
                                .key("public-url")
                                .w_full()
                                .wrap(),
                        )
                        .child(
                            Button::new("Copy public URL")
                                .on_press_tx(|s: &mut Workspace, tx: &mut Tx| {
                                    if let Some(url) = &s.tunnel_snapshot.public_url {
                                        tx.copy(url.clone());
                                        s.message = "Public URL copied".into();
                                        s.failed = false;
                                    }
                                })
                                .build(k)
                                .key("copy-public-url"),
                        ),
                );
            }
        }
        if !snapshot.enrollment_code.is_empty() {
            card = card.child(
                col()
                    .key("verification")
                    .role("group")
                    .label("Verification code")
                    .gap(8.0)
                    .child(font_text("Verification code", 13.0, 400.0, p.muted, ui))
                    .child(
                        font_text(snapshot.enrollment_code.clone(), 22.0, SEMIBOLD, p.text, ui)
                            .key("verification-code"),
                    ),
            );
        }
        if !snapshot.enrollment_url.is_empty() {
            card = card.child(
                Button::new("Continue with GitHub")
                    .variant(ButtonVariant::Contrast)
                    .disabled(self.account_busy)
                    .on_press_tx(|s: &mut Workspace, tx: &mut Tx| {
                        match s.tunnel_service.authorization_url() {
                            Ok(url) => {
                                if let Err(error) = tx.open_url(&url) {
                                    s.fail(error.to_string());
                                }
                            }
                            Err(error) => s.fail(error.to_string()),
                        }
                    })
                    .build(k)
                    .key("github-sign-in"),
            );
        }
        let error = snapshot.account_error(self.tunnel_service.required());
        if !error.is_empty() && snapshot.supported {
            card = card.child(account_status("account-error", error, true, ui));
        }
        if snapshot.retry_available {
            card = card.child(
                Button::new("Retry connection")
                    .disabled(self.account_busy)
                    .on_press(|s: &mut Workspace| {
                        s.message.clear();
                        s.failed = false;
                        if let Err(error) = s.tunnel_service.retry() {
                            s.fail(error.to_string());
                        }
                    })
                    .build(k)
                    .key("retry-tunnel"),
            );
        }
        if !self.message.is_empty() {
            card = card.child(account_status(
                "account-message",
                self.message.clone(),
                self.failed,
                ui,
            ));
        }
        if !locked {
            card = card.child(
                Button::new("Back to workspace")
                    .variant(ButtonVariant::Contrast)
                    .disabled(self.account_busy)
                    .on_press(|s: &mut Workspace| s.close_account())
                    .build(k)
                    .key("close-account"),
            );
        }
        if snapshot.connected && self.tunnel_service.required() {
            card = card.child(
                Button::new("Sign out / switch account")
                    .variant(ButtonVariant::Ghost)
                    .disabled(self.account_busy || self.busy)
                    .on_press(|s: &mut Workspace| s.sign_out_account())
                    .build(k)
                    .key("sign-out-account"),
            );
        }
        let mut screen = col()
            .key("account-screen")
            .role("group")
            .label("Account and connection")
            .modal(false, |s: &mut Workspace| s.close_account())
            .focus_return("account-settings")
            .w_full()
            .h_full()
            .gap(16.0)
            .center()
            .fill(p.canvas)
            .child(card)
            .child(
                Button::new("scimtest Help")
                    .variant(ButtonVariant::Ghost)
                    .on_press(|s: &mut Workspace| {
                        let (title, body) = crate::information::about();
                        crate::information::show_message(s.shell.as_ref(), title, body);
                    })
                    .build(k)
                    .key("account-help"),
            );
        if self.updates.available() {
            screen = screen.child(self.updates.button(ui));
        }
        screen
    }

    pub(super) fn sign_out_account(&mut self) {
        if self.account_busy || self.busy {
            return;
        }
        self.message.clear();
        self.failed = false;
        self.account_busy = true;
        let tunnel = self.tunnel_service.clone();
        self.task(async move { tunnel.logout().await }, |s, result, _| {
            s.account_busy = false;
            if let Err(error) = result {
                s.fail(error.to_string());
            }
        });
    }
}
