use super::Workspace;
use crate::theme::Palette;
use gpui::{ClipboardItem, Context, Div, FontWeight, div, prelude::*, px};
use gpui_component::{
    Disableable, StyledExt,
    button::{Button, ButtonVariants},
};

impl Workspace {
    pub(super) fn account_locked(&self) -> bool {
        self.tunnel_service.required() && !self.tunnel_snapshot.connected
    }
    pub(super) fn account_screen(&self, cx: &mut Context<Self>) -> gpui::Stateful<Div> {
        let palette = Palette::get(cx);
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
        let mut card = div()
            .id("account-card")
            .role(gpui::Role::Group)
            .aria_label(format!("{title}. {description}"))
            .v_flex()
            .gap_4()
            .p_8()
            .w(px(520.))
            .rounded_lg()
            .border_1()
            .border_color(palette.line)
            .bg(palette.card)
            .child(
                div()
                    .text_size(px(12.))
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_color(palette.accent)
                    .child("scimtest"),
            )
            .child(
                div()
                    .text_size(px(24.))
                    .font_weight(FontWeight::SEMIBOLD)
                    .child(title),
            )
            .child(div().text_color(palette.muted).child(description));
        if snapshot.connected {
            if !snapshot.github_login.is_empty() {
                card = card.child(div().child(super::view::accessible_text(
                    "github-login",
                    format!("Signed in as {}", snapshot.github_login),
                )));
            }
            if let Some(url) = &snapshot.public_url {
                card = card.child(
                    div()
                        .v_flex()
                        .gap_2()
                        .child(div().text_color(palette.muted).child("Public URL"))
                        .child(
                            div()
                                .text_color(palette.accent)
                                .child(super::view::accessible_text("public-url", url.clone())),
                        )
                        .child(
                            Button::new("copy-public-url")
                                .label("Copy public URL")
                                .on_click(cx.listener(|view, _, _, cx| {
                                    if let Some(url) = &view.tunnel_snapshot.public_url {
                                        cx.write_to_clipboard(ClipboardItem::new_string(
                                            url.clone(),
                                        ));
                                        view.message = "Public URL copied".into();
                                        view.failed = false;
                                        cx.notify();
                                    }
                                })),
                        ),
                );
            }
        }
        if !snapshot.enrollment_code.is_empty() {
            card = card.child(
                div()
                    .id("verification")
                    .role(gpui::Role::Group)
                    .aria_label("Verification code")
                    .v_flex()
                    .gap_2()
                    .child(div().text_color(palette.muted).child("Verification code"))
                    .child(
                        div()
                            .text_size(px(22.))
                            .font_weight(FontWeight::SEMIBOLD)
                            .child(super::view::accessible_text(
                                "verification-code",
                                snapshot.enrollment_code.clone(),
                            )),
                    ),
            );
        }
        if !snapshot.enrollment_url.is_empty() {
            card = card.child(
                Button::new("github-sign-in")
                    .label("Continue with GitHub")
                    .primary()
                    .disabled(self.account_busy)
                    .on_click(cx.listener(|view, _, _, cx| {
                        match view.tunnel_service.authorization_url() {
                            Ok(url) => cx.open_url(&url),
                            Err(error) => {
                                view.message = error.to_string();
                                view.failed = true;
                            }
                        }
                        cx.notify();
                    })),
            );
        }
        let error = snapshot.account_error(self.tunnel_service.required());
        if !error.is_empty() && snapshot.supported {
            card = card.child(
                super::view::accessible_status("account-error", error.clone(), true)
                    .text_color(palette.danger)
                    .child(error),
            );
        }
        if snapshot.retry_available {
            card = card.child(
                Button::new("retry-tunnel")
                    .label("Retry connection")
                    .disabled(self.account_busy)
                    .on_click(cx.listener(|view, _, _, cx| {
                        view.message.clear();
                        view.failed = false;
                        if let Err(error) = view.tunnel_service.retry() {
                            view.message = error.to_string();
                            view.failed = true;
                        }
                        cx.notify();
                    })),
            );
        }
        if !self.message.is_empty() {
            card = card.child(
                super::view::accessible_status(
                    "account-message",
                    self.message.clone(),
                    self.failed,
                )
                .text_color(if self.failed {
                    palette.danger
                } else {
                    palette.muted
                })
                .child(self.message.clone()),
            );
        }
        if !locked {
            card = card.child(
                Button::new("close-account")
                    .label("Back to workspace")
                    .primary()
                    .disabled(self.account_busy)
                    .on_click(cx.listener(|view, _, _, cx| {
                        view.account_open = false;
                        view.message.clear();
                        view.failed = false;
                        cx.notify();
                    })),
            );
        }
        if snapshot.connected && self.tunnel_service.required() {
            card = card.child(
                Button::new("sign-out-account")
                    .label("Sign out / switch account")
                    .ghost()
                    .disabled(self.account_busy || self.busy)
                    .on_click(cx.listener(|view, _, _, cx| view.sign_out_account(cx))),
            );
        }
        div()
            .id("account-screen")
            .role(gpui::Role::Group)
            .aria_label("Account and connection")
            .track_focus(&self.account_focus)
            .v_flex()
            .size_full()
            .items_center()
            .justify_center()
            .text_size(px(13.))
            .text_color(palette.text)
            .bg(palette.canvas)
            .child(card)
            .child(
                Button::new("account-help")
                    .label("scimtest Help")
                    .ghost()
                    .on_click(|_, _, cx| crate::information::show_about(cx)),
            )
            .when(self.updates.read(cx).available(), |screen| {
                screen.child(crate::updates::button(&self.updates, cx))
            })
    }
    fn sign_out_account(&mut self, cx: &mut Context<Self>) {
        if self.account_busy || self.busy {
            return;
        }
        self.message.clear();
        self.failed = false;
        let tunnel = self.tunnel_service.clone();
        let task = self.executor.spawn(async move { tunnel.logout().await });
        self.account_busy = true;
        cx.spawn(async move |view, cx| {
            let result = task.await;
            let _ = view.update(cx, |view, cx| {
                view.account_busy = false;
                let error = match result {
                    Ok(Ok(())) => None,
                    Ok(Err(error)) => Some(error.to_string()),
                    Err(error) => Some(error.to_string()),
                };
                if let Some(error) = error {
                    view.message = error;
                    view.failed = true;
                }
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }
}
