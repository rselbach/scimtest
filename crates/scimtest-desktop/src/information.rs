use rune::{Cx, El, Key, KeyEvent, ScrollSpec, Tx, col, el, row};
use rune_kit::{Button, Markdown};
use std::path::{Path, PathBuf};

use crate::{
    Shell,
    theme::{SEMIBOLD, Ui},
    workspace::view::rule,
};

/// The window that shows About, release notes and update messages.
#[derive(Default)]
pub struct Information {
    title: String,
    body: String,
}

fn bundled_notes() -> Option<String> {
    let path = std::env::current_exe()
        .ok()?
        .parent()?
        .parent()?
        .join("Resources/ReleaseNotes.md");
    let text = std::fs::read_to_string(path).ok()?;
    (!text.trim().is_empty()).then_some(text)
}

pub fn release_notes() -> (String, String) {
    let notes = bundled_notes().unwrap_or_else(|| {
        "# Rust desktop preview\n\nNative tools for OIDC, SAML, SCIM, directory management, traffic inspection, fault injection, and lifecycle scenarios.\n\n[Published release notes](https://github.com/rselbach/scimtest/releases)".into()
    });
    (
        format!(
            "What's New in scimtest {}",
            scimtest_core::runtime::version()
        ),
        notes,
    )
}

/// Shows `title` and its Markdown `message` in the information window.
pub fn show_message(shell: Option<&Shell>, title: String, message: String) {
    let Some(shell) = shell else {
        eprintln!("{title}: {message}");
        return;
    };
    shell
        .information
        .update(move |s: &mut Information, tx: &mut Tx| {
            tx.set_title(title.clone());
            s.title = title;
            s.body = message;
        });
    shell.information_window.open();
}

/// Whether this version's release notes still need showing after an update.
pub fn release_notes_due(state_file: &Path) -> Option<PathBuf> {
    bundled_notes()?;
    let version = scimtest_core::runtime::version();
    let marker = state_file.with_extension("release-notes-version");
    match std::fs::read_to_string(&marker) {
        Ok(presented) if presented.trim() == version => return None,
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
            eprintln!("Read release notes version: {error}");
        }
        _ => {}
    }
    Some(marker)
}

pub fn remember_version(path: PathBuf, version: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path)?;
    file.write_all(version.as_bytes())?;
    file.sync_all()
}

pub fn on_key(_: &mut Information, event: &KeyEvent, tx: &mut Tx) -> bool {
    if event.key != Key::Escape {
        return false;
    }
    tx.close_window();
    true
}

pub fn view(s: &Information, cx: &mut Cx<Information>) -> El {
    let ui = Ui::new(cx.system_dark());
    let p = ui.p;
    let body = col()
        .key("information")
        .w_full()
        .h_full()
        .fill(p.card)
        .child(
            rune::text(s.title.clone())
                .key("information-title")
                .role("heading")
                .level(1)
                .font(ui.font(17.0, SEMIBOLD))
                .color(p.text)
                .px(24.0)
                .pt(20.0)
                .wrap(),
        )
        .child(
            col()
                .key("information-body")
                .label(s.title.clone())
                .w_full()
                .grow(1.0)
                .min_h(0.0)
                .scroll(ScrollSpec {
                    stick_bottom: false,
                })
                .child(
                    el().w_full().padding(24.0).child(
                        Markdown::new(s.body.clone())
                            .selectable(true)
                            .on_link_tx(|_: &mut Information, url: &str, tx: &mut Tx| {
                                if let Err(error) = tx.open_url(url) {
                                    eprintln!("Open {url}: {error}");
                                }
                            })
                            .build(&ui.k),
                    ),
                ),
        )
        .child(rule(p))
        .child(
            row().w_full().padding(16.0).justify_end().child(
                Button::new("Done")
                    .on_press_tx(|_: &mut Information, tx: &mut Tx| tx.close_window())
                    .build(&ui.k)
                    .key("done")
                    .default_button(),
            ),
        );
    rune_kit::root(body, Vec::new())
}
