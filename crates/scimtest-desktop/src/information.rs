use gpui::{
    App, AppContext, Bounds, Context, Entity, FocusHandle, IntoElement, Render, SharedString,
    Window, WindowBounds, WindowOptions, div, prelude::*, px, size,
};
use gpui_base::text::{TextView, TextViewState};
use gpui_component::{Root, StyledExt, button::Button};
use std::path::{Path, PathBuf};

#[cfg(test)]
mod tests;

fn bundled_notes() -> Option<String> {
    let path = std::env::current_exe()
        .ok()?
        .parent()?
        .parent()?
        .join("Resources/ReleaseNotes.md");
    let text = std::fs::read_to_string(path).ok()?;
    (!text.trim().is_empty()).then_some(text)
}

pub fn show_about(cx: &mut App) {
    open(
        "About scimtest".into(),
        format!(
            "# scimtest {}\n\nA local identity test environment for OIDC, SAML, and SCIM.\n\n[Documentation](https://github.com/rselbach/scimtest#readme) · [Source and license](https://github.com/rselbach/scimtest)\n\nCopyright Rafael Selbach. Licensed under Apache 2.0.",
            scimtest_core::runtime::version()
        ).into(),
        cx,
    );
}

pub fn show_release_notes(cx: &mut App) {
    let notes = bundled_notes().unwrap_or_else(|| {
        "# Rust desktop preview\n\nNative tools for OIDC, SAML, SCIM, directory management, traffic inspection, fault injection, and lifecycle scenarios.\n\n[Published release notes](https://github.com/rselbach/scimtest/releases)".into()
    });
    open(
        format!(
            "What's New in scimtest {}",
            scimtest_core::runtime::version()
        )
        .into(),
        notes.into(),
        cx,
    );
}

pub fn show_after_update(state_file: &Path, cx: &mut App) {
    if bundled_notes().is_none() {
        return;
    }
    let version = scimtest_core::runtime::version();
    let marker = state_file.with_extension("release-notes-version");
    match std::fs::read_to_string(&marker) {
        Ok(presented) if presented.trim() == version => return,
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
            eprintln!("Read release notes version: {error}");
        }
        _ => {}
    }
    cx.spawn(async move |cx| {
        cx.background_executor()
            .timer(std::time::Duration::from_millis(750))
            .await;
        cx.update(move |cx| {
            show_release_notes(cx);
            if let Err(error) = remember_version(marker, version) {
                eprintln!("Remember release notes version: {error}");
            }
        });
    })
    .detach();
}

fn remember_version(path: PathBuf, version: &str) -> std::io::Result<()> {
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

struct Information {
    title: SharedString,
    text: Entity<TextViewState>,
    focus: FocusHandle,
}

impl Information {
    fn new(title: SharedString, body: SharedString, cx: &mut Context<Self>) -> Self {
        Self {
            text: cx.new(|cx| TextViewState::markdown(&body, cx)),
            title,
            focus: cx.focus_handle(),
        }
    }
}

fn open(title: SharedString, body: SharedString, cx: &mut App) {
    let options = WindowOptions {
        window_bounds: Some(WindowBounds::Windowed(Bounds::centered(
            None,
            size(px(620.), px(480.)),
            cx,
        ))),
        window_min_size: Some(size(px(400.), px(280.))),
        titlebar: Some(gpui::TitlebarOptions {
            title: Some(title.clone()),
            ..Default::default()
        }),
        ..Default::default()
    };
    match cx.open_window(options, |window, cx| {
        let view = cx.new(|cx| Information::new(title, body, cx));
        let focus = view.read(cx).focus.clone();
        window.focus(&focus, cx);
        cx.new(|cx| Root::new(view, window, cx))
    }) {
        Ok(window) => {
            let _ = window.update(cx, |_, window, _| window.activate_window());
        }
        Err(error) => eprintln!("Open information window: {error}"),
    }
}

pub fn show_message(title: String, message: String, cx: &mut App) {
    open(title.into(), message.into(), cx);
}

impl Render for Information {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let palette = crate::theme::Palette::get(cx);
        div()
            .v_flex()
            .size_full()
            .bg(palette.card)
            .text_color(palette.text)
            .track_focus(&self.focus)
            .on_key_down(cx.listener(|view, event: &gpui::KeyDownEvent, window, cx| {
                if event.keystroke.key == "escape" {
                    window.remove_window();
                    return;
                }
                let modifiers = &event.keystroke.modifiers;
                let key = event.keystroke.key.as_str();
                if modifiers.alt
                    || modifiers.shift
                    || (modifiers.platform && !matches!(key, "up" | "down" | "home" | "end"))
                    || (modifiers.control && !matches!(key, "home" | "end"))
                {
                    return;
                }
                let key = match key {
                    "up" if modifiers.platform => "home",
                    "down" if modifiers.platform => "end",
                    key => key,
                };
                let list = view.text.read(cx).list_state();
                let line = window.line_height();
                let page = (list.viewport_bounds().size.height - line).max(line);
                match key {
                    "down" => list.scroll_by(line),
                    "up" => list.scroll_by(-line),
                    "pagedown" => list.scroll_by(page),
                    "pageup" => list.scroll_by(-page),
                    "home" => list.scroll_to(Default::default()),
                    "end" => list.scroll_to_end(),
                    _ => return,
                }
                window.refresh();
                cx.stop_propagation();
            }))
            .child(
                div()
                    .px_6()
                    .pt_5()
                    .flex_shrink_0()
                    .text_lg()
                    .font_weight(gpui::FontWeight::SEMIBOLD)
                    .child(self.title.clone()),
            )
            .child(
                div()
                    .id("information-body")
                    .flex_1()
                    .min_h_0()
                    .p_6()
                    .overflow_hidden()
                    .child(
                        TextView::new(&self.text)
                            .aria_label(self.title.clone())
                            .selectable(true)
                            .scrollable(true),
                    ),
            )
            .child(
                div()
                    .h_flex()
                    .flex_shrink_0()
                    .justify_end()
                    .p_4()
                    .border_t_1()
                    .border_color(palette.line)
                    .child(
                        Button::new("done")
                            .label("Done")
                            .on_click(|_, window, _| window.remove_window()),
                    ),
            )
    }
}
