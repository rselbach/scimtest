use std::borrow::Cow;

use gpui::{AssetSource, SharedString};

pub struct Assets;

const ICONS: &[(&str, &str)] = &[
    (
        "icons/eye.svg",
        r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="none" stroke="white" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M1 8s2.5-4.5 7-4.5S15 8 15 8s-2.5 4.5-7 4.5S1 8 1 8Z"/><circle cx="8" cy="8" r="2"/></svg>"#,
    ),
    (
        "icons/user.svg",
        r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="none" stroke="white" stroke-width="1.5" stroke-linecap="round"><circle cx="8" cy="6" r="2.6"/><path d="M3 14c0-2.4 2.2-4 5-4s5 1.6 5 4"/></svg>"#,
    ),
    (
        "icons/users.svg",
        r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="none" stroke="white" stroke-width="1.5" stroke-linecap="round"><circle cx="5" cy="6" r="2.2"/><circle cx="11" cy="6" r="1.9"/><path d="M1.5 13c0-2 1.6-3.2 3.5-3.2s3.5 1.2 3.5 3.2M9 13c0-1.4 1-2.4 2.5-2.4s2.5 1 2.5 2.4"/></svg>"#,
    ),
    (
        "icons/environments.svg",
        r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="none" stroke="white" stroke-width="1.5" stroke-linecap="round"><rect x="2.5" y="3" width="11" height="10" rx="2"/><path d="M5.5 6h5M5.5 8.5h5"/></svg>"#,
    ),
    (
        "icons/edit.svg",
        r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="none" stroke="white" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="m11.5 2.5 2 2L5 13H3v-2zM10 4l2 2"/></svg>"#,
    ),
    (
        "icons/trash.svg",
        r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="none" stroke="white" stroke-width="1.5" stroke-linecap="round"><path d="M3 4h10M6 4V2.5h4V4M4.5 4l.6 9h5.8l.6-9M7 6.5v4M9 6.5v4"/></svg>"#,
    ),
    (
        "icons/chevron-down.svg",
        r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="none" stroke="white" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="m4 6 4 4 4-4"/></svg>"#,
    ),
    (
        "icons/check.svg",
        r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m3 8 3 3 7-7"/></svg>"#,
    ),
    (
        "icons/history.svg",
        r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="none" stroke="white" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="8" cy="8" r="5.5"/><path d="M8 5v3.2l2 1.3"/></svg>"#,
    ),
    (
        "icons/restore.svg",
        r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="none" stroke="white" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M3 8a5 5 0 1 0 1.5-3.6M3 2.5v3h3"/></svg>"#,
    ),
    (
        "icons/circle-check.svg",
        r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="none" stroke="white" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="8" cy="8" r="5.5"/><path d="m5.6 8.2 1.7 1.7 3.2-3.4"/></svg>"#,
    ),
    (
        "icons/chevron-right.svg",
        r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="none" stroke="white" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="m6 4 4 4-4 4"/></svg>"#,
    ),
    (
        "icons/shield.svg",
        r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="none" stroke="white" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M8 1.8 13 3.6v4c0 3-2.2 5.2-5 6.6-2.8-1.4-5-3.6-5-6.6v-4z"/></svg>"#,
    ),
    (
        "icons/pulse.svg",
        r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="none" stroke="white" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M1.5 8h3l1.8-4 3 8 1.8-4h3.4"/></svg>"#,
    ),
    (
        "icons/tools.svg",
        r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="none" stroke="white" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="m3 13 6-6M9.5 3.5a2.5 2.5 0 0 1 3 3L11 7.5 8.5 5z"/></svg>"#,
    ),
    (
        "icons/globe.svg",
        r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="none" stroke="white" stroke-width="1.5" stroke-linecap="round"><circle cx="8" cy="8" r="5.8"/><ellipse cx="8" cy="8" rx="2.6" ry="5.8"/><path d="M2.2 8h11.6"/></svg>"#,
    ),
    (
        "icons/lifecycle.svg",
        r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="none" stroke="white" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M2.5 5h8l-2-2M13.5 11h-8l2 2"/></svg>"#,
    ),
    (
        "icons/id-card.svg",
        r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="none" stroke="white" stroke-width="1.5" stroke-linecap="round"><rect x="1.8" y="3.2" width="12.4" height="9.6" rx="2"/><circle cx="5.6" cy="7.2" r="1.4"/><path d="M9 6.8h3M9 9.2h3M4 11.2h3"/></svg>"#,
    ),
    (
        "icons/close.svg",
        r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="none" stroke="white" stroke-width="1.5" stroke-linecap="round"><path d="m4 4 8 8M4 12l8-8"/></svg>"#,
    ),
];

impl AssetSource for Assets {
    fn load(&self, path: &str) -> gpui::Result<Option<Cow<'static, [u8]>>> {
        if path == "app-icon.png" {
            return Ok(Some(Cow::Borrowed(include_bytes!(
                "../assets/app-icon.png"
            ))));
        }
        Ok(ICONS
            .iter()
            .find(|(name, _)| *name == path)
            .map(|(_, svg)| Cow::Borrowed(svg.as_bytes())))
    }

    fn list(&self, path: &str) -> gpui::Result<Vec<SharedString>> {
        Ok(ICONS
            .iter()
            .map(|(name, _)| *name)
            .chain(["app-icon.png"])
            .filter(|name| name.starts_with(path))
            .map(SharedString::from)
            .collect())
    }
}
