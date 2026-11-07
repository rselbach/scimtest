use gpui::{App, Hsla, px, rgb};
use gpui_component::{ActiveTheme, Theme};

#[derive(Clone, Copy)]
pub struct Palette {
    pub canvas: Hsla,
    pub sidebar: Hsla,
    pub card: Hsla,
    pub toolbar: Hsla,
    pub text: Hsla,
    pub strong: Hsla,
    pub muted: Hsla,
    pub line: Hsla,
    pub soft: Hsla,
    pub accent: Hsla,
    pub selected: Hsla,
    pub success: Hsla,
    pub danger: Hsla,
}

impl Palette {
    pub fn get(cx: &App) -> Self {
        if cx.theme().is_dark() {
            return Self {
                canvas: rgb(0x1c1c1e).into(),
                sidebar: rgb(0x262629).into(),
                card: rgb(0x2c2c2e).into(),
                toolbar: rgb(0x232325).into(),
                text: rgb(0xe5e5e7).into(),
                strong: rgb(0xf5f5f7).into(),
                muted: rgb(0xa1a1a6).into(),
                line: rgb(0x454547).into(),
                soft: rgb(0x333335).into(),
                accent: rgb(0x0a84ff).into(),
                selected: rgb(0x233e5d).into(),
                success: rgb(0x30d158).into(),
                danger: rgb(0xff453a).into(),
            };
        }
        Self {
            canvas: rgb(0xf5f5f7).into(),
            sidebar: rgb(0xeaeaed).into(),
            card: rgb(0xffffff).into(),
            toolbar: rgb(0xf6f6f8).into(),
            text: rgb(0x2c2c2e).into(),
            strong: rgb(0x111113).into(),
            muted: rgb(0x6e6e73).into(),
            line: rgb(0xd8d8dc).into(),
            soft: rgb(0xf0f0f2).into(),
            accent: rgb(0x007aff).into(),
            selected: rgb(0xd5e2f5).into(),
            success: rgb(0x248a3d).into(),
            danger: rgb(0xd70015).into(),
        }
    }
}

pub fn apply(cx: &mut App) {
    let palette = Palette::get(cx);
    Theme::update(cx, |theme| {
        theme.font_size = px(13.);
        theme.radius = px(6.);
        theme.radius_lg = px(11.);
        theme.background = palette.card;
        theme.foreground = palette.text;
        theme.border = palette.line;
        theme.input = palette.line;
        theme.muted = palette.soft;
        theme.muted_foreground = palette.muted;
        theme.primary = palette.accent;
        theme.primary_hover = palette.accent.opacity(0.88);
        theme.primary_active = palette.accent.opacity(0.78);
        theme.primary_foreground = rgb(0xffffff).into();
        theme.button_primary = palette.accent;
        theme.button_primary_hover = palette.accent.opacity(0.88);
        theme.button_primary_active = palette.accent.opacity(0.78);
        theme.button_primary_foreground = rgb(0xffffff).into();
        theme.secondary = palette.card;
        theme.secondary_hover = palette.soft;
        theme.secondary_foreground = palette.text;
        theme.accent = palette.selected;
        theme.accent_foreground = palette.text;
        theme.ring = palette.accent;
        theme.caret = palette.accent;
        theme.link = palette.accent;
        theme.selection = palette.selected;
        theme.popover = palette.card;
        theme.popover_foreground = palette.text;
    });
}
