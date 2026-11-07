use rune::{Color, TextStyle};
use rune_kit::{Kit, PaletteSeed};

#[derive(Clone, Copy)]
pub struct Palette {
    pub canvas: Color,
    pub sidebar: Color,
    pub card: Color,
    pub toolbar: Color,
    pub text: Color,
    pub strong: Color,
    pub muted: Color,
    pub line: Color,
    pub soft: Color,
    pub accent: Color,
    pub selected: Color,
    pub success: Color,
    pub danger: Color,
}

fn hex(value: u32) -> Color {
    rune::color::hex(&format!("#{value:06x}")).unwrap_or(Color::BLACK)
}

impl Palette {
    pub fn get(dark: bool) -> Self {
        if dark {
            return Self {
                canvas: hex(0x1c1c1e),
                sidebar: hex(0x262629),
                card: hex(0x2c2c2e),
                toolbar: hex(0x232325),
                text: hex(0xe5e5e7),
                strong: hex(0xf5f5f7),
                muted: hex(0xa1a1a6),
                line: hex(0x454547),
                soft: hex(0x333335),
                accent: hex(0x0a84ff),
                selected: hex(0x233e5d),
                success: hex(0x30d158),
                danger: hex(0xff453a),
            };
        }
        Self {
            canvas: hex(0xf5f5f7),
            sidebar: hex(0xeaeaed),
            card: hex(0xffffff),
            toolbar: hex(0xf6f6f8),
            text: hex(0x2c2c2e),
            strong: hex(0x111113),
            muted: hex(0x6e6e73),
            line: hex(0xd8d8dc),
            soft: hex(0xf0f0f2),
            accent: hex(0x007aff),
            selected: hex(0xd5e2f5),
            success: hex(0x248a3d),
            danger: hex(0xd70015),
        }
    }
}

/// The palette and the component kit built from it, for one view pass.
pub struct Ui {
    pub p: Palette,
    pub k: Kit,
}

impl Ui {
    pub fn new(dark: bool) -> Self {
        let p = Palette::get(dark);
        let mut k = Kit::from_palette(PaletteSeed {
            bg: p.card,
            fg: p.text,
            accent: p.accent,
        });
        k.radius.md = 6.0;
        k.radius.lg = 11.0;
        Self { p, k }
    }

    /// Text at `size` points and `weight`, in the kit's UI face.
    pub fn font(&self, size: f32, weight: f32) -> TextStyle {
        TextStyle {
            size,
            weight,
            line_height: 0.0,
            ..self.k.ty.ui
        }
    }
}

pub const REGULAR: f32 = 400.0;
pub const MEDIUM: f32 = 500.0;
pub const SEMIBOLD: f32 = 600.0;
pub const BOLD: f32 = 700.0;
