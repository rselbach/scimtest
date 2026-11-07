//! Grain-gradient fills under the toolbar, the sidebar and the selected page. Views place
//! `El::effect` slots with [`under`]; [`Fills`] paints rune-fx layers into them each frame.
//! Every fill is still, so the window rests between frames as it does without them.

use rune::{
    El,
    compose::{Compositor, DeviceKey, Frame},
    render::KIND_EFFECT,
};
use rune_fx::{
    FillParams, Fx, FxFrame, FxOptions, FxRenderer, FxSlot, GrainGradientParams, Shape, Stops,
};

use crate::{theme::Ui, workspace::Workspace};

/// Where a fill goes; also its effect slot's mark.
#[derive(Clone, Copy)]
pub enum Fill {
    Toolbar = 1,
    Sidebar = 2,
    Selected = 3,
}

/// An effect slot stretched under its parent's content, with corners of `radius`. Put it
/// before the parent's other children so they paint over the fill.
pub fn under(fill: Fill, radius: f32, ui: &Ui) -> El {
    rune::effect(fill as u32)
        .effect_data([if ui.dark { 1.0 } else { 0.0 }, 0.0, 0.0, 0.0])
        .pin(Some(0.0), Some(0.0), Some(0.0), Some(0.0))
        .radius(radius)
}

/// The fill and its opacity for a slot's mark, in the dark or light theme.
fn fill(mark: u32, dark: bool) -> Option<(FillParams, f32)> {
    let still = |p: GrainGradientParams| GrainGradientParams { fps: 0.0, ..p };
    Some(match (mark, dark) {
        (1, true) => (still(GrainGradientParams::ember()).into(), 0.3),
        (1, false) => (
            still(GrainGradientParams {
                colors: Stops::hex(&[0xeee6f7, 0xf5c4da, 0xffcfae, 0xfff0dc]),
                ..GrainGradientParams::ember()
            })
            .into(),
            0.75,
        ),
        (2, true) => (still(GrainGradientParams::halo()).into(), 0.35),
        (2, false) => (
            still(GrainGradientParams {
                colors: Stops::hex(&[0xfbfcff, 0xd6e2ff, 0xc2c9f2, 0xe0dcef]),
                ..GrainGradientParams::halo()
            })
            .into(),
            0.7,
        ),
        (3, _) => (still(GrainGradientParams::sweep()).border(1.5), 1.0),
        _ => return None,
    })
}

/// Draws the frame through Rune's renderer, painting the fills at their slots.
#[derive(Default)]
pub struct Fills {
    renderer: Option<(DeviceKey, FxRenderer)>,
}

impl Compositor<Workspace> for Fills {
    fn render(&mut self, f: &mut Frame<'_, Workspace>) {
        let (mut layers, mut slots, mut marks, mut scale) =
            (Vec::new(), Vec::new(), Vec::new(), 1.0);
        for (i, slot) in f.rt.instances.iter().enumerate() {
            let mark = f.rt.marks.get(i).copied().unwrap_or(0);
            if slot.params[1] != KIND_EFFECT {
                continue;
            }
            let Some((params, opacity)) = fill(mark, slot.uv[0] != 0.0) else {
                continue;
            };
            // Slot records are in device pixels; fills are shaped in points.
            scale = slot.params[3].max(f32::EPSILON);
            let [x, y, w, h] = slot.rect.map(|v| v / scale);
            layers.push(
                Fx::fill(params)
                    .on(Shape::rounded(x, y, w, h, slot.radii[0] / scale))
                    .opacity(opacity),
            );
            slots.push(FxSlot::default().scale(scale).clip(slot.clip, slot.fade));
            marks.push(mark);
        }
        if layers.is_empty() {
            f.draw_ui();
            return;
        }
        let key = f.device_key();
        if self.renderer.as_ref().map(|(k, _)| *k) != Some(key) {
            let mut renderer = FxRenderer::new(f.device, f.format, FxOptions { dither: true });
            renderer.add_format(f.device, wgpu::TextureFormat::Rgba16Float);
            self.renderer = Some((key, renderer));
        }
        let Some((_, fx)) = self.renderer.as_mut() else {
            return;
        };
        fx.set_srgb_blend(f.srgb_blend());
        let frame = FxFrame {
            viewport: [f.size.0, f.size.1],
            scale,
            layers: &layers,
            backdrop: None,
            sources: &[],
        };
        fx.prepare_with_slots(f.device, f.queue, &frame, &slots);
        let clear = f.rt.clear_color();
        f.ui.prepare(
            f.device,
            f.queue,
            &mut f.rt.text.atlas,
            &f.rt.instances,
            f.size,
        );
        let fx = &*fx;
        f.ui.draw_with(f.encoder, f.target, clear, &mut |pass, site| {
            if let Some(layer) = marks.iter().position(|mark| *mark == site.mark) {
                fx.draw_layer_in(pass, site.format, site.origin, layer);
            }
        });
    }
}
