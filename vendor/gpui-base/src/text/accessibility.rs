use std::{collections::BTreeMap, ops::Range, sync::Arc};

use gpui::{
    A11ySubtreeBuilder, Pixels, Point, TextLayout,
    accesskit::{Node, NodeId, Rect, Role, TextPosition, TextSelection},
};
use unicode_segmentation::UnicodeSegmentation;

use super::{RenderedText, inline::InlineState};

pub(super) struct TextRun {
    range: Range<usize>,
    offsets: Vec<usize>,
    node: Node,
    id: Option<NodeId>,
    line: usize,
}

#[derive(Clone, Copy)]
struct CharacterGeometry {
    origin: Point<Pixels>,
    width: Pixels,
    height: Pixels,
}

/// This frame's rendered text, including offscreen blocks. Only laid-out
/// characters receive glyph geometry; text is never positioned by estimation.
pub(super) struct TextSnapshot {
    revision: usize,
    text: RenderedText,
    geometry: BTreeMap<usize, CharacterGeometry>,
    runs: Vec<TextRun>,
    pub(super) selected_range: (usize, usize),
}

impl TextSnapshot {
    pub(super) fn new(text: RenderedText, revision: usize, selected_range: (usize, usize)) -> Self {
        Self {
            revision,
            text,
            geometry: BTreeMap::new(),
            runs: Vec::new(),
            selected_range,
        }
    }

    pub(super) fn record_geometry(
        &mut self,
        source: &Arc<std::sync::Mutex<InlineState>>,
        source_start: usize,
        text: &str,
        layout: &TextLayout,
        scale: f32,
    ) {
        let Some((range, _)) = self
            .text
            .index()
            .selection_spans
            .iter()
            .find(|(_, state)| Arc::ptr_eq(state, source))
        else {
            return;
        };
        let start = range.start + source_start;
        if self.text.as_str().get(start..start + text.len()) != Some(text) {
            return;
        }
        let height = layout.line_height() * scale;
        let mut line_start = 0;
        for (offset, ch) in text.char_indices() {
            let Some(origin) = layout
                .position_for_index(offset)
                .map(|origin| origin * scale)
            else {
                continue;
            };
            let width = if ch == '\n' || ch == '\r' {
                gpui::px(0.)
            } else {
                layout
                    .line_layout_for_index(offset)
                    .map(|line| {
                        let local = offset - line_start;
                        (line.unwrapped_layout.x_for_index(local + ch.len_utf8())
                            - line.unwrapped_layout.x_for_index(local))
                        .abs()
                            * scale
                    })
                    .unwrap_or(gpui::px(0.))
            };
            self.geometry.insert(
                start + offset,
                CharacterGeometry {
                    origin,
                    width,
                    height,
                },
            );
            if ch == '\n' {
                line_start = offset + 1;
            }
        }
    }

    pub(super) fn publish(&mut self, builder: &mut A11ySubtreeBuilder) {
        self.build_runs();
        for run in &mut self.runs {
            run.id = Some(builder.synthetic_node_id((
                "reader-text",
                self.revision,
                run.range.start,
                run.range.end,
            )));
        }
        builder.parent_node().set_value(self.text.as_str());
        builder.parent_node().set_read_only();
        for (index, run) in self.runs.iter().enumerate() {
            let mut node = run.node.clone();
            if let Some(previous) = index
                .checked_sub(1)
                .and_then(|index| self.runs.get(index))
                .filter(|previous| previous.line == run.line)
            {
                node.set_previous_on_line(previous.id.unwrap());
            }
            if let Some(next) = self
                .runs
                .get(index + 1)
                .filter(|next| next.line == run.line)
            {
                node.set_next_on_line(next.id.unwrap());
            }
            builder.push_child(run.id.unwrap(), node);
        }
        if let Some(selection) = self.selection(self.selected_range.0, self.selected_range.1) {
            builder.parent_node().set_text_selection(selection);
        }
    }

    fn build_runs(&mut self) {
        self.runs.clear();
        let text = self.text.as_str();
        let words: Vec<usize> = text
            .split_word_bound_indices()
            .filter_map(|(offset, word)| (!word.trim_start().is_empty()).then_some(offset))
            .collect();
        let mut line = 0;
        let mut start = 0;
        for raw in text
            .split_inclusive('\n')
            .chain((text.is_empty() || text.ends_with('\n')).then_some(""))
        {
            let mut offsets: Vec<usize> = raw
                .char_indices()
                .filter_map(|(offset, ch)| {
                    (ch != '\n' || offset == 0 || raw.as_bytes()[offset - 1] != b'\r')
                        .then_some(start + offset)
                })
                .collect();
            offsets.push(start + raw.len());
            let mut chunk = 0;
            loop {
                let geometry = self.geometry.get(&offsets[chunk]);
                let mut end = chunk + 1;
                while end < offsets.len() - 1 && end - chunk < 255 {
                    let next = self.geometry.get(&offsets[end]);
                    if !same_line(geometry, next) {
                        break;
                    }
                    end += 1;
                }
                let end = end.min(offsets.len() - 1);
                let character_offsets = offsets[chunk..=end].to_vec();
                let range = offsets[chunk]..offsets[end];
                let mut node = Node::new(Role::TextRun);
                node.set_value(&text[range.clone()]);
                node.set_character_lengths(
                    character_offsets
                        .windows(2)
                        .map(|pair| (pair[1] - pair[0]) as u8)
                        .collect::<Vec<_>>(),
                );
                node.set_word_starts(
                    words[words.partition_point(|offset| *offset < range.start)..]
                        .iter()
                        .take_while(|offset| **offset < range.end)
                        .filter_map(|offset| {
                            character_offsets
                                .binary_search(offset)
                                .ok()
                                .map(|index| index as u8)
                        })
                        .collect::<Vec<_>>(),
                );
                if let Some(first) = geometry {
                    let characters: Vec<_> = character_offsets[..character_offsets.len() - 1]
                        .iter()
                        .filter_map(|offset| self.geometry.get(offset))
                        .collect();
                    if characters.len() == character_offsets.len() - 1 {
                        let left = characters
                            .iter()
                            .map(|c| f32::from(c.origin.x))
                            .fold(f32::INFINITY, f32::min);
                        let right = characters
                            .iter()
                            .map(|c| f32::from(c.origin.x + c.width))
                            .fold(f32::NEG_INFINITY, f32::max);
                        if !characters.is_empty() {
                            node.set_text_direction(gpui::accesskit::TextDirection::LeftToRight);
                            node.set_bounds(Rect::new(
                                left as f64,
                                f32::from(first.origin.y) as f64,
                                right as f64,
                                f32::from(first.origin.y + first.height) as f64,
                            ));
                            node.set_character_positions(
                                characters
                                    .iter()
                                    .map(|c| f32::from(c.origin.x) - left)
                                    .collect::<Vec<_>>(),
                            );
                            node.set_character_widths(
                                characters
                                    .iter()
                                    .map(|c| f32::from(c.width))
                                    .collect::<Vec<_>>(),
                            );
                        }
                    }
                }
                self.runs.push(TextRun {
                    range: range.clone(),
                    offsets: character_offsets,
                    id: None,
                    node,
                    line,
                });
                if end == offsets.len() - 1 {
                    break;
                }
                if !same_line(geometry, self.geometry.get(&offsets[end])) {
                    line += 1;
                }
                chunk = end;
            }
            start += raw.len();
            line += 1;
        }
    }

    fn position(&self, offset: usize) -> Option<TextPosition> {
        let run = self
            .runs
            .iter()
            .rev()
            .find(|run| run.range.start <= offset && offset <= run.range.end)?;
        Some(TextPosition {
            node: run.id?,
            character_index: run.offsets.binary_search(&offset).ok()?,
        })
    }

    pub(super) fn selection(&self, anchor: usize, focus: usize) -> Option<TextSelection> {
        Some(TextSelection {
            anchor: self.position(anchor)?,
            focus: self.position(focus)?,
        })
    }

    pub(super) fn selection_offsets(
        &self,
        selection: &TextSelection,
        revision: usize,
    ) -> Option<(usize, usize)> {
        if revision != self.revision {
            return None;
        }
        let offset = |position: TextPosition| {
            self.runs
                .iter()
                .find(|run| run.id == Some(position.node))?
                .offsets
                .get(position.character_index)
                .copied()
        };
        Some((offset(selection.anchor)?, offset(selection.focus)?))
    }
}

fn same_line(a: Option<&CharacterGeometry>, b: Option<&CharacterGeometry>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => a.origin.y == b.origin.y && a.height == b.height,
        (None, None) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::text::{SelectionFormat, TextView, TextViewState};
    use gpui::{
        AppContext, Context, Entity, IntoElement, Render, TestAppContext, VisualTestContext,
        Window, div, prelude::*, px, size,
    };

    struct Reader(Entity<TextViewState>);

    impl Render for Reader {
        fn render(&mut self, _: &mut Window, _: &mut Context<Self>) -> impl IntoElement {
            div()
                .size_full()
                .child(crate::TextSelectionLayer)
                .child(TextView::new(&self.0).scrollable(true))
        }
    }

    fn fixture<'a>(
        cx: &'a mut TestAppContext,
        source: &str,
    ) -> (Entity<TextViewState>, &'a mut VisualTestContext) {
        cx.update(crate::init);
        let mut state = None;
        let (_, cx) = cx.add_window_view(|_, cx| {
            let text = cx.new(|cx| TextViewState::markdown(source, cx));
            state = Some(text.clone());
            Reader(text)
        });
        cx.run_until_parked();
        cx.simulate_resize(size(px(400.), px(280.)));
        cx.update(|window, cx| {
            window.activate_window();
            window.draw(cx).clear(cx);
        });
        (state.unwrap(), cx)
    }

    fn request(state: &TextViewState, anchor: usize, focus: usize) -> gpui::accesskit::ActionData {
        let mut snapshot = state.accessibility_text.borrow_mut();
        let snapshot = snapshot.as_mut().unwrap();
        snapshot.build_runs();
        for (index, run) in snapshot.runs.iter_mut().enumerate() {
            run.id = Some(NodeId(
                ((snapshot.revision as u64) << 32) | index as u64 + 10,
            ));
        }
        gpui::accesskit::ActionData::SetTextSelection(snapshot.selection(anchor, focus).unwrap())
    }

    #[gpui::test]
    fn reader_selection_copies_exact_rendered_unicode_and_rejects_stale_ranges(
        cx: &mut TestAppContext,
    ) {
        let (state, cx) = fixture(
            cx,
            "# Greendale\n\nTroy **Barnes** 🦀\n\nTroy **Barnes** 🦀",
        );
        let (text, selected) = cx.update(|window, cx| {
            state.update(cx, |state, cx| {
                let text = state.rendered_text();
                let start = text.as_str().rfind("Troy Barnes").unwrap();
                let range = start..text.len() - 1;
                let selected = text.as_str()[range.clone()].to_owned();
                let data = request(state, range.end, range.start);
                state.handle_accessibility_selection(Some(&data), window, cx);
                assert_eq!(state.accessibility_selection(), (range.end, range.start));
                assert_eq!(state.selected_text(), selected);
                assert!(state.focus_handle.is_focused(window));
                (text.as_str().to_owned(), selected)
            })
        });
        cx.update(|window, cx| {
            window.draw(cx).clear(cx);
            assert_eq!(crate::TextSelection::selected_text(window, cx), selected);
        });
        let copy = if cfg!(target_os = "macos") {
            "cmd-c"
        } else {
            "ctrl-c"
        };
        cx.simulate_keystrokes(copy);
        cx.update(|window, cx| {
            assert_eq!(
                cx.read_from_clipboard().and_then(|item| item.text()),
                Some(selected.clone())
            );
            state.update(cx, |state, cx| {
                assert_eq!(state.rendered_text().as_str(), text);
                state.set_selection_format(SelectionFormat::Source, cx);
                assert_eq!(state.selected_text(), "Troy **Barnes** 🦀");
                let range = state.accessibility_selection();
                let old = request(state, range.0, range.1);
                state.set_text("# Abed Nadir\n\nA new Greendale document.", cx);
                state.handle_accessibility_selection(Some(&old), window, cx);
                assert!(state.selected_text().is_empty());
            });
        });
        cx.run_until_parked();
    }

    #[gpui::test]
    fn reader_offscreen_selection_reveals_and_survives_reflow(cx: &mut TestAppContext) {
        let source = (1..=60).map(|chapter|
            format!("## Greendale {chapter}\n\nTroy and Abed review **chapter {chapter}** at Greendale Community College."))
            .collect::<Vec<_>>().join("\n\n");
        let (state, cx) = fixture(cx, &source);
        let list = cx.update(|_, cx| state.read(cx).list_state.clone());
        assert_eq!(list.scroll_px_offset_for_scrollbar().y, px(0.));
        cx.update(|window, cx| {
            state.update(cx, |state, cx| {
                let text = state.rendered_text();
                let start = text.as_str().rfind("chapter 60").unwrap();
                let data = request(state, start, start + "chapter 60".len());
                state.handle_accessibility_selection(Some(&data), window, cx);
                assert_eq!(state.selected_text(), "chapter 60");
            })
        });
        for _ in 0..4 {
            cx.update(|window, cx| window.draw(cx).clear(cx));
        }
        cx.update(|_, cx| {
            let range = state.read(cx).accessibility_selection();
            let mut snapshot = state.read(cx).accessibility_text.borrow_mut();
            let snapshot = snapshot.as_mut().unwrap();
            assert!(snapshot.geometry.contains_key(&range.0));
            snapshot.build_runs();
            let run = snapshot
                .runs
                .iter()
                .find(|run| run.range.contains(&range.0))
                .unwrap();
            assert!(run.node.bounds().is_some());
            assert_eq!(
                run.node.text_direction(),
                Some(gpui::accesskit::TextDirection::LeftToRight)
            );
        });
        assert!(list.scroll_px_offset_for_scrollbar().y < px(0.));
        cx.simulate_resize(size(px(300.), px(220.)));
        cx.update(|window, cx| {
            assert_eq!(window.viewport_size(), size(px(300.), px(220.)));
            window.draw(cx).clear(cx);
            assert_eq!(state.read(cx).selected_text(), "chapter 60");
            state.update(cx, |state, cx| {
                let range = state.accessibility_selection();
                let data = request(state, range.0, range.1);
                state.handle_accessibility_selection(Some(&data), window, cx);
            });
        });
        for _ in 0..4 {
            cx.update(|window, cx| window.draw(cx).clear(cx));
        }
        cx.update(|_, cx| {
            let snapshot = state.read(cx).accessibility_text.borrow();
            let snapshot = snapshot.as_ref().unwrap();
            let range = state.read(cx).accessibility_selection();
            assert!(
                snapshot.geometry.contains_key(&range.0),
                "selected {range:?}; geometry count {}; keys {:?}; scroll {:?}",
                snapshot.geometry.len(),
                snapshot.geometry.keys().collect::<Vec<_>>(),
                list.scroll_px_offset_for_scrollbar()
            );
            let glyph = snapshot.geometry[&range.0];
            assert!(glyph.width > px(0.) && glyph.height > px(0.));
        });
    }

    #[gpui::test]
    fn reader_long_unicode_runs_are_complete_and_keep_valid_selection_positions(
        cx: &mut TestAppContext,
    ) {
        let source = format!("```text\n{}\r\nTroy and Abed\n```", "Troy 🦀 ".repeat(80));
        let (state, cx) = fixture(cx, &source);
        cx.update(|_, cx| {
            let state = state.read(cx);
            let text = state.rendered_text();
            let start = text.as_str().rfind('🦀').unwrap();
            let data = request(state, start, start + '🦀'.len_utf8());
            let gpui::accesskit::ActionData::SetTextSelection(selection) = data else {
                unreachable!()
            };
            let snapshot = state.accessibility_text.borrow();
            let snapshot = snapshot.as_ref().unwrap();
            assert_eq!(
                snapshot
                    .runs
                    .iter()
                    .map(|run| run.node.value().unwrap())
                    .collect::<String>(),
                text.as_str()
            );
            assert!(snapshot.runs.iter().all(|run| run.offsets.len() <= 256));
            assert_eq!(
                snapshot.selection_offsets(&selection, snapshot.revision),
                Some((start, start + '🦀'.len_utf8()))
            );
            assert!(
                snapshot
                    .selection_offsets(&selection, snapshot.revision + 1)
                    .is_none()
            );
        });
    }

    #[gpui::test]
    fn reader_geometry_uses_physical_pixels_after_display_scale_changes(cx: &mut TestAppContext) {
        let (state, cx) = fixture(cx, "Troy and Abed at Greendale.");
        cx.simulate_scale_factor_change(1.);
        let logical = cx.update(|window, cx| {
            assert_eq!(window.scale_factor(), 1.);
            window.draw(cx).clear(cx);
            state
                .read(cx)
                .accessibility_text
                .borrow()
                .as_ref()
                .unwrap()
                .geometry[&0]
        });
        cx.simulate_scale_factor_change(2.);
        cx.update(|window, cx| {
            assert_eq!(window.scale_factor(), 2.);
            window.draw(cx).clear(cx);
            let snapshot = state.read(cx).accessibility_text.borrow();
            let physical = snapshot.as_ref().unwrap().geometry[&0];
            assert_eq!(physical.origin, logical.origin * 2.);
            assert_eq!(physical.width, logical.width * 2.);
            assert_eq!(physical.height, logical.height * 2.);
        });
    }
}
