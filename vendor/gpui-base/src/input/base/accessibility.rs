use std::ops::Range;

use gpui::accesskit::{Node, NodeId, Rect, Role, TextDirection, TextPosition, TextSelection};
use gpui::{A11ySubtreeBuilder, Bounds, Half, Pixels, Size, TextAlign, px};
use unicode_segmentation::UnicodeSegmentation;

use super::{InputBaseState, InputModeKind, layout::LastLayout};

struct TextRun {
    range: Range<usize>,
    offsets: Vec<usize>,
    node: Node,
    id: Option<NodeId>,
    line: usize,
}

/// One frame's text and geometry. Prepaint fills this before the input root
/// publishes its synthetic children; paint's last_layout is one frame too old.
pub(super) struct TextSnapshot {
    revision: u64,
    value: String,
    runs: Vec<TextRun>,
    anchor: usize,
    focus: usize,
    disabled: bool,
    readonly: bool,
    scale_factor: f32,
}

impl TextSnapshot {
    pub(super) fn new<M: InputModeKind>(
        state: &InputBaseState<M>,
        layout: &LastLayout,
        bounds: Bounds<Pixels>,
        scroll_size: Size<Pixels>,
        ghost_row: Option<usize>,
        ghost_height: Pixels,
        scale_factor: f32,
    ) -> Self {
        let text = state.text.to_string();
        let selection = state.selected_range();
        let (anchor, focus) = if state.is_selection_reversed() {
            (selection.end, selection.start)
        } else {
            (selection.start, selection.end)
        };
        let mut snapshot = Self {
            revision: state.document_revision,
            value: String::new(),
            runs: Vec::new(),
            anchor,
            focus,
            disabled: state.disabled,
            readonly: !state.is_editable(),
            scale_factor,
        };
        let word_starts: Vec<usize> = text
            .split_word_bound_indices()
            .filter_map(|(offset, word)| (!word.trim_start().is_empty()).then_some(offset))
            .collect();
        let horizontal = match layout.text_align {
            TextAlign::Right => (scroll_size.width - bounds.size.width).max(px(0.)),
            TextAlign::Center => (scroll_size.width - bounds.size.width).half().max(px(0.)),
            _ => px(0.),
        };
        let mut top = bounds.origin.y + layout.visible_top;
        let mut start = 0;
        let mut visual_line = 0;
        // split_inclusive preserves hard breaks, while the extra empty line
        // preserves the caret after a final newline (and in an empty input).
        for (row, raw) in text
            .split_inclusive('\n')
            .chain(
                text.ends_with('\n')
                    .then_some("")
                    .or_else(|| text.is_empty().then_some("")),
            )
            .enumerate()
        {
            let content = raw.strip_suffix('\n').unwrap_or(raw);
            let shaped = layout
                .line(row)
                .filter(|line| line.len() == content.len() || content.is_empty());
            if let Some(line) = shaped {
                let mut local = 0;
                let visual_count = if content.is_empty() {
                    1
                } else {
                    line.wrapped_lines.len()
                };
                for (index, wrapped) in line.wrapped_lines.iter().take(visual_count).enumerate() {
                    let last = index + 1 == line.wrapped_lines.len();
                    let end = if last {
                        raw.len()
                    } else {
                        (local + wrapped.len).min(content.len())
                    };
                    let indent = if index == 0 { px(0.) } else { line.wrap_indent };
                    let left = bounds.origin.x
                        + layout.line_number_width
                        + horizontal
                        + layout.alignment_offset(wrapped.width)
                        + indent;
                    snapshot.push_runs(
                        &text,
                        start + local..start + end,
                        visual_line,
                        &word_starts,
                        Some((left, top, layout.line_height, wrapped)),
                    );
                    local = end;
                    top += layout.line_height;
                    visual_line += 1;
                }
                if ghost_row == Some(row) {
                    top += ghost_height;
                }
            } else {
                // Offscreen or folded text is readable without inventing glyph
                // bounds. Visible plain text uses this frame's actual shaping.
                snapshot.push_runs(
                    &text,
                    start..start + raw.len(),
                    visual_line,
                    &word_starts,
                    None,
                );
                if let Some(line) = layout.line(row) {
                    top += line.size(layout.line_height).height;
                    if ghost_row == Some(row) {
                        top += ghost_height;
                    }
                }
                visual_line += 1;
            }
            start += raw.len();
        }
        snapshot.value = text;
        snapshot
    }

    fn push_runs(
        &mut self,
        text: &str,
        range: Range<usize>,
        line: usize,
        word_starts: &[usize],
        geometry: Option<(Pixels, Pixels, Pixels, &super::display_map::InputLine)>,
    ) {
        let offsets = character_offsets(&text[range.clone()]);
        // AccessKit stores word indices in u8. Long visual lines therefore
        // need multiple linked runs, even when they have no soft wraps.
        let count = offsets.len() - 1;
        for chunk_start in (0..count.max(1)).step_by(255) {
            let chunk_end = (chunk_start + 255).min(count);
            let offsets: Vec<usize> = offsets[chunk_start..=chunk_end]
                .iter()
                .map(|offset| range.start + offset)
                .collect();
            let start = offsets[0];
            let end = *offsets.last().unwrap();
            let mut node = Node::new(Role::TextRun);
            node.set_value(&text[start..end]);
            node.set_character_lengths(
                offsets
                    .windows(2)
                    .map(|pair| (pair[1] - pair[0]) as u8)
                    .collect::<Vec<_>>(),
            );
            node.set_word_starts(
                word_starts[word_starts.partition_point(|offset| *offset < start)..]
                    .iter()
                    .take_while(|offset| **offset < end)
                    .filter_map(|offset| {
                        if *offset < start || *offset >= end {
                            return None;
                        }
                        offsets.binary_search(offset).ok().map(|index| index as u8)
                    })
                    .collect::<Vec<_>>(),
            );
            if let Some((left, top, height, shaped)) = geometry {
                let positions: Vec<f32> = offsets
                    .iter()
                    .map(|offset| {
                        f32::from(shaped.x_for_index((offset - range.start).min(shaped.len)))
                            * self.scale_factor
                    })
                    .collect();
                let min = positions.iter().copied().fold(f32::INFINITY, f32::min);
                let max = positions.iter().copied().fold(f32::NEG_INFINITY, f32::max);
                node.set_bounds(Rect::new(
                    (f32::from(left) * self.scale_factor + min) as f64,
                    (f32::from(top) * self.scale_factor) as f64,
                    (f32::from(left) * self.scale_factor + max) as f64,
                    (f32::from(top + height) * self.scale_factor) as f64,
                ));
                node.set_text_direction(TextDirection::LeftToRight);
                node.set_character_positions(
                    positions[..positions.len() - 1]
                        .iter()
                        .map(|position| *position - min)
                        .collect::<Vec<_>>(),
                );
                node.set_character_widths(
                    positions
                        .windows(2)
                        .map(|pair| (pair[1] - pair[0]).abs())
                        .collect::<Vec<_>>(),
                );
            }
            self.runs.push(TextRun {
                range: start..end,
                offsets,
                node,
                id: None,
                line,
            });
        }
    }

    pub(super) fn publish(&mut self, builder: &mut A11ySubtreeBuilder) {
        builder.parent_node().set_value(self.value.as_str());
        if self.disabled {
            builder.parent_node().set_disabled();
        }
        if self.readonly {
            builder.parent_node().set_read_only();
        }
        for (index, run) in self.runs.iter_mut().enumerate() {
            run.id = Some(builder.synthetic_node_id((
                "input-text",
                self.revision,
                index,
                run.range.start,
                run.range.end,
            )));
        }
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
        if let Some(selection) = self.selection() {
            builder.parent_node().set_text_selection(selection);
        }
    }

    pub(super) fn selection(&self) -> Option<TextSelection> {
        Some(TextSelection {
            anchor: self.position(self.anchor)?,
            focus: self.position(self.focus)?,
        })
    }

    #[cfg(test)]
    pub(super) fn selection_for_test(&mut self) -> TextSelection {
        // TestPlatform doesn't activate AccessKit. Native checks exercise the
        // real subtree builder; editor tests use known IDs for action dispatch.
        for (index, run) in self.runs.iter_mut().enumerate() {
            run.id = Some(NodeId(index as u64 + 10));
        }
        self.selection().unwrap()
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

    pub(super) fn selection_offsets(
        &self,
        selection: &TextSelection,
        revision: u64,
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

fn character_offsets(text: &str) -> Vec<usize> {
    let mut offsets: Vec<usize> = text
        .char_indices()
        .filter_map(|(offset, ch)| {
            // The editor also treats CRLF as a single selectable character.
            (ch != '\n' || offset == 0 || text.as_bytes()[offset - 1] != b'\r').then_some(offset)
        })
        .collect();
    offsets.push(text.len());
    offsets
}

#[cfg(test)]
mod tests {
    use super::*;
    use gpui::{
        AppContext, Context, Entity, IntoElement, ParentElement, Render, Styled, TestAppContext,
        Window, div, size,
    };

    #[gpui::test]
    fn text_run_geometry_tracks_display_scale_in_both_directions(cx: &mut TestAppContext) {
        struct OffsetInput(Entity<crate::input::TextareaState>);

        impl Render for OffsetInput {
            fn render(&mut self, _: &mut Window, _: &mut Context<Self>) -> impl IntoElement {
                div().size_full().p(px(16.)).child(self.0.clone())
            }
        }

        cx.update(crate::init);
        let text = format!(
            "Troy 🦀 Barnes at Greendale Community College.\n{}",
            "Abed Nadir ".repeat(24)
        );
        let (root, cx) = cx.add_window_view(|window, cx| {
            OffsetInput(cx.new(|cx| {
                let mut state = crate::input::TextareaState::new(window, cx)
                    .default_value(text.clone())
                    .soft_wrap(true);
                state.set_accessibility(crate::input::InputAccessibility::new(Some(
                    Role::MultilineTextInput,
                )));
                state
            }))
        });
        let state = cx.update(|_, cx| root.read(cx).0.clone());
        cx.simulate_resize(size(px(300.), px(200.)));
        cx.simulate_scale_factor_change(1.);
        let logical = cx.update(|window, cx| {
            assert_eq!(window.viewport_size(), size(px(300.), px(200.)));
            assert_eq!(window.scale_factor(), 1.);
            window.draw(cx).clear(cx);
            let state = state.read(cx);
            let snapshot = state.accessibility_text.borrow();
            let snapshot = snapshot.as_ref().unwrap();
            assert!(
                snapshot
                    .runs
                    .iter()
                    .filter_map(|run| run.node.bounds())
                    .any(|bounds| bounds.x0 >= 16. && bounds.y0 >= 16.)
            );
            snapshot
                .runs
                .iter()
                .map(|run| run.node.clone())
                .collect::<Vec<_>>()
        });
        for scale in [2., 1.] {
            cx.simulate_scale_factor_change(scale);
            cx.update(|window, cx| {
                assert_eq!(window.viewport_size(), size(px(300.), px(200.)));
                assert_eq!(window.scale_factor(), scale);
                window.draw(cx).clear(cx);
                let state = state.read(cx);
                let snapshot = state.accessibility_text.borrow();
                let snapshot = snapshot.as_ref().unwrap();
                assert_eq!(snapshot.runs.len(), logical.len());
                for (run, logical) in snapshot.runs.iter().zip(&logical) {
                    assert_eq!(run.node.value(), logical.value());
                    assert_eq!(run.node.character_lengths(), logical.character_lengths());
                    let factor = f64::from(scale);
                    assert_eq!(
                        run.node.bounds(),
                        logical.bounds().map(|bounds| Rect::new(
                            bounds.x0 * factor,
                            bounds.y0 * factor,
                            bounds.x1 * factor,
                            bounds.y1 * factor,
                        ))
                    );
                    if let Some(positions) = logical.character_positions() {
                        let want: Vec<_> = positions.iter().map(|value| value * scale).collect();
                        assert_eq!(run.node.character_positions(), Some(want.as_slice()));
                    }
                    if let Some(widths) = logical.character_widths() {
                        let want: Vec<_> = widths.iter().map(|value| value * scale).collect();
                        assert_eq!(run.node.character_widths(), Some(want.as_slice()));
                    }
                }
            });
        }
    }

    #[gpui::test]
    fn text_runs_follow_fresh_wrapping_and_preserve_empty_lines(cx: &mut TestAppContext) {
        cx.update(crate::init);
        let text = format!("{}\r\nGreendale\n", "Troy 🦀 ".repeat(30));
        let (state, cx) = cx.add_window_view(|window, cx| {
            let mut state = crate::input::TextareaState::new(window, cx)
                .default_value(text.clone())
                .soft_wrap(true);
            state.set_accessibility(crate::input::InputAccessibility::new(Some(
                Role::MultilineTextInput,
            )));
            state
        });
        cx.simulate_resize(size(px(240.), px(500.)));
        let narrow_rows = cx.update(|window, cx| {
            window.draw(cx).clear(cx);
            let state = state.read(cx);
            let snapshot = state.accessibility_text.borrow();
            let snapshot = snapshot.as_ref().unwrap();
            assert_eq!(
                snapshot
                    .runs
                    .iter()
                    .map(|run| run.node.value().unwrap())
                    .collect::<String>(),
                text
            );
            assert_eq!(snapshot.runs.last().unwrap().node.value(), Some(""));
            let visible: Vec<_> = snapshot
                .runs
                .iter()
                .filter_map(|run| run.node.bounds())
                .collect();
            assert!(
                visible.len() > 3,
                "long line must wrap in the narrow window"
            );
            assert!(visible.windows(2).any(|pair| pair[1].y0 > pair[0].y0));
            for run in snapshot
                .runs
                .iter()
                .filter(|run| run.node.bounds().is_some())
            {
                assert_eq!(
                    run.node.character_positions().unwrap().len(),
                    run.node.character_lengths().len()
                );
                assert_eq!(
                    run.node.character_widths().unwrap().len(),
                    run.node.character_lengths().len()
                );
                assert!(run.node.bounds().unwrap().height() > 0.);
            }
            visible.len()
        });
        cx.simulate_resize(size(px(600.), px(500.)));
        cx.update(|window, cx| {
            assert_eq!(window.viewport_size(), size(px(600.), px(500.)));
            window.draw(cx).clear(cx);
            let viewport_width =
                f64::from(f32::from(window.viewport_size().width) * window.scale_factor());
            let state = state.read(cx);
            let snapshot = state.accessibility_text.borrow();
            let visible_rows = snapshot
                .as_ref()
                .unwrap()
                .runs
                .iter()
                .filter(|run| run.node.bounds().is_some())
                .count();
            assert!(
                visible_rows < narrow_rows,
                "resize must use this frame's wrapping"
            );
            assert!(
                snapshot
                    .as_ref()
                    .unwrap()
                    .runs
                    .iter()
                    .filter_map(|run| run.node.bounds())
                    .all(|bounds| bounds.x1 <= viewport_width)
            );
        });
    }

    #[gpui::test]
    fn empty_input_keeps_one_caret_run_and_excludes_wrapped_placeholder(cx: &mut TestAppContext) {
        cx.update(crate::init);
        let (state, cx) = cx.add_window_view(|window, cx| {
            let mut state = crate::input::TextareaState::new(window, cx)
                .placeholder("Greendale placeholder ".repeat(30))
                .soft_wrap(true);
            state.set_accessibility(crate::input::InputAccessibility::new(Some(
                Role::MultilineTextInput,
            )));
            state
        });
        cx.simulate_resize(size(px(240.), px(200.)));
        cx.update(|window, cx| {
            window.draw(cx).clear(cx);
            let state = state.read(cx);
            let mut snapshot = state.accessibility_text.borrow_mut();
            let snapshot = snapshot.as_mut().unwrap();
            assert_eq!(snapshot.runs.len(), 1);
            assert_eq!(snapshot.runs[0].node.value(), Some(""));
            assert!(snapshot.runs[0].node.character_lengths().is_empty());
            let selection = snapshot.selection_for_test();
            assert_eq!(
                snapshot.selection_offsets(&selection, state.document_revision),
                Some((0, 0))
            );
        });
    }

    fn snapshot() -> TextSnapshot {
        TextSnapshot {
            revision: 7,
            value: String::new(),
            runs: Vec::new(),
            anchor: 0,
            focus: 0,
            disabled: false,
            readonly: false,
            scale_factor: 1.,
        }
    }

    #[test]
    fn unicode_and_crlf_match_the_editors_selectable_boundaries() {
        assert_eq!(
            character_offsets("Troy 🦀e\u{301}\r\n"),
            [0, 1, 2, 3, 4, 5, 9, 10, 12, 14]
        );
        assert_eq!(character_offsets(""), [0]);
        let mut snapshot = snapshot();
        snapshot.push_runs("🦀\r\n", 0..6, 0, &[0], None);
        assert_eq!(snapshot.runs[0].node.character_lengths(), [4, 2]);
    }

    #[test]
    fn long_lines_preserve_text_word_starts_and_selection_validation() {
        let text = "Troy 🦀 ".repeat(100);
        let words: Vec<_> = text
            .split_word_bound_indices()
            .filter_map(|(offset, word)| (!word.trim_start().is_empty()).then_some(offset))
            .collect();
        let mut snapshot = snapshot();
        snapshot.push_runs(&text, 0..text.len(), 0, &words, None);
        assert!(snapshot.runs.len() > 1);
        assert_eq!(
            snapshot
                .runs
                .iter()
                .map(|run| run.node.value().unwrap())
                .collect::<String>(),
            text
        );
        for (index, run) in snapshot.runs.iter_mut().enumerate() {
            run.id = Some(NodeId(index as u64 + 10));
            assert!(run.node.character_lengths().len() <= 255);
            assert_eq!(
                run.node
                    .character_lengths()
                    .iter()
                    .map(|n| *n as usize)
                    .sum::<usize>(),
                run.range.len()
            );
            assert!(
                run.node
                    .word_starts()
                    .iter()
                    .all(|index| (*index as usize) < run.node.character_lengths().len())
            );
        }
        snapshot.anchor = text.len();
        snapshot.focus = 5;
        let mut selection = snapshot.selection().unwrap();
        assert_eq!(
            snapshot.selection_offsets(&selection, 7),
            Some((text.len(), 5))
        );
        assert_eq!(snapshot.selection_offsets(&selection, 8), None);
        selection.focus.node = NodeId(999);
        assert_eq!(snapshot.selection_offsets(&selection, 7), None);
        selection.focus = TextPosition {
            node: NodeId(10),
            character_index: 999,
        };
        assert_eq!(snapshot.selection_offsets(&selection, 7), None);
    }
}
