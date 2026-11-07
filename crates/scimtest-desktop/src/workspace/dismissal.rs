use rune::{El, row};
use rune_kit::{Button, ButtonVariant, Dialog};

use super::Workspace;
use crate::theme::Ui;

impl Workspace {
    pub(super) fn close_editor(&mut self) {
        self.editor = None;
        self.editor_dirty = false;
        self.discarding = false;
        self.open_menu = None;
        self.message.clear();
    }

    pub(super) fn cancel_discard(&mut self) {
        self.discarding = false;
    }

    /// Closes the editor, first asking before it drops unsaved changes.
    pub(super) fn request_editor_dismiss(&mut self) {
        if self.busy || self.editor.is_none() {
            return;
        }
        if self.discarding {
            self.cancel_discard();
            return;
        }
        if self.editor_dirty {
            self.discarding = true;
            return;
        }
        self.close_editor();
    }

    pub(super) fn discard_confirmation(&self, ui: &Ui, layer: &mut Vec<El>) {
        let k = &ui.k;
        Dialog::new("discard", "Discard unsaved changes?")
            .open(self.discarding)
            .width(420.0)
            .fit()
            .on_close(|s: &mut Workspace| s.cancel_discard())
            .child(
                row()
                    .key("discard-actions")
                    .w_full()
                    .padding(16.0)
                    .gap(8.0)
                    .justify_end()
                    .child(
                        Button::new("Cancel")
                            .variant(ButtonVariant::Ghost)
                            .on_press(|s: &mut Workspace| s.cancel_discard())
                            .build(k)
                            .key("cancel-discard"),
                    )
                    .child(
                        Button::new("Continue")
                            .variant(ButtonVariant::Danger)
                            .on_press(|s: &mut Workspace| s.close_editor())
                            .build(k)
                            .key("confirm-discard")
                            .default_button(),
                    ),
            )
            .build(k, layer);
    }
}
