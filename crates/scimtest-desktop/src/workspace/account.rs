use rune::El;

use super::{Workspace, view::placeholder};
use crate::theme::Ui;

impl Workspace {
    pub(super) fn account_locked(&self) -> bool {
        false
    }

    pub(super) fn account_screen(&self, ui: &Ui, _layer: &mut Vec<El>) -> El {
        placeholder("Account & connection", ui)
    }

    pub(super) fn sign_out_account(&mut self) {}
}
