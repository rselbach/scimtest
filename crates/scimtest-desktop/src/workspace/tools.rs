use rune::{El, TextEdit};

use super::{Workspace, view::placeholder};
use crate::theme::Ui;

impl Workspace {
    pub(super) fn open_tools(&mut self) {}

    pub(super) fn open_idp(&mut self) {}

    pub(super) fn tools_body(&self, _count: &TextEdit, _domain: &TextEdit, ui: &Ui) -> El {
        placeholder("Bulk tools", ui)
    }

    pub(super) fn idp_body(&self, _base_url: &TextEdit, _trust_proxy: bool, ui: &Ui) -> El {
        placeholder("IDP and tunnel settings", ui)
    }
}
