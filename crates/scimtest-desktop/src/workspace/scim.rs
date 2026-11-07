use rune::El;

use super::{Workspace, view::placeholder};
use crate::theme::Ui;

#[derive(Default)]
pub(super) struct Inspector {}

impl Workspace {
    pub(super) fn scim_running(&self) -> bool {
        false
    }

    pub(super) fn refresh_scim(&mut self) {}

    pub(super) fn scim_action(&mut self, _action: &'static str, _target: Option<(String, String)>) {
    }

    pub(super) fn scim_inspector(&self, ui: &Ui, _layer: &mut Vec<El>) -> El {
        placeholder("SCIM provisioning", ui)
    }
}
