use rune::El;

use super::super::{Workspace, view::placeholder};
use crate::theme::Ui;

impl Workspace {
    pub(in crate::workspace) fn oidc_inspector(&self, ui: &Ui, _layer: &mut Vec<El>) -> El {
        placeholder("OIDC Inspector", ui)
    }
}
