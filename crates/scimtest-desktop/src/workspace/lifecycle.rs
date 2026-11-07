use rune::El;
use scimtest_core::oidc::LifecycleRun;

use super::{Workspace, view::placeholder};
use crate::theme::Ui;

#[derive(Default)]
pub(super) struct Inspector {
    pub runs: Vec<LifecycleRun>,
}

pub(super) struct Form;

impl Form {
    pub fn fields(&self, _workspace: &Workspace, ui: &Ui, _layer: &mut Vec<El>) -> El {
        placeholder("Lifecycle scenario", ui)
    }
}

impl Workspace {
    pub(super) fn save_lifecycle(&mut self) {}

    pub(super) fn lifecycle_inspector(&self, ui: &Ui, _layer: &mut Vec<El>) -> El {
        placeholder("Lifecycle", ui)
    }
}
