use rune::El;
use scimtest_core::diagnostics::Snapshot;

use super::{Workspace, view::placeholder};
use crate::theme::Ui;

#[derive(Default)]
pub(super) struct Inspector {
    pub snapshot: Snapshot,
}

impl Workspace {
    pub(super) fn refresh_traffic(&mut self) {}

    pub(super) fn traffic_inspector(&self, ui: &Ui, _layer: &mut Vec<El>) -> El {
        placeholder("Traffic", ui)
    }
}
