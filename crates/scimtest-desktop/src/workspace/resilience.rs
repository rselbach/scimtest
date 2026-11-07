use rune::El;
use scimtest_core::oidc::{Faults, ResiliencePreset, ResilienceRun};

use super::{Workspace, view::placeholder};
use crate::theme::Ui;

#[derive(Default)]
pub(super) struct Inspector {
    pub presets: Vec<ResiliencePreset>,
    pub run: Option<ResilienceRun>,
    pub manual: Faults,
}

impl Workspace {
    pub(super) fn resilience_active(&self) -> bool {
        false
    }

    pub(super) fn disarm_resilience(&mut self) {}

    pub(super) fn resilience_inspector(&self, ui: &Ui, _layer: &mut Vec<El>) -> El {
        placeholder("Fault Injection", ui)
    }
}
