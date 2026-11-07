use rune::El;
use serde_json::Value;

use super::{Workspace, view::placeholder};
use crate::theme::Ui;

#[derive(Default)]
pub(super) struct Inspector {
    pub inspections: Vec<Value>,
    pub logouts: Vec<Value>,
}

impl Workspace {
    pub(super) fn run_saml(&mut self) {}

    pub(super) fn saml_inspector(&self, ui: &Ui, _layer: &mut Vec<El>) -> El {
        placeholder("SAML Inspector", ui)
    }
}
