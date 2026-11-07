use rune::{El, TextEdit};
use scimtest_core::{Error, configuration::SettingsPatch, model::*};

use super::{Workspace, view::placeholder};
use crate::theme::Ui;

#[derive(Clone, Copy)]
pub(super) enum Section {
    Basics,
}

pub(super) struct EnvironmentForm;

impl EnvironmentForm {
    pub fn new(_environment: Option<&Environment>) -> Result<Self, Error> {
        Ok(Self)
    }

    pub fn patch(&self) -> Result<SettingsPatch, Error> {
        Ok(SettingsPatch::default())
    }

    pub fn first_error(&self, _name: &TextEdit) -> Option<(Section, String)> {
        None
    }

    pub fn body(
        &self,
        _workspace: &Workspace,
        _name: &TextEdit,
        _slug: &TextEdit,
        _id: Option<&str>,
        ui: &Ui,
        _layer: &mut Vec<El>,
    ) -> El {
        placeholder("Environment settings", ui)
    }

    pub fn nav(&self, _workspace: &Workspace, _ui: &Ui) -> El {
        rune::el()
    }
}

impl Workspace {
    pub(super) fn show_environment_error(&mut self, _section: Section, message: String) {
        self.fail(message);
    }
}
