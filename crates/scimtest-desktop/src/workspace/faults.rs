use rune::El;
use scimtest_core::{Error, oidc::Faults};

use super::{Workspace, view::placeholder};
use crate::theme::Ui;

pub(super) struct Form;

impl Form {
    pub fn values(&self) -> Result<Faults, Error> {
        Ok(Faults::default())
    }

    pub fn fields(&self, _workspace: &Workspace, ui: &Ui, _layer: &mut Vec<El>) -> El {
        placeholder("Custom faults", ui)
    }
}
