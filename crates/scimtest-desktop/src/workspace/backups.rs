use std::{io::Read, path::PathBuf};

use rune::{FileDialogOptions, FileDialogResult, Tx};
use scimtest_core::{Error, backup::StateBackup};

use super::{Editor, Workspace};

/// Backups larger than this are refused before parsing.
const BACKUP_LIMIT: usize = 25 << 20;

fn documents() -> PathBuf {
    dirs::document_dir().unwrap_or_else(std::env::temp_dir)
}

impl Workspace {
    pub(super) fn export_backup(&mut self, tx: &mut Tx) {
        let Some(directory) = self.directory() else {
            return;
        };
        let environment = directory.environment.id.clone();
        let options = FileDialogOptions {
            directory: Some(documents()),
            file_name: Some(format!("{}-backup.json", directory.environment.slug)),
            ..Default::default()
        };
        tx.save_file(
            options,
            move |s: &mut Workspace, result: FileDialogResult, _: &mut Tx| match result {
                Ok(Some(path)) => s.command(move |store| {
                    store.write_backup(&environment, &path)?;
                    Ok((format!("Backup saved to {}", path.display()), None))
                }),
                Ok(None) => {}
                Err(error) => s.fail(format!("Could not open the save dialog: {error}")),
            },
        );
    }

    pub(super) fn import_backup(&mut self, tx: &mut Tx) {
        let options = FileDialogOptions {
            title: "Choose an environment backup".into(),
            directory: Some(documents()),
            ..Default::default()
        };
        tx.open_file(
            options,
            |s: &mut Workspace, result: FileDialogResult, _: &mut Tx| match result {
                Ok(Some(path)) => s.read_backup(path),
                Ok(None) => {}
                Err(error) => s.fail(format!("Could not open the file dialog: {error}")),
            },
        );
    }

    fn read_backup(&mut self, path: PathBuf) {
        self.background(
            move || {
                let mut data = Vec::new();
                std::fs::File::open(path)?
                    .take(BACKUP_LIMIT as u64 + 1)
                    .read_to_end(&mut data)?;
                if data.len() > BACKUP_LIMIT {
                    return Err(Error::Validation("Backup is larger than 25 MiB".into()));
                }
                Ok::<StateBackup, Error>(serde_json::from_slice(&data)?)
            },
            |s, read| match read {
                Ok(backup)
                    if Some(&backup.state.environment.id) == s.selected.as_ref()
                        && backup.version == 1 =>
                {
                    s.open_editor(Editor::RestoreBackup {
                        backup: Box::new(backup),
                    });
                }
                Ok(_) => s.fail("Choose a version 1 backup for the selected environment".into()),
                Err(error) => s.fail(error.to_string()),
            },
        );
    }
}
