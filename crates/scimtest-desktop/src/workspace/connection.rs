use std::path::PathBuf;

use rune::{FileDialogOptions, Tx};
use scimtest_core::Error;

use super::Workspace;

impl Workspace {
    /// Copies an environment's connection config JSON, or with `save` writes it to a file
    /// the user picks.
    pub(super) fn export_connection(&mut self, environment: String, save: bool, tx: &mut Tx) {
        if self.busy {
            return;
        }
        let Some(directory) = self
            .directories
            .iter()
            .find(|directory| directory.environment.id == environment)
        else {
            return;
        };
        let file_name = format!("{}-config.json", directory.environment.slug);
        self.busy = true;
        self.message.clear();
        self.failed = false;
        if !save {
            self.write_connection(environment, None);
            return;
        }
        let options = FileDialogOptions {
            title: "Save config JSON".into(),
            directory: Some(dirs::document_dir().unwrap_or_else(std::env::temp_dir)),
            file_name: Some(file_name),
            ..Default::default()
        }
        .filter("JSON", &["json"]);
        tx.save_file(options, move |s: &mut Workspace, result, _| match result {
            Ok(Some(path)) => s.write_connection(environment, Some(path)),
            Ok(None) => s.busy = false,
            Err(error) => {
                s.busy = false;
                s.fail(format!("Could not open the save dialog: {error}"));
            }
        });
    }

    /// Writes the config to `path`, or copies its JSON without one.
    fn write_connection(&self, environment: String, path: Option<PathBuf>) {
        let store = self.store.clone();
        let tunnel = self.tunnel_service.clone();
        let local_base = self.api_url.clone();
        let work = self.executor.spawn_blocking(move || {
            let base = tunnel.effective_base(&local_base)?;
            if let Some(path) = path {
                store.write_connection_config(&environment, &base, &path)?;
                return Ok::<_, Error>((None, format!("Config saved to {}", path.display())));
            }
            let json =
                serde_json::to_string_pretty(&store.connection_config(&environment, &base)?)?;
            Ok((Some(json), "Config JSON copied".into()))
        });
        self.task(work, |s, result, tx| {
            s.busy = false;
            match result {
                Ok(Ok((json, message))) => {
                    if let Some(json) = json {
                        tx.copy(json);
                    }
                    s.message = message;
                    s.failed = false;
                }
                Ok(Err(error)) => s.fail(error.to_string()),
                Err(error) => s.fail(error.to_string()),
            }
        });
    }
}
